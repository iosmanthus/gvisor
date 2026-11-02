// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/fanotify"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// FanotifyInit implements Linux syscall fanotify_init(2).
func FanotifyInit(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Uint()
	eventFFlags := args[1].Uint()

	// Same order as Linux fanotify_init(): privilege, then flags.
	if !t.Credentials().HasCapabilityIn(linux.CAP_SYS_ADMIN, t.Kernel().RootUserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}
	if flags&^fanotify.InitFlags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	switch flags & linux.FAN_ALL_CLASS_BITS {
	case linux.FAN_CLASS_NOTIF, linux.FAN_CLASS_CONTENT, linux.FAN_CLASS_PRE_CONTENT:
	default:
		return 0, nil, linuxerr.EINVAL
	}
	if eventFFlags&^fanotify.EventFFlags != 0 || eventFFlags&linux.O_ACCMODE == linux.O_ACCMODE {
		return 0, nil, linuxerr.EINVAL
	}
	file, err := fanotify.New(t, t.Kernel().VFS(), flags, eventFFlags)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)
	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.FAN_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

// FanotifyMark implements Linux syscall fanotify_mark(2).
func FanotifyMark(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, linuxerr.ENOSYS
}
