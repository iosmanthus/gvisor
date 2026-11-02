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
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/fanotify"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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


// fanMarkFlags are the fanotify_mark(2) flags that gVisor supports.
const fanMarkFlags = linux.FAN_MARK_ADD | linux.FAN_MARK_REMOVE | linux.FAN_MARK_DONT_FOLLOW |
	linux.FAN_MARK_ONLYDIR | linux.FAN_MARK_MOUNT | linux.FAN_MARK_IGNORED_MASK |
	linux.FAN_MARK_IGNORED_SURV_MODIFY | linux.FAN_MARK_FLUSH | linux.FAN_MARK_FILESYSTEM

// fanLinuxValidMask is every bit Linux accepts in a mask before it looks up
// the group (FANOTIFY_EVENTS | FANOTIFY_EVENT_FLAGS | FANOTIFY_PERM_EVENTS).
const fanLinuxValidMask = linux.FAN_ACCESS | linux.FAN_MODIFY | linux.FAN_ATTRIB | linux.FAN_CLOSE |
	linux.FAN_OPEN | linux.FAN_MOVED_FROM | linux.FAN_MOVED_TO | linux.FAN_CREATE | linux.FAN_DELETE |
	linux.FAN_DELETE_SELF | linux.FAN_MOVE_SELF | linux.FAN_OPEN_EXEC | linux.FAN_FS_ERROR |
	linux.FAN_RENAME | linux.FAN_OPEN_PERM | linux.FAN_ACCESS_PERM | linux.FAN_OPEN_EXEC_PERM |
	linux.FAN_ONDIR | linux.FAN_EVENT_ON_CHILD

// fanFDEvents are the bits that a group without FID reporting can use
// (FANOTIFY_FD_EVENTS plus the event flags).
const fanFDEvents = linux.FAN_ACCESS | linux.FAN_MODIFY | linux.FAN_CLOSE | linux.FAN_OPEN |
	linux.FAN_OPEN_EXEC | linux.FAN_OPEN_PERM | linux.FAN_ACCESS_PERM | linux.FAN_OPEN_EXEC_PERM |
	linux.FAN_ONDIR | linux.FAN_EVENT_ON_CHILD

// fanPermEvents are the permission events.
const fanPermEvents = linux.FAN_OPEN_PERM | linux.FAN_ACCESS_PERM | linux.FAN_OPEN_EXEC_PERM

// FanotifyMark implements Linux syscall fanotify_mark(2).
func FanotifyMark(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	gfd := args[0].Int()
	flags := args[1].Uint()
	mask := args[2].Uint64()
	dirfd := args[3].Int()
	addr := args[4].Pointer()

	// Checks before the group lookup, in the order of Linux
	// do_fanotify_mark().
	if mask>>32 != 0 || flags&^fanMarkFlags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	var kind uint8
	switch flags & (linux.FAN_MARK_MOUNT | linux.FAN_MARK_FILESYSTEM) {
	case 0:
		kind = vfs.FanotifyMarkInode
	case linux.FAN_MARK_MOUNT:
		kind = vfs.FanotifyMarkMount
	case linux.FAN_MARK_FILESYSTEM:
		kind = vfs.FanotifyMarkFilesystem
	default:
		return 0, nil, linuxerr.EINVAL
	}
	cmd := flags & (linux.FAN_MARK_ADD | linux.FAN_MARK_REMOVE | linux.FAN_MARK_FLUSH)
	switch cmd {
	case linux.FAN_MARK_ADD, linux.FAN_MARK_REMOVE:
		if mask == 0 {
			return 0, nil, linuxerr.EINVAL
		}
	case linux.FAN_MARK_FLUSH:
		if flags&^(linux.FAN_MARK_MOUNT|linux.FAN_MARK_FILESYSTEM|linux.FAN_MARK_FLUSH) != 0 {
			return 0, nil, linuxerr.EINVAL
		}
	default:
		return 0, nil, linuxerr.EINVAL
	}
	if mask&^fanLinuxValidMask != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	ignored := flags&linux.FAN_MARK_IGNORED_MASK != 0
	if ignored {
		// Event flags have no meaning in an ignored mask.
		mask &^= linux.FAN_ONDIR | linux.FAN_EVENT_ON_CHILD
	}

	f := t.GetFile(gfd)
	if f == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer f.DecRef(t)
	g, ok := f.Impl().(*fanotify.Group)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}
	// Linux checks the caller, not the group creator, for mount and
	// filesystem marks; this includes FAN_MARK_REMOVE and FAN_MARK_FLUSH.
	if kind != vfs.FanotifyMarkInode && !t.Credentials().HasCapabilityIn(linux.CAP_SYS_ADMIN, t.Kernel().RootUserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}
	if mask&fanPermEvents != 0 && g.Priority() == 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if mask&^fanFDEvents != 0 {
		// Directory entry events need FID reporting, which gVisor does not
		// support.
		return 0, nil, linuxerr.EINVAL
	}
	if mask&(linux.FAN_OPEN_PERM|linux.FAN_OPEN_EXEC_PERM) != 0 {
		// Not supported yet: these need the open path to delay O_TRUNC and
		// copy-up until the listener answers.
		return 0, nil, linuxerr.EINVAL
	}
	if cmd == linux.FAN_MARK_FLUSH {
		g.Flush(t, kind)
		return 0, nil, nil
	}

	// Resolve the object (Linux fanotify_find_path()). A NULL pathname means
	// dirfd itself.
	var path fspath.Path
	emptyPath := allowEmptyPath
	if addr != 0 {
		var err error
		if path, err = copyInPath(t, addr); err != nil {
			return 0, nil, err
		}
		emptyPath = disallowEmptyPath
	}
	if flags&linux.FAN_MARK_ONLYDIR != 0 {
		path.Dir = true
	}
	follow := followFinalSymlink
	if flags&linux.FAN_MARK_DONT_FOLLOW != 0 {
		follow = nofollowFinalSymlink
	}
	tpop, err := getTaskPathOperation(t, dirfd, path, emptyPath, follow, 0)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)
	vfsObj := t.Kernel().VFS()
	vd, err := vfsObj.GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{
		CheckSearchable: path.Dir,
	})
	if err != nil {
		return 0, nil, err
	}
	defer vd.DecRef(t)
	if err := vfsObj.AccessAt(t, t.Credentials(), vfs.MayRead, &tpop.pop); err != nil {
		return 0, nil, err
	}
	stat, err := vfsObj.StatAt(t, t.Credentials(), &vfs.PathOperation{Root: vd, Start: vd}, &vfs.StatOptions{Mask: linux.STATX_TYPE | linux.STATX_INO})
	if err != nil {
		return 0, nil, err
	}
	if path.Dir && linux.FileMode(stat.Mode).FileType() != linux.ModeDirectory {
		return 0, nil, linuxerr.ENOTDIR
	}
	if cmd == linux.FAN_MARK_ADD {
		// Linux fanotify_events_supported() runs only for FAN_MARK_ADD.
		fsFlags := vd.Mount().Filesystem().FanotifyFlags()
		if mask&fanPermEvents != 0 && fsFlags&vfs.FanotifyNoPermEvents != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if kind != vfs.FanotifyMarkInode && fsFlags&vfs.FanotifyNoUser != 0 {
			return 0, nil, linuxerr.EINVAL
		}
	}
	// FAN_EVENT_ON_CHILD only has a meaning on directory inode marks.
	if kind != vfs.FanotifyMarkInode || linux.FileMode(stat.Mode).FileType() != linux.ModeDirectory {
		mask &^= linux.FAN_EVENT_ON_CHILD
	}
	return 0, nil, g.UpdateMark(t, vd, kind, cmd == linux.FAN_MARK_ADD, mask, ignored,
		flags&linux.FAN_MARK_IGNORED_SURV_MODIFY != 0, stat.Ino, uint64(linux.MakeDeviceID(uint16(stat.DevMajor), stat.DevMinor)))
}
