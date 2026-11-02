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

package vfs

import (
	"errors"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// ErrFanotifyStale is returned by OpenFanotifyEventFile when the object of an
// event cannot be opened again (Linux EOPENSTALE). The reader drops the
// event.
var ErrFanotifyStale = errors.New("fanotify: cannot open the event object again")

// OpenFanotifyEventFile opens vd for a fanotify event, as Linux
// fanotify_user.c:create_fd() does with dentry_open(): there is no path walk
// and no DAC check, and the new file gives no events.
func (vfs *VirtualFilesystem) OpenFanotifyEventFile(ctx context.Context, creds *auth.Credentials, vd VirtualDentry, flags uint32) (*FileDescription, error) {
	pop := PathOperation{Root: vd, Start: vd}
	fd, err := vfs.OpenAt(ctx, creds, &pop, &OpenOptions{
		Flags:        flags,
		NoNotify:     true,
		SkipDACCheck: true,
	})
	// A remote file that was deleted or replaced cannot be opened again (gofer
	// reopens by name). Linux drops such events (EOPENSTALE).
	if linuxerr.Equals(linuxerr.ESTALE, err) || linuxerr.Equals(linuxerr.ENOENT, err) {
		return nil, ErrFanotifyStale
	}
	return fd, err
}
