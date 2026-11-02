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

package fanotify

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// mergeKey identifies the events that merge (Linux fanotify_should_merge()):
// the same object and the same origin.
type mergeKey struct {
	mnt *vfs.Mount
	d   *vfs.Dentry
	key originKey
}

// tryMergeLocked ORs the mask of ev into the newest queued event with the
// same key, and returns true if there is one. Linux searches up to 128
// events of one hash bucket, newest first; a map to the newest event gives
// the same result while fewer than 128 other events share the bucket.
//
// +checklocks:g.queueMu
func (g *Group) tryMergeLocked(ev *event, vd vfs.VirtualDentry) bool {
	if ev.perm != nil {
		return false // Linux never merges permission events.
	}
	old, ok := g.merge[mergeKey{vd.Mount(), vd.Dentry(), ev.origin.key}]
	if !ok {
		return false
	}
	old.mask |= ev.mask
	return true
}

// rememberLocked records ev as the newest queued event of its key.
//
// +checklocks:g.queueMu
func (g *Group) rememberLocked(ev *event) {
	if ev.perm == nil && ev.vd.Ok() {
		g.merge[mergeKey{ev.vd.Mount(), ev.vd.Dentry(), ev.origin.key}] = ev
	}
}

// forgetLocked removes ev from the merge map when it leaves the queue.
//
// +checklocks:g.queueMu
func (g *Group) forgetLocked(ev *event) {
	if ev.perm != nil || !ev.vd.Ok() {
		return
	}
	k := mergeKey{ev.vd.Mount(), ev.vd.Dentry(), ev.origin.key}
	if g.merge[k] == ev {
		delete(g.merge, k)
	}
}

// addOverflowLocked queues the overflow event unless it is queued already.
// It does not count against the queue limit (Linux fsnotify_insert_event()).
//
// +checklocks:g.queueMu
func (g *Group) addOverflowLocked() {
	if g.overflowQueued {
		return
	}
	g.overflowQueued = true
	g.pushLocked(&event{mask: linux.FAN_Q_OVERFLOW})
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl. It supports FIONREAD.
func (g *Group) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	if args[1].Int() != linux.FIONREAD {
		return 0, linuxerr.ENOTTY
	}
	g.queueMu.Lock()
	n := uint32(g.qlen * metadataLen)
	g.queueMu.Unlock()
	var buf [4]byte
	hostarch.ByteOrder.PutUint32(buf[:], n)
	_, err := uio.CopyOut(ctx, args[2].Pointer(), buf[:], usermem.IOOpts{})
	return 0, err
}
