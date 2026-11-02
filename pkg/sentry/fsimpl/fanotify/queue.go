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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// MaxQueuedEvents is the queue size without FAN_UNLIMITED_QUEUE (Linux
// FANOTIFY_DEFAULT_MAX_EVENTS).
const MaxQueuedEvents = 16384

// metadataLen is the size of struct fanotify_event_metadata.
const metadataLen = 24

// event is one queued event.
//
// +stateify savable
type event struct {
	eventEntry

	// vd holds a reference while the event is queued or owned by a reader.
	// It is empty for the overflow event.
	vd vfs.VirtualDentry

	mask   uint64
	origin origin

	// perm is set for permission events.
	perm *permState
}

// HandleEvent implements vfs.FanotifyGroup.HandleEvent.
func (g *Group) HandleEvent(ctx context.Context, info *vfs.FanotifyEventInfo) error {
	if info.Mask&linux.FAN_ACCESS_PERM != 0 {
		return g.handlePermEvent(ctx, info)
	}
	ev := &event{mask: info.Mask, origin: originFromContext(ctx, g.flags)}
	g.queueMu.Lock()
	if g.shutdown {
		g.queueMu.Unlock()
		return nil
	}
	// Linux fsnotify_insert_event() checks for a full queue before it
	// merges.
	if !g.roomLocked() {
		g.addOverflowLocked()
		g.queueMu.Unlock()
		g.queue.Notify(waiter.ReadableEvents)
		return nil
	}
	if g.tryMergeLocked(ev, info.Target) {
		g.queueMu.Unlock()
		return nil
	}
	info.Target.IncRef()
	ev.vd = info.Target
	g.pushLocked(ev)
	g.rememberLocked(ev)
	g.queueMu.Unlock()
	g.queue.Notify(waiter.ReadableEvents)
	return nil
}

// roomLocked returns true if one more event fits in the queue.
//
// +checklocks:g.queueMu
func (g *Group) roomLocked() bool {
	return g.flags&linux.FAN_UNLIMITED_QUEUE != 0 || g.qlen < MaxQueuedEvents
}

// pushLocked appends ev to the queue.
//
// +checklocks:g.queueMu
func (g *Group) pushLocked(ev *event) {
	g.events.PushBack(ev)
	g.qlen++
}

// Read implements vfs.FileDescriptionImpl.Read. It follows Linux
// fanotify_read() and copy_event_to_user().
func (g *Group) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return 0, linuxerr.EINVAL
	}
	var done int64
	for {
		g.queueMu.Lock()
		ev := g.events.Front()
		if ev == nil {
			g.queueMu.Unlock()
			if done > 0 {
				return done, nil
			}
			return 0, linuxerr.ErrWouldBlock
		}
		if dst.NumBytes() < metadataLen {
			g.queueMu.Unlock()
			if done > 0 {
				return done, nil
			}
			return 0, linuxerr.EINVAL
		}
		// From here this reader owns the event and its references.
		g.events.Remove(ev)
		g.qlen--
		g.forgetLocked(ev)
		if ev.mask&linux.FAN_Q_OVERFLOW != 0 {
			g.overflowQueued = false
		}
		if ev.perm != nil {
			ev.perm.state = permReported
		}
		g.queueMu.Unlock()

		n, err := g.copyEvent(ctx, t, ev, dst)
		g.finishEvent(ctx, ev, err)
		if err == vfs.ErrFanotifyStale {
			continue
		}
		if err == linuxerr.EFAULT {
			// Linux returns EFAULT even after it copied earlier events.
			return 0, err
		}
		if err != nil {
			if done > 0 {
				return done, nil
			}
			return 0, err
		}
		done += n
		dst = dst.DropFirst64(n)
	}
}

// copyEvent opens the file of ev, installs its fd in the reader's FD table,
// and copies the metadata to dst.
func (g *Group) copyEvent(ctx context.Context, t *kernel.Task, ev *event, dst usermem.IOSequence) (int64, error) {
	md := linux.FanotifyEventMetadata{
		EventLen:    metadataLen,
		Vers:        linux.FANOTIFY_METADATA_VERSION,
		MetadataLen: metadataLen,
		Mask:        ev.mask,
		FD:          linux.FAN_NOFD,
		PID:         ev.origin.idIn(t.PIDNamespace()),
	}
	var file *vfs.FileDescription
	if ev.vd.Ok() {
		var err error
		file, err = g.vfsObj.OpenFanotifyEventFile(ctx, t.Credentials(), ev.vd, g.eventFFlags&^linux.O_CLOEXEC)
		if err != nil {
			return 0, err
		}
		defer file.DecRef(ctx)
		fd, err := t.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: g.eventFFlags&linux.O_CLOEXEC != 0})
		if err != nil {
			return 0, err
		}
		md.FD = fd
	}
	var buf [metadataLen]byte
	md.MarshalUnsafe(buf[:])
	if _, err := dst.CopyOut(ctx, buf[:]); err != nil {
		if file != nil {
			// Remove the fd only if its slot still holds our file: another
			// thread can close it and get the same number.
			t.FDTable().RemoveIf(ctx, func(f *vfs.FileDescription, _ kernel.FDFlags) bool {
				return f == file
			})
		}
		return 0, linuxerr.EFAULT
	}
	if ev.perm != nil {
		ev.perm.fd = md.FD
	}
	return metadataLen, nil
}

// finishEvent completes a read attempt of ev.
func (g *Group) finishEvent(ctx context.Context, ev *event, err error) {
	if ev.perm != nil {
		g.finishPermEvent(ctx, ev, err)
		return
	}
	if ev.vd.Ok() {
		ev.vd.DecRef(ctx)
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (g *Group) Readiness(mask waiter.EventMask) waiter.EventMask {
	g.queueMu.Lock()
	defer g.queueMu.Unlock()
	if g.events.Empty() {
		return 0
	}
	return mask & waiter.ReadableEvents
}

// Stubs completed by later changes.

// +checklocks:g.queueMu
func (g *Group) tryMergeLocked(ev *event, vd vfs.VirtualDentry) bool {
	return false
}

// +checklocks:g.queueMu
func (g *Group) rememberLocked(ev *event) {}

// +checklocks:g.queueMu
func (g *Group) forgetLocked(ev *event) {}

// +checklocks:g.queueMu
func (g *Group) addOverflowLocked() {}

// Permission event states.
const (
	permQueued = iota
	permReported
)

// permState is the permission part of an event.
//
// +stateify savable
type permState struct {
	state int
	fd    int32
}

func (g *Group) handlePermEvent(ctx context.Context, info *vfs.FanotifyEventInfo) error {
	return nil
}

func (g *Group) finishPermEvent(ctx context.Context, ev *event, err error) {}
