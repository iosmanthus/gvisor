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

// Permission event states (Linux FAN_EVENT_*).
const (
	// permQueued: the event is in the queue.
	permQueued = iota

	// permReported: a reader took the event, or it is on the access list.
	permReported

	// permAnswered: the event has an answer; the waiter owns it.
	permAnswered

	// permCanceled: the waiter left; the reader or the access list owns the
	// event.
	permCanceled
)

// permState is the permission part of an event.
//
// +stateify savable
type permState struct {
	state    int
	response uint32

	// fd is the event fd number that the reader got, or -1.
	fd int32

	// done is closed when the event gets an answer.
	done chan struct{} `state:"nosave"`
}

// answerLocked answers ev and wakes its waiter, which then owns ev.
//
// +checklocks:g.queueMu
func (g *Group) answerLocked(ev *event, response uint32) {
	ev.perm.state = permAnswered
	ev.perm.response = response
	close(ev.perm.done)
}

// handlePermEvent queues a FAN_ACCESS_PERM event and waits for the answer,
// as Linux fanotify_get_response() does.
func (g *Group) handlePermEvent(ctx context.Context, info *vfs.FanotifyEventInfo) error {
	// Only the task goroutine itself can wait. Other contexts (an AIO
	// goroutine, the supervisor) get no permission event.
	t, ok := ctx.(*kernel.Task)
	if !ok {
		return nil
	}
	ev := &event{
		mask:   info.Mask,
		origin: originFromContext(ctx, g.flags),
		perm:   &permState{state: permQueued, fd: -1, done: make(chan struct{})},
	}
	g.queueMu.Lock()
	if g.shutdown {
		g.queueMu.Unlock()
		return nil
	}
	if !g.roomLocked() {
		// A full queue allows the operation at once (Linux
		// fanotify_handle_event()).
		g.addOverflowLocked()
		g.queueMu.Unlock()
		g.queue.Notify(waiter.ReadableEvents)
		return nil
	}
	info.Target.IncRef()
	ev.vd = info.Target
	g.pushLocked(ev)
	g.queueMu.Unlock()
	g.queue.Notify(waiter.ReadableEvents)

	// Only a fatal signal or a stop request (for example a checkpoint) ends
	// the wait early, as with Linux TASK_KILLABLE.
	err := t.BlockKillable(ev.perm.done)

	g.queueMu.Lock()
	if err != nil && ev.perm.state != permAnswered {
		if ev.perm.state == permQueued {
			// Nobody saw the event: remove it.
			g.events.Remove(ev)
			g.qlen--
			g.queueMu.Unlock()
			ev.vd.DecRef(ctx)
		} else {
			// A reader has the event or it is on the access list; a later
			// answer consumes it.
			ev.perm.state = permCanceled
			g.queueMu.Unlock()
		}
		// Linux can only end this wait for a fatal signal, so the caller
		// never sees the error. gVisor also ends it for a stop (for example a
		// checkpoint); the operation must then restart, also when a signal
		// handler runs first.
		return linuxerr.ERESTARTNOINTR
	}
	resp := ev.perm.response
	g.queueMu.Unlock()
	ev.vd.DecRef(ctx)
	if resp == linux.FAN_DENY {
		return linuxerr.EPERM
	}
	return nil
}

// finishPermEvent completes a read attempt of a permission event (Linux
// copy_event_to_user() and fanotify_read()).
func (g *Group) finishPermEvent(ctx context.Context, ev *event, err error) {
	g.queueMu.Lock()
	if err == nil {
		// Also a canceled event goes to the access list, so that a later
		// answer consumes it.
		g.access.PushBack(ev)
		g.queueMu.Unlock()
		return
	}
	if ev.perm.state == permCanceled {
		g.queueMu.Unlock()
		ev.vd.DecRef(ctx)
		return
	}
	g.answerLocked(ev, linux.FAN_DENY)
	g.queueMu.Unlock()
}

// Write implements vfs.FileDescriptionImpl.Write. It takes a struct
// fanotify_response (Linux process_access_response()).
func (g *Group) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	var r linux.FanotifyResponse
	n := int64(r.SizeBytes())
	if src.NumBytes() < n {
		return 0, linuxerr.EINVAL
	}
	var buf [8]byte
	if _, err := src.CopyIn(ctx, buf[:]); err != nil {
		return 0, err
	}
	r.UnmarshalUnsafe(buf[:])
	if r.Response != linux.FAN_ALLOW && r.Response != linux.FAN_DENY {
		return 0, linuxerr.EINVAL
	}
	if r.FD < 0 {
		return 0, linuxerr.EINVAL
	}
	g.queueMu.Lock()
	// The ABI has no event identifier: answer the first event that has this
	// fd number.
	for ev := g.access.Front(); ev != nil; ev = ev.Next() {
		if ev.perm.fd != r.FD {
			continue
		}
		g.access.Remove(ev)
		if ev.perm.state == permCanceled {
			g.queueMu.Unlock()
			ev.vd.DecRef(ctx)
			return n, nil
		}
		g.answerLocked(ev, r.Response)
		g.queueMu.Unlock()
		return n, nil
	}
	g.queueMu.Unlock()
	return 0, linuxerr.ENOENT
}
