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

// Package fanotify implements fanotify groups, the file descriptions that
// fanotify_init(2) returns.
package fanotify

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

// InitFlags are the fanotify_init(2) flags that gVisor supports.
const InitFlags = linux.FAN_CLOEXEC | linux.FAN_NONBLOCK | linux.FAN_ALL_CLASS_BITS |
	linux.FAN_UNLIMITED_QUEUE | linux.FAN_UNLIMITED_MARKS | linux.FAN_REPORT_TID

// EventFFlags are the event_f_flags that Linux accepts
// (FANOTIFY_INIT_ALL_EVENT_F_BITS).
const EventFFlags = linux.O_ACCMODE | linux.O_APPEND | linux.O_NONBLOCK |
	linux.O_SYNC | linux.O_DSYNC | linux.O_CLOEXEC | linux.O_LARGEFILE | linux.O_NOATIME

// Group is a fanotify group. It implements vfs.FileDescriptionImpl and
// vfs.FanotifyGroup.
//
// +stateify savable
type Group struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	vfsObj      *vfs.VirtualFilesystem
	id          uint64
	flags       uint32 // fanotify_init flags
	eventFFlags uint32 // normalized event_f_flags

	// queue wakes readers and epoll. It is saved: epoll registrations live
	// here.
	queue waiter.Queue

	// markMu protects marks. It is the outermost fanotify lock: it can be
	// held while vfs mark containers and filesystem locks are taken.
	markMu groupMarkMutex `state:"nosave"`

	// marks are the marks of this group. vfs can detach a mark when its
	// object goes away; such marks stay here until the group next prunes.
	//
	// +checklocks:markMu
	marks []*vfs.FanotifyMark

	// queueMu protects the event queue. It is the innermost fanotify lock.
	queueMu groupQueueMutex `state:"nosave"`

	// events is the queue of events not yet read.
	//
	// +checklocks:queueMu
	events eventList

	// qlen is the length of events.
	//
	// +checklocks:queueMu
	qlen int

	// overflowQueued is true while the overflow event is in events.
	//
	// +checklocks:queueMu
	overflowQueued bool

	// merge maps the key of each queued notification event to the newest
	// such event. It is rebuilt on restore.
	//
	// +checklocks:queueMu
	merge map[mergeKey]*event `state:"nosave"`

	// shutdown is set when the group is released. No event is queued after.
	//
	// +checklocks:queueMu
	shutdown bool
}

var _ vfs.FileDescriptionImpl = (*Group)(nil)
var _ vfs.FanotifyGroup = (*Group)(nil)

// New creates a group. The caller checked privilege and flags.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, flags, eventFFlags uint32) (*vfs.FileDescription, error) {
	if vfsObj.FanotifyGroupsAdd(1) > vfs.MaxFanotifyGroups {
		vfsObj.FanotifyGroupsAdd(-1)
		return nil, linuxerr.EMFILE
	}
	vd := vfsObj.NewAnonVirtualDentry("[fanotify]")
	defer vd.DecRef(ctx)
	g := &Group{
		vfsObj: vfsObj,
		merge:  make(map[mergeKey]*event),
		id:     uniqueid.GlobalFromContext(ctx),
		flags:  flags,
		// Linux adds O_LARGEFILE on 64-bit (force_o_largefile()).
		eventFFlags: eventFFlags | linux.O_LARGEFILE,
	}
	fileFlags := uint32(linux.O_RDWR)
	if flags&linux.FAN_NONBLOCK != 0 {
		fileFlags |= linux.O_NONBLOCK
	}
	if err := g.vfsfd.Init(g, fileFlags, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		vfsObj.FanotifyGroupsAdd(-1)
		return nil, err
	}
	return &g.vfsfd, nil
}

// ID implements vfs.FanotifyGroup.ID.
func (g *Group) ID() uint64 {
	return g.id
}

// Priority implements vfs.FanotifyGroup.Priority.
func (g *Group) Priority() int {
	switch g.flags & linux.FAN_ALL_CLASS_BITS {
	case linux.FAN_CLASS_PRE_CONTENT:
		return 2
	case linux.FAN_CLASS_CONTENT:
		return 1
	default:
		return 0
	}
}

// Release implements vfs.FileDescriptionImpl.Release.
func (g *Group) Release(ctx context.Context) {
	g.markMu.Lock()
	for _, m := range g.marks {
		m.Detach(ctx)
	}
	g.marks = nil
	g.markMu.Unlock()

	var drop []vfs.VirtualDentry
	g.queueMu.Lock()
	g.shutdown = true
	for ev := g.events.Front(); ev != nil; ev = g.events.Front() {
		g.events.Remove(ev)
		if ev.vd.Ok() {
			drop = append(drop, ev.vd)
		}
	}
	g.qlen = 0
	clear(g.merge)
	g.overflowQueued = false
	g.queueMu.Unlock()
	// Drop references without queueMu: a drop can run filesystem teardown.
	for _, vd := range drop {
		vd.DecRef(ctx)
	}
	g.vfsObj.FanotifyGroupsAdd(-1)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (g *Group) EventRegister(e *waiter.Entry) error {
	g.queue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (g *Group) EventUnregister(e *waiter.Entry) {
	g.queue.EventUnregister(e)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (g *Group) Epollable() bool {
	return true
}
