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
	"bytes"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// FanotifyGroup is a fanotify group, implemented by
// pkg/sentry/fsimpl/fanotify. vfs uses it to deliver events.
type FanotifyGroup interface {
	// ID is unique for the life of the group.
	ID() uint64

	// Priority is 2 for FAN_CLASS_PRE_CONTENT, 1 for FAN_CLASS_CONTENT, and
	// 0 for FAN_CLASS_NOTIF. It does not change.
	Priority() int

	// HandleEvent queues an event for this group. For a permission event it
	// blocks the calling task until the listener answers, and returns
	// linuxerr.EPERM if the listener denies the operation.
	//
	// Preconditions: The caller holds no vfs, filesystem, or mark lock.
	HandleEvent(ctx context.Context, ev *FanotifyEventInfo) error

}

// FanotifyEventInfo describes one event for one group.
type FanotifyEventInfo struct {
	// Target is the object of the event. HandleEvent takes its own
	// references if it keeps Target.
	Target VirtualDentry

	// Mask is the reported mask: FAN_* event bits only, without FAN_ONDIR
	// and FAN_EVENT_ON_CHILD.
	Mask uint64
}


// MaxFanotifyGroups is the number of fanotify groups in one sandbox. Linux
// limits groups for each user (fs.fanotify.max_user_groups, default 128).
// gVisor has no per-user counts, so the limit applies to the whole sandbox.
const MaxFanotifyGroups = 128

// FanotifyGroupsAdd adds delta to the number of live fanotify groups and
// returns the new number.
func (vfs *VirtualFilesystem) FanotifyGroupsAdd(delta int64) int64 {
	return vfs.fanotifyGroups.Add(delta)
}

// Mark kinds.
const (
	FanotifyMarkInode uint8 = iota
	FanotifyMarkMount
	FanotifyMarkFilesystem
)

// Filesystem flags for fanotify. See Filesystem.SetFanotifyFlags.
const (
	// FanotifyNoUser marks kernel-internal filesystems (Linux SB_NOUSER).
	// Mount and filesystem marks are not allowed on them.
	FanotifyNoUser = 1 << iota

	// FanotifyNoPermEvents marks filesystems that do not allow permission
	// events (Linux FS_DISALLOW_NOTIFY_PERM).
	FanotifyNoPermEvents
)

// FanotifyMark is one mark of one group on one object.
//
// A mark is detached once, by FanotifyUpdateMark, Detach, or the teardown of
// its object. Groups check Detached and drop detached marks from their own
// lists when they next use them, so teardown never calls into a group.
//
// +stateify savable
type FanotifyMark struct {
	vfs    *VirtualFilesystem
	group  FanotifyGroup
	kind   uint8
	mask   atomicbitops.Uint64
	ignore atomicbitops.Uint64
	surv   atomicbitops.Bool

	// detached is set once, by the first caller that detaches the mark.
	detached atomicbitops.Bool

	// container holds the mark. It does not change.
	container *fanotifyMarks

	// Exactly one of these is set, by kind.
	inode *Dentry
	mount *Mount
	fs    *Filesystem

	// ino and dev identify the object in fdinfo. They are set when the
	// mark is created.
	ino uint64
	dev uint64
}

// Group returns the group of m.
func (m *FanotifyMark) Group() FanotifyGroup {
	return m.group
}

// Kind returns the kind of m.
func (m *FanotifyMark) Kind() uint8 {
	return m.kind
}

// Mask returns the event mask of m, including FAN_ONDIR and
// FAN_EVENT_ON_CHILD.
func (m *FanotifyMark) Mask() uint64 {
	return m.mask.Load()
}

// Ignore returns the ignored mask of m.
func (m *FanotifyMark) Ignore() uint64 {
	return m.ignore.Load()
}

// SurvivesModify returns true if FAN_MARK_IGNORED_SURV_MODIFY is set.
func (m *FanotifyMark) SurvivesModify() bool {
	return m.surv.Load()
}

// StatIDs returns the inode number and device of the object of m.
func (m *FanotifyMark) StatIDs() (ino, dev uint64) {
	return m.ino, m.dev
}

// MountID returns the ID of the mount of a mount mark.
func (m *FanotifyMark) MountID() uint64 {
	return m.mount.ID
}

// Detached returns true if m is no longer on its object.
func (m *FanotifyMark) Detached() bool {
	return m.detached.Load()
}

// fanotifyMarks holds the marks on one object.
//
// +stateify savable
type fanotifyMarks struct {
	mu fanotifyMarksRWMutex `state:"nosave"`

	// marks maps group IDs to marks.
	//
	// +checklocks:mu
	marks map[uint64]*FanotifyMark

	// dead is set when the object goes away. No mark can be added after.
	//
	// +checklocks:mu
	dead bool

	// interest is the fast-path mask: the union of the interest of all
	// marks. It is rebuilt on restore.
	interest atomicbitops.Uint64 `state:"nosave"`
}

// fanotifyInterest returns the bits of one mark that must reach the event
// dispatcher (Linux fsnotify_calc_mask()).
func fanotifyInterest(mask, ignore uint64, surv bool) uint64 {
	in := mask | (ignore &^ (linux.FAN_ONDIR | linux.FAN_EVENT_ON_CHILD))
	if ignore != 0 && !surv {
		// A modification must reach the dispatcher to clear the ignore mask.
		in |= linux.FAN_MODIFY
	}
	return in
}

// recalcLocked rebuilds c.interest.
//
// +checklocks:c.mu
func (c *fanotifyMarks) recalcLocked() {
	var in uint64
	for _, m := range c.marks {
		in |= fanotifyInterest(m.mask.Load(), m.ignore.Load(), m.surv.Load())
	}
	c.interest.Store(in)
}

// size returns the number of marks in c.
func (c *fanotifyMarks) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.marks)
}

// detachLocked removes m from c and updates the counters. It returns false
// if m was already detached.
//
// +checklocks:c.mu
func (c *fanotifyMarks) detachLocked(m *FanotifyMark) bool {
	if !m.detached.CompareAndSwap(false, true) {
		return false
	}
	delete(c.marks, m.group.ID())
	m.vfs.fanotifyMarks.Add(-1)
	if m.kind == FanotifyMarkInode {
		m.vfs.fanotifyInodeMarks.Add(-1)
	}
	return true
}

// detachAll marks c dead and detaches all its marks. It is called when the
// object goes away; it does not call into groups, so callers can hold vfs
// and filesystem locks.
func (c *fanotifyMarks) detachAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dead = true
	for _, m := range c.marks {
		c.detachLocked(m)
	}
	c.interest.Store(0)
}

// fanotifyContainerFor returns the container of kind at vd.
func fanotifyContainerFor(vd VirtualDentry, kind uint8) (*fanotifyMarks, error) {
	switch kind {
	case FanotifyMarkMount:
		return &vd.mount.fanotify, nil
	case FanotifyMarkFilesystem:
		return &vd.mount.fs.fanotify, nil
	default:
		ws := vd.dentry.Watches()
		if ws == nil {
			return nil, linuxerr.EINVAL
		}
		return &ws.fanotify, nil
	}
}

// FanotifyUpdateMark adds bits to (add is true), or removes bits from, the
// mark of g on the object of kind at vd. newMarkAllowed is called before a
// new mark is created; if it returns false, the result is ENOSPC. Removing
// bits from an object without a mark of g returns ENOENT.
//
// Preconditions: The caller holds g's mark lock and no vfs lock.
func (vfs *VirtualFilesystem) FanotifyUpdateMark(ctx context.Context, g FanotifyGroup, vd VirtualDentry, kind uint8, add bool, mask, ignore uint64, surv bool, ino, dev uint64, newMarkAllowed func() bool) (m *FanotifyMark, created bool, err error) {
	c, err := fanotifyContainerFor(vd, kind)
	if err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	m = c.marks[g.ID()]
	if !add {
		if m == nil {
			c.mu.Unlock()
			return nil, false, linuxerr.ENOENT
		}
		m.mask.Store(m.mask.Load() &^ mask)
		m.ignore.Store(m.ignore.Load() &^ ignore)
		// A mark with only event flags left goes away (Linux
		// fanotify_remove_mark()).
		destroyed := false
		if m.mask.Load()&^(linux.FAN_ONDIR|linux.FAN_EVENT_ON_CHILD) == 0 && m.ignore.Load() == 0 {
			destroyed = c.detachLocked(m)
		}
		c.recalcLocked()
		c.mu.Unlock()
		if destroyed {
			m.afterDetach(ctx)
		}
		return m, false, nil
	}
	if m == nil {
		if c.dead {
			c.mu.Unlock()
			return nil, false, linuxerr.ENOENT
		}
		if !newMarkAllowed() {
			c.mu.Unlock()
			return nil, false, linuxerr.ENOSPC
		}
		m = &FanotifyMark{vfs: vfs, group: g, kind: kind, container: c, ino: ino, dev: dev}
		switch kind {
		case FanotifyMarkMount:
			m.mount = vd.mount
		case FanotifyMarkFilesystem:
			m.fs = vd.mount.fs
		default:
			m.inode = vd.dentry
		}
		if c.marks == nil {
			c.marks = make(map[uint64]*FanotifyMark, 1)
		}
		c.marks[g.ID()] = m
		vfs.fanotifyMarks.Add(1)
		if kind == FanotifyMarkInode {
			vfs.fanotifyInodeMarks.Add(1)
		}
		created = true
	}
	m.mask.Store(m.mask.Load() | mask)
	m.ignore.Store(m.ignore.Load() | ignore)
	if surv {
		m.surv.Store(true) // It only grows, as in Linux.
	}
	c.recalcLocked()
	c.mu.Unlock()
	return m, created, nil
}

// Detach removes m from its object. It returns true if this call detached m.
//
// Preconditions: The caller holds no vfs, filesystem, or mark container lock.
func (m *FanotifyMark) Detach(ctx context.Context) bool {
	c := m.container
	c.mu.Lock()
	ok := c.detachLocked(m)
	if ok {
		c.recalcLocked()
	}
	c.mu.Unlock()
	if ok {
		m.afterDetach(ctx)
	}
	return ok
}

// afterDetach lets the filesystem drop a dentry that only an inode mark kept
// cached, as Inotify.RmWatch does.
func (m *FanotifyMark) afterDetach(ctx context.Context) {
	if m.kind != FanotifyMarkInode {
		return
	}
	if ws := m.inode.Watches(); ws != nil && ws.Size() == 0 {
		m.inode.OnZeroWatches(ctx)
	}
}

// FDInfoProvider is implemented by FileDescriptionImpls that print
// type-specific lines in /proc/[pid]/fdinfo/[fd], after the common fields.
type FDInfoProvider interface {
	// FDInfo appends the lines to buf.
	FDInfo(ctx context.Context, buf *bytes.Buffer)
}
