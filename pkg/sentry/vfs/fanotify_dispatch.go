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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Roles of a mark in one event.
const (
	fanRoleInode uint8 = iota
	fanRoleParent
	fanRoleMount
	fanRoleFS
)

// fanotifyEventFlags are the event flags. Groups without FID reporting never
// report them.
const fanotifyEventFlags = linux.FAN_ONDIR | linux.FAN_EVENT_ON_CHILD

// fanotifySnapMax is the number of marks that a snapshot holds on the stack.
const fanotifySnapMax = 8

// fanotifySnap is a copy of one mark, taken under its container lock.
type fanotifySnap struct {
	group  FanotifyGroup
	role   uint8
	mask   uint64
	ignore uint64
}

// fanotifyApplicable is Linux fsnotify_mask_applicable().
func fanotifyApplicable(mask uint64, isDir bool, role uint8) bool {
	if isDir && mask&linux.FAN_ONDIR == 0 {
		return false
	}
	if role == fanRoleParent && mask&linux.FAN_EVENT_ON_CHILD == 0 {
		return false
	}
	return true
}

// fanotifyEffectiveIgnore is Linux fsnotify_effective_ignore_mask() for a
// legacy ignored mask (FAN_MARK_IGNORED_MASK): it applies to directories,
// and to children when the mark watches children.
func fanotifyEffectiveIgnore(s *fanotifySnap, isDir bool) uint64 {
	if s.ignore == 0 {
		return 0
	}
	if !isDir && s.role != fanRoleParent {
		return s.ignore
	}
	flags := uint64(linux.FAN_ONDIR) | s.mask&linux.FAN_EVENT_ON_CHILD
	if !fanotifyApplicable(flags, isDir, s.role) {
		return 0
	}
	return s.ignore &^ fanotifyEventFlags
}

// fanotifyGroupMask is Linux fanotify_group_event_mask() for a group without
// FID reporting. snaps are the marks of one group that apply to the event.
// It returns the mask to report, or 0.
func fanotifyGroupMask(snaps []fanotifySnap, event uint64, isDir bool) uint64 {
	var marks, ignore uint64
	for i := range snaps {
		s := &snaps[i]
		ignore |= fanotifyEffectiveIgnore(s, isDir)
		if !fanotifyApplicable(s.mask, isDir, s.role) {
			continue
		}
		marks |= s.mask
	}
	return event & marks &^ ignore &^ fanotifyEventFlags
}

// snapInto appends to dst a copy of each mark of c that has a bit of event
// in its mask or ignored mask. For FAN_MODIFY it first clears the ignored
// masks that do not survive modification (Linux send_to_group()), so the
// modification itself is not ignored.
func (c *fanotifyMarks) snapInto(dst []fanotifySnap, role uint8, event uint64) []fanotifySnap {
	if c.interest.Load()&event == 0 {
		return dst
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, m := range c.marks {
		if event&linux.FAN_MODIFY != 0 && !m.surv.Load() && m.ignore.Load() != 0 {
			m.ignore.Store(0)
		}
		mask, ignore := m.mask.Load(), m.ignore.Load()
		if (mask|ignore)&event == 0 {
			continue
		}
		dst = append(dst, fanotifySnap{group: m.group, role: role, mask: mask, ignore: ignore})
	}
	return dst
}

// fanotifyPathEvent delivers event on vd, whose file type is ftype (S_IFMT
// bits), to all groups with matching marks. It returns the first error from
// a group, which is EPERM if a permission group denies the operation.
//
// Preconditions: The caller holds no vfs, filesystem, or mark lock.
func (vfs *VirtualFilesystem) fanotifyPathEvent(ctx context.Context, vd VirtualDentry, ftype uint32, event uint64) error {
	// Groups without FID reporting only see regular files and directories.
	if ftype != linux.S_IFREG && ftype != linux.S_IFDIR {
		return nil
	}
	isDir := ftype == linux.S_IFDIR
	var buf [fanotifySnapMax]fanotifySnap
	snaps := buf[:0]
	snaps = vd.mount.fanotify.snapInto(snaps, fanRoleMount, event)
	snaps = vd.mount.fs.fanotify.snapInto(snaps, fanRoleFS, event)
	if ws := vd.dentry.Watches(); ws != nil {
		snaps = ws.fanotify.snapInto(snaps, fanRoleInode, event)
	}
	if pp, ok := vd.dentry.impl.(FanotifyParentProvider); ok && vfs.fanotifyInodeMarks.Load() != 0 {
		if parent := pp.LockParentWatches(); parent != nil {
			snaps = parent.fanotify.snapInto(snaps, fanRoleParent, event)
		}
		pp.UnlockParentWatches()
	}
	if len(snaps) == 0 {
		return nil
	}
	// Deliver in priority order: pre-content, content, notification groups
	// (Linux fsnotify_compare_groups()), and each group once.
	fanotifySortSnaps(snaps)
	for i := 0; i < len(snaps); {
		j := i + 1
		for j < len(snaps) && snaps[j].group == snaps[i].group {
			j++
		}
		if mask := fanotifyGroupMask(snaps[i:j], event, isDir); mask != 0 {
			ev := FanotifyEventInfo{Target: vd, Mask: mask}
			if err := snaps[i].group.HandleEvent(ctx, &ev); err != nil {
				return err
			}
		}
		i = j
	}
	return nil
}

// fanotifySortSnaps sorts snaps by group priority (highest first), then by
// group ID. It is an insertion sort: snapshots are short, and it does not make
// the stack array of the caller escape to the heap as sort.Slice would.
func fanotifySortSnaps(snaps []fanotifySnap) {
	less := func(a, b *fanotifySnap) bool {
		pa, pb := a.group.Priority(), b.group.Priority()
		if pa != pb {
			return pa > pb
		}
		return a.group.ID() < b.group.ID()
	}
	for i := 1; i < len(snaps); i++ {
		for j := i; j > 0 && less(&snaps[j], &snaps[j-1]); j-- {
			snaps[j], snaps[j-1] = snaps[j-1], snaps[j]
		}
	}
}

// fanotifyInodeModify handles a modification that has no path (truncate,
// mtime change). Groups without FID reporting get no event, but ignored
// masks that do not survive modification are cleared.
func fanotifyInodeModify(d *Dentry, fs *Filesystem) {
	var buf [fanotifySnapMax]fanotifySnap
	if ws := d.Watches(); ws != nil {
		ws.fanotify.snapInto(buf[:0], fanRoleInode, linux.FAN_MODIFY)
	}
	if fs != nil {
		fs.fanotify.snapInto(buf[:0], fanRoleFS, linux.FAN_MODIFY)
	}
}

// FanotifyParentProvider is implemented by DentryImpls that support
// FAN_EVENT_ON_CHILD.
type FanotifyParentProvider interface {
	// LockParentWatches takes the filesystem's ancestry lock for reading and
	// returns the Watches of the parent, or nil if there is no parent. The
	// caller must not block, must not take group locks, and must call
	// UnlockParentWatches.
	LockParentWatches() *Watches

	// UnlockParentWatches releases the lock that LockParentWatches took.
	UnlockParentWatches()
}

// CheckAccessPerm sends FAN_ACCESS_PERM for a read from fd (Linux
// rw_verify_area()). It returns EPERM if a listener denies the read, or a
// restart error if a fatal signal or a stop interrupted the wait.
//
// Preconditions: The caller holds no vfs, filesystem, or mark lock.
func (fd *FileDescription) CheckAccessPerm(ctx context.Context) error {
	if fd.opts.NoNotify {
		return nil
	}
	vfs := fd.vd.mount.vfs
	if vfs.fanotifyMarks.Load() == 0 {
		return nil
	}
	return vfs.fanotifyPathEvent(ctx, fd.vd, fd.fileType(ctx), linux.FAN_ACCESS_PERM)
}

// checkReadPerm is CheckAccessPerm for Read and PRead: it does nothing if the
// caller already checked this operation, and nothing for a zero-length vector
// (Linux do_readv()).
func (fd *FileDescription) checkReadPerm(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) error {
	if opts.FanotifyChecked || (opts.Vector && dst.NumBytes() == 0) {
		return nil
	}
	return fd.CheckAccessPerm(ctx)
}
