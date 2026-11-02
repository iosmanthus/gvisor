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
	"gvisor.dev/gvisor/pkg/context"
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

	// MarkDetached tells the group that vfs removed m from its object.
	//
	// Preconditions: The caller holds no vfs, filesystem, or mark lock.
	MarkDetached(ctx context.Context, m *FanotifyMark)
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

// FanotifyMark is one mark of one group on one object.
//
// +stateify savable
type FanotifyMark struct{}

// MaxFanotifyGroups is the number of fanotify groups in one sandbox. Linux
// limits groups for each user (fs.fanotify.max_user_groups, default 128).
// gVisor has no per-user counts, so the limit applies to the whole sandbox.
const MaxFanotifyGroups = 128

// FanotifyGroupsAdd adds delta to the number of live fanotify groups and
// returns the new number.
func (vfs *VirtualFilesystem) FanotifyGroupsAdd(delta int64) int64 {
	return vfs.fanotifyGroups.Add(delta)
}
