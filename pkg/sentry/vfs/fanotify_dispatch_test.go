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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestFanotifyGroupMask(t *testing.T) {
	const (
		acc  = linux.FAN_ACCESS
		mod  = linux.FAN_MODIFY
		open = linux.FAN_OPEN
		dir  = linux.FAN_ONDIR
		kid  = linux.FAN_EVENT_ON_CHILD
	)
	for _, tc := range []struct {
		name  string
		snaps []fanotifySnap
		event uint64
		isDir bool
		want  uint64
	}{
		{"file with a filesystem mark", []fanotifySnap{{role: fanRoleFS, mask: acc}}, acc, false, acc},
		{"directory needs FAN_ONDIR", []fanotifySnap{{role: fanRoleFS, mask: acc}}, acc, true, 0},
		{"FAN_ONDIR is not reported", []fanotifySnap{{role: fanRoleFS, mask: acc | dir}}, acc, true, acc},
		{"FAN_ONDIR applies to each mark", []fanotifySnap{{role: fanRoleMount, mask: open | dir}, {role: fanRoleFS, mask: acc}}, acc, true, 0},
		{"parent needs FAN_EVENT_ON_CHILD", []fanotifySnap{{role: fanRoleParent, mask: acc}}, acc, false, 0},
		{"parent with FAN_EVENT_ON_CHILD", []fanotifySnap{{role: fanRoleParent, mask: acc | kid}}, acc, false, acc},
		{"ignore-only inode mark suppresses a filesystem mark", []fanotifySnap{{role: fanRoleFS, mask: acc}, {role: fanRoleInode, ignore: acc}}, acc, false, 0},
		{"legacy ignore mask applies to directories", []fanotifySnap{{role: fanRoleFS, mask: acc | dir}, {role: fanRoleInode, ignore: acc}}, acc, true, 0},
		{"parent ignore mask needs the parent child flag", []fanotifySnap{{role: fanRoleFS, mask: acc}, {role: fanRoleParent, ignore: acc}}, acc, false, acc},
		{"parent ignore mask with the child flag", []fanotifySnap{{role: fanRoleFS, mask: acc}, {role: fanRoleParent, mask: kid, ignore: acc}}, acc, false, 0},
		{"event without a subscription", []fanotifySnap{{role: fanRoleFS, mask: acc}}, mod, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fanotifyGroupMask(tc.snaps, tc.event, tc.isDir); got != tc.want {
				t.Errorf("fanotifyGroupMask() = %#x, want %#x", got, tc.want)
			}
		})
	}
}
