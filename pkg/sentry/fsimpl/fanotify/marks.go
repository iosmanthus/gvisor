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
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// MaxMarks is the number of marks of one group without FAN_UNLIMITED_MARKS.
// Linux counts marks for each user (fs.fanotify.max_user_marks, at least
// 8192). gVisor has no per-user counts, so the limit applies to each group.
const MaxMarks = 8192

// pruneLocked drops marks that vfs detached.
//
// +checklocks:g.markMu
func (g *Group) pruneLocked() {
	n := 0
	for _, m := range g.marks {
		if !m.Detached() {
			g.marks[n] = m
			n++
		}
	}
	clear(g.marks[n:])
	g.marks = g.marks[:n]
}

// UpdateMark implements fanotify_mark(2) FAN_MARK_ADD (add is true) and
// FAN_MARK_REMOVE after the syscall layer checked and normalized the
// arguments. If ignored is true, mask applies to the ignored mask.
func (g *Group) UpdateMark(ctx context.Context, vd vfs.VirtualDentry, kind uint8, add bool, mask uint64, ignored, surv bool) error {
	var markMask, ignoreMask uint64
	if ignored {
		ignoreMask = mask
	} else {
		markMask = mask
	}
	g.markMu.Lock()
	defer g.markMu.Unlock()
	g.pruneLocked()
	m, created, err := g.vfsObj.FanotifyUpdateMark(ctx, g, vd, kind, add, markMask, ignoreMask, surv, func() bool {
		return g.flags&linux.FAN_UNLIMITED_MARKS != 0 || len(g.marks) < MaxMarks
	})
	if err != nil {
		return err
	}
	if created {
		g.marks = append(g.marks, m)
	}
	return nil
}

// Flush implements fanotify_mark(2) FAN_MARK_FLUSH: it removes all marks of
// kind.
func (g *Group) Flush(ctx context.Context, kind uint8) {
	g.markMu.Lock()
	defer g.markMu.Unlock()
	for _, m := range g.marks {
		if m.Kind() == kind {
			m.Detach(ctx)
		}
	}
	g.pruneLocked()
}
