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
	"context"
)

// beforeSave drops the marks that vfs detached. A detached mark can point to
// an object that cannot be saved, for example a deleted gofer dentry.
func (g *Group) beforeSave() {
	g.markMu.Lock()
	g.pruneLocked()
	g.markMu.Unlock()
}

// afterLoad rebuilds the state that is not saved.
func (g *Group) afterLoad(context.Context) {
	g.merge = make(map[mergeKey]*event)
	// No task waits for a permission event at save time: a checkpoint stops
	// all tasks, which ends their waits. The channels only need to exist.
	for ev := g.events.Front(); ev != nil; ev = ev.Next() { // +checklocksignore
		if ev.perm != nil {
			ev.perm.done = make(chan struct{})
			continue
		}
		g.rememberLocked(ev) // +checklocksforce: not yet visible.
	}
	for ev := g.access.Front(); ev != nil; ev = ev.Next() { // +checklocksignore
		ev.perm.done = make(chan struct{})
	}
}
