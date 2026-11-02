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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// nsID is the number of an event origin in one PID namespace.
//
// +stateify savable
type nsID struct {
	ns *kernel.PIDNamespace
	id kernel.ThreadID
}

// originKey identifies an event origin for merging. Linux compares the
// struct pid of the reported kind: the thread group without FAN_REPORT_TID,
// the thread with it. The start time keeps a reused PID apart.
//
// +stateify savable
type originKey struct {
	rootID kernel.ThreadID
	start  int64
}

// origin records who caused an event. Linux keeps a struct pid, so a reader
// sees the PID also after the origin exits. gVisor removes reaped tasks from
// its PID maps, so the numbers are copied when the event happens.
//
// +stateify savable
type origin struct {
	// ids has the number of the origin in its own PID namespace and in each
	// ancestor, up to the root.
	ids []nsID
	key originKey
}

// originFromContext returns the origin of an event that happens in ctx.
func originFromContext(ctx context.Context, flags uint32) origin {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return origin{}
	}
	tid := flags&linux.FAN_REPORT_TID != 0
	tg := t.ThreadGroup()
	var o origin
	for ns := t.PIDNamespace(); ns != nil; ns = ns.Parent() {
		var id kernel.ThreadID
		if tid {
			id = ns.IDOfTask(t)
		} else {
			id = ns.IDOfThreadGroup(tg)
		}
		o.ids = append(o.ids, nsID{ns: ns, id: id})
	}
	if len(o.ids) == 0 {
		return o
	}
	o.key.rootID = o.ids[len(o.ids)-1].id
	if tid {
		o.key.start = t.StartTime().Nanoseconds()
	} else if leader := tg.Leader(); leader != nil {
		o.key.start = leader.StartTime().Nanoseconds()
	}
	return o
}

// idIn returns the number of the origin in ns, or 0 if ns cannot see the
// origin.
func (o *origin) idIn(ns *kernel.PIDNamespace) int32 {
	for _, x := range o.ids {
		if x.ns == ns {
			return int32(x.id)
		}
	}
	return 0
}
