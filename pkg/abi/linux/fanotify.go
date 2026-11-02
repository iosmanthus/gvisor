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

package linux

// Flags for fanotify_init(2), from include/uapi/linux/fanotify.h.
const (
	FAN_CLOEXEC           = 0x00000001
	FAN_NONBLOCK          = 0x00000002
	FAN_CLASS_NOTIF       = 0x00000000
	FAN_CLASS_CONTENT     = 0x00000004
	FAN_CLASS_PRE_CONTENT = 0x00000008
	FAN_ALL_CLASS_BITS    = FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT
	FAN_UNLIMITED_QUEUE   = 0x00000010
	FAN_UNLIMITED_MARKS   = 0x00000020
	FAN_ENABLE_AUDIT      = 0x00000040
	FAN_REPORT_PIDFD      = 0x00000080
	FAN_REPORT_TID        = 0x00000100
	FAN_REPORT_FID        = 0x00000200
	FAN_REPORT_DIR_FID    = 0x00000400
	FAN_REPORT_NAME       = 0x00000800
	FAN_REPORT_TARGET_FID = 0x00001000
)

// Flags for fanotify_mark(2).
const (
	FAN_MARK_ADD                 = 0x00000001
	FAN_MARK_REMOVE              = 0x00000002
	FAN_MARK_DONT_FOLLOW         = 0x00000004
	FAN_MARK_ONLYDIR             = 0x00000008
	FAN_MARK_MOUNT               = 0x00000010
	FAN_MARK_IGNORED_MASK        = 0x00000020
	FAN_MARK_IGNORED_SURV_MODIFY = 0x00000040
	FAN_MARK_FLUSH               = 0x00000080
	FAN_MARK_FILESYSTEM          = 0x00000100
	FAN_MARK_EVICTABLE           = 0x00000200
	FAN_MARK_IGNORE              = 0x00000400
	FAN_MARK_INODE               = 0x00000000
	FAN_MARK_TYPE_MASK           = FAN_MARK_INODE | FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM
)

// Event bits for fanotify_mark(2) masks and fanotify_event_metadata.mask.
const (
	FAN_ACCESS         = 0x00000001
	FAN_MODIFY         = 0x00000002
	FAN_ATTRIB         = 0x00000004
	FAN_CLOSE_WRITE    = 0x00000008
	FAN_CLOSE_NOWRITE  = 0x00000010
	FAN_OPEN           = 0x00000020
	FAN_MOVED_FROM     = 0x00000040
	FAN_MOVED_TO       = 0x00000080
	FAN_CREATE         = 0x00000100
	FAN_DELETE         = 0x00000200
	FAN_DELETE_SELF    = 0x00000400
	FAN_MOVE_SELF      = 0x00000800
	FAN_OPEN_EXEC      = 0x00001000
	FAN_Q_OVERFLOW     = 0x00004000
	FAN_FS_ERROR       = 0x00008000
	FAN_OPEN_PERM      = 0x00010000
	FAN_ACCESS_PERM    = 0x00020000
	FAN_OPEN_EXEC_PERM = 0x00040000
	FAN_EVENT_ON_CHILD = 0x08000000
	FAN_RENAME         = 0x10000000
	FAN_ONDIR          = 0x40000000
	FAN_CLOSE          = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE
)

// Values for fanotify_response.response and fanotify_event_metadata.
const (
	FAN_ALLOW                 = 0x01
	FAN_DENY                  = 0x02
	FAN_AUDIT                 = 0x10
	FAN_INFO                  = 0x20
	FAN_NOFD                  = -1
	FANOTIFY_METADATA_VERSION = 3
)

// FanotifyEventMetadata is struct fanotify_event_metadata.
//
// +marshal
type FanotifyEventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	FD          int32
	PID         int32
}

// FanotifyResponse is struct fanotify_response.
//
// +marshal
type FanotifyResponse struct {
	FD       int32
	Response uint32
}
