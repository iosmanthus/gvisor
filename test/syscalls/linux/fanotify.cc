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

#include <fcntl.h>
#include <poll.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void SkipIfNoSysAdmin() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
}

PosixErrorOr<FileDescriptor> FanInit(unsigned flags, unsigned f_flags) {
  int fd = fanotify_init(flags, f_flags);
  if (fd < 0) {
    return PosixError(errno, "fanotify_init");
  }
  return FileDescriptor(fd);
}

PosixError FanMark(int gfd, unsigned flags, uint64_t mask, int dirfd,
                   const char* path) {
  if (fanotify_mark(gfd, flags, mask, dirfd, path) < 0) {
    return PosixError(errno, "fanotify_mark");
  }
  return NoError();
}

struct FanEvent {
  uint64_t mask;
  int pid;
  FileDescriptor fd;  // Empty for FAN_NOFD.
  std::string path;   // readlink(/proc/self/fd/N); empty for FAN_NOFD.
};

// ReadEvents polls gfd for up to timeout_ms, then reads all available events.
PosixErrorOr<std::vector<FanEvent>> ReadEvents(int gfd, int timeout_ms) {
  struct pollfd pfd = {.fd = gfd, .events = POLLIN};
  int r = poll(&pfd, 1, timeout_ms);
  if (r < 0) {
    return PosixError(errno, "poll");
  }
  std::vector<FanEvent> out;
  if (r == 0) {
    return out;
  }
  char buf[4096] __attribute__((aligned(8)));
  ssize_t len = read(gfd, buf, sizeof(buf));
  if (len < 0) {
    return PosixError(errno, "read");
  }
  for (auto* m = reinterpret_cast<fanotify_event_metadata*>(buf);
       FAN_EVENT_OK(m, len); m = FAN_EVENT_NEXT(m, len)) {
    if (m->vers != FANOTIFY_METADATA_VERSION) {
      return PosixError(EINVAL, "bad metadata version");
    }
    FanEvent ev{m->mask, m->pid, FileDescriptor(), ""};
    if (m->fd >= 0) {
      ev.fd = FileDescriptor(m->fd);
      auto target = ReadLink(absl::StrCat("/proc/self/fd/", m->fd));
      if (!target.ok()) {
        return target.error();
      }
      ev.path = target.ValueOrDie();
    }
    out.push_back(std::move(ev));
  }
  return out;
}

TEST(FanotifyTest, InitNotifClassSucceeds) {
  SkipIfNoSysAdmin();
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_NOTIF, O_RDONLY));
  EXPECT_GE(g.get(), 0);
}

TEST(FanotifyTest, InitRequiresSysAdmin) {
  SkipIfNoSysAdmin();
  AutoCapability cap(CAP_SYS_ADMIN, false);
  EXPECT_THAT(fanotify_init(FAN_CLASS_NOTIF, O_RDONLY),
              SyscallFailsWithErrno(EPERM));
  // Linux checks privilege before flags (fanotify_user.c:1471).
  EXPECT_THAT(fanotify_init(0x80000000, O_RDONLY),
              SyscallFailsWithErrno(EPERM));
}

TEST(FanotifyTest, InitRejectsBadFlags) {
  SkipIfNoSysAdmin();
  EXPECT_THAT(fanotify_init(0x80000000, O_RDONLY),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(
      fanotify_init(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT, O_RDONLY),
      SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_init(FAN_CLASS_NOTIF, O_ACCMODE),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_init(FAN_CLASS_NOTIF, O_RDONLY | O_CREAT),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_init(FAN_REPORT_PIDFD | FAN_REPORT_TID, O_RDONLY),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FanotifyTest, InitOutOfScopeFlagsRejectedOnGvisor) {
  SKIP_IF(!IsRunningOnGvisor());
  SkipIfNoSysAdmin();
  for (unsigned f :
       {static_cast<unsigned>(FAN_REPORT_FID),
        static_cast<unsigned>(FAN_REPORT_DIR_FID | FAN_REPORT_NAME),
        static_cast<unsigned>(FAN_REPORT_PIDFD),
        static_cast<unsigned>(FAN_ENABLE_AUDIT)}) {
    EXPECT_THAT(fanotify_init(f, O_RDONLY), SyscallFailsWithErrno(EINVAL))
        << f;
  }
}

TEST(FanotifyTest, InitGroupLimit) {
  SkipIfNoSysAdmin();
  // Linux: fs.fanotify.max_user_groups (default 128) for each user.
  // gVisor: 128 for the sandbox. Both give EMFILE at the limit.
  std::vector<FileDescriptor> groups;
  int err = 0;
  for (int i = 0; i < 200; i++) {
    int fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
    if (fd < 0) {
      err = errno;
      break;
    }
    groups.emplace_back(fd);
  }
  EXPECT_EQ(err, EMFILE);
  EXPECT_LE(groups.size(), 128u);
  ASSERT_FALSE(groups.empty());
  groups.pop_back();  // Closing one group frees a slot.
  int fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
}

TEST(FanotifyTest, InitFdFlagsAndName) {
  SkipIfNoSysAdmin();
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY));
  EXPECT_THAT(fcntl(g.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
  int fl = fcntl(g.get(), F_GETFL);
  ASSERT_THAT(fl, SyscallSucceeds());
  EXPECT_EQ(fl & O_ACCMODE, O_RDWR);
  EXPECT_TRUE(fl & O_NONBLOCK);
  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(
                ReadLink(absl::StrCat("/proc/self/fd/", g.get()))),
            "anon_inode:[fanotify]");
  char buf[64];
  EXPECT_THAT(read(g.get(), buf, sizeof(buf)), SyscallFailsWithErrno(EAGAIN));
  EXPECT_THAT(read(g.get(), buf, 1), SyscallFailsWithErrno(EAGAIN));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
