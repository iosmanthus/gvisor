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
#include <sched.h>
#include <sys/fanotify.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

// After sys/mount.h: linux/aio_abi.h includes linux/fs.h.
#include <linux/aio_abi.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/strings/str_cat.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/epoll_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

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

TEST(FanotifyTest, MarkValidation) {
  SkipIfNoSysAdmin();
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_NOTIF, O_RDONLY));
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const char* p = dir.path().c_str();
  // Unknown flag, two mark types, no command, two commands.
  EXPECT_THAT(
      fanotify_mark(g.get(), FAN_MARK_ADD | 0x80000000, FAN_OPEN, AT_FDCWD, p),
      SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_mark(g.get(),
                            FAN_MARK_ADD | FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM,
                            FAN_OPEN, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_mark(g.get(), 0, FAN_OPEN, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD | FAN_MARK_REMOVE, FAN_OPEN,
                            AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  // Empty mask for ADD and REMOVE.
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD, 0, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE, 0, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  // FLUSH accepts only the mark-type bits.
  for (unsigned extra : {FAN_MARK_ONLYDIR, FAN_MARK_DONT_FOLLOW,
                         FAN_MARK_IGNORED_MASK}) {
    EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_FLUSH | extra, 0, AT_FDCWD,
                              nullptr),
                SyscallFailsWithErrno(EINVAL))
        << extra;
  }
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_FLUSH | FAN_MARK_MOUNT, 0,
                            AT_FDCWD, nullptr),
              SyscallSucceeds());
  // Mask validation comes before the fd lookup.
  EXPECT_THAT(fanotify_mark(-1, FAN_MARK_ADD, 0, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(fanotify_mark(-1, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, p),
              SyscallFailsWithErrno(EBADF));
  // Not a fanotify fd.
  FileDescriptor other = ASSERT_NO_ERRNO_AND_VALUE(Open(p, O_RDONLY));
  EXPECT_THAT(fanotify_mark(other.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  // Permission events need a content class.
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  // FID-only events on a group without FID reporting.
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD, FAN_CREATE, AT_FDCWD, p),
              SyscallFailsWithErrno(EINVAL));
  // ONLYDIR on a file.
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD | FAN_MARK_ONLYDIR, FAN_OPEN,
                            AT_FDCWD, file.path().c_str()),
              SyscallFailsWithErrno(ENOTDIR));
  // REMOVE without a mark.
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE, FAN_OPEN, AT_FDCWD, p),
              SyscallFailsWithErrno(ENOENT));
  // ADD, then REMOVE. Removing bits that are not set succeeds while the mark
  // exists; the mark goes away with its last bit.
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN | FAN_ACCESS, AT_FDCWD, p));
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE, FAN_OPEN, AT_FDCWD, p),
              SyscallSucceeds());
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE, FAN_OPEN, AT_FDCWD, p),
              SyscallSucceeds());
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE, FAN_ACCESS, AT_FDCWD, p),
              SyscallSucceeds());
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE, FAN_ACCESS, AT_FDCWD, p),
              SyscallFailsWithErrno(ENOENT));
}

TEST(FanotifyTest, OpenPermRejectedOnGvisor) {
  // gVisor does not support FAN_OPEN_PERM and FAN_OPEN_EXEC_PERM yet.
  SKIP_IF(!IsRunningOnGvisor());
  SkipIfNoSysAdmin();
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  for (uint64_t m : {static_cast<uint64_t>(FAN_OPEN_PERM),
                     static_cast<uint64_t>(FAN_OPEN_EXEC_PERM)}) {
    EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD, m, AT_FDCWD,
                              dir.path().c_str()),
                SyscallFailsWithErrno(EINVAL));
  }
}

TEST(FanotifyTest, MountMarkNeedsCurrentSysAdmin) {
  SkipIfNoSysAdmin();
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_NOTIF, O_RDONLY));
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const char* p = dir.path().c_str();
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN, AT_FDCWD, p));
  AutoCapability cap(CAP_SYS_ADMIN, false);
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                            FAN_OPEN, AT_FDCWD, p),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                            FAN_OPEN, AT_FDCWD, p),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_FLUSH | FAN_MARK_MOUNT, 0,
                            AT_FDCWD, nullptr),
              SyscallFailsWithErrno(EPERM));
  // Inode marks do not need CAP_SYS_ADMIN.
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, p),
              SyscallSucceeds());
}

TEST(FanotifyTest, InternalObjectsAndProc) {
  SkipIfNoSysAdmin();
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  int mfd = memfd_create("fan", 0);
  ASSERT_THAT(mfd, SyscallSucceeds());
  FileDescriptor memfd(mfd);
  // Inode mark on a memfd by fd: allowed. Mount mark: rejected.
  EXPECT_THAT(
      fanotify_mark(g.get(), FAN_MARK_ADD, FAN_MODIFY, memfd.get(), nullptr),
      SyscallSucceeds());
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_MODIFY,
                            memfd.get(), nullptr),
              SyscallFailsWithErrno(EINVAL));
  // Permission marks on procfs are rejected on ADD. Removing a permission
  // bit from a notification mark on procfs succeeds.
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD,
                            "/proc/self/status"),
              SyscallFailsWithErrno(EINVAL));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_ACCESS, AT_FDCWD,
                          "/proc/self/status"));
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_REMOVE, FAN_ACCESS_PERM,
                            AT_FDCWD, "/proc/self/status"),
              SyscallSucceeds());
}

TEST(FanotifyTest, MarksDoNotKeepMountBusy) {
  SkipIfNoSysAdmin();
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", dir.path(), "tmpfs", 0, "", 0));
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_NOTIF, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN,
                          AT_FDCWD, dir.path().c_str()));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_OPEN, AT_FDCWD, dir.path().c_str()));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, dir.path().c_str()));
  // A normal umount succeeds while the marks exist.
  ASSERT_THAT(umount(dir.path().c_str()), SyscallSucceeds());
  mount.Release();  // Already unmounted.
  // The group still works after its objects went away.
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_FLUSH | FAN_MARK_MOUNT, 0,
                            AT_FDCWD, nullptr),
              SyscallSucceeds());
}

// EventsAfter runs fn, then returns all events that arrive within 200 ms of
// the last one.
std::vector<FanEvent> EventsAfter(int g, const std::function<void()>& fn) {
  fn();
  std::vector<FanEvent> all;
  while (true) {
    auto evs = ReadEvents(g, 200);
    if (!evs.ok() || evs.ValueOrDie().empty()) {
      break;
    }
    for (auto& e : evs.ValueOrDie()) {
      all.push_back(std::move(e));
    }
  }
  return all;
}

PosixErrorOr<FileDescriptor> InotifyInit1(int flags) {
  int fd = inotify_init1(flags);
  if (fd < 0) {
    return PosixError(errno, "inotify_init1");
  }
  return FileDescriptor(fd);
}

TEST(FanotifyTest, InodeMarkSeesOnlyItsFile) {
  SkipIfNoSysAdmin();
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto a = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "aaa", 0644));
  auto b = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "bbb", 0644));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD,
                          FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE, AT_FDCWD,
                          a.path().c_str()));
  MaybeSave();  // Marks and their interest masks survive restore.
  auto evs = EventsAfter(g.get(), [&] {
    char c;
    FileDescriptor fa = ASSERT_NO_ERRNO_AND_VALUE(Open(a.path(), O_RDONLY));
    ASSERT_THAT(read(fa.get(), &c, 1), SyscallSucceedsWithValue(1));
    FileDescriptor fb = ASSERT_NO_ERRNO_AND_VALUE(Open(b.path(), O_RDONLY));
    ASSERT_THAT(read(fb.get(), &c, 1), SyscallSucceedsWithValue(1));
  });
  uint64_t all = 0;
  for (auto& e : evs) {
    EXPECT_EQ(e.path, a.path());
    EXPECT_EQ(e.pid, getpid());
    all |= e.mask;
  }
  EXPECT_EQ(all, FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE);
}

TEST(FanotifyTest, MountMarkExcludesBindMountAndSubmount) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string sub = JoinPath(top.path(), "sub");
  ASSERT_THAT(mkdir(sub.c_str(), 0755), SyscallSucceeds());
  auto subm = ASSERT_NO_ERRNO_AND_VALUE(Mount("", sub, "tmpfs", 0, "", 0));
  auto bind = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto bindm = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(top.path(), bind.path(), "", MS_BIND, "", 0));
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(top.path(), "f"), "x"));
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(sub, "f"), "x"));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN,
                          AT_FDCWD, top.path().c_str()));
  auto evs = EventsAfter(g.get(), [&] {
    Open(JoinPath(top.path(), "f"), O_RDONLY).IgnoreError();
    Open(JoinPath(sub, "f"), O_RDONLY).IgnoreError();
    Open(JoinPath(bind.path(), "f"), O_RDONLY).IgnoreError();
  });
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].path, JoinPath(top.path(), "f"));
}

TEST(FanotifyTest, FilesystemMarkSeesAllMounts) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  auto bind = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto bindm = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(top.path(), bind.path(), "", MS_BIND, "", 0));
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(top.path(), "f"), "x"));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_OPEN, AT_FDCWD, top.path().c_str()));
  auto evs = EventsAfter(g.get(), [&] {
    Open(JoinPath(top.path(), "f"), O_RDONLY).IgnoreError();
    Open(JoinPath(bind.path(), "f"), O_RDONLY).IgnoreError();
  });
  EXPECT_EQ(evs.size(), 2);
}

TEST(FanotifyTest, EventMasksAndSpecialFiles) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string f = JoinPath(top.path(), "f");
  std::string fifo = JoinPath(top.path(), "p");
  ASSERT_NO_ERRNO(CreateWithContents(f, "abc"));
  ASSERT_THAT(mkfifo(fifo.c_str(), 0644), SyscallSucceeds());
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(
      g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
      FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE | FAN_ONDIR, AT_FDCWD,
      top.path().c_str()));
  auto evs = EventsAfter(g.get(), [&] {
    // O_TRUNC and ftruncate give no fanotify event without FID reporting.
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f, O_RDWR | O_TRUNC));
    ASSERT_THAT(write(fd.get(), "x", 1), SyscallSucceeds());
    ASSERT_THAT(ftruncate(fd.get(), 0), SyscallSucceeds());
    ASSERT_THAT(fallocate(fd.get(), 0, 0, 4096), SyscallSucceeds());
    // A FIFO gives no event.
    FileDescriptor p = ASSERT_NO_ERRNO_AND_VALUE(Open(fifo, O_RDWR));
  });
  uint64_t all = 0;
  for (auto& e : evs) {
    EXPECT_EQ(e.path, f);
    EXPECT_EQ(e.mask & (FAN_ONDIR | FAN_EVENT_ON_CHILD), 0);
    all |= e.mask;
  }
  EXPECT_EQ(all, FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE);
}

TEST(FanotifyTest, EventFdIsSilentAndReopensUnlinked) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string f = JoinPath(top.path(), "f");
  ASSERT_NO_ERRNO(CreateWithContents(f, "abc"));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  FileDescriptor g2 = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(InotifyInit1(IN_NONBLOCK));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_OPEN | FAN_ACCESS | FAN_CLOSE, AT_FDCWD,
                          top.path().c_str()));
  {
    FileDescriptor w = ASSERT_NO_ERRNO_AND_VALUE(Open(f, O_WRONLY));
    ASSERT_THAT(unlink(f.c_str()), SyscallSucceeds());
  }  // CLOSE_WRITE on an unlinked file.
  auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 1000));
  ASSERT_FALSE(evs.empty());
  EXPECT_EQ(evs.back().path, f + " (deleted)");
  // Watch with a second group and with inotify, then use the event fd.
  ASSERT_NO_ERRNO(FanMark(g2.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_OPEN | FAN_ACCESS | FAN_CLOSE, AT_FDCWD,
                          top.path().c_str()));
  ASSERT_THAT(inotify_add_watch(in.get(), top.path().c_str(), IN_ALL_EVENTS),
              SyscallSucceeds());
  char buf[8];
  // The event fd has event_f_flags (O_RDONLY).
  EXPECT_THAT(read(evs.back().fd.get(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(3));
  evs.back().fd.reset();
  EXPECT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g2.get(), 300)).empty());
  char ibuf[256];
  EXPECT_THAT(read(in.get(), ibuf, sizeof(ibuf)),
              SyscallFailsWithErrno(EAGAIN));
}

TEST(FanotifyTest, ReadEdgeCases) {
  SkipIfNoSysAdmin();
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  char tiny[4];
  // An empty queue gives EAGAIN, also with a small buffer.
  EXPECT_THAT(read(g.get(), tiny, sizeof(tiny)),
              SyscallFailsWithErrno(EAGAIN));
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, f.path().c_str()));
  Open(f.path(), O_RDONLY).IgnoreError();
  EXPECT_THAT(read(g.get(), tiny, sizeof(tiny)),
              SyscallFailsWithErrno(EINVAL));
}

// LowestFreeFd returns the number that the next new fd gets.
int LowestFreeFd() {
  int fd = open("/dev/null", O_RDONLY);
  TEST_PCHECK(fd >= 0);
  close(fd);
  return fd;
}

TEST(FanotifyTest, ReadFaultAndEmfileDoNotLeakFds) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto f2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, f.path().c_str()));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, f2.path().c_str()));
  Open(f.path(), O_RDONLY).IgnoreError();
  Open(f2.path(), O_RDONLY).IgnoreError();
  // The buffer ends at an unmapped page: the first event fits, the second
  // does not.
  char* mem = static_cast<char*>(mmap(nullptr, 2 * kPageSize,
                                      PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  ASSERT_NE(mem, MAP_FAILED);
  ASSERT_THAT(munmap(mem + kPageSize, kPageSize), SyscallSucceeds());
  int free_before = LowestFreeFd();
  char* buf = mem + kPageSize - sizeof(fanotify_event_metadata);
  EXPECT_THAT(read(g.get(), buf, 2 * sizeof(fanotify_event_metadata)),
              SyscallFailsWithErrno(EFAULT));
  // Linux keeps the first event: its fd is installed.
  auto* md = reinterpret_cast<fanotify_event_metadata*>(buf);
  EXPECT_EQ(md->fd, free_before);
  close(md->fd);
  // The faulted second event left no fd behind.
  EXPECT_EQ(LowestFreeFd(), free_before);
  munmap(mem, kPageSize);
  // EMFILE while the event fd is installed.
  Open(f.path(), O_RDONLY).IgnoreError();
  struct rlimit old;
  ASSERT_THAT(getrlimit(RLIMIT_NOFILE, &old), SyscallSucceeds());
  struct rlimit lim = old;
  lim.rlim_cur = LowestFreeFd();
  ASSERT_THAT(setrlimit(RLIMIT_NOFILE, &lim), SyscallSucceeds());
  char ok[64] __attribute__((aligned(8)));
  EXPECT_THAT(read(g.get(), ok, sizeof(ok)), SyscallFailsWithErrno(EMFILE));
  ASSERT_THAT(setrlimit(RLIMIT_NOFILE, &old), SyscallSucceeds());
}

TEST(FanotifyTest, TwoReadersGetEachEventOnce) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_OPEN, AT_FDCWD, top.path().c_str()));
  constexpr int kFiles = 200;
  for (int i = 0; i < kFiles; i++) {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
        Open(JoinPath(top.path(), absl::StrCat("f", i)), O_CREAT | O_RDONLY,
             0644));
  }
  std::atomic<int> total(0);
  auto drain = [&] {
    while (true) {
      auto evs = ReadEvents(g.get(), 200);
      if (!evs.ok() || evs.ValueOrDie().empty()) {
        return;
      }
      total += evs.ValueOrDie().size();
    }
  };
  ScopedThread t1(drain);
  ScopedThread t2(drain);
  t1.Join();
  t2.Join();
  EXPECT_EQ(total.load(), kFiles);
}

TEST(FanotifyTest, OnDirAndChild) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string d = JoinPath(top.path(), "d");
  std::string f = JoinPath(d, "f");
  ASSERT_THAT(mkdir(d.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_ERRNO(CreateWithContents(f, "x"));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  // A directory mark without FAN_ONDIR and FAN_EVENT_ON_CHILD sees nothing.
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, d.c_str()));
  EXPECT_TRUE(EventsAfter(g.get(), [&] {
                Open(d, O_RDONLY | O_DIRECTORY).IgnoreError();
                Open(f, O_RDONLY).IgnoreError();
              }).empty());
  // With FAN_ONDIR the directory open is reported, without the FAN_ONDIR
  // bit.
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN | FAN_ONDIR, AT_FDCWD, d.c_str()));
  auto evs = EventsAfter(
      g.get(), [&] { Open(d, O_RDONLY | O_DIRECTORY).IgnoreError(); });
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].mask, FAN_OPEN);
  // With FAN_EVENT_ON_CHILD the open of the child is reported.
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN | FAN_EVENT_ON_CHILD,
                          AT_FDCWD, d.c_str()));
  evs = EventsAfter(g.get(), [&] { Open(f, O_RDONLY).IgnoreError(); });
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].path, f);
  EXPECT_EQ(evs[0].mask, FAN_OPEN);
}

TEST(FanotifyTest, OnDirIsPerMark) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT,
                          FAN_OPEN | FAN_ONDIR, AT_FDCWD, top.path().c_str()));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_ACCESS, AT_FDCWD, top.path().c_str()));
  auto evs = EventsAfter(g.get(), [&] {
    FileDescriptor dfd = ASSERT_NO_ERRNO_AND_VALUE(
        Open(top.path(), O_RDONLY | O_DIRECTORY));
    char buf[256];
    // getdents gives FAN_ACCESS on a directory.
    ASSERT_THAT(syscall(SYS_getdents64, dfd.get(), buf, sizeof(buf)),
                SyscallSucceeds());
  });
  uint64_t all = 0;
  for (auto& e : evs) {
    all |= e.mask;
  }
  // No FAN_ACCESS: the mark that wants it has no FAN_ONDIR.
  EXPECT_EQ(all, FAN_OPEN);
}

TEST(FanotifyTest, IgnoreMasks) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string a = JoinPath(top.path(), "a");
  std::string b = JoinPath(top.path(), "b");
  ASSERT_NO_ERRNO(CreateWithContents(a, "x"));
  ASSERT_NO_ERRNO(CreateWithContents(b, "x"));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_ACCESS | FAN_MODIFY, AT_FDCWD,
                          top.path().c_str()));
  // An ignore-only inode mark on a suppresses the filesystem mark for a.
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                          FAN_ACCESS, AT_FDCWD, a.c_str()));
  MaybeSave();  // Ignored masks survive restore.
  auto read1 = [](const std::string& p) {
    char c;
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(p, O_RDONLY));
    ASSERT_THAT(read(fd.get(), &c, 1), SyscallSucceeds());
  };
  auto write1 = [](const std::string& p) {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(p, O_WRONLY));
    ASSERT_THAT(write(fd.get(), "y", 1), SyscallSucceeds());
  };
  auto evs = EventsAfter(g.get(), [&] {
    read1(a);
    read1(b);
  });
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].path, b);
  // A modification of a clears the ignore mask; the modification itself is
  // reported.
  evs = EventsAfter(g.get(), [&] { write1(a); });
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].mask, FAN_MODIFY);
  evs = EventsAfter(g.get(), [&] { read1(a); });
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].mask, FAN_ACCESS);
  // With FAN_MARK_IGNORED_SURV_MODIFY the ignore mask stays.
  ASSERT_NO_ERRNO(FanMark(
      g.get(),
      FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
      FAN_ACCESS, AT_FDCWD, a.c_str()));
  EventsAfter(g.get(), [&] { write1(a); });
  EXPECT_TRUE(EventsAfter(g.get(), [&] { read1(a); }).empty());
}

TEST(FanotifyTest, IgnoreClearedByUnsubscribedModify) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "x", 0644));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_ACCESS, AT_FDCWD, f.path().c_str()));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                          FAN_ACCESS, AT_FDCWD, f.path().c_str()));
  {
    // The mark does not subscribe to FAN_MODIFY; the write still clears the
    // ignore mask (Linux fsnotify_calc_mask()).
    FileDescriptor w = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_WRONLY));
    ASSERT_THAT(write(w.get(), "y", 1), SyscallSucceeds());
  }
  auto evs = EventsAfter(g.get(), [&] {
    char c;
    FileDescriptor r = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    ASSERT_THAT(read(r.get(), &c, 1), SyscallSucceeds());
  });
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].mask, FAN_ACCESS);
}

TEST(FanotifyTest, MergeAndThreads) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string a = JoinPath(top.path(), "a");
  std::string b = JoinPath(top.path(), "b");
  ASSERT_NO_ERRNO(CreateWithContents(a, "xxxx"));
  ASSERT_NO_ERRNO(CreateWithContents(b, "xxxx"));
  for (bool tid : {false, true}) {
    SCOPED_TRACE(tid ? "FAN_REPORT_TID" : "TGID");
    FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(FanInit(
        FAN_CLASS_NOTIF | FAN_NONBLOCK | (tid ? FAN_REPORT_TID : 0), O_RDONLY));
    ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                            FAN_ACCESS, AT_FDCWD, top.path().c_str()));
    FileDescriptor fa = ASSERT_NO_ERRNO_AND_VALUE(Open(a, O_RDONLY));
    FileDescriptor fb = ASSERT_NO_ERRNO_AND_VALUE(Open(b, O_RDONLY));
    char c;
    // a, b, a: the second access of a merges into the first, also with b
    // between them.
    ASSERT_THAT(pread(fa.get(), &c, 1, 0), SyscallSucceeds());
    ASSERT_THAT(pread(fb.get(), &c, 1, 0), SyscallSucceeds());
    ASSERT_THAT(pread(fa.get(), &c, 1, 1), SyscallSucceeds());
    // Another thread of this process reads b.
    ScopedThread([&] {
      char d;
      ASSERT_THAT(pread(fb.get(), &d, 1, 2), SyscallSucceeds());
    }).Join();
    int n = 0;
    ASSERT_THAT(ioctl(g.get(), FIONREAD, &n), SyscallSucceeds());
    auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 1000));
    EXPECT_EQ(n, static_cast<int>(evs.size() * sizeof(fanotify_event_metadata)));
    // Without FAN_REPORT_TID the thread's access of b merges with the main
    // thread's (same TGID); with it, it is a separate event.
    EXPECT_EQ(evs.size(), tid ? 3u : 2u);
    if (!tid) {
      for (auto& e : evs) {
        EXPECT_EQ(e.pid, getpid());
      }
    }
  }
}

TEST(FanotifyTest, PidOfExitedProcessAndOtherNamespace) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "x", 0644));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, f.path().c_str()));
  pid_t child = fork();
  if (child == 0) {
    int fd = open(f.path().c_str(), O_RDONLY);
    _exit(fd >= 0 ? 0 : 1);
  }
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  MaybeSave();  // A queued event survives restore.
  // The child is reaped; the event still has its PID.
  auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 1000));
  ASSERT_EQ(evs.size(), 1);
  EXPECT_EQ(evs[0].pid, child);
  // A reader in a child PID namespace cannot see an origin outside it.
  Open(f.path(), O_RDONLY).IgnoreError();
  pid_t outer = fork();
  if (outer == 0) {
    TEST_PCHECK(unshare(CLONE_NEWPID) == 0);
    pid_t inner = fork();  // PID 1 of the new namespace.
    if (inner == 0) {
      char buf[256] __attribute__((aligned(8)));
      ssize_t len = read(g.get(), buf, sizeof(buf));
      TEST_PCHECK(len >= static_cast<ssize_t>(sizeof(fanotify_event_metadata)));
      auto* md = reinterpret_cast<fanotify_event_metadata*>(buf);
      _exit(md->pid == 0 ? 0 : 1);
    }
    int st;
    TEST_PCHECK(waitpid(inner, &st, 0) == inner);
    _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 2);
  }
  ASSERT_THAT(RetryEINTR(waitpid)(outer, &status, 0),
              SyscallSucceedsWithValue(outer));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0) << status;
}

TEST(FanotifyTest, OverflowOnce) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_OPEN, AT_FDCWD, top.path().c_str()));
  // More events than the default queue holds, none of them mergeable.
  constexpr int kQueue = 16384;
  DisableSave ds;  // Too many syscalls to save after each one.
  for (int i = 0; i < kQueue + 100; i++) {
    int fd = open(JoinPath(top.path(), absl::StrCat("f", i)).c_str(),
                  O_CREAT | O_RDONLY, 0644);
    ASSERT_THAT(fd, SyscallSucceeds());
    close(fd);
  }
  int overflows = 0;
  int events = 0;
  char buf[4096] __attribute__((aligned(8)));
  ssize_t len;
  while ((len = read(g.get(), buf, sizeof(buf))) > 0) {
    for (auto* md = reinterpret_cast<fanotify_event_metadata*>(buf);
         FAN_EVENT_OK(md, len); md = FAN_EVENT_NEXT(md, len)) {
      if (md->mask & FAN_Q_OVERFLOW) {
        overflows++;
        EXPECT_EQ(md->fd, FAN_NOFD);
      } else {
        events++;
        close(md->fd);
      }
    }
  }
  EXPECT_EQ(overflows, 1);
  EXPECT_EQ(events, kQueue);
}

TEST(FanotifyTest, PollAndEpoll) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "x", 0644));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, f.path().c_str()));
  FileDescriptor ep = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  ASSERT_NO_ERRNO(
      RegisterEpollFD(ep.get(), g.get(), EPOLLIN | EPOLLRDNORM | EPOLLOUT, 0));
  struct pollfd p = {.fd = g.get(), .events = POLLIN | POLLRDNORM | POLLOUT};
  // Never writable, not readable while empty.
  EXPECT_THAT(poll(&p, 1, 0), SyscallSucceedsWithValue(0));
  Open(f.path(), O_RDONLY).IgnoreError();
  EXPECT_THAT(poll(&p, 1, 1000), SyscallSucceedsWithValue(1));
  EXPECT_EQ(p.revents, POLLIN | POLLRDNORM);
  struct epoll_event ev;
  EXPECT_THAT(RetryEINTR(epoll_wait)(ep.get(), &ev, 1, 1000),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(ev.events, EPOLLIN | EPOLLRDNORM);
}

constexpr int64_t kOverlayfsSuperMagic = 0x794c7630;

TEST(FanotifyTest, RootFilesystemEventsWithCopyUp) {
  SkipIfNoSysAdmin();
  // The runner may put lower.txt in the test directory before the sandbox
  // starts; on an overlay root it is then in the lower layer, and opening it
  // for writing copies it up.
  std::string f = JoinPath(GetAbsoluteTestTmpdir(), "lower.txt");
  if (access(f.c_str(), F_OK) != 0) {
    ASSERT_NO_ERRNO(CreateWithContents(f, "abc"));
  }
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE,
                          AT_FDCWD, GetAbsoluteTestTmpdir().c_str()));
  auto evs = EventsAfter(g.get(), [&] {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f, O_RDWR));
    char c;
    ASSERT_THAT(read(fd.get(), &c, 1), SyscallSucceeds());
    ASSERT_THAT(write(fd.get(), "x", 1), SyscallSucceeds());
  });
  uint64_t all = 0;
  for (auto& e : evs) {
    if (e.pid != getpid()) {
      continue;  // The mark covers the whole filesystem.
    }
    // Never a path of an overlay layer.
    EXPECT_EQ(e.path, f);
    all |= e.mask;
  }
  EXPECT_EQ(all, FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE);
}

TEST(FanotifyTest, OverlayInodeMarkIsPerName) {
  SkipIfNoSysAdmin();
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string a = JoinPath(dir.path(), "a");
  std::string b = JoinPath(dir.path(), "b");
  ASSERT_NO_ERRNO(CreateWithContents(a, "x"));
  ASSERT_THAT(link(a.c_str(), b.c_str()), SyscallSucceeds());
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, a.c_str()));
  auto evs = EventsAfter(g.get(), [&] { Open(b, O_RDONLY).IgnoreError(); });
  struct statfs sfs;
  ASSERT_THAT(statfs(dir.path().c_str(), &sfs), SyscallSucceeds());
  if (IsRunningOnGvisor() && sfs.f_type == kOverlayfsSuperMagic) {
    // gVisor overlay has no shared inode for hard links: a mark through one
    // name does not see the other name. This is the same limit as for
    // inotify watches.
    EXPECT_TRUE(evs.empty());
  } else {
    EXPECT_EQ(evs.size(), 1);
  }
}

// PermListener answers each FAN_ACCESS_PERM event of g with resp until stop
// is set, and counts them in seen.
void PermListener(int g, uint32_t resp, std::atomic<bool>* stop,
                  std::atomic<int>* seen) {
  while (!stop->load()) {
    struct pollfd p = {.fd = g, .events = POLLIN};
    if (poll(&p, 1, 100) <= 0) {
      continue;
    }
    char buf[4096] __attribute__((aligned(8)));
    ssize_t len = read(g, buf, sizeof(buf));
    if (len <= 0) {
      continue;
    }
    for (auto* m = reinterpret_cast<fanotify_event_metadata*>(buf);
         FAN_EVENT_OK(m, len); m = FAN_EVENT_NEXT(m, len)) {
      if (m->mask & FAN_ACCESS_PERM) {
        struct fanotify_response r = {.fd = m->fd, .response = resp};
        TEST_PCHECK(write(g, &r, sizeof(r)) == sizeof(r));
        seen->fetch_add(1);
      }
      if (m->fd >= 0) {
        close(m->fd);
      }
    }
  }
}

void Answer(int g, int fd, uint32_t resp) {
  struct fanotify_response r = {.fd = fd, .response = resp};
  TEST_PCHECK(write(g, &r, sizeof(r)) == sizeof(r));
}

TEST(FanotifyPermTest, AllowDenyAndNoAccessEventOnDeny) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "abc", 0644));
  for (uint32_t resp : {FAN_ALLOW, FAN_DENY}) {
    SCOPED_TRACE(resp == FAN_ALLOW ? "allow" : "deny");
    FileDescriptor g =
        ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
    FileDescriptor gn = ASSERT_NO_ERRNO_AND_VALUE(
        FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
    ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD,
                            f.path().c_str()));
    ASSERT_NO_ERRNO(FanMark(gn.get(), FAN_MARK_ADD, FAN_ACCESS, AT_FDCWD,
                            f.path().c_str()));
    std::atomic<bool> stop(false);
    std::atomic<int> seen(0);
    ScopedThread listener([&] { PermListener(g.get(), resp, &stop, &seen); });
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    char buf[3];
    if (resp == FAN_ALLOW) {
      EXPECT_THAT(read(fd.get(), buf, 3), SyscallSucceedsWithValue(3));
      EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(gn.get(), 1000)).size(),
                1);
    } else {
      EXPECT_THAT(read(fd.get(), buf, 3), SyscallFailsWithErrno(EPERM));
      // A denied read gives no FAN_ACCESS.
      EXPECT_TRUE(ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(gn.get(), 300)).empty());
    }
    stop = true;
    listener.Join();
    EXPECT_EQ(seen.load(), 1);
  }
}

TEST(FanotifyPermTest, ResponseErrors) {
  SkipIfNoSysAdmin();
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  struct fanotify_response r = {.fd = 5, .response = FAN_ALLOW};
  EXPECT_THAT(write(g.get(), &r, 4), SyscallFailsWithErrno(EINVAL));
  r.response = 7;
  EXPECT_THAT(write(g.get(), &r, sizeof(r)), SyscallFailsWithErrno(EINVAL));
  r = {.fd = -1, .response = FAN_ALLOW};
  EXPECT_THAT(write(g.get(), &r, sizeof(r)), SyscallFailsWithErrno(EINVAL));
  r = {.fd = 1000, .response = FAN_ALLOW};
  EXPECT_THAT(write(g.get(), &r, sizeof(r)), SyscallFailsWithErrno(ENOENT));
}

TEST(FanotifyPermTest, CloseAllowsWaitersAndReleasesReferences) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string f = JoinPath(top.path(), "f");
  ASSERT_NO_ERRNO(CreateWithContents(f, "abc"));
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT,
                          FAN_ACCESS_PERM, AT_FDCWD, top.path().c_str()));
  // One reader waits after the listener read its event; then the group
  // closes without an answer.
  ScopedThread reader([&] {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f, O_RDONLY));
    char c;
    EXPECT_THAT(read(fd.get(), &c, 1), SyscallSucceedsWithValue(1));
  });
  auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 5000));
  ASSERT_EQ(evs.size(), 1);
  evs.clear();
  g.reset();  // Closing the group allows the waiting read.
  reader.Join();
  // No reference is left: a normal unmount succeeds.
  ASSERT_THAT(umount(top.path().c_str()), SyscallSucceeds());
  m.Release();
}

TEST(FanotifyPermTest, KilledWaiterThenCloseThenUmount) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  std::string f = JoinPath(top.path(), "f");
  ASSERT_NO_ERRNO(CreateWithContents(f, "abc"));
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT,
                          FAN_ACCESS_PERM, AT_FDCWD, top.path().c_str()));
  pid_t child = fork();
  if (child == 0) {
    int fd = open(f.c_str(), O_RDONLY);
    char c;
    (void)!read(fd, &c, 1);  // Waits for an answer.
    _exit(0);
  }
  auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 5000));
  ASSERT_EQ(evs.size(), 1);
  ASSERT_THAT(kill(child, SIGKILL), SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFSIGNALED(status));
  MaybeSave();  // The canceled event survives restore.
  // The canceled event still consumes one answer.
  struct fanotify_response r = {.fd = evs[0].fd.get(), .response = FAN_ALLOW};
  EXPECT_THAT(write(g.get(), &r, sizeof(r)),
              SyscallSucceedsWithValue(sizeof(r)));
  EXPECT_THAT(write(g.get(), &r, sizeof(r)), SyscallFailsWithErrno(ENOENT));
  evs.clear();
  g.reset();
  ASSERT_THAT(umount(top.path().c_str()), SyscallSucceeds());
  m.Release();
}

TEST(FanotifyPermTest, NonFatalSignalDoesNotStopWait) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "abc", 0644));
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD,
                          f.path().c_str()));
  struct sigaction sa = {};
  sa.sa_handler = +[](int) {};
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGUSR1, sa));
  std::atomic<pid_t> tid(0);
  std::atomic<bool> done(false);
  ScopedThread reader([&] {
    tid = gettid();
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    char c;
    EXPECT_THAT(read(fd.get(), &c, 1), SyscallSucceedsWithValue(1));
    done = true;
  });
  auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 5000));
  ASSERT_EQ(evs.size(), 1);
  ASSERT_THAT(tgkill(getpid(), tid.load(), SIGUSR1), SyscallSucceeds());
  absl::SleepFor(absl::Milliseconds(200));
  EXPECT_FALSE(done.load());  // Still waiting.
  Answer(g.get(), evs[0].fd.get(), FAN_ALLOW);
  // After a save and restore the read restarts and sends a new event.
  while (!done.load()) {
    for (auto& e : ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 100))) {
      Answer(g.get(), e.fd.get(), FAN_ALLOW);
    }
  }
  reader.Join();
  EXPECT_TRUE(done.load());
}

TEST(FanotifyPermTest, ListenerReadsOwnEventFdUnderAccessPerm) {
  SkipIfNoSysAdmin();
  // On gVisor use the sandbox root (overlay in the default configuration);
  // on Linux a separate tmpfs, so that the mark does not stop the host.
  std::string base = GetAbsoluteTestTmpdir();
  Cleanup unmount;
  TempPath mnt;
  if (!IsRunningOnGvisor()) {
    mnt = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    unmount = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("", mnt.path(), "tmpfs", 0, "", 0));
    base = mnt.path();
  }
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base));
  std::string f = JoinPath(dir.path(), "f");
  ASSERT_NO_ERRNO(CreateWithContents(f, "abc"));
  // FAN_REPORT_TID tells the two reading threads apart.
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_CONTENT | FAN_REPORT_TID, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_ACCESS_PERM, AT_FDCWD, dir.path().c_str()));
  std::atomic<bool> done(false);
  ScopedThread reader([&] {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f, O_RDONLY));
    char c;
    EXPECT_THAT(read(fd.get(), &c, 1), SyscallSucceedsWithValue(1));
    done = true;
  });
  auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 5000));
  ASSERT_EQ(evs.size(), 1);
  // Read the event fd in another thread. If that read made an event, it
  // would wait for us: we see it here, answer it so nothing hangs, and
  // fail.
  std::atomic<pid_t> self_tid(0);
  ScopedThread self_reader([&] {
    self_tid = gettid();
    char buf[3];
    EXPECT_THAT(pread(evs[0].fd.get(), buf, 3, 0), SyscallSucceedsWithValue(3));
  });
  for (auto& e : ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 500))) {
    EXPECT_NE(e.pid, self_tid.load());
    Answer(g.get(), e.fd.get(), FAN_ALLOW);
  }
  self_reader.Join();
  Answer(g.get(), evs[0].fd.get(), FAN_ALLOW);
  // After a save and restore the read restarts and sends a new event.
  while (!done.load()) {
    for (auto& e : ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 100))) {
      Answer(g.get(), e.fd.get(), FAN_ALLOW);
    }
  }
  reader.Join();
  // Remove the mark before the directory goes away.
  g.reset();
}

TEST(FanotifyPermTest, LargeBufferReturnsAtOnce) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "abc", 0644));
  FileDescriptor g =  // Blocking.
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD,
                          f.path().c_str()));
  ScopedThread reader([&] {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    char c;
    EXPECT_THAT(read(fd.get(), &c, 1), SyscallSucceedsWithValue(1));
  });
  // A blocking read with room for many events returns the one event; it
  // does not wait for more.
  std::vector<char> buf(64 * 1024);
  ssize_t len = read(g.get(), buf.data(), buf.size());
  ASSERT_EQ(len, sizeof(fanotify_event_metadata));
  auto* md = reinterpret_cast<fanotify_event_metadata*>(buf.data());
  Answer(g.get(), md->fd, FAN_ALLOW);
  close(md->fd);
  reader.Join();
}

TEST(FanotifyPermTest, ProcfsPermMarkRejected) {
  SkipIfNoSysAdmin();
  FileDescriptor g =
      ASSERT_NO_ERRNO_AND_VALUE(FanInit(FAN_CLASS_CONTENT, O_RDONLY));
  EXPECT_THAT(fanotify_mark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT,
                            FAN_ACCESS_PERM, AT_FDCWD, "/proc"),
              SyscallFailsWithErrno(EINVAL));
}

// PermEventsDuring marks path with FAN_ACCESS_PERM, runs fn while a listener
// answers resp, and returns the number of permission events, or -1 on a
// setup error.
int PermEventsDuring(const std::string& path, uint32_t resp,
                     const std::function<void()>& fn) {
  auto g_or = FanInit(FAN_CLASS_CONTENT, O_RDONLY);
  if (!g_or.ok()) {
    return -1;
  }
  FileDescriptor g = std::move(g_or).ValueOrDie();
  if (fanotify_mark(g.get(), FAN_MARK_ADD, FAN_ACCESS_PERM | FAN_ONDIR,
                    AT_FDCWD, path.c_str()) != 0) {
    return -1;
  }
  std::atomic<bool> stop(false);
  std::atomic<int> seen(0);
  ScopedThread listener([&] { PermListener(g.get(), resp, &stop, &seen); });
  fn();
  // Let the listener see late events before it stops.
  absl::SleepFor(absl::Milliseconds(200));
  stop = true;
  listener.Join();
  return seen.load();
}

TEST(FanotifyPermTest, OneEventPerOperation) {
  SkipIfNoSysAdmin();
  // Linux 6.8 checks sendfile and copy_file_range once; Linux 6.6 checks
  // each internal chunk. gVisor follows 6.8.
  auto once = [](int n) { return IsRunningOnGvisor() ? n == 1 : n >= 1; };
  // Bigger than the internal buffers of sendfile and copy_file_range.
  const std::string big(256 * 1024, 'x');
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), big, 0644));
  auto out = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  int n = PermEventsDuring(f.path(), FAN_ALLOW, [&] {
    FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    FileDescriptor o = ASSERT_NO_ERRNO_AND_VALUE(Open(out.path(), O_WRONLY));
    EXPECT_THAT(sendfile(o.get(), in.get(), nullptr, big.size()),
                SyscallSucceedsWithValue(big.size()));
  });
  EXPECT_TRUE(once(n)) << "sendfile: " << n;

  n = PermEventsDuring(f.path(), FAN_ALLOW, [&] {
    FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    FileDescriptor o = ASSERT_NO_ERRNO_AND_VALUE(Open(out.path(), O_WRONLY));
    EXPECT_THAT(syscall(SYS_copy_file_range, in.get(), nullptr, o.get(),
                        nullptr, big.size(), 0),
                SyscallSucceedsWithValue(big.size()));
  });
  EXPECT_TRUE(once(n)) << "copy_file_range: " << n;

  n = PermEventsDuring(f.path(), FAN_ALLOW, [&] {
    FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    int p[2];
    ASSERT_THAT(pipe(p), SyscallSucceeds());
    FileDescriptor r(p[0]);
    FileDescriptor w(p[1]);
    EXPECT_THAT(splice(in.get(), nullptr, w.get(), nullptr, 4096, 0),
                SyscallSucceedsWithValue(4096));
  });
  EXPECT_EQ(n, 1) << "splice";

  // A zero-length read is checked; a zero-length vector is not.
  n = PermEventsDuring(f.path(), FAN_ALLOW, [&] {
    FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    char c;
    EXPECT_THAT(read(in.get(), &c, 0), SyscallSucceedsWithValue(0));
  });
  EXPECT_EQ(n, 1) << "read of 0 bytes";

  n = PermEventsDuring(f.path(), FAN_ALLOW, [&] {
    FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    struct iovec iov = {nullptr, 0};
    EXPECT_THAT(readv(in.get(), &iov, 1), SyscallSucceedsWithValue(0));
  });
  EXPECT_EQ(n, 0) << "readv of 0 bytes";

  // Validation comes first: no event for a write-only fd.
  n = PermEventsDuring(f.path(), FAN_ALLOW, [&] {
    FileDescriptor wo = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_WRONLY));
    char c;
    EXPECT_THAT(read(wo.get(), &c, 1), SyscallFailsWithErrno(EBADF));
  });
  EXPECT_EQ(n, 0) << "read of a write-only fd";
}

TEST(FanotifyPermTest, DenyEveryReadPath) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "abcdef", 0644));
  auto out = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  PermEventsDuring(f.path(), FAN_DENY, [&] {
    FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    FileDescriptor o = ASSERT_NO_ERRNO_AND_VALUE(Open(out.path(), O_WRONLY));
    char buf[6];
    struct iovec iov = {buf, sizeof(buf)};
    EXPECT_THAT(read(in.get(), buf, 6), SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(pread(in.get(), buf, 6, 0), SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(readv(in.get(), &iov, 1), SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(preadv2(in.get(), &iov, 1, 0, 0), SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(sendfile(o.get(), in.get(), nullptr, 6),
                SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(syscall(SYS_copy_file_range, in.get(), nullptr, o.get(),
                        nullptr, 6, 0),
                SyscallFailsWithErrno(EPERM));
  });
}

TEST(FanotifyPermTest, DenyGetdentsAndAio) {
  SkipIfNoSysAdmin();
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "abcdef", 0644));
  PermEventsDuring(dir.path(), FAN_DENY, [&] {
    FileDescriptor d = ASSERT_NO_ERRNO_AND_VALUE(
        Open(dir.path(), O_RDONLY | O_DIRECTORY));
    char buf[256];
    EXPECT_THAT(syscall(SYS_getdents64, d.get(), buf, sizeof(buf)),
                SyscallFailsWithErrno(EPERM));
  });
  PermEventsDuring(f.path(), FAN_DENY, [&] {
    // AIO checks the read when io_submit queues it.
    aio_context_t ctx = 0;
    ASSERT_THAT(syscall(SYS_io_setup, 1, &ctx), SyscallSucceeds());
    FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));
    char buf[6];
    struct iocb cb = {};
    cb.aio_fildes = in.get();
    cb.aio_lio_opcode = IOCB_CMD_PREAD;
    cb.aio_buf = reinterpret_cast<uint64_t>(buf);
    cb.aio_nbytes = sizeof(buf);
    struct iocb* cbs[1] = {&cb};
    EXPECT_THAT(syscall(SYS_io_submit, ctx, 1, cbs),
                SyscallFailsWithErrno(EPERM));
    syscall(SYS_io_destroy, ctx);
  });
}

TEST(FanotifyPermTest, ExecReadsAreChecked) {
  SkipIfNoSysAdmin();
  // A copy of this test binary is a valid executable on every host.
  auto exe = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(),
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/self/exe")), 0755));
  int n = PermEventsDuring(exe.path(), FAN_DENY, [&] {
    pid_t c = fork();
    if (c == 0) {
      execl(exe.path().c_str(), "fanotify_test", "--gtest_list_tests",
            nullptr);
      _exit(errno == EPERM ? 42 : 43);
    }
    int status;
    ASSERT_THAT(RetryEINTR(waitpid)(c, &status, 0), SyscallSucceeds());
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 42) << status;
  });
  EXPECT_GE(n, 1);
}

TEST(FanotifyTest, Fdinfo) {
  SkipIfNoSysAdmin();
  auto top = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto m = ASSERT_NO_ERRNO_AND_VALUE(Mount("", top.path(), "tmpfs", 0, "", 0));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN,
                          AT_FDCWD, top.path().c_str()));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                          FAN_MODIFY, AT_FDCWD, top.path().c_str()));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_ACCESS, AT_FDCWD, top.path().c_str()));
  std::string info = ASSERT_NO_ERRNO_AND_VALUE(
      GetContents(absl::StrCat("/proc/self/fdinfo/", g.get())));
  // Linux prints the init flags and event_f_flags (with O_LARGEFILE).
  EXPECT_THAT(info, ::testing::ContainsRegex(
                        "fanotify flags:[0-9a-f]+ event-flags:[0-9a-f]+\n"));
  EXPECT_THAT(info,
              ::testing::ContainsRegex("fanotify mnt_id:[0-9a-f]+ "
                                       "mflags:0 mask:20 ignored_mask:0\n"));
  EXPECT_THAT(info,
              ::testing::ContainsRegex("fanotify sdev:[0-9a-f]+ "
                                       "mflags:0 mask:2 ignored_mask:0\n"));
  // Linux adds file handle fields after this; gVisor has no file handles.
  EXPECT_THAT(info, ::testing::ContainsRegex(
                        "fanotify ino:[0-9a-f]+ sdev:[0-9a-f]+ "
                        "mflags:0 mask:1 ignored_mask:0"));
}

TEST(FanotifyTest, EpollAfterRestore) {
  SkipIfNoSysAdmin();
  auto f = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "x", 0644));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(
      FanMark(g.get(), FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, f.path().c_str()));
  for (uint32_t et : {0u, static_cast<uint32_t>(EPOLLET)}) {
    SCOPED_TRACE(et ? "edge-triggered" : "level-triggered");
    FileDescriptor ep = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
    ASSERT_NO_ERRNO(RegisterEpollFD(ep.get(), g.get(), EPOLLIN | et, 0));
    MaybeSave();  // The queue is empty at save time.
    for (int round = 0; round < 2; round++) {
      Open(f.path(), O_RDONLY).IgnoreError();
      struct epoll_event ev;
      ASSERT_THAT(RetryEINTR(epoll_wait)(ep.get(), &ev, 1, 2000),
                  SyscallSucceedsWithValue(1));
      ASSERT_FALSE(ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 0)).empty());
    }
  }
}

TEST(FanotifyPermTest, ExecWaitSurvivesSave) {
  SkipIfNoSysAdmin();
  auto exe = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(),
      ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/self/exe")), 0755));
  FileDescriptor g = ASSERT_NO_ERRNO_AND_VALUE(
      FanInit(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY));
  ASSERT_NO_ERRNO(FanMark(g.get(), FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD,
                          exe.path().c_str()));
  pid_t c = fork();
  if (c == 0) {
    execl(exe.path().c_str(), "fanotify_test", "--gtest_list_tests", nullptr);
    _exit(errno == EINTR ? 43 : 44);
  }
  // The child waits in exec for the first answer.
  auto evs = ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 5000));
  ASSERT_FALSE(evs.empty());
  // A checkpoint here interrupts the wait; the exec must restart.
  MaybeSave();
  for (auto& e : evs) {
    Answer(g.get(), e.fd.get(), FAN_ALLOW);
  }
  // Answer every later event until the child exits.
  int status = 0;
  for (int i = 0; i < 500; i++) {
    pid_t r = waitpid(c, &status, WNOHANG);
    ASSERT_THAT(r, SyscallSucceeds());
    if (r == c) {
      break;
    }
    for (auto& e : ASSERT_NO_ERRNO_AND_VALUE(ReadEvents(g.get(), 20))) {
      Answer(g.get(), e.fd.get(), FAN_ALLOW);
    }
  }
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0) << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
