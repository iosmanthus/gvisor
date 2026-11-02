load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "group_mark_mutex",
    out = "group_mark_mutex.go",
    package = "fanotify",
    prefix = "groupMark",
)

go_library(
    name = "fanotify",
    srcs = [
        "group.go",
        "group_mark_mutex.go",
        "marks.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/fanotify",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
