load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

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

declare_mutex(
    name = "group_queue_mutex",
    out = "group_queue_mutex.go",
    package = "fanotify",
    prefix = "groupQueue",
)

go_template_instance(
    name = "event_list",
    out = "event_list.go",
    package = "fanotify",
    prefix = "event",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*event",
        "Linker": "*event",
    },
)

go_library(
    name = "fanotify",
    srcs = [
        "event_list.go",
        "group.go",
        "group_mark_mutex.go",
        "group_queue_mutex.go",
        "marks.go",
        "merge.go",
        "origin.go",
        "perm.go",
        "queue.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/fanotify",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
