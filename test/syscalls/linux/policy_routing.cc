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

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/fib_rules.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// FlushRules removes the IPv4 rules other than the default ones.
void FlushRules() {
  FileDescriptor fd =
      TEST_CHECK_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  struct {
    struct nlmsghdr hdr;
    struct fib_rule_hdr rule;
  } dump = {};
  dump.hdr.nlmsg_len = sizeof(dump);
  dump.hdr.nlmsg_type = RTM_GETRULE;
  dump.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  dump.hdr.nlmsg_seq = 1;
  dump.rule.family = AF_INET;
  std::vector<std::pair<uint32_t, uint32_t>> found;  // priority, table
  TEST_CHECK_NO_ERRNO(NetlinkRequestResponse(
      fd, &dump, sizeof(dump),
      [&](const struct nlmsghdr* hdr) {
        if (hdr->nlmsg_type != RTM_NEWRULE) return;
        const auto* r =
            reinterpret_cast<const struct fib_rule_hdr*>(NLMSG_DATA(hdr));
        uint32_t prio = 0, table = r->table;
        int len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
        for (const struct rtattr* a = reinterpret_cast<const struct rtattr*>(
                 reinterpret_cast<const char*>(r) + NLMSG_ALIGN(sizeof(*r)));
             RTA_OK(a, len); a = RTA_NEXT(a, len)) {
          if (a->rta_type == FRA_PRIORITY) memcpy(&prio, RTA_DATA(a), 4);
          if (a->rta_type == FRA_TABLE) memcpy(&table, RTA_DATA(a), 4);
        }
        if (prio != 0 && prio != 32766 && prio != 32767) {
          found.push_back({prio, table});
        }
      },
      false));
  for (const auto& [prio, table] : found) {
    struct {
      struct nlmsghdr hdr;
      struct fib_rule_hdr rule;
      struct rtattr attr;
      uint32_t prio;
    } del = {};
    del.hdr.nlmsg_len = sizeof(del);
    del.hdr.nlmsg_type = RTM_DELRULE;
    del.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    del.hdr.nlmsg_seq = 2;
    del.rule.family = AF_INET;
    del.rule.table = table < 256 ? table : RT_TABLE_UNSPEC;
    del.rule.action = FR_ACT_TO_TBL;
    del.attr.rta_type = FRA_PRIORITY;
    del.attr.rta_len = RTA_LENGTH(sizeof(del.prio));
    del.prio = prio;
    TEST_CHECK_NO_ERRNO(
        NetlinkRequestAckOrError(fd, 2, &del, del.hdr.nlmsg_len));
  }
}

// InNewNetns runs fn in a child with lo up and forwarding on. On Linux the
// child gets a new network namespace. On gVisor /proc/sys/net always shows
// the root network namespace (gvisor.dev/issue/1833), so the child stays in
// the sandbox's namespace: its tun devices, and their routes, go away when it
// exits, and it removes the rules an earlier test left.
void InNewNetns(const std::function<void()>& fn) {
  EXPECT_THAT(InForkedProcess([&] {
                if (IsRunningOnGvisor()) {
                  FlushRules();
                } else {
                  TEST_PCHECK(unshare(CLONE_NEWNET) == 0);
                }
                Link lo = TEST_CHECK_NO_ERRNO_AND_VALUE(LoopbackLink());
                TEST_CHECK_NO_ERRNO(LinkChangeFlags(lo.index, IFF_UP, IFF_UP));
                // Forwarding on; no reverse-path filter (Linux only files).
                SetContents("/proc/sys/net/ipv4/ip_forward", "1").IgnoreError();
                SetContents("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
                    .IgnoreError();
                SetContents("/proc/sys/net/ipv4/conf/default/rp_filter", "0")
                    .IgnoreError();
                fn();
              }),
              IsPosixErrorOkAndHolds(0));
}

// GetLinkByName returns the link named name.
PosixErrorOr<Link> GetLinkByName(const std::string& name) {
  ASSIGN_OR_RETURN_ERRNO(auto links, DumpLinks());
  for (const auto& link : links) {
    if (link.name == name) {
      return link;
    }
  }
  return PosixError(ENOENT, "interface not found");
}

// Tun is a tun device (IFF_TUN | IFF_NO_PI) with one IPv4 address, up.
struct Tun {
  int fd;
  int index;
};

Tun MakeTun(const char* name, const char* addr, int prefix) {
  int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
  TEST_PCHECK(fd >= 0);
  struct ifreq ifr = {};
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, name, IFNAMSIZ);
  TEST_PCHECK(ioctl(fd, TUNSETIFF, &ifr) == 0);
  Link link = TEST_CHECK_NO_ERRNO_AND_VALUE(GetLinkByName(name));
  TEST_CHECK_NO_ERRNO(LinkChangeFlags(link.index, IFF_UP, IFF_UP));
  struct in_addr a;
  TEST_CHECK(inet_pton(AF_INET, addr, &a) == 1);
  FileDescriptor nl = TEST_CHECK_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  TEST_CHECK_NO_ERRNO(
      LinkAddLocalAddr(nl, link.index, AF_INET, prefix, &a, sizeof(a)));
  return {fd, link.index};
}

uint16_t Checksum(const void* data, size_t len) {
  uint32_t sum = 0;
  const uint16_t* p = static_cast<const uint16_t*>(data);
  for (; len > 1; len -= 2) sum += *p++;
  if (len) sum += *reinterpret_cast<const uint8_t*>(p);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}

// WriteUDP writes an IPv4 UDP packet from src to dst into a tun device, as if
// it arrived on that interface.
void WriteUDP(int fd, const char* src, const char* dst) {
  char pkt[sizeof(struct iphdr) + sizeof(struct udphdr) + 4] = {};
  auto* ip = reinterpret_cast<struct iphdr*>(pkt);
  ip->version = 4;
  ip->ihl = 5;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->tot_len = htons(sizeof(pkt));
  TEST_CHECK(inet_pton(AF_INET, src, &ip->saddr) == 1);
  TEST_CHECK(inet_pton(AF_INET, dst, &ip->daddr) == 1);
  ip->check = Checksum(ip, sizeof(*ip));
  auto* udp = reinterpret_cast<struct udphdr*>(ip + 1);
  udp->source = htons(4000);
  udp->dest = htons(4001);
  udp->len = htons(sizeof(*udp) + 4);
  memcpy(udp + 1, "ping", 4);
  TEST_PCHECK(write(fd, pkt, sizeof(pkt)) == sizeof(pkt));
}

// ReadsUDPTo returns true if a UDP packet to dst comes out of fd within 1 s.
bool ReadsUDPTo(int fd, const char* dst) {
  struct in_addr want;
  TEST_CHECK(inet_pton(AF_INET, dst, &want) == 1);
  for (int i = 0; i < 10; i++) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 100) <= 0) continue;
    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < static_cast<ssize_t>(sizeof(struct iphdr))) continue;
    auto* ip = reinterpret_cast<struct iphdr*>(buf);
    if (ip->version == 4 && ip->protocol == IPPROTO_UDP &&
        ip->daddr == want.s_addr) {
      return true;
    }
  }
  return false;
}

// ModifyRule sends type (RTM_NEWRULE or RTM_DELRULE) for "from <src>/<len>
// iif <iif> lookup <table> priority <prio>"; src may be nullptr and iif "".
void ModifyRule(uint16_t type, const char* src, int len, const char* iif,
                int table, int prio) {
  FileDescriptor fd = TEST_CHECK_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  struct {
    struct nlmsghdr hdr;
    struct fib_rule_hdr rule;
    char buf[128];
  } req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.rule));
  req.hdr.nlmsg_type = type;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  if (type == RTM_NEWRULE) {
    req.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
  }
  req.hdr.nlmsg_seq = 1;
  req.rule.family = AF_INET;
  req.rule.table = table;
  req.rule.action = FR_ACT_TO_TBL;
  auto add = [&](uint16_t type, const void* data, size_t n) {
    auto* a = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<char*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
    a->rta_type = type;
    a->rta_len = RTA_LENGTH(n);
    memcpy(RTA_DATA(a), data, n);
    req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_ALIGN(a->rta_len);
  };
  uint32_t p = prio;
  add(FRA_PRIORITY, &p, sizeof(p));
  if (src) {
    struct in_addr a;
    TEST_CHECK(inet_pton(AF_INET, src, &a) == 1);
    req.rule.src_len = len;
    add(FRA_SRC, &a, sizeof(a));
  }
  if (iif[0]) add(FRA_IIFNAME, iif, strlen(iif) + 1);
  TEST_CHECK_NO_ERRNO(NetlinkRequestAckOrError(fd, 1, &req, req.hdr.nlmsg_len));
}

// AddRule adds a rule (see ModifyRule).
void AddRule(const char* src, int len, const char* iif, int table, int prio) {
  ModifyRule(RTM_NEWRULE, src, len, iif, table, prio);
}

// AddDefaultRoute adds "default dev <index> table <table>".
void AddDefaultRoute(int index, int table) {
  FileDescriptor fd = TEST_CHECK_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  struct {
    struct nlmsghdr hdr;
    struct rtmsg rt;
    char buf[64];
  } req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.rt));
  req.hdr.nlmsg_type = RTM_NEWROUTE;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
  req.hdr.nlmsg_seq = 1;
  req.rt.rtm_family = AF_INET;
  req.rt.rtm_table = table;
  req.rt.rtm_protocol = RTPROT_BOOT;
  req.rt.rtm_scope = RT_SCOPE_LINK;
  req.rt.rtm_type = RTN_UNICAST;
  auto* a = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<char*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  a->rta_type = RTA_OIF;
  a->rta_len = RTA_LENGTH(sizeof(int));
  memcpy(RTA_DATA(a), &index, sizeof(int));
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_ALIGN(a->rta_len);
  TEST_CHECK_NO_ERRNO(NetlinkRequestAckOrError(fd, 1, &req, req.hdr.nlmsg_len));
}

void SkipIfNoNetAdmin() {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
}

TEST(PolicyRoutingTest, ForwardedBySource) {
  SkipIfNoNetAdmin();
  InNewNetns([] {
    Tun in = MakeTun("pr-in", "192.0.2.1", 24);
    Tun out = MakeTun("pr-out", "203.0.113.1", 24);
    AddDefaultRoute(out.index, 100);
    // No rule yet: the main table has no route, so nothing goes out.
    WriteUDP(in.fd, "192.0.2.5", "198.51.100.7");
    TEST_CHECK(!ReadsUDPTo(out.fd, "198.51.100.7"));
    AddRule("192.0.2.0", 24, "", 100, 100);
    WriteUDP(in.fd, "192.0.2.5", "198.51.100.7");
    TEST_CHECK(ReadsUDPTo(out.fd, "198.51.100.7"));
    // A source outside 192.0.2.0/24 does not match; main has no route.
    WriteUDP(in.fd, "198.18.5.5", "198.51.100.7");
    TEST_CHECK(!ReadsUDPTo(out.fd, "198.51.100.7"));
  });
}

TEST(PolicyRoutingTest, ForwardedByInputInterface) {
  SkipIfNoNetAdmin();
  InNewNetns([] {
    Tun in = MakeTun("pr-in", "192.0.2.1", 24);
    Tun out = MakeTun("pr-out", "203.0.113.1", 24);
    AddDefaultRoute(out.index, 100);
    AddRule(nullptr, 0, "pr-in", 100, 100);
    WriteUDP(in.fd, "192.0.2.5", "198.51.100.7");
    TEST_CHECK(ReadsUDPTo(out.fd, "198.51.100.7"));
  });
}

TEST(PolicyRoutingTest, FallThroughToMain) {
  SkipIfNoNetAdmin();
  InNewNetns([] {
    Tun in = MakeTun("pr-in", "192.0.2.1", 24);
    Tun out = MakeTun("pr-out", "203.0.113.1", 24);
    // Table 100 is empty; the rule matches but must fall through to main.
    AddRule("192.0.2.0", 24, "", 100, 100);
    AddDefaultRoute(out.index, RT_TABLE_MAIN);
    WriteUDP(in.fd, "192.0.2.5", "198.51.100.7");
    TEST_CHECK(ReadsUDPTo(out.fd, "198.51.100.7"));
  });
}

TEST(PolicyRoutingTest, LocalTrafficUsesMainUnlessSourceMatches) {
  SkipIfNoNetAdmin();
  InNewNetns([] {
    Tun in = MakeTun("pr-in", "192.0.2.1", 24);
    Tun out = MakeTun("pr-out", "203.0.113.1", 24);
    AddDefaultRoute(out.index, 100);
    AddRule("192.0.2.0", 24, "", 100, 100);
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons(9)};
    TEST_CHECK(inet_pton(AF_INET, "198.51.100.7", &dst.sin_addr) == 1);
    // Unbound: source 0.0.0.0 does not match; main has no route.
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_PCHECK(s >= 0);
    TEST_CHECK(sendto(s, "x", 1, 0, reinterpret_cast<sockaddr*>(&dst),
                      sizeof(dst)) < 0 &&
               errno == ENETUNREACH);
    close(s);
    // Bound to 192.0.2.1: the rule matches and table 100 sends it out.
    s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in src = {.sin_family = AF_INET};
    TEST_CHECK(inet_pton(AF_INET, "192.0.2.1", &src.sin_addr) == 1);
    TEST_PCHECK(bind(s, reinterpret_cast<sockaddr*>(&src), sizeof(src)) == 0);
    TEST_PCHECK(sendto(s, "x", 1, 0, reinterpret_cast<sockaddr*>(&dst),
                       sizeof(dst)) == 1);
    TEST_CHECK(ReadsUDPTo(out.fd, "198.51.100.7"));
    close(s);
  });
}

TEST(PolicyRoutingTest, PriorityOrder) {
  SkipIfNoNetAdmin();
  InNewNetns([] {
    Tun in = MakeTun("pr-in", "192.0.2.1", 24);
    Tun a = MakeTun("pr-a", "203.0.113.1", 24);
    Tun b = MakeTun("pr-b", "198.18.0.1", 24);
    AddDefaultRoute(a.index, 100);
    AddDefaultRoute(b.index, 200);
    AddRule("192.0.2.0", 24, "", 200, 50);   // wins: lower priority value
    AddRule("192.0.2.0", 24, "", 100, 100);
    WriteUDP(in.fd, "192.0.2.5", "198.51.100.7");
    TEST_CHECK(ReadsUDPTo(b.fd, "198.51.100.7"));
    TEST_CHECK(!ReadsUDPTo(a.fd, "198.51.100.7"));
  });
}

TEST(PolicyRoutingTest, LinkRemovalCleansAllTables) {
  SkipIfNoNetAdmin();
  InNewNetns([] {
    Tun out = MakeTun("pr-out", "203.0.113.1", 24);
    AddDefaultRoute(out.index, 100);
    close(out.fd);  // The non-persistent tun goes away with its routes.
    FileDescriptor nl =
        TEST_CHECK_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
    bool found = false;
    TEST_CHECK_NO_ERRNO(DumpRoutes(nl, AF_INET, [&](const nlmsghdr* hdr) {
      if (RouteTable(hdr) == 100) found = true;
    }));
    TEST_CHECK(!found);
  });
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
