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

package stack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func newRouteTableTestStack(t *testing.T) *Stack {
	t.Helper()
	s := New(Options{
		NetworkProtocols: []NetworkProtocolFactory{func(s *Stack) NetworkProtocol {
			return &fwdTestNetworkProtocol{stack: s}
		}},
	})
	t.Cleanup(s.Close)
	ep := &fwdTestLinkEndpoint{
		C:        make(chan *PacketBuffer, 1),
		mtu:      fwdTestNetDefaultMTU,
		linkAddr: "a",
	}
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC(1): %s", err)
	}
	return s
}

func testSubnet(a byte, prefix int) tcpip.Subnet {
	return tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{a, 0, 0, 0}), PrefixLen: prefix}.Subnet()
}

func TestRouteTablesAreSeparate(t *testing.T) {
	s := newRouteTableTestStack(t)
	main := tcpip.Route{Destination: testSubnet(10, 8), NIC: 1}
	other := tcpip.Route{Destination: testSubnet(10, 8), NIC: 1, Table: 100}
	s.AddRoute(main)
	s.AddRoute(other)
	if got := s.GetRouteTable(); len(got) != 2 || got[0].TableID() != tcpip.RouteTableMain || got[1].TableID() != 100 {
		t.Fatalf("GetRouteTable() = %v, want the main route then the table 100 route", got)
	}
	if n := s.RemoveRoutes(func(r tcpip.Route) bool { return r.Equal(main) }); n != 1 {
		t.Fatalf("RemoveRoutes(main) = %d, want 1", n)
	}
	if got := s.GetRouteTable(); len(got) != 1 || got[0].TableID() != 100 {
		t.Fatalf("GetRouteTable() = %v, want only the table 100 route", got)
	}
}

func TestRemoveNICCleansAllTables(t *testing.T) {
	s := newRouteTableTestStack(t)
	s.AddRoute(tcpip.Route{Destination: testSubnet(10, 8), NIC: 1})
	s.AddRoute(tcpip.Route{Destination: testSubnet(0, 0), NIC: 1, Table: 100})
	if err := s.RemoveNIC(1); err != nil {
		t.Fatalf("RemoveNIC(1): %s", err)
	}
	if got := s.GetRouteTable(); len(got) != 0 {
		t.Fatalf("GetRouteTable() = %v, want none", got)
	}
}

func TestDefaultRules(t *testing.T) {
	s := newRouteTableTestStack(t)
	got := s.GetRules()
	want := []tcpip.Rule{
		{Priority: 0, NetProto: fwdTestNetNumber, Table: tcpip.RouteTableLocal},
		{Priority: 32766, NetProto: fwdTestNetNumber, Table: tcpip.RouteTableMain},
		{Priority: 32767, NetProto: fwdTestNetNumber, Table: tcpip.RouteTableDefault},
	}
	if len(got) != len(want) {
		t.Fatalf("GetRules() = %v, want %v", got, want)
	}
	for i := range want {
		if !got[i].Equal(want[i]) || !got[i].IsDefault() {
			t.Errorf("rule %d = %v, want default rule %v", i, got[i], want[i])
		}
	}
	if s.PolicyRouting() {
		t.Errorf("PolicyRouting() = true with the default rules")
	}
}

func TestRuleOrderAndDuplicates(t *testing.T) {
	s := newRouteTableTestStack(t)
	a := tcpip.Rule{Priority: 100, NetProto: fwdTestNetNumber, Src: testSubnet(10, 8), HasSrc: true, Table: 100}
	b := tcpip.Rule{Priority: 50, NetProto: fwdTestNetNumber, InNICName: "eth0", Table: 200}
	c := tcpip.Rule{Priority: 100, NetProto: fwdTestNetNumber, Dst: testSubnet(20, 8), HasDst: true, Table: 300}
	for _, r := range []tcpip.Rule{a, b, c} {
		if !s.AddRule(r) {
			t.Fatalf("AddRule(%v) = false", r)
		}
	}
	if s.AddRule(a) {
		t.Errorf("AddRule of an equal rule = true, want false")
	}
	if !s.PolicyRouting() {
		t.Errorf("PolicyRouting() = false with custom rules")
	}
	got := s.GetRules()
	wantTables := []uint32{tcpip.RouteTableLocal, 200, 100, 300, tcpip.RouteTableMain, tcpip.RouteTableDefault}
	if len(got) != len(wantTables) {
		t.Fatalf("GetRules() = %v", got)
	}
	for i, table := range wantTables {
		if got[i].Table != table {
			t.Errorf("rule %d table = %d, want %d (rules %v)", i, got[i].Table, table, got)
		}
	}
	for _, r := range []tcpip.Rule{a, b, c} {
		if !s.RemoveRule(func(x tcpip.Rule) bool { return x.Equal(r) }) {
			t.Fatalf("RemoveRule(%v) = false", r)
		}
	}
	if s.PolicyRouting() {
		t.Errorf("PolicyRouting() = true after removing the custom rules")
	}
	if s.RemoveRule(func(x tcpip.Rule) bool { return x.Equal(a) }) {
		t.Errorf("RemoveRule of a missing rule = true")
	}
}
