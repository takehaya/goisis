package server

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// mtPeerServer builds a two-node Level-2 topology — this node and one peer, a
// metric-10 edge each way — so a test only has to say what reachability the
// peer advertises.
func mtPeerServer(t *testing.T, now time.Time, peerTLVs ...packet.TLV) *IsisServer {
	t.Helper()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	s := mustServer(t,
		WithSystemID(self),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level2:    true,
			Padding:   ptrFalse(),
		}),
	)
	injectLSP(s, self, []packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(peer, 0), Metric: 10}}},
	}, now)
	tlvs := append([]packet.TLV{
		&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{{NeighborID: nodeID(self, 0), Metric: 10}}},
	}, peerTLVs...)
	injectLSP(s, peer, tlvs, now)
	return s
}

// TestMTIPv6ReachabilityProducesRoutes is the failure this change exists for: a
// peer configured for multi-topology IPv6 puts its IPv6 prefixes in TLV 237
// under MT #2 and none in TLV 236, and before TLV 237 was decoded goisis filed
// it as an UnknownTLV and learned no IPv6 route from that peer at all.
func TestMTIPv6ReachabilityProducesRoutes(t *testing.T) {
	now := time.Now()
	prefix := netip.MustParsePrefix("2001:db8:1::/48")
	s := mtPeerServer(t, now, &packet.MTIPv6ReachabilityTLV{
		MTID:     packet.MTIDIPv6Unicast,
		Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: prefix}},
	})

	routes := s.computeSPF(packet.Level2, 0, flexAlgoAffinity{}, now)
	r, ok := routes[prefix]
	if !ok {
		t.Fatalf("no route for %s learned from TLV 237; have %v", prefix, keys(routes))
	}
	// The path metric is the MT #0 edge (10) plus the prefix metric (5): MT #2
	// reachability is folded into the one RIB but computed over MT #0's edges.
	if r.metric != 15 {
		t.Errorf("metric = %d, want 15", r.metric)
	}
}

// TestMTIPv6ReachabilityIgnoresOtherTopologies pins which MT IDs reach the RIB.
// MT #0 in TLV 237 is the case RFC 5120 section 7.4 says MUST be ignored; MT #4
// (IPv6 multicast) and TLV 235's IPv4 are topologies with their own RIBs that
// goisis does not compute. The MT #2 prefix is the positive control: it shares
// the LSP and the SPF run with the three that must not appear, so an empty RIB
// cannot pass this test.
func TestMTIPv6ReachabilityIgnoresOtherTopologies(t *testing.T) {
	now := time.Now()
	var (
		wanted    = netip.MustParsePrefix("2001:db8:2::/48") // MT #2
		mtZero    = netip.MustParsePrefix("2001:db8:0::/48") // MT #0 in TLV 237
		multicast = netip.MustParsePrefix("2001:db8:4::/48") // MT #4
		mtIPv4    = netip.MustParsePrefix("10.3.0.0/16")     // MT #3 in TLV 235
	)
	s := mtPeerServer(t, now,
		&packet.MTIPv6ReachabilityTLV{MTID: packet.MTIDStandard, Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: mtZero}}},
		&packet.MTIPv6ReachabilityTLV{MTID: packet.MTIDIPv6Unicast, Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: wanted}}},
		&packet.MTIPv6ReachabilityTLV{MTID: 4, Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: multicast}}},
		&packet.MTIPReachabilityTLV{MTID: 3, Prefixes: []packet.ExtendedIPReachEntry{{Metric: 5, Prefix: mtIPv4}}},
	)

	routes := s.computeSPF(packet.Level2, 0, flexAlgoAffinity{}, now)
	if _, ok := routes[wanted]; !ok {
		t.Fatalf("MT #2 prefix %s missing; the run learned nothing, so the rest proves nothing", wanted)
	}
	for _, p := range []netip.Prefix{mtZero, multicast, mtIPv4} {
		if _, ok := routes[p]; ok {
			t.Errorf("%s reached the RIB from a topology goisis does not compute", p)
		}
	}
}

// TestMTIPv6ReachabilityStaysOutOfAFlexAlgo pins the other half of the fold's
// guard: MT #2 reachability belongs to algorithm 0, exactly as the plain IP
// reachability beside it does. RFC 9350 gives a Flexible Algorithm no fallback
// to plain reachability — its only prefixes are the SRv6 locators advertised
// for it — so folding an MT peer's prefixes in would install them in every
// Flex-Algo RIB, reached over a path that algorithm's own constraints may have
// pruned.
func TestMTIPv6ReachabilityStaysOutOfAFlexAlgo(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	self := packet.SystemID{0, 0, 0, 0, 0, 1}
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	loc := netip.MustParsePrefix("fc00:128:2::/48")
	mt := netip.MustParsePrefix("2001:db8:2::/48")

	injectLSP(s, self, []packet.TLV{partCap(), isReach(peer)}, now)
	injectLSP(s, peer, []packet.TLV{partCap(), isReach(self), algoLocTLV(loc),
		&packet.MTIPv6ReachabilityTLV{MTID: packet.MTIDIPv6Unicast, Prefixes: []packet.IPv6ReachEntry{{Metric: 5, Prefix: mt}}},
	}, now)

	routes := s.computeSPF(packet.Level2, 128, flexAlgoAffinity{}, now)
	// The locator is the control: the peer advertising the MT prefix is
	// reachable under algo 128, so the prefix's absence is the rule at work
	// and not a run that computed nothing.
	if _, ok := routes[loc]; !ok {
		t.Fatalf("algo 128 did not reach %s; the run learned nothing, so the rest proves nothing", loc)
	}
	if _, ok := routes[mt]; ok {
		t.Errorf("%s reached a Flex-Algo RIB, which RFC 9350's no-fallback rule keeps to SRv6 locators", mt)
	}
	// And it is still algorithm 0's, so this is a boundary and not a loss.
	if _, ok := s.computeSPF(packet.Level2, 0, flexAlgoAffinity{}, now)[mt]; !ok {
		t.Errorf("%s reached neither RIB", mt)
	}
}

// TestMTNotOriginated pins the decision not to advertise multi-topology: goisis
// computes one topology, and RFC 5120 section 7.1 makes the absence of TLV 229
// mean "MT #0 only", which is exactly true of it. Claiming MT #2 there would
// also oblige it to advertise MT #2 IS reachability (section 3) and to run a
// second decision process for it (section 6).
func TestMTNotOriginated(t *testing.T) {
	now := time.Now()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level2:    true,
			Padding:   ptrFalse(),
		}),
		WithAdvertisedPrefix(netip.MustParsePrefix("2001:db8:9::/48"), 10),
	)
	s.regenerateLSPs(false, now)

	var v6 int
	for id, e := range s.dbs[packet.Level2].entries {
		if id.NodeID().SystemID() != s.systemID {
			continue
		}
		for _, tlv := range e.lsp.TLVs {
			switch tlv.(type) {
			case *packet.MTopologiesTLV, *packet.MTISReachabilityTLV,
				*packet.MTIPReachabilityTLV, *packet.MTIPv6ReachabilityTLV:
				t.Errorf("own LSP advertises TLV %d; goisis participates in MT #0 only", tlv.Type())
			case *packet.IPv6ReachabilityTLV:
				v6++
			}
		}
	}
	// Positive control: the IPv6 prefix is advertised, in TLV 236 where MT #0
	// puts it — so "no MT TLVs" is not "no reachability at all".
	if v6 == 0 {
		t.Error("own LSP carries no TLV 236; the origination under test emitted nothing")
	}
}

// Multi-topology reachability is folded into the one RIB so that this node can
// forward to it (TestMTIPv6ReachabilityProducesRoutes), and that is as far as
// the fold goes: re-originating it is a separate claim, made to a separate
// level, and goisis has no way to make it honestly. RFC 5120 section 4 says
// "Route leaking between the levels SHOULD only be performed within the same
// MT", and goisis originates no MT TLV at all (TestMTNotOriginated) — so the
// only thing it could put in its Level-2 LSP is TLV 236, which says "reachable
// in the default topology" on evidence that only ever said "reachable in IPv6
// unicast".
func TestAnMTOnlyPrefixIsNotExportedIntoLevel2(t *testing.T) {
	var (
		mtOnly  = netip.MustParsePrefix("2001:db8:2::/48") // B advertises it in TLV 237 alone
		ordinar = netip.MustParsePrefix("2001:db8:1::/48") // and this one in TLV 236
	)
	s := l1l2Server(t, true)
	now := time.Now()
	injectB(s, now,
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{{Prefix: ordinar, Metric: 5}}},
		&packet.MTIPv6ReachabilityTLV{MTID: packet.MTIDIPv6Unicast,
			Prefixes: []packet.IPv6ReachEntry{{Prefix: mtOnly, Metric: 5}}},
	)
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	// Positive control: the TLV 236 prefix from the same LSP still exports, at
	// the metric it always did — so "nothing exported" cannot pass this test.
	if got, want := l2OwnReach(t, s)[ordinar], []uint32{15}; !slices.Equal(got, want) {
		t.Errorf("L2 LSP metrics for the TLV 236 prefix %s = %v, want %v", ordinar, got, want)
	}
	if m, ok := l2OwnReach(t, s)[mtOnly]; ok {
		t.Errorf("%s was re-originated into our Level-2 LSP as MT #0 reachability at metric %v; "+
			"the only advertisement for it was MT #2", mtOnly, m)
	}
	// The fold itself still stands: the route is in our own RIB.
	if _, ok := s.rib[mtOnly]; !ok {
		t.Errorf("%s is not in the RIB; withholding the export must not withhold the route", mtOnly)
	}
}

// The downward direction of the same rule: a Level-2 prefix whose only
// advertisement is MT #2 is not leaked into the Level-1 area as MT #0 either.
func TestAnMTOnlyPrefixIsNotLeakedIntoLevel1(t *testing.T) {
	var (
		mtOnly  = netip.MustParsePrefix("2001:db8:2::/48")
		ordinar = netip.MustParsePrefix("2001:db8:1::/48")
	)
	s := l1l2Server(t, true, WithL2LeakFilter(permitEverything()))
	now := time.Now()
	injectB(s, now) // a Level-1 neighbour with no reachability of its own
	injectBL2(s, now,
		&packet.IPv6ReachabilityTLV{Prefixes: []packet.IPv6ReachEntry{{Prefix: ordinar, Metric: 5}}},
		&packet.MTIPv6ReachabilityTLV{MTID: packet.MTIDIPv6Unicast,
			Prefixes: []packet.IPv6ReachEntry{{Prefix: mtOnly, Metric: 5}}},
	)
	s.regenerateLSPs(false, now)
	s.updateRIB(now)
	s.drainLSPGen(now)

	got := ownIPReach(t, s, packet.Level1)
	if want := []ownReach{{metric: 15, down: true}}; !slices.Equal(got[ordinar], want) {
		t.Errorf("L1 LSP entries for the TLV 236 prefix %s = %v, want %v", ordinar, got[ordinar], want)
	}
	if e, ok := got[mtOnly]; ok {
		t.Errorf("%s was leaked into our Level-1 LSP as MT #0 reachability %v; "+
			"the only advertisement for it was MT #2", mtOnly, e)
	}
}
