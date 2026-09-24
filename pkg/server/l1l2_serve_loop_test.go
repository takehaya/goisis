package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// routeVia returns the route s holds for p together with its next hops, or
// ok=false when the RIB does not have it. Read over the public API: the only
// server this test may touch during convergence is the observer.
func routeVia(t *testing.T, s *IsisServer, p netip.Prefix) (RouteInfo, bool) {
	t.Helper()
	routes, err := s.ListRoutes(context.Background())
	if err != nil {
		return RouteInfo{}, false
	}
	for _, r := range routes {
		if r.Prefix == p {
			return r, true
		}
	}
	return RouteInfo{}, false
}

// TestL1PrefixReachesAnL2NeighborThroughTheServeLoop is the one test where the
// three mechanisms this release added to the management loop run together:
// the SPF hold, the LSP generation throttle, and the Level-1 to Level-2 export.
//
//	B (L1 only) --- A (L1L2) --- C (L2 only)
//
// B originates a prefix. A's Level-1 SPF reaches it, updateRIB puts it in the
// export set and sets lspGenPending — after that iteration's SPF check has
// already run, so the new Level-2 LSP is built by a LATER drainLSPGen, which
// marks dirty again and lets the hold decide when the second SPF runs.
//
// The second prefix is what makes the test bite: it is originated once the
// network is quiet, so B's LSP is the only event in it, and nothing else asks A
// to re-originate. Nothing outside the protocol pokes A either — the test reads
// only C. A regression that stopped updateRIB requesting the regeneration, or
// that moved the drain out of the hand-off, therefore leaves C without the
// route rather than merely late.
//
// The latency of that hand-off is a documented property (docs/design.md,
// Origination: at most minLSPGenInterval plus one housekeeping tick), so the
// assertions are on convergence, not on a deadline. All three instances run on
// one clock the test steps, so those intervals pass as fast as the three loops
// can be stepped through them; steadyHello rather than fastHello because a
// stepped clock's hellos are a whole tick apart (see steadyHello).
func TestL1PrefixReachesAnL2NeighborThroughTheServeLoop(t *testing.T) {
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	configured := netip.MustParsePrefix("10.1.0.0/24")
	runtime := netip.MustParsePrefix("10.2.0.0/24")
	aToC := netip.MustParseAddr("10.0.2.1") // A's address on the A-C link = C's next hop

	link := func(a, b byte) (*datalink.MockTransport, *datalink.MockTransport) {
		ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, a, b}, 1500)
		tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, b, a}, 1500)
		datalink.Link(ta, tb)
		return ta, tb
	}
	p2p := func(name string, tr *datalink.MockTransport, l2 bool, addr netip.Addr) CircuitConfig {
		c := CircuitConfig{
			Name: name, Transport: tr, P2P: true,
			Level1: !l2, Level2: l2, Padding: ptrFalse(),
			IPv4Addrs: []netip.Addr{addr},
		}
		steadyHello(&c)
		return c
	}

	taB, tbA := link(0xa, 0xb) // the Level-1 link
	taC, tcA := link(0xa, 0xc) // the Level-2 link
	clk := newFakeClock()

	// Both prefixes cost 5 at B; A's Level-1 path to B costs DefaultMetric, and
	// C's Level-2 path to A another DefaultMetric.
	const prefixMetric = 5
	b := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area),
		WithCircuit(p2p("b", tbA, false, netip.MustParseAddr("10.0.1.2"))),
		WithAdvertisedPrefix(configured, prefixMetric), WithClock(clk),
	)
	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(p2p("a1", taB, false, netip.MustParseAddr("10.0.1.1"))),
		WithCircuit(p2p("a2", taC, true, aToC)), WithClock(clk),
	)
	c := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 3}), WithAreaAddresses(area),
		WithCircuit(p2p("c", tcA, true, netip.MustParseAddr("10.0.2.3"))), WithClock(clk),
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bctx, stopB := context.WithCancel(ctx)
	defer stopB()
	go a.Serve(ctx)  //nolint:errcheck // ctx shutdown
	go b.Serve(bctx) //nolint:errcheck // ctx shutdown
	go c.Serve(ctx)  //nolint:errcheck // ctx shutdown

	const wantMetric = DefaultMetric + DefaultMetric + prefixMetric
	exported := func(p netip.Prefix) bool {
		r, ok := routeVia(t, c, p)
		return ok && r.Metric == wantMetric && r.Level == packet.Level2 &&
			len(r.NextHops) == 1 && r.NextHops[0].Gateway == aToC && r.NextHops[0].Interface == "c"
	}
	waitClock(t, clk, "C installs the Level-1 prefix A exports", func() bool { return exported(configured) })

	// From here the network is converged and idle, so B's LSP is the only event
	// A sees for the second prefix.
	if err := b.AddPrefix(context.Background(), AdvertisedPrefix{Prefix: runtime, Metric: prefixMetric}); err != nil {
		t.Fatalf("AddPrefix on B: %v", err)
	}
	waitClock(t, clk, "C installs a prefix B originated after convergence", func() bool { return exported(runtime) })

	// B leaves: its clean-shutdown purge reaches A, A's Level-1 SPF loses both
	// prefixes, and the same hand-off must run in reverse.
	stopB()
	stopped(t, b) // B's loop takes its timers off the clock on the way out
	waitClock(t, clk, "C withdraws both prefixes once B is gone", func() bool {
		_, got1 := routeVia(t, c, configured)
		_, got2 := routeVia(t, c, runtime)
		return !got1 && !got2
	})
}
