package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// p2pHelloEchoing builds a point-to-point hello from src whose TLV 240 claims
// an Up handshake with neighbor/neighborCircID.
func p2pHelloEchoing(src packet.SystemID, area packet.AreaAddress, neighbor packet.SystemID, neighborCircID uint32) *packet.P2PHello {
	return &packet.P2PHello{
		CircuitType:    packet.CircuitTypeLevel2,
		SourceID:       src,
		HoldingTime:    30,
		LocalCircuitID: 1,
		TLVs: []packet.TLV{
			&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{area}},
			&packet.P2PThreeWayAdjacencyTLV{
				State:                     packet.P2PAdjStateUp,
				HasLocal:                  true,
				ExtLocalCircuitID:         7,
				HasNeighbor:               true,
				NeighborSystemID:          neighbor,
				NeighborExtLocalCircuitID: neighborCircID,
			},
		},
	}
}

// TestP2PHelloEchoingAnotherNeighborTearsDownAdjacency checks RFC 5303 3.2:
// once the peer's TLV 240 names a neighbor other than us, the adjacency is
// Down at once rather than lingering in Init until the hold timer.
func TestP2PHelloEchoingAnotherNeighborTearsDownAdjacency(t *testing.T) {
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	sysA := packet.SystemID{0, 0, 0, 0, 0, 1}
	sysB := packet.SystemID{0, 0, 0, 0, 0, 2}
	sysC := packet.SystemID{0, 0, 0, 0, 0, 3}
	peer := packet.SNPA{0, 0, 0, 0, 0, 0xb2}

	cfg := CircuitConfig{
		Name:      "a",
		Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500),
		P2P:       true, Level2: true, Padding: ptrFalse(),
	}
	fastHello(&cfg)
	a := mustServer(t, WithSystemID(sysA), WithAreaAddresses(area), WithCircuit(cfg))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown

	sub, err := a.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// B echoes us, so the handshake completes and the adjacency reaches Up.
	// Hellos are driven on the Serve loop directly: a live peer would keep
	// re-forming the adjacency and the teardown below could not be observed.
	deliver := func(h *packet.P2PHello) {
		t.Helper()
		if err := a.mgmtOperation(ctx, func() error {
			a.processP2PHello(a.circuits[0], peer, h)
			return nil
		}); err != nil {
			t.Fatalf("mgmtOperation: %v", err)
		}
	}
	var extCircID uint32
	if err := a.mgmtOperation(ctx, func() error { extCircID = a.circuits[0].extCircID; return nil }); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	deliver(p2pHelloEchoing(sysB, area, sysA, extCircID))
	if st, ok := adjState(t, a, packet.Level2); !ok || st != AdjUp {
		t.Fatalf("adjacency to b = %v (present=%v), want Up", st, ok)
	}

	// B is now handshaking with C: our adjacency is Down, not Init.
	deliver(p2pHelloEchoing(sysB, area, sysC, extCircID))

	adjs, err := a.ListAdjacencies(ctx)
	if err != nil {
		t.Fatalf("ListAdjacencies: %v", err)
	}
	if len(adjs) != 0 {
		t.Errorf("adjacencies after the peer handshakes with another router = %d, want 0", len(adjs))
	}
	down := false
	for len(sub.Events) > 0 {
		ev := <-sub.Events
		if ev.Adjacency != nil && ev.Adjacency.State == AdjDown {
			down = true
		}
	}
	if !down {
		t.Error("no Down adjacency event was emitted")
	}
}

// TestHelloWithOwnSystemIDIsIgnoredAndWarnedOnce checks that a hello carrying
// our own system ID (a duplicate system ID on the segment) forms no adjacency
// and is warned about once per circuit, not once per hello.
func TestHelloWithOwnSystemIDIsIgnoredAndWarnedOnce(t *testing.T) {
	sys := packet.SystemID{0, 0, 0, 0, 0, 1}
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	peer := packet.SNPA{0, 0, 0, 0, 0, 0xb2}

	run := func(t *testing.T, cfg CircuitConfig, deliver func(s *IsisServer, c *circuit)) {
		t.Helper()
		// Only the Serve goroutine writes to buf, and every read below is
		// ordered after a mgmtOperation round-trip, so no lock is needed.
		var buf bytes.Buffer
		fastHello(&cfg)
		s := mustServer(t, WithSystemID(sys), WithAreaAddresses(area), WithCircuit(cfg),
			WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.Serve(ctx) //nolint:errcheck // ctx shutdown

		for range 2 {
			if err := s.mgmtOperation(ctx, func() error {
				deliver(s, s.circuits[0])
				return nil
			}); err != nil {
				t.Fatalf("mgmtOperation: %v", err)
			}
		}

		adjs, err := s.ListAdjacencies(ctx)
		if err != nil {
			t.Fatalf("ListAdjacencies: %v", err)
		}
		if len(adjs) != 0 {
			t.Errorf("hello carrying our own system ID formed %d adjacencies, want 0", len(adjs))
		}
		if n := strings.Count(buf.String(), "duplicate system ID"); n != 1 {
			t.Errorf("duplicate system ID warnings for 2 hellos = %d, want 1", n)
		}
	}

	t.Run("lan", func(t *testing.T) {
		cfg := CircuitConfig{
			Name:      "lan",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500),
			Level2:    true, Padding: ptrFalse(),
		}
		run(t, cfg, func(s *IsisServer, c *circuit) {
			s.processLANHello(c, peer, &packet.LANHello{
				Level:       packet.Level2,
				CircuitType: packet.CircuitTypeLevel2,
				SourceID:    sys,
				HoldingTime: 30,
				Priority:    64,
				TLVs:        []packet.TLV{&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{area}}},
			})
		})
	})

	t.Run("p2p", func(t *testing.T) {
		cfg := CircuitConfig{
			Name:      "p2p",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa2}, 1500),
			P2P:       true, Level2: true, Padding: ptrFalse(),
		}
		run(t, cfg, func(s *IsisServer, c *circuit) {
			s.processP2PHello(c, peer, p2pHelloEchoing(sys, area, sys, c.extCircID))
		})
	})
}

// TestLANHelloWithManyNeighborsSerializes is a regression for the LAN hello
// that stopped being sent once a circuit had 43 neighbors: every SNPA went
// into a single IS Neighbors TLV, whose value overflowed the 255-octet limit
// and made Serialize fail, so the circuit fell silent until the neighbors
// aged out. ISO 10589 8.4.5 lets a hello carry several IS Neighbors TLVs.
func TestLANHelloWithManyNeighborsSerializes(t *testing.T) {
	for _, n := range []int{43, 200} {
		t.Run(fmt.Sprintf("%d_neighbors", n), func(t *testing.T) {
			s, c := snpServer(t, false)
			want := make([]packet.SNPA, n)
			for i := range want {
				want[i] = packet.SNPA{0x02, 0, 0, 0, byte(i / 256), byte(i % 256)}
				id := packet.SystemID{0, 0, 0, 0, byte(i / 256), byte(i % 256)}
				c.adjs[packet.Level2][id] = &adjacency{systemID: id, snpa: want[i], state: AdjUp}
			}

			wire, err := s.buildLANHello(c, packet.Level2).Serialize()
			if err != nil {
				t.Fatalf("serialize LAN hello with %d neighbors: %v", n, err)
			}
			if budget := c.cfg.Transport.MTU() - 3; len(wire) > budget {
				t.Errorf("hello is %d octets, over the %d-octet MTU budget", len(wire), budget)
			}
			pdu, err := packet.DecodePDU(wire)
			if err != nil {
				t.Fatalf("decode hello: %v", err)
			}
			for _, snpa := range want {
				if !snpaListed(pdu.(*packet.LANHello).TLVs, snpa) {
					t.Fatalf("SNPA %s missing from the hello: the neighbor never completes the handshake", snpa)
				}
			}
		})
	}
}

// ipv6AddrTLVs returns the addresses of every IPv6 Interface Addresses TLV
// (232) among tlvs, concatenated.
func ipv6AddrTLVs(tlvs []packet.TLV) []netip.Addr {
	var out []netip.Addr
	for _, tlv := range tlvs {
		if t, ok := tlv.(*packet.IPv6InterfaceAddressesTLV); ok {
			out = append(out, t.Addresses...)
		}
	}
	return out
}

// TestInterfaceAddressesSplitBetweenHelloAndLSP: a circuit's IPv6 addresses are
// published in two places for two different jobs. TLV 232 of an IIH is what a
// neighbor uses as an IPv6 next hop, so it carries the link-locals and only
// those (RFC 5308 3); the non-link-local ones go in TLV 232 of the node's own
// fragment-0 LSP, where a peer resolves an on-link End.X next hop from them
// (see endXNexthop). IPv4 is unaffected: TLV 132 stays in the hello.
func TestInterfaceAddressesSplitBetweenHelloAndLSP(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	sink := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	datalink.Link(tr, sink)

	v4 := netip.MustParseAddr("10.0.0.1")
	ll := netip.MustParseAddr("fe80::a1")
	global := netip.MustParseAddr("2001:db8::a1")
	cfg := CircuitConfig{Name: "a", Transport: tr, Level2: true, Padding: ptrFalse(),
		IPv4Addrs: []netip.Addr{v4}, IPv6Addrs: []netip.Addr{ll, global}}
	fastHello(&cfg)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg),
	)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	f, err := sink.Recv()
	if err != nil {
		t.Fatalf("receive the first hello: %v", err)
	}
	pdu, err := packet.DecodePDU(packet.TrimToPDULength(f.PDU))
	if err != nil {
		t.Fatalf("decode the first hello: %v", err)
	}
	h, ok := pdu.(*packet.LANHello)
	if !ok {
		t.Fatalf("first PDU on the circuit is %T, want a LAN hello", pdu)
	}
	if got := ipv6AddrTLVs(h.TLVs); !slices.Equal(got, []netip.Addr{ll}) {
		t.Errorf("hello TLV 232 = %v, want only the link-local %s", got, ll)
	}
	var helloV4 []netip.Addr
	for _, tlv := range h.TLVs {
		if t, ok := tlv.(*packet.IPInterfaceAddressesTLV); ok {
			helloV4 = append(helloV4, t.Addresses...)
		}
	}
	if !slices.Equal(helloV4, []netip.Addr{v4}) {
		t.Errorf("hello TLV 132 = %v, want %s", helloV4, v4)
	}

	waitFor(t, "the node LSP carries the non-link-local address", func() bool {
		return slices.Equal(ipv6AddrTLVs(ownLSPTLVs(t, s)), []netip.Addr{global})
	})
}

// TestHelloKeepsGlobalIPv6WhenTheCircuitHasNoLinkLocal: filtering the IIH down
// to link-locals must never empty it. A circuit with no link-local address
// would otherwise send no TLV 232 at all, costing the neighbor every IPv6 route
// through this node.
func TestHelloKeepsGlobalIPv6WhenTheCircuitHasNoLinkLocal(t *testing.T) {
	global := netip.MustParseAddr("2001:db8::a1")
	if got := helloIPv6Addrs([]netip.Addr{global}); !slices.Equal(got, []netip.Addr{global}) {
		t.Errorf("hello TLV 232 = %v, want the circuit's only address %s", got, global)
	}
}

// TestAdjacencyLimitDropsNewSystemIDs: a circuit forms at most
// AdjacencyLimit adjacencies. At the cap, a hello from a System ID the circuit
// holds no adjacency for is dropped, counted under adjacency_limit and warned
// about once for the circuit, while the neighbors already adjacent keep
// refreshing. On an unauthenticated segment a station reaches Up by echoing our
// SNPA, and each one it reaches Up as costs an End.X SID, an IS reachability
// entry and a kernel route; the LSDB cap bounds none of that.
func TestAdjacencyLimitDropsNewSystemIDs(t *testing.T) {
	local := packet.SNPA{0, 0, 0, 0, 0, 0xa1}
	limit := 2
	var logs bytes.Buffer
	m := newCountingMetrics()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(local, 1500),
			Level2:    true, Padding: ptrFalse(),
			AdjacencyLimit: &limit,
		}),
		WithMetrics(m),
		WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
	)
	c := s.circuits[0]
	station := func(n byte) (packet.SystemID, packet.SNPA, *packet.LANHello) {
		id := packet.SystemID{0, 0, 0, 0, 0, n}
		snpa := packet.SNPA{0, 0, 0, 0, 0, n}
		return id, snpa, neighborHello(id, 64, packet.NodeID{}, local)
	}

	for _, n := range []byte{0x10, 0x11} {
		id, snpa, h := station(n)
		s.processLANHello(c, snpa, h)
		if adj, ok := c.adjs[packet.Level2][id]; !ok || adj.state != AdjUp {
			t.Fatalf("station %v below the limit of %d did not reach Up", id, limit)
		}
	}
	for _, n := range []byte{0x12, 0x13} {
		id, snpa, h := station(n)
		s.processLANHello(c, snpa, h)
		if _, ok := c.adjs[packet.Level2][id]; ok {
			t.Errorf("station %v formed an adjacency past the limit of %d", id, limit)
		}
	}
	if n := m.count("pdu_drop", "c", dropAdjacencyLimit); n != 2 {
		t.Errorf("hellos dropped at the adjacency limit = %d, want 2", n)
	}
	if n := strings.Count(logs.String(), "adjacency limit"); n != 1 {
		t.Errorf("adjacency-limit warnings for 2 turned-away stations = %d, want 1: the log is edge-triggered per circuit", n)
	}

	// The cap turns away new stations, never an adjacency that already formed:
	// a neighbor at the cap keeps refreshing its holding time.
	id, snpa, h := station(0x10)
	adj := c.adjs[packet.Level2][id]
	stale := time.Now().Add(-time.Minute)
	adj.lastHeard = stale
	s.processLANHello(c, snpa, h)
	if !adj.lastHeard.After(stale) || adj.state != AdjUp {
		t.Errorf("neighbor %v at the cap did not refresh: lastHeard %v, state %v", id, adj.lastHeard, adj.state)
	}
}
