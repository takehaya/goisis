package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

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
