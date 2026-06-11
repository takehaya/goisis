package server

import (
	"context"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// fastHello shortens timers so adjacency tests converge quickly.
func fastHello(cfg *CircuitConfig) {
	cfg.HelloInterval = 50 * time.Millisecond
	cfg.HoldingMultiplier = 3
}

// waitFor polls fn until it returns true or the deadline passes.
func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func adjState(t *testing.T, s *IsisServer, level packet.Level) (AdjState, bool) {
	t.Helper()
	adjs, err := s.ListAdjacencies(context.Background())
	if err != nil {
		t.Fatalf("ListAdjacencies: %v", err)
	}
	for _, a := range adjs {
		if a.Level == level {
			return a.State, true
		}
	}
	return AdjDown, false
}

func TestLANThreeWayAdjacency(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level1: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level1: true, Padding: ptrFalse()}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	waitFor(t, "a sees b Up", func() bool { st, ok := adjState(t, a, packet.Level1); return ok && st == AdjUp })
	waitFor(t, "b sees a Up", func() bool { st, ok := adjState(t, b, packet.Level1); return ok && st == AdjUp })
}

func TestLANNoAdjacencyAcrossAreasL1(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	cfgA := CircuitConfig{Name: "a", Transport: ta, Level1: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level1: true, Padding: ptrFalse()}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}), WithCircuit(cfgA))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x02}), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// L1 across different areas must never form an adjacency.
	time.Sleep(500 * time.Millisecond)
	if _, ok := adjState(t, a, packet.Level1); ok {
		t.Error("a formed an L1 adjacency across different areas")
	}
}

func TestP2PThreeWayAdjacency(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	cfgA := CircuitConfig{Name: "a", Transport: ta, P2P: true, Level2: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, P2P: true, Level2: true, Padding: ptrFalse()}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	waitFor(t, "a sees b Up (p2p)", func() bool { st, ok := adjState(t, a, packet.Level2); return ok && st == AdjUp })
	waitFor(t, "b sees a Up (p2p)", func() bool { st, ok := adjState(t, b, packet.Level2); return ok && st == AdjUp })
}

func TestAdjacencyExpires(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level1: true, Padding: ptrFalse(), HelloInterval: 50 * time.Millisecond, HoldingMultiplier: 3}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level1: true, Padding: ptrFalse(), HelloInterval: 50 * time.Millisecond, HoldingMultiplier: 3}

	a := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area), WithCircuit(cfgA))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	bctx, bcancel := context.WithCancel(context.Background())
	go b.Serve(bctx) //nolint:errcheck // ctx shutdown
	defer cancel()

	waitFor(t, "a sees b Up", func() bool { st, ok := adjState(t, a, packet.Level1); return ok && st == AdjUp })

	// Stop b; a's adjacency must expire after the holding time (~3*50ms).
	bcancel()
	_ = tb.Close()
	waitFor(t, "a expires adjacency to b", func() bool { _, ok := adjState(t, a, packet.Level1); return !ok })
}

func ptrFalse() *bool { b := false; return &b }
