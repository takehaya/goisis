package server

import (
	"context"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// ownOverload returns whether this node's own L2 LSP has the overload bit set
// (and whether the LSP exists), via white-box access on the Serve goroutine.
func ownOverload(t *testing.T, s *IsisServer) (set, exists bool) {
	t.Helper()
	_ = s.mgmtOperation(context.Background(), func() error {
		if e := s.dbs[packet.Level2].get(lspID(s.systemID, 0)); e != nil {
			set, exists = e.lsp.Overload, true
		}
		return nil
	})
	return
}

// liveLSPFrom reports whether s holds a live (non-purged, non-expired) L2 node
// LSP from sys.
func liveLSPFrom(t *testing.T, s *IsisServer, sys packet.SystemID) bool {
	t.Helper()
	live := false
	_ = s.mgmtOperation(context.Background(), func() error {
		if e := s.dbs[packet.Level2].get(lspID(sys, 0)); e != nil {
			live = e.purgedAt.IsZero() && e.remaining(time.Now()) > 0
		}
		return nil
	})
	return live
}

// TestOverloadOnStartup checks the overload bit is set in the own LSP at
// startup and cleared once the configured window elapses.
func TestOverloadOnStartup(t *testing.T) {
	mock := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: mock, Level2: true, Padding: ptrFalse()}),
		WithOverloadOnStartup(1500*time.Millisecond),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown

	waitFor(t, "own LSP has the overload bit set at startup", func() bool {
		set, ok := ownOverload(t, s)
		return ok && set
	})
	waitFor(t, "overload bit clears after the window", func() bool {
		set, ok := ownOverload(t, s)
		return ok && !set
	})
}

// TestCleanShutdownPurgesOwnLSP checks that a clean shutdown floods a purge so
// the peer drops our LSP promptly rather than waiting out the lifetime.
func TestCleanShutdownPurgesOwnLSP(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)
	area := packet.AreaAddress{0x49, 0x00, 0x01}
	aSys := packet.SystemID{0, 0, 0, 0, 0, 1}

	cfgA := CircuitConfig{Name: "a", Transport: ta, P2P: true, Level2: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, P2P: true, Level2: true, Padding: ptrFalse()}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(aSys), WithAreaAddresses(area), WithCircuit(cfgA))
	b := mustServer(t, WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area), WithCircuit(cfgB))

	actx, acancel := context.WithCancel(context.Background())
	bctx, bcancel := context.WithCancel(context.Background())
	defer bcancel()
	go a.Serve(actx) //nolint:errcheck // ctx shutdown
	go b.Serve(bctx) //nolint:errcheck // ctx shutdown

	waitFor(t, "b has a live LSP from A", func() bool { return liveLSPFrom(t, b, aSys) })

	// Clean shutdown of A must purge its LSP; B drops it well within the
	// multi-minute lifetime.
	acancel()
	waitFor(t, "b drops A's LSP after the clean-shutdown purge", func() bool { return !liveLSPFrom(t, b, aSys) })
}
