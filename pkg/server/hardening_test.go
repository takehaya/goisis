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

// TestProcessLSPRefloodsPurgeOverSameSeqLive: when we hold a purge and a peer
// floods a live copy at the same sequence number, we re-flood our purge (a
// purge supersedes a live LSP at equal seq, ISO 10589 7.3.16.2).
func TestProcessLSPRefloodsPurgeOverSameSeqLive(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}),
	)
	c := s.circuits[0]
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)

	live := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 5, ISType: 2}
	lraw, err := live.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, lraw, live, now) // install live seq 5

	purge := &packet.LSP{Level: packet.Level2, RemainingTime: 0, LSPID: foreign, SequenceNumber: 5, ISType: 2}
	praw, err := purge.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, praw, purge, now) // adopt the purge at seq 5
	if e := s.dbs[packet.Level2].get(foreign); e == nil || e.purgedAt.IsZero() {
		t.Fatal("expected to hold a purge for the foreign LSP")
	}

	c.clearSRM(packet.Level2, foreign) // isolate the next step
	s.processLSP(c, lraw, live, now)   // peer re-floods the live copy at seq 5
	if _, ok := c.srm[packet.Level2][foreign]; !ok {
		t.Error("held purge was not re-flooded (SRM unset) when a peer sent a live LSP at the same seq")
	}
}

// TestLaggedReportedAfterServerStop: a resource-exhaustion drop must still be
// reported by Lagged() even when the Serve loop has already stopped (so the
// WatchEvent handler returns CodeResourceExhausted, not a clean stop).
func TestLaggedReportedAfterServerStop(t *testing.T) {
	mock := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: mock, Level2: true, Padding: ptrFalse()}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx); close(done) }()

	sub, err := s.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a lagging drop on the Serve loop.
	if err := s.mgmtOperation(context.Background(), func() error {
		sub.w.lagged = true
		s.dropWatcher(sub.w)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done

	if !sub.Lagged() {
		t.Error("Lagged() = false after server stop; the resource-exhaustion drop must survive shutdown")
	}
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
