package server

import (
	"context"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func hasLSPFrom(t *testing.T, s *IsisServer, sysID packet.SystemID) bool {
	t.Helper()
	lsps, err := s.ListLSDB(context.Background())
	if err != nil {
		t.Fatalf("ListLSDB: %v", err)
	}
	for _, l := range lsps {
		if l.LSPID.NodeID().SystemID() == sysID && l.SequenceNumber > 0 {
			return true
		}
	}
	return false
}

// TestFloodingTwoNodes verifies that two goisis instances on a shared
// segment flood their LSPs to each other and converge their databases.
func TestFloodingTwoNodes(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	idA := packet.SystemID{0, 0, 0, 0, 0, 1}
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}
	cfgA := CircuitConfig{Name: "a", Transport: ta, Level2: true, Padding: ptrFalse()}
	cfgB := CircuitConfig{Name: "b", Transport: tb, Level2: true, Padding: ptrFalse()}
	fastHello(&cfgA)
	fastHello(&cfgB)

	a := mustServer(t, WithSystemID(idA), WithAreaAddresses(area), WithCircuit(cfgA))
	b := mustServer(t, WithSystemID(idB), WithAreaAddresses(area), WithCircuit(cfgB))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	// Each side must learn the other's node LSP.
	waitFor(t, "a has b's LSP", func() bool { return hasLSPFrom(t, a, idB) })
	waitFor(t, "b has a's LSP", func() bool { return hasLSPFrom(t, b, idA) })
	// And each must hold its own.
	waitFor(t, "a has its own LSP", func() bool { return hasLSPFrom(t, a, idA) })
	waitFor(t, "b has its own LSP", func() bool { return hasLSPFrom(t, b, idB) })
}

func TestNewer(t *testing.T) {
	now := time.Now()
	mk := func(seq uint32, rem uint16) *lspEntry {
		return &lspEntry{lsp: &packet.LSP{SequenceNumber: seq}, inserted: now, lifetime: rem}
	}
	if !newer(2, 1000, mk(1, 1000), now) {
		t.Error("higher seqno should be newer")
	}
	if newer(1, 1000, mk(2, 1000), now) {
		t.Error("lower seqno should not be newer")
	}
	if !newer(5, 0, mk(5, 1000), now) {
		t.Error("a purge (lifetime 0) should supersede a live copy at equal seqno")
	}
	if newer(5, 1000, mk(5, 1000), now) {
		t.Error("identical copies are not newer")
	}
	if !newer(1, 1000, nil, now) {
		t.Error("anything is newer than a missing entry")
	}
}

func TestProcessLSPInstallAndPurge(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}),
	)
	c := s.circuits[0]
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)

	// Install a foreign LSP.
	lsp := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 3, ISType: 2}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, lsp, now)
	if s.dbs[packet.Level2].get(foreign) == nil {
		t.Fatal("foreign LSP was not installed")
	}

	// A purge (remaining 0, higher seqno) must supersede it.
	purge := &packet.LSP{Level: packet.Level2, RemainingTime: 0, LSPID: foreign, SequenceNumber: 4, ISType: 2}
	praw, err := purge.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, praw, purge, now)
	e := s.dbs[packet.Level2].get(foreign)
	if e == nil || e.purgedAt.IsZero() {
		t.Fatal("purge was not recorded")
	}
}

func TestProcessLSPReoriginatesOwn(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	id := packet.SystemID{0, 0, 0, 0, 0, 1}
	s := mustServer(t,
		WithSystemID(id),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}),
	)
	c := s.circuits[0]
	now := time.Now()
	s.regenerateLSPs(false, now) // originate our node LSP at seq 1
	own := lspID(id, 0)
	if e := s.dbs[packet.Level2].get(own); e == nil || e.lsp.SequenceNumber != 1 {
		t.Fatalf("own LSP not at seq 1: %+v", e)
	}

	// Receive a stale copy of our own LSP with a higher sequence number
	// (e.g. left over from a previous incarnation); we must reclaim it with
	// an even higher sequence number.
	ghost := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: own, SequenceNumber: 10, ISType: 2}
	raw, err := ghost.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, ghost, now)
	if e := s.dbs[packet.Level2].get(own); e == nil || e.lsp.SequenceNumber != 11 || !e.own {
		t.Fatalf("own LSP not reclaimed above seq 10: %+v", e)
	}
}
