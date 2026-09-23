package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// ownSeq returns the sequence number of this node's Level-2 LSP.
func ownSeq(t *testing.T, s *IsisServer) uint32 {
	t.Helper()
	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("this node's own LSP was never originated")
	}
	return e.lsp.SequenceNumber
}

// ownSeqOnLoop is ownSeq for a server whose Serve loop is running: call it from
// inside a management operation, the only place the LSDB may be read. It
// reports rather than fails, since t.Fatal off the test goroutine would only
// kill the loop.
func ownSeqOnLoop(s *IsisServer) uint32 {
	if e := s.dbs[packet.Level2].get(lspID(s.systemID, 0)); e != nil {
		return e.lsp.SequenceNumber
	}
	return 0
}

// listsNeighbor reports whether this node's Level-2 LSP advertises IS
// reachability to id.
func listsNeighbor(t *testing.T, s *IsisServer, id packet.SystemID) bool {
	t.Helper()
	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("this node's own LSP was never originated")
	}
	for _, tlv := range e.lsp.TLVs {
		r, ok := tlv.(*packet.ExtendedISReachabilityTLV)
		if !ok {
			continue
		}
		for _, n := range r.Neighbors {
			if n.NeighborID.SystemID() == id {
				return true
			}
		}
	}
	return false
}

// TestLSPRegenerationCoalescesWithinTheMinimumInterval: a flapping adjacency
// costs one re-origination per minimumLSPGenerationInterval, not one per flap,
// and the LSP generated at the end of the interval reflects the final state.
func TestLSPRegenerationCoalescesWithinTheMinimumInterval(t *testing.T) {
	s, c := snpServer(t, true)
	t0 := time.Now()
	s.requestLSPRegen()
	s.drainLSPGen(t0)
	base := ownSeq(t, s)

	neighbor := packet.SystemID{0, 0, 0, 0, 0, 2}
	var l2 levelSet
	l2.add(packet.Level2)
	// Ten flaps within the interval; each would change our IS reachability.
	for i := 1; i <= 10; i++ {
		if i%2 == 0 {
			c.p2pAdj = &adjacency{systemID: neighbor, state: AdjUp, levels: l2}
		} else {
			c.p2pAdj = nil
		}
		s.requestLSPRegen()
		s.drainLSPGen(t0.Add(time.Duration(i) * 50 * time.Millisecond))
	}
	if got := ownSeq(t, s); got > base+1 {
		t.Errorf("sequence number %d after 10 flaps in 500 ms, want at most %d", got, base+1)
	}

	s.drainLSPGen(t0.Add(1100 * time.Millisecond))
	if got := ownSeq(t, s); got != base+1 {
		t.Errorf("sequence number %d after the interval elapsed, want %d", got, base+1)
	}
	if !listsNeighbor(t, s, neighbor) {
		t.Error("the coalesced LSP omits the neighbor: it does not reflect the final adjacency state")
	}
}

// TestFirstRegenerationRequestIsImmediate: the throttle delays a burst, never
// the first change after a quiet period.
func TestFirstRegenerationRequestIsImmediate(t *testing.T) {
	s, _ := snpServer(t, true)
	t0 := time.Now()
	s.requestLSPRegen()
	s.drainLSPGen(t0)

	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("no own LSP: the first request was deferred")
	}
	if !e.inserted.Equal(t0) {
		t.Errorf("originated at %v, want %v", e.inserted, t0)
	}
}

// TestRefreshIsJittered: an own LSP is refreshed up to 25 % early, so nodes
// that booted together do not refresh in lockstep, and never later than
// maximumLSPGenerationInterval.
func TestRefreshIsJittered(t *testing.T) {
	s, _ := snpServer(t, true)
	t0 := time.Now()
	s.regenerateLSPs(false, t0)
	base := ownSeq(t, s)

	lo, hi := t0.Add((refreshSeconds-refreshSeconds/4)*time.Second), t0.Add(refreshSeconds*time.Second)
	for id, e := range s.dbs[packet.Level2].entries {
		if !e.own {
			continue
		}
		if e.refreshAt.Before(lo) || e.refreshAt.After(hi) {
			t.Errorf("%v refreshAt is %v after origination, want within [%v, %v]",
				id, e.refreshAt.Sub(t0), lo.Sub(t0), hi.Sub(t0))
		}
	}

	s.refreshOwnLSPs(t0.Add((refreshSeconds - refreshSeconds/4 - 1) * time.Second))
	if got := ownSeq(t, s); got != base {
		t.Errorf("sequence number %d before the earliest jittered deadline, want %d", got, base)
	}
	s.refreshOwnLSPs(t0.Add(refreshSeconds * time.Second))
	if got := ownSeq(t, s); got != base+1 {
		t.Errorf("sequence number %d at maximumLSPGenerationInterval, want %d (refreshed)", got, base+1)
	}
}

// TestOperatorMutationIsVisibleToTheNextRPC: an operator mutation asks for a
// regeneration like any protocol event does, and still reads back its own
// write. mgmtOperation replies from inside the loop iteration that ran the
// mutation, but that iteration drains the request before it dequeues the next
// operation, so the RPC that follows reports the new prefix rather than the
// state before it.
func TestOperatorMutationIsVisibleToTheNextRPC(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	p := netip.MustParsePrefix("10.9.9.0/24")

	// Open the generation interval first: under test is the loop's ordering,
	// not whether the throttle happens to be holding an LSP back.
	if err := s.mgmtOperation(ctx, func() error { s.nextLSPGen = time.Time{}; return nil }); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	if err := s.AddPrefix(ctx, AdvertisedPrefix{Prefix: p, Metric: 10}); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}

	// ListLSDBDetail, not ListLSDB: only the detail form renders TLV text, and
	// the text is how this test sees what the LSP now carries.
	lsps, err := s.ListLSDBDetail(ctx)
	if err != nil {
		t.Fatalf("ListLSDBDetail: %v", err)
	}
	for _, l := range lsps {
		if l.Own && slices.ContainsFunc(l.TLVs, func(line string) bool { return strings.Contains(line, p.String()) }) {
			return
		}
	}
	t.Errorf("the RPC issued right after AddPrefix does not report %s in our own LSP", p)
}

// TestAddressPushBurstCostsOneRegeneration: the netlink watcher re-reads and
// pushes an interface's whole address set per message, so one renumbering
// arrives as a burst of pushes. Each goes through the generation throttle, so
// the burst costs one re-origination, carrying the addresses the last push left.
func TestAddressPushBurstCostsOneRegeneration(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()

	// Hold the throttle shut across the burst, so what the drain below shows is
	// how many re-originations the burst asked for and not how fast the test ran.
	var base uint32
	if err := s.mgmtOperation(ctx, func() error {
		s.nextLSPGen = time.Now().Add(time.Hour)
		base = ownSeqOnLoop(s)
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}

	var last netip.Prefix
	for i := 1; i <= 5; i++ {
		last = netip.MustParsePrefix(fmt.Sprintf("10.9.%d.0/24", i))
		addr := netip.MustParseAddr(fmt.Sprintf("10.9.%d.1", i))
		if err := s.SetCircuitAddresses(ctx, "c", []netip.Addr{addr}, nil, []netip.Prefix{last}); err != nil {
			t.Fatalf("SetCircuitAddresses(%s): %v", last, err)
		}
	}

	if err := s.mgmtOperation(ctx, func() error {
		if got := ownSeqOnLoop(s); got != base {
			t.Errorf("own LSP sequence number %d during the burst, want %d: a push re-originated past the throttle", got, base)
		}
		s.nextLSPGen = time.Time{}
		s.drainLSPGen(time.Now())
		if got := ownSeqOnLoop(s); got != base+1 {
			t.Errorf("own LSP sequence number %d after the burst, want %d: the burst cost more than one re-origination", got, base+1)
		}
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}

	if got := v4ReachMetrics(ownLSPTLVs(t, s), last); len(got) != 1 {
		t.Errorf("TLV 135 metrics for %s = %v, want one entry: the coalesced LSP must carry what the last push left", last, got)
	}
}
