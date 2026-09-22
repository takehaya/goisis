package server

import (
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
