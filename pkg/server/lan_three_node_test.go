package server

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// waitForLong is waitFor with an explicit budget, for the cases that wait on
// the DIS's csnpInterval CSNP cycle rather than on the sub-second hello timers.
// Success returns as soon as fn is true, so a wide budget only lengthens the
// genuine-failure path.
func waitForLong(t *testing.T, what string, fn func() bool, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// steadyHello trades convergence speed for a holding time that survives a
// loaded machine. fastHello's holding time is one second (the wire field is in
// seconds), which a test that watches the LAN for a whole csnpInterval cannot
// rely on: one stalled second re-elects the DIS and invalidates the run.
func steadyHello(cfg *CircuitConfig) {
	cfg.HelloInterval = 250 * time.Millisecond
	cfg.HoldingMultiplier = 20
}

// lanNode builds a server with one broadcast Level-2 circuit on tr, at the
// given DIS priority. Its System ID is ...00:id. tune adjusts the circuit
// config after the fastHello defaults.
func lanNode(t *testing.T, id byte, tr *datalink.MockTransport, prio uint8, tune ...func(*CircuitConfig)) *IsisServer {
	t.Helper()
	cfg := CircuitConfig{
		Name:      fmt.Sprintf("c%d", id),
		Transport: tr,
		Level2:    true,
		Priority:  u8(prio),
		Padding:   ptrFalse(),
	}
	fastHello(&cfg)
	for _, f := range tune {
		f(&cfg)
	}
	return mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, id}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg),
	)
}

// lanUpPeers returns the System IDs this server holds an Up Level-2 adjacency
// to. A server whose loop has stopped reports none.
func lanUpPeers(t *testing.T, s *IsisServer) map[packet.SystemID]bool {
	t.Helper()
	out := map[packet.SystemID]bool{}
	adjs, err := s.ListAdjacencies(context.Background())
	if err != nil {
		return out
	}
	for _, a := range adjs {
		if a.Level == packet.Level2 && a.State == AdjUp {
			out[a.SystemID] = true
		}
	}
	return out
}

// lanLiveLSPs snapshots the live Level-2 database as LSP ID -> sequence
// number. Purged entries are excluded on purpose: a purge is only stored by a
// node that already held the LSP (ISO 10589 7.3.16.4 a), so the databases must
// agree on the live set but need not agree on which purges they kept.
func lanLiveLSPs(t *testing.T, s *IsisServer) map[packet.LSPID]uint32 {
	t.Helper()
	out := map[packet.LSPID]uint32{}
	lsps, err := s.ListLSDB(context.Background())
	if err != nil {
		return out
	}
	for _, l := range lsps {
		if l.Level == packet.Level2 && l.Remaining > 0 {
			out[l.LSPID] = l.SequenceNumber
		}
	}
	return out
}

// lanPseudonodes returns the distinct LAN IDs whose pseudonode LSP is live in
// the given database snapshot.
func lanPseudonodes(live map[packet.LSPID]uint32) map[packet.NodeID]bool {
	out := map[packet.NodeID]bool{}
	for id := range live {
		if nid := id.NodeID(); nid.PseudonodeID() != 0 {
			out[nid] = true
		}
	}
	return out
}

// lanID is the LAN ID this server advertises when it is DIS on its only
// circuit: its System ID plus that circuit's pseudonode octet.
func lanID(t *testing.T, s *IsisServer) packet.NodeID {
	t.Helper()
	var n packet.NodeID
	if err := s.mgmtOperation(context.Background(), func() error {
		n = nodeID(s.systemID, s.circuits[0].pseudonodeID)
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	return n
}

// lanPseudonodeMembers reads the System IDs listed in the Extended IS
// Reachability TLV (22) of a pseudonode LSP as s stores it.
func lanPseudonodeMembers(t *testing.T, s *IsisServer, lan packet.NodeID) map[packet.SystemID]bool {
	t.Helper()
	out := map[packet.SystemID]bool{}
	if err := s.mgmtOperation(context.Background(), func() error {
		e := s.dbs[packet.Level2].get(lspID(lan.SystemID(), lan.PseudonodeID()))
		if e == nil {
			return nil
		}
		for _, tlv := range e.lsp.TLVs {
			r, ok := tlv.(*packet.ExtendedISReachabilityTLV)
			if !ok {
				continue
			}
			for _, n := range r.Neighbors {
				out[n.NeighborID.SystemID()] = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	return out
}

// lanISNeighbors returns the NodeIDs this server advertises as IS reachability
// in its own node LSP — on a broadcast circuit, the DIS's LAN ID.
func lanISNeighbors(t *testing.T, s *IsisServer) map[packet.NodeID]bool {
	t.Helper()
	out := map[packet.NodeID]bool{}
	for _, tlv := range ownLSPTLVs(t, s) {
		r, ok := tlv.(*packet.ExtendedISReachabilityTLV)
		if !ok {
			continue
		}
		for _, n := range r.Neighbors {
			out[n.NeighborID] = true
		}
	}
	return out
}

// TestThreeNodeLANElectsOneDISAndListsAllMembers: three nodes on one broadcast
// segment elect exactly one DIS (C, by priority), that DIS is the only node
// with a live pseudonode LSP, the pseudonode LSP lists all three members, and
// all three databases converge on the same LSPs at the same sequence numbers.
func TestThreeNodeLANElectsOneDISAndListsAllMembers(t *testing.T) {
	trA := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	trB := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	trC := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xc3}, 1500)
	datalink.Link(trA, trB, trC)

	a := lanNode(t, 1, trA, 64)
	b := lanNode(t, 2, trB, 64)
	c := lanNode(t, 3, trC, 100) // highest priority: C must win the election

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, s := range []*IsisServer{a, b, c} {
		go s.Serve(ctx) //nolint:errcheck // ctx shutdown
	}

	idA := packet.SystemID{0, 0, 0, 0, 0, 1}
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}
	idC := packet.SystemID{0, 0, 0, 0, 0, 3}
	all := map[packet.SystemID]bool{idA: true, idB: true, idC: true}

	for _, n := range []struct {
		s     *IsisServer
		self  packet.SystemID
		peers []packet.SystemID
	}{
		{a, idA, []packet.SystemID{idB, idC}},
		{b, idB, []packet.SystemID{idA, idC}},
		{c, idC, []packet.SystemID{idA, idB}},
	} {
		waitFor(t, fmt.Sprintf("%s sees both peers Up", n.self), func() bool {
			up := lanUpPeers(t, n.s)
			return len(up) == 2 && up[n.peers[0]] && up[n.peers[1]]
		})
	}

	// Exactly one pseudonode LSP exists across the LAN, and it is C's.
	wantLAN := lanID(t, c)
	for _, s := range []*IsisServer{a, b, c} {
		waitForLong(t, "every database holds C's pseudonode LSP and no other", func() bool {
			pns := lanPseudonodes(lanLiveLSPs(t, s))
			return len(pns) == 1 && pns[wantLAN]
		}, 10*time.Second)
	}

	// The pseudonode LSP enumerates every LAN member, C itself included.
	waitForLong(t, "C's pseudonode LSP lists all three members", func() bool {
		return maps.Equal(lanPseudonodeMembers(t, c, wantLAN), all)
	}, 10*time.Second)

	// And the three databases agree, LSP by LSP.
	waitForLong(t, "all three databases converge", func() bool {
		la, lb, lc := lanLiveLSPs(t, a), lanLiveLSPs(t, b), lanLiveLSPs(t, c)
		return maps.Equal(la, lb) && maps.Equal(lb, lc)
	}, 10*time.Second)
	if got := len(lanLiveLSPs(t, a)); got != 4 {
		// A, B, C node LSPs plus C's pseudonode LSP.
		t.Errorf("converged database holds %d LSPs, want 4", got)
	}
}

// TestLateJoinerResynchronizesFromDISCSNPs: LSPs that reached the DIS by a path
// other than flooding still reach a node that joins the LAN later, because the
// DIS advertises its whole database in periodic CSNPs and the joiner requests
// what it lacks. With a database too large for one CSNP this only works if
// sendCSNP splits it into range-bounded PDUs — a single oversized CSNP would
// fail to send and the joiner would never converge.
func TestLateJoinerResynchronizesFromDISCSNPs(t *testing.T) {
	trA := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	trB := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	trC := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xc3}, 1500)
	datalink.Link(trA, trB, trC)

	a := lanNode(t, 1, trA, 100) // highest priority: A is DIS, so A sends the CSNPs
	b := lanNode(t, 2, trB, 64)
	c := lanNode(t, 3, trC, 64)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	idB := packet.SystemID{0, 0, 0, 0, 0, 2}
	waitFor(t, "A and B converge", func() bool {
		return lanUpPeers(t, a)[idB] && len(lanPseudonodes(lanLiveLSPs(t, a))) == 1
	})

	// Install 150 foreign LSPs straight into A's database without flooding
	// them, so the only way they can reach C is A's CSNPs. 150 entries need
	// more than one CSNP at a 1500-octet MTU.
	const foreign = 150
	want := map[packet.LSPID]bool{}
	if err := a.mgmtOperation(context.Background(), func() error {
		now := time.Now()
		for i := 0; i < foreign; i++ {
			//nolint:gosec // i < 150, so the conversions cannot overflow
			id := lspID(packet.SystemID{0x20, 0, 0, 0, byte(i / 256), byte(i % 256)}, 0)
			lsp := &packet.LSP{
				Level: packet.Level2, LSPID: id, SequenceNumber: uint32(i + 1),
				RemainingTime: maxAgeSeconds, ISType: 2,
			}
			raw, err := a.serializeLSP(lsp)
			if err != nil {
				return err
			}
			a.dbs[packet.Level2].entries[id] = &lspEntry{
				lsp: lsp, raw: raw, inserted: now, lifetime: maxAgeSeconds,
			}
			want[id] = true
		}
		return nil
	}); err != nil {
		t.Fatalf("inject foreign LSPs: %v", err)
	}

	go c.Serve(ctx) //nolint:errcheck // ctx shutdown

	// A CSNP goes out every csnpInterval, the request and the reply each ride
	// the next housekeeping tick, so a joiner that just missed a CSNP needs a
	// little over csnpInterval.
	waitForLong(t, "C learns all 150 LSPs it could only have seen in a CSNP", func() bool {
		live := lanLiveLSPs(t, c)
		for id := range want {
			if _, ok := live[id]; !ok {
				return false
			}
		}
		return true
	}, 15*time.Second)
}

// TestDISFailoverPurgesOldPseudonode: when the DIS leaves the LAN the survivors
// elect a new one, the departed DIS's pseudonode LSP is purged, the new DIS
// originates its own, and the survivors' IS reachability follows to the new
// pseudonode.
func TestDISFailoverPurgesOldPseudonode(t *testing.T) {
	trA := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	trB := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	trC := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xc3}, 1500)
	datalink.Link(trA, trB, trC)

	a := lanNode(t, 1, trA, 64)
	b := lanNode(t, 2, trB, 64) // equal priority, higher SNPA: B wins once C goes
	c := lanNode(t, 3, trC, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cctx, ccancel := context.WithCancel(context.Background())
	go a.Serve(ctx)  //nolint:errcheck // ctx shutdown
	go b.Serve(ctx)  //nolint:errcheck // ctx shutdown
	go c.Serve(cctx) //nolint:errcheck // ctx shutdown

	idA := packet.SystemID{0, 0, 0, 0, 0, 1}
	idB := packet.SystemID{0, 0, 0, 0, 0, 2}
	cLAN := lanID(t, c)
	bLAN := lanID(t, b)

	for _, s := range []*IsisServer{a, b} {
		waitFor(t, "C is DIS for the whole LAN", func() bool {
			pns := lanPseudonodes(lanLiveLSPs(t, s))
			return len(pns) == 1 && pns[cLAN]
		})
	}

	// C leaves cleanly: its shutdown purges the LSPs it originated, its node
	// LSP and its pseudonode LSP alike.
	ccancel()

	waitForLong(t, "A and B are left alone with each other", func() bool {
		return len(lanUpPeers(t, a)) == 1 && lanUpPeers(t, a)[idB] &&
			len(lanUpPeers(t, b)) == 1 && lanUpPeers(t, b)[idA]
	}, 10*time.Second)

	for _, s := range []*IsisServer{a, b} {
		waitForLong(t, "B's pseudonode LSP replaces C's", func() bool {
			pns := lanPseudonodes(lanLiveLSPs(t, s))
			return len(pns) == 1 && pns[bLAN]
		}, 10*time.Second)
	}
	waitForLong(t, "B's pseudonode LSP lists both survivors", func() bool {
		return maps.Equal(lanPseudonodeMembers(t, b, bLAN),
			map[packet.SystemID]bool{idA: true, idB: true})
	}, 10*time.Second)

	for _, s := range []*IsisServer{a, b} {
		waitForLong(t, "IS reachability points at the new pseudonode", func() bool {
			return maps.Equal(lanISNeighbors(t, s), map[packet.NodeID]bool{bLAN: true})
		}, 10*time.Second)
	}
}

// TestNonDISDoesNotSendCSNPs: on a broadcast circuit only the DIS multicasts
// CSNPs (ISO 10589 7.3.15.1). A passive listener on the segment must see CSNPs
// from the DIS and from nobody else.
func TestNonDISDoesNotSendCSNPs(t *testing.T) {
	trA := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	trB := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	trC := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xc3}, 1500)
	sink := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	datalink.Link(trA, trB, trC)

	a := lanNode(t, 1, trA, 64, steadyHello)
	b := lanNode(t, 2, trB, 64, steadyHello)
	c := lanNode(t, 3, trC, 100, steadyHello) // DIS

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, s := range []*IsisServer{a, b, c} {
		go s.Serve(ctx) //nolint:errcheck // ctx shutdown
	}

	idC := packet.SystemID{0, 0, 0, 0, 0, 3}
	cLAN := lanID(t, c)
	// Every node, not just A: the election has a real transient in which a
	// node elects itself before the winner's hello arrives (a losing candidate
	// originates its own pseudonode LSP and, for that window, is DIS as far as
	// its own circuit is concerned). Observing from t=0 would buffer that
	// node's CSNP and fail the test on behaviour the protocol allows.
	for _, s := range []*IsisServer{a, b, c} {
		waitForLong(t, "every node agrees C is DIS", func() bool {
			pns := lanPseudonodes(lanLiveLSPs(t, s))
			return len(pns) == 1 && pns[cLAN] && maps.Equal(lanISNeighbors(t, s), map[packet.NodeID]bool{cLAN: true})
		}, 10*time.Second)
	}

	// Drain continuously: the mock inbox drops once it is full, and hellos
	// alone outrun its 256-frame buffer over this window.
	var (
		mu    sync.Mutex
		csnps []*packet.CSNP
	)
	seen := func() int { mu.Lock(); defer mu.Unlock(); return len(csnps) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			// Buffered frames still drain from a closed inbox, so this returns
			// only once everything sent before the Close below is accounted for.
			f, err := sink.Recv()
			if err != nil {
				return
			}
			pdu, err := packet.DecodePDU(f.PDU)
			if err != nil {
				continue
			}
			if csnp, ok := pdu.(*packet.CSNP); ok {
				mu.Lock()
				csnps = append(csnps, csnp)
				mu.Unlock()
			}
		}
	}()
	// Only now does the listener join the segment, so nothing it reports
	// predates the settled election. Linking pairwise leaves the three nodes'
	// existing peer lists alone.
	for _, tr := range []*datalink.MockTransport{trA, trB, trC} {
		datalink.Link(tr, sink)
	}

	// Observe a whole csnpInterval, which is every sender's period, and require
	// at least one CSNP in it: without one the check below would be vacuous,
	// and the DIS's own periodic emission is what guarantees there is one.
	start := time.Now()
	waitForLong(t, "a full CSNP cycle on a settled segment",
		func() bool { return time.Since(start) >= csnpInterval && seen() > 0 },
		3*csnpInterval)
	_ = sink.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	for _, csnp := range csnps {
		if src := csnp.SourceID.SystemID(); src != idC {
			t.Errorf("CSNP from %s, want only the DIS %s", src, idC)
		}
	}
}
