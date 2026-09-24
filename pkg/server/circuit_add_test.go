package server

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// endXP2PCircuit is p2pCircuit with the /64 its neighbor's global address sits
// in connected: endXNexthop hands an adjacency an End.X SID only for an address
// on one of the circuit's directly-connected prefixes.
func endXP2PCircuit(name string, snpa byte, subnet netip.Prefix) CircuitConfig {
	cfg := p2pCircuit(name, datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, snpa}, 1500))
	cfg.ConnectedPrefixes = []netip.Prefix{subnet}
	return cfg
}

// endXAdjUp is upP2PAdj plus the neighbor's global on-link address, the next
// hop an End.X SID towards it forwards to.
func endXAdjUp(c *circuit, id packet.SystemID, addr netip.Addr, now time.Time) {
	upP2PAdj(c, id, now)
	c.p2pAdj.neighborIPv6 = []netip.Addr{addr}
}

// TestAddCircuitKeepsExistingEndXFunctionValues guarantees that a circuit joins
// at the end of s.circuits, so the End.X SID of a circuit that did not change
// keeps the function value it already had — through the addition itself, and
// through the reconvergence afterwards that reallocates every SID at once.
//
// endXAdjs walks s.circuits in order and that order is what hands out function
// values. Keeping the slice in name order, or slotting a new circuit into the
// gap a deleted one left, are both tidier and both silently renumber the SID
// space of links that did not change — pointing traffic at End.X SIDs the
// neighbors have not been told about.
func TestAddCircuitKeepsExistingEndXFunctionValues(t *testing.T) {
	loc := netip.MustParsePrefix("fc00:0:1::/48")
	zSub, aSub := netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:2::/64")
	zAddr, aAddr := netip.MustParseAddr("2001:db8:1::2"), netip.MustParseAddr("2001:db8:2::2")
	zNbr, aNbr := packet.SystemID{0, 0, 0, 0, 0, 0x2a}, packet.SystemID{0, 0, 0, 0, 0, 0x2b}

	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(endXP2PCircuit("z", 0x01, zSub)),
		WithSRv6Locator(loc),
	)
	now := time.Now()
	endXAdjUp(s.circuits[0], zNbr, zAddr, now)
	s.regenerateLSPs(false, now)
	zKey := endXKey{locator: loc, circuit: "z", neighbor: zNbr}
	before, ok := s.endXSIDs[zKey]
	if !ok {
		t.Fatalf("the fixture never allocated an End.X SID for circuit z")
	}

	// "a" sorts ahead of "z", so a slice kept in name order puts the new
	// circuit first.
	if err := s.addCircuit(endXP2PCircuit("a", 0x02, aSub), now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}
	endXAdjUp(s.circuitNamed("a"), aNbr, aAddr, now)
	s.regenerateLSPs(false, now)
	if got := s.endXSIDs[zKey].sid; got != before.sid {
		t.Errorf("End.X SID of circuit z after circuit a was added = %s, want %s", got, before.sid)
	}

	// The addition alone leaves z's allocation in place because it is keyed on
	// the circuit name. The order decides which function each circuit gets when
	// they are allocated together, which is what a reconvergence does: both
	// adjacencies go and come back, and both SIDs are released and taken again
	// in one pass.
	zc, ac := s.circuitNamed("z"), s.circuitNamed("a")
	zc.p2pAdj, ac.p2pAdj = nil, nil
	s.regenerateLSPs(false, now)
	if n := len(s.endXSIDs); n != 0 {
		t.Fatalf("End.X SIDs held after both adjacencies went down = %d, want 0", n)
	}
	endXAdjUp(zc, zNbr, zAddr, now)
	endXAdjUp(ac, aNbr, aAddr, now)
	s.regenerateLSPs(false, now)
	if got := s.endXSIDs[zKey].sid; got != before.sid {
		t.Errorf("End.X SID of circuit z after a reconvergence = %s, want %s: the added circuit took its function value",
			got, before.sid)
	}
}

// TestAddCircuitWithASmallerMTURefragmentsBeforeReturning guarantees that a
// circuit narrower than the LSPs this node already originated has re-fragmented
// them by the time the call returns, with no housekeeping tick in between.
//
// Asking the throttle for a regeneration is not enough: originate refuses to
// store a fragment over the budget and returns, so the database keeps the
// oversize fragments and the new circuit floods what it cannot transmit, once
// per retransmission interval, for as long as minLSPGenInterval holds the
// regeneration back.
func TestAddCircuitWithASmallerMTURefragmentsBeforeReturning(t *testing.T) {
	s := mustServer(t, mtuOptions(1500)...)
	now := time.Now()
	s.regenerateLSPs(false, now)
	if n := len(ownFragments(s)); n < 2 {
		t.Fatalf("the fixture originated %d fragments, want the reachability to span >= 2", n)
	}

	if err := s.addCircuit(lanCircuit("narrow", 0x77, 600), now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}
	if want := 600 - 3; s.lspBufferSize != want {
		t.Fatalf("LSP buffer size after a 600-octet circuit joined = %d, want %d", s.lspBufferSize, want)
	}
	for level, db := range s.dbs {
		for id, e := range db.entries {
			if !e.own || !e.purgedAt.IsZero() {
				continue
			}
			if len(e.raw) > s.lspBufferSize {
				t.Errorf("%v LSP %v is %d octets, over the %d the new circuit can carry",
					level, id, len(e.raw), s.lspBufferSize)
			}
		}
	}
}

// TestAddCircuitStartsALevelThatHadNoCircuit guarantees that the first circuit
// at a level brings the whole level up with it: the database it originates
// into, the level in the IS-Type this node advertises, and its own node LSP
// from sequence 1 with the ATT bit an L1L2 node owes its area.
//
// The database is created lazily and originate dereferences s.dbs[level]
// without a nil check, so the level must not reach levelCap ahead of it.
func TestAddCircuitStartsALevelThatHadNoCircuit(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(lanCircuit("l2", 0x01, 1500)),
	)
	now := time.Now()
	s.regenerateLSPs(false, now)
	if s.dbs[packet.Level1] != nil {
		t.Fatalf("the fixture already has a Level-1 database")
	}

	l1 := lanCircuit("l1", 0x02, 1500)
	l1.Level1, l1.Level2 = true, false
	if err := s.addCircuit(l1, now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}

	if got := s.isType(); got != 3 {
		t.Errorf("IS-Type after a Level-1 circuit joined a Level-2 node = %d, want 3", got)
	}
	e := s.dbs[packet.Level1].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatalf("no own Level-1 LSP after the node's first Level-1 circuit was added")
	}
	if e.lsp.SequenceNumber != 1 {
		t.Errorf("own Level-1 LSP sequence number = %d, want 1: the level has never been originated at before",
			e.lsp.SequenceNumber)
	}
	if !e.lsp.AttDefault {
		t.Errorf("own Level-1 LSP does not set ATT, though this node is now Level-2 as well")
	}
}

// TestAddCircuitRefusesADuplicateName guarantees that a name already configured
// is refused and not replaced — replacing would drop the running circuit with
// its transport open and its reader goroutine still on it — and that the
// refusal leaves the caller's transport for the caller to close, which is the
// contract AddCircuit states and the only thing that closes it.
func TestAddCircuitRefusesADuplicateName(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(lanCircuit("a", 0xa1, 1500)),
	)
	now := time.Now()
	s.regenerateLSPs(false, now)
	running := s.circuitNamed("a")

	dup := lanCircuit("a", 0xa2, 1500)
	if err := s.addCircuit(dup, now); err == nil {
		t.Fatal("a second circuit named a was accepted; the running one is now unreachable with its transport open")
	}
	if len(s.circuits) != 1 || s.circuitNamed("a") != running {
		t.Errorf("circuits after the refused addition = %d, want the one that was already running", len(s.circuits))
	}
	if err := dup.Transport.Send(packet.SNPA{}, []byte{0x83}); errors.Is(err, datalink.ErrClosed) {
		t.Errorf("the refused addition closed the caller's transport")
	}
}

// TestDeleteThenAddCircuitLeavesANodeThatCouldHaveStarted guarantees that a
// removal followed by an addition puts this node in a state it could have
// booted into: every own LSP it still holds belongs to a circuit or a level it
// still has, the IS-Type matches the circuits it has, and the octet handed to
// the new circuit is not one the area still holds a copy of.
//
// Handing the freed octet straight back is what the rotator exists to avoid:
// the purge deleteCircuit issued for it is still in this node's database and
// still in every peer's, so the new circuit's pseudonode LSP would have to
// climb over a copy that is already out there.
func TestDeleteThenAddCircuitLeavesANodeThatCouldHaveStarted(t *testing.T) {
	a := lanCircuit("a", 0xa1, 1500)
	a.Level1 = true
	s := deleteFixture(t, a, lanCircuit("b", 0xb1, 1500))
	now := time.Now()
	freed := s.circuitNamed("a").pseudonodeID
	if err := s.deleteCircuit("a", now); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}
	purged := s.dbs[packet.Level1].get(lspID(s.systemID, 0))
	if purged == nil || purged.purgedAt.IsZero() {
		t.Fatalf("the delete left no Level-1 purge for the addition to climb over")
	}

	c := lanCircuit("c", 0xc1, 1500)
	c.Level1 = true
	if err := s.addCircuit(c, now); err != nil {
		t.Fatalf("addCircuit: %v", err)
	}

	if got := s.circuitNamed("c").pseudonodeID; got == freed {
		t.Errorf("the new circuit took octet %d straight back, while this node's purge for it is still in the database", got)
	}
	if got := s.isType(); got != 3 {
		t.Errorf("IS-Type = %d, want 3: the node has a Level-1/Level-2 circuit again", got)
	}
	e := s.dbs[packet.Level1].get(lspID(s.systemID, 0))
	if e == nil || !e.purgedAt.IsZero() {
		t.Fatalf("own Level-1 LSP after the level came back = %v, want a live one", e)
	}
	if e.lsp.SequenceNumber <= purged.lsp.SequenceNumber {
		t.Errorf("own Level-1 LSP re-originated at sequence %d, at or under the purge's %d that peers still hold",
			e.lsp.SequenceNumber, purged.lsp.SequenceNumber)
	}
	live := map[uint8]bool{}
	for _, other := range s.circuits {
		live[other.pseudonodeID] = true
	}
	for level, db := range s.dbs {
		for id, entry := range db.entries {
			if !entry.own || !entry.purgedAt.IsZero() {
				continue
			}
			if pn := id.NodeID().PseudonodeID(); pn != 0 && !live[pn] {
				t.Errorf("own %v LSP %v names pseudonode octet %d, which no circuit holds", level, id, pn)
			} else if pn == 0 && !s.levelCap.has(level) {
				t.Errorf("own %v node LSP %v at a level no circuit is at", level, id)
			}
		}
	}
}
