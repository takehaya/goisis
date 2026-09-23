package server

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// TestLSPWithOurSystemIDForPseudonodeWeDoNotOwnIsPurged: an LSP whose source is
// our own System ID but which we did not originate must be purged, not stored
// (ISO 10589 7.3.16.4 c).
func TestLSPWithOurSystemIDForPseudonodeWeDoNotOwnIsPurged(t *testing.T) {
	s, c := snpServer(t, false)
	now := time.Now()
	// Pseudonode 0x7f matches none of our circuits, so we can never be its DIS.
	id := lspID(s.systemID, 0x7f)

	lsp := &packet.LSP{
		Level: packet.Level2, RemainingTime: 1000, LSPID: id, SequenceNumber: 4, ISType: 2,
		TLVs: []packet.TLV{&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{{0x49, 0x00, 0x01}}}},
	}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, lsp, now)

	e := s.dbs[packet.Level2].get(id)
	if e == nil {
		t.Fatal("no entry: the LSP was neither stored nor purged")
	}
	if e.remaining(now) != 0 || e.purgedAt.IsZero() {
		t.Errorf("entry is live (remaining %d, purgedAt %v): want a purge", e.remaining(now), e.purgedAt)
	}
	if e.own {
		t.Error("entry marked own: the refresh path would re-originate an LSP we never originated")
	}
	if e.lsp.SequenceNumber != 4 {
		// A purge supersedes a live copy at equal sequence (7.3.16.2), so the
		// received number is kept; only the originator may advance it.
		t.Errorf("SequenceNumber = %d, want 4 (the received number)", e.lsp.SequenceNumber)
	}
	if len(e.lsp.TLVs) != 1 || e.lsp.TLVs[0].Type() != packet.TLVTypePurgeOriginatorID {
		t.Errorf("purge carries %d TLVs, want only the Purge Originator Identification TLV", len(e.lsp.TLVs))
	}
	if !hasSRM(c, id) {
		t.Error("purge not flagged for flooding on the circuit")
	}
}

// TestLSPForPseudonodeWeAreDISForIsReoriginated: a pseudonode LSP we do own is
// reclaimed with a higher sequence number, not purged.
func TestLSPForPseudonodeWeAreDISForIsReoriginated(t *testing.T) {
	s, c := snpServer(t, false)
	now := time.Now()
	c.dis[packet.Level2] = nodeID(s.systemID, c.pseudonodeID)
	s.regenerateLSPs(false, now)

	id := lspID(s.systemID, c.pseudonodeID)
	if s.dbs[packet.Level2].get(id) == nil {
		t.Fatal("pseudonode LSP was not originated")
	}

	foreign := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: id, SequenceNumber: 10, ISType: 2}
	raw, err := foreign.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, foreign, now)

	e := s.dbs[packet.Level2].get(id)
	if e.remaining(now) == 0 || !e.own {
		t.Errorf("entry is a purge (remaining %d, own %v): want our live pseudonode LSP", e.remaining(now), e.own)
	}
	if e.lsp.SequenceNumber <= 10 {
		t.Errorf("SequenceNumber = %d, want above the 10 seen on the wire", e.lsp.SequenceNumber)
	}
}

// TestForeignLSPIsStillInstalled pins that the purge is keyed on the System ID:
// an LSP from another node installs live as before.
func TestForeignLSPIsStillInstalled(t *testing.T) {
	s, c := snpServer(t, false)
	now := time.Now()
	id := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)

	lsp := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: id, SequenceNumber: 3, ISType: 2}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, lsp, now)

	if e := s.dbs[packet.Level2].get(id); e == nil || e.remaining(now) == 0 {
		t.Errorf("foreign LSP not installed live: %+v", e)
	}
}

// TestForgedFragmentOfOurNodeLSPIsPurged: an LSP naming a fragment of our own
// node LSP that we never originated is a stranger's claim about us, whatever
// fragment number it carries. It must be purged (ISO 10589 7.3.16.4 b), not
// stored and not counted as a reclamation: there is nothing of ours to reclaim.
func TestForgedFragmentOfOurNodeLSPIsPurged(t *testing.T) {
	s, c, m := metricsServer(t, false)
	now := time.Now()
	s.regenerateLSPs(false, now) // our node LSP fits fragment 0; 7 is never ours
	id := lspIDFrag(s.systemID, 0, 7)

	lsp := &packet.LSP{
		Level: packet.Level2, RemainingTime: 1000, LSPID: id, SequenceNumber: 4, ISType: 2,
		TLVs: []packet.TLV{&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{{0x49, 0x00, 0x01}}}},
	}
	s.processLSP(c, serialize(t, lsp), lsp, now)

	e := s.dbs[packet.Level2].get(id)
	if e == nil {
		t.Fatal("no entry: the forged fragment was neither stored nor purged")
	}
	if e.remaining(now) != 0 || e.purgedAt.IsZero() {
		t.Errorf("entry is live (remaining %d, purgedAt %v): want a purge", e.remaining(now), e.purgedAt)
	}
	if e.own {
		t.Error("entry marked own: the refresh path would keep re-originating a fragment we never built")
	}
	if e.lsp.SequenceNumber != 4 {
		// A purge supersedes a live copy at equal sequence (7.3.16.2), so the
		// received number is kept; only the originator may advance it.
		t.Errorf("SequenceNumber = %d, want 4 (the received number)", e.lsp.SequenceNumber)
	}
	if len(e.lsp.TLVs) != 1 || e.lsp.TLVs[0].Type() != packet.TLVTypePurgeOriginatorID {
		t.Errorf("purge carries %d TLVs, want only the Purge Originator Identification TLV", len(e.lsp.TLVs))
	}
	if !hasSRM(c, id) {
		t.Error("purge not flagged for flooding on the circuit")
	}
	if got := m.count("pdu_drop", "c", "own_fragment_purge"); got != 1 {
		t.Errorf("own_fragment_purge drops = %d, want 1", got)
	}
	if got := m.count("pdu_drop", "c", "own_lsp_reclaimed"); got != 0 {
		t.Errorf("own_lsp_reclaimed drops = %d, want 0: nothing of ours was reclaimed", got)
	}
}

// TestForgedOwnLSPAtMaxSequenceIsPurgedAndReoriginated: one forged copy of our
// node LSP at the maximum sequence number must not make us re-originate at
// sequence 0. Every peer reads 0 as older than the forgery and floods the
// forgery back, so our reachability, adjacencies and locators would leave the
// area while the attacker's content stayed behind as ours. ISO 10589 7.3.16.1:
// purge at the maximum sequence number, hold the ID down until the purge has
// aged out area-wide, then re-originate from 1.
func TestForgedOwnLSPAtMaxSequenceIsPurgedAndReoriginated(t *testing.T) {
	victim, vc, m := metricsServer(t, false)
	peer := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 3}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "p",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 3}, 1500),
			Level2:    true,
			Padding:   ptrFalse(),
		}),
	)
	pc := peer.circuits[0]
	now := time.Now()
	own := lspID(victim.systemID, 0)

	victim.regenerateLSPs(false, now) // seq 1
	victim.regenerateLSPs(true, now)  // seq 2
	deliverEntry(t, peer, pc, victim.dbs[packet.Level2].get(own), now)

	attacker := netip.MustParsePrefix("203.0.113.0/24")
	forged := &packet.LSP{
		Level: packet.Level2, RemainingTime: 1000, LSPID: own, SequenceNumber: math.MaxUint32, ISType: 2,
		TLVs: []packet.TLV{
			&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{{0x49, 0x00, 0x01}}},
			&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{{Metric: 1, Prefix: attacker}}},
		},
	}
	fraw := serialize(t, forged)
	peer.processLSP(pc, fraw, decodeLSP(t, fraw), now)
	if !lspHasPrefix(peer.dbs[packet.Level2].get(own), attacker) {
		t.Fatal("setup: the peer did not take the forged copy")
	}

	victim.processLSP(vc, fraw, decodeLSP(t, fraw), now)

	ve := victim.dbs[packet.Level2].get(own)
	if ve == nil {
		t.Fatal("victim holds no copy of its own LSP after the forgery")
	}
	if ve.lsp.SequenceNumber != math.MaxUint32 {
		t.Errorf("victim's copy is at seq %d, want %d: any lower number (0 above all) is read as older than the forgery",
			ve.lsp.SequenceNumber, uint32(math.MaxUint32))
	}
	if ve.remaining(now) != 0 || ve.purgedAt.IsZero() {
		t.Errorf("victim's copy is live (remaining %d, purgedAt %v): want the 7.3.16.1 purge", ve.remaining(now), ve.purgedAt)
	}
	if lspHasPrefix(ve, attacker) {
		t.Error("victim re-originated the attacker's prefix as its own")
	}
	if !hasSRM(vc, own) {
		t.Error("the purge was not flagged for flooding on the circuit")
	}
	if got := m.count("pdu_drop", "c", "own_seq_wrap"); got != 1 {
		t.Errorf("own_seq_wrap drops = %d, want 1", got)
	}

	deliverEntry(t, peer, pc, ve, now)
	pe := peer.dbs[packet.Level2].get(own)
	if pe == nil || pe.remaining(now) != 0 {
		t.Fatalf("peer still holds a live copy of the victim's LSP: %+v", pe)
	}
	if lspHasPrefix(pe, attacker) {
		t.Error("the attacker's prefix is still attributed to the victim in the peer's database")
	}

	// Nothing may be re-originated while the purge is still alive area-wide.
	mid := now.Add(30 * time.Second)
	victim.housekeeping(mid)
	if e := victim.dbs[packet.Level2].get(own); e != nil && e.remaining(mid) != 0 {
		t.Errorf("victim re-originated during the hold-down: seq %d", e.lsp.SequenceNumber)
	}

	// Well past the hold-down: the ID is free again and restarts from 1.
	later := now.Add(2 * time.Minute)
	victim.housekeeping(later)
	peer.housekeeping(later) // ages the purge out of the peer's database too
	ve = victim.dbs[packet.Level2].get(own)
	if ve == nil || ve.lsp.SequenceNumber != 1 || !ve.own || ve.remaining(later) == 0 {
		t.Fatalf("victim did not re-originate from seq 1 after the hold-down: %+v", ve)
	}

	deliverEntry(t, peer, pc, ve, later)
	pe = peer.dbs[packet.Level2].get(own)
	if pe == nil || pe.lsp.SequenceNumber != 1 || pe.remaining(later) == 0 {
		t.Fatalf("peer rejected the victim's fresh LSP: %+v", pe)
	}
	if lspHasPrefix(pe, attacker) {
		t.Error("the attacker's prefix survived in the peer's database")
	}
}

// decodeLSP decodes one serialized LSP, so each recipient in a test gets its
// own copy rather than aliasing another database's entry.
func decodeLSP(t *testing.T, raw []byte) *packet.LSP {
	t.Helper()
	pdu, err := packet.DecodePDU(raw)
	if err != nil {
		t.Fatalf("decode LSP: %v", err)
	}
	lsp, ok := pdu.(*packet.LSP)
	if !ok {
		t.Fatalf("decoded %T, want *packet.LSP", pdu)
	}
	return lsp
}

// deliverEntry replays one server's stored LSP into another's update process,
// as flooding would, at the given time.
func deliverEntry(t *testing.T, dst *IsisServer, c *circuit, e *lspEntry, now time.Time) {
	t.Helper()
	if e == nil {
		t.Fatal("nothing to deliver: the source holds no such LSP")
	}
	raw := e.wire(now)
	dst.processLSP(c, raw, decodeLSP(t, raw), now)
}

// lspHasPrefix reports whether an LSDB entry advertises a prefix.
func lspHasPrefix(e *lspEntry, p netip.Prefix) bool {
	if e == nil {
		return false
	}
	for _, tlv := range e.lsp.TLVs {
		reach, ok := tlv.(*packet.ExtendedIPReachabilityTLV)
		if !ok {
			continue
		}
		for _, entry := range reach.Prefixes {
			if entry.Prefix == p {
				return true
			}
		}
	}
	return false
}
