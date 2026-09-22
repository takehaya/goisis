package server

import (
	"testing"
	"time"

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
