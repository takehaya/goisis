package server

import (
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// snpServer builds a single, non-running server with one circuit at Level 2 and
// returns it plus the circuit, for white-box CSNP/PSNP tests.
func snpServer(t *testing.T, p2p bool) (*IsisServer, *circuit) {
	t.Helper()
	cfg := CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, P2P: p2p, Padding: ptrFalse()}
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg),
	)
	return s, s.circuits[0]
}

func putEntry(s *IsisServer, id packet.LSPID, seq uint32, rem uint16, now time.Time) {
	s.dbs[packet.Level2].entries[id] = &lspEntry{
		lsp:      &packet.LSP{Level: packet.Level2, LSPID: id, SequenceNumber: seq, RemainingTime: rem, ISType: 2},
		inserted: now, lifetime: rem,
	}
}

func fullRangeCSNP(entries ...packet.LSPEntry) *packet.CSNP {
	var end packet.LSPID
	for i := range end {
		end[i] = 0xff
	}
	return &packet.CSNP{
		Level: packet.Level2, SourceID: nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0),
		StartLSP: packet.LSPID{}, EndLSP: end,
		TLVs: []packet.TLV{&packet.LSPEntriesTLV{Entries: entries}},
	}
}

func hasSRM(c *circuit, id packet.LSPID) bool { _, ok := c.srm[packet.Level2][id]; return ok }
func hasSSN(c *circuit, id packet.LSPID) bool { return c.ssn[packet.Level2][id] }

// TestProcessCSNPDecisionTree covers each arm of the CSNP reconciliation:
// request what we lack/are-behind-on (SSN), resend what we hold newer or that
// conflicts at equal sequence (SRM), resend range entries the sender omitted
// (SRM), and acknowledge-by-silence what matches (clear SRM).
func TestProcessCSNPDecisionTree(t *testing.T) {
	now := time.Now()
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}

	missing := lspID(peer, 0)  // sender lists it, we lack it -> request
	behind := lspID(peer, 1)   // sender newer than us -> request
	ahead := lspID(peer, 2)    // we newer than sender -> resend
	conflict := lspID(peer, 3) // equal seq, different checksum -> resend
	equal := lspID(peer, 4)    // identical -> clear SRM
	omitted := lspID(peer, 5)  // we hold it, sender didn't list it -> resend

	s, c := snpServer(t, false)
	putEntry(s, behind, 1, 1000, now)
	putEntry(s, ahead, 5, 1000, now)
	putEntry(s, conflict, 3, 1000, now) // local checksum 0
	putEntry(s, equal, 4, 1000, now)    // local checksum 0
	putEntry(s, omitted, 1, 1000, now)
	// Pre-set SRM on `equal` so we can prove it gets cleared.
	c.setSRM(packet.Level2, equal, now)

	s.processCSNP(c, fullRangeCSNP(
		packet.LSPEntry{LSPID: missing, SequenceNumber: 1, RemainingTime: 1000},
		packet.LSPEntry{LSPID: behind, SequenceNumber: 9, RemainingTime: 1000},
		packet.LSPEntry{LSPID: ahead, SequenceNumber: 1, RemainingTime: 1000},
		packet.LSPEntry{LSPID: conflict, SequenceNumber: 3, RemainingTime: 1000, Checksum: 0x1234},
		packet.LSPEntry{LSPID: equal, SequenceNumber: 4, RemainingTime: 1000, Checksum: 0},
	), now)

	if !hasSSN(c, missing) {
		t.Error("missing LSP: expected SSN (request)")
	}
	if !hasSSN(c, behind) {
		t.Error("behind LSP: expected SSN (request)")
	}
	if !hasSRM(c, ahead) {
		t.Error("ahead LSP: expected SRM (resend ours)")
	}
	if !hasSRM(c, conflict) {
		t.Error("equal-seq/different-checksum: expected SRM (resend ours)")
	}
	if hasSRM(c, equal) {
		t.Error("identical LSP: expected SRM cleared")
	}
	if !hasSRM(c, omitted) {
		t.Error("omitted-from-range LSP: expected SRM (sender lacks it)")
	}
}

// TestProcessPSNPAckVsRequest covers the P2P-acknowledgement vs LAN-request
// split: on a p2p circuit a PSNP confirming our copy clears SRM; on a LAN the
// DIS treats a stale listed entry as a request and re-sends (SRM).
func TestProcessPSNPAck(t *testing.T) {
	now := time.Now()
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	own := lspID(packet.SystemID{0, 0, 0, 0, 0, 1}, 0)
	_ = peer

	s, c := snpServer(t, true) // p2p
	putEntry(s, own, 3, 1000, now)
	c.setSRM(packet.Level2, own, now) // we were retransmitting it

	// Peer acknowledges seq >= ours -> stop retransmitting.
	s.processPSNP(c, &packet.PSNP{
		Level: packet.Level2, SourceID: nodeID(peer, 0),
		TLVs: []packet.TLV{&packet.LSPEntriesTLV{Entries: []packet.LSPEntry{
			{LSPID: own, SequenceNumber: 3, RemainingTime: 1000},
		}}},
	}, now)
	if hasSRM(c, own) {
		t.Error("p2p PSNP ack (seq>=ours): expected SRM cleared")
	}
}

func TestProcessPSNPLANRequest(t *testing.T) {
	now := time.Now()
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	id := lspID(peer, 0)

	s, c := snpServer(t, false) // LAN
	putEntry(s, id, 5, 1000, now)

	// LAN PSNP lists a stale copy -> DIS re-sends our newer one.
	s.processPSNP(c, &packet.PSNP{
		Level: packet.Level2, SourceID: nodeID(peer, 0),
		TLVs: []packet.TLV{&packet.LSPEntriesTLV{Entries: []packet.LSPEntry{
			{LSPID: id, SequenceNumber: 2, RemainingTime: 1000},
		}}},
	}, now)
	if !hasSRM(c, id) {
		t.Error("LAN PSNP request (we hold newer): expected SRM set")
	}
}
