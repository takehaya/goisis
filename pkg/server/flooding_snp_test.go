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

	s, c := snpServer(t, false)                               // LAN
	c.dis[packet.Level2] = nodeID(s.systemID, c.pseudonodeID) // we are the DIS
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

// collectCSNPs runs sendCSNP with a second transport on the circuit's segment
// and returns every CSNP it emitted, together with each one's wire length.
func collectCSNPs(t *testing.T, s *IsisServer, c *circuit, now time.Time) ([]*packet.CSNP, []int) {
	t.Helper()
	sink := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	datalink.Link(c.cfg.Transport.(*datalink.MockTransport), sink)
	s.sendCSNP(c, packet.Level2, now)
	// Buffered frames still drain from a closed inbox; Recv reports ErrClosed
	// once they are gone, which ends the loop.
	_ = sink.Close()

	var (
		csnps []*packet.CSNP
		sizes []int
	)
	for {
		f, err := sink.Recv()
		if err != nil {
			return csnps, sizes
		}
		pdu, err := packet.DecodePDU(f.PDU)
		if err != nil {
			t.Fatalf("decode emitted PDU: %v", err)
		}
		csnp, ok := pdu.(*packet.CSNP)
		if !ok {
			t.Fatalf("expected a CSNP, got %T", pdu)
		}
		csnps = append(csnps, csnp)
		sizes = append(sizes, len(f.PDU))
	}
}

func csnpEntries(csnp *packet.CSNP) []packet.LSPEntry {
	var out []packet.LSPEntry
	for _, tlv := range csnp.TLVs {
		if le, ok := tlv.(*packet.LSPEntriesTLV); ok {
			out = append(out, le.Entries...)
		}
	}
	return out
}

// fillLSDB installs n entries whose LSP IDs are spread over the ID space in an
// order unrelated to insertion, so a CSNP split that did not sort would produce
// overlapping ranges.
func fillLSDB(s *IsisServer, n int, now time.Time) map[packet.LSPID]bool {
	want := map[packet.LSPID]bool{}
	for i := 0; i < n; i++ {
		// The low two octets encode i, which keeps the IDs distinct; the high
		// octets scramble the ordering.
		id := packet.LSPID{byte(i * 37 % 251), byte(i * 11 % 241), 0, 0, 0, 0, byte(i / 256), byte(i % 256)}
		putEntry(s, id, uint32(i+1), 1000, now)
		want[id] = true
	}
	return want
}

// TestSendCSNPSplitsDatabaseIntoContiguousInBudgetRanges guarantees that a
// database too large for one PDU is advertised as several CSNPs that each fit
// the architectural receive buffer, whose ranges tile the whole LSP-ID space
// without gaps or overlap, and that every entry is advertised exactly once
// inside the range of the CSNP carrying it.
func TestSendCSNPSplitsDatabaseIntoContiguousInBudgetRanges(t *testing.T) {
	now := time.Now()
	s, c := snpServer(t, false)
	want := fillLSDB(s, 300, now)

	csnps, sizes := collectCSNPs(t, s, c, now)
	if len(csnps) < 2 {
		t.Fatalf("300 LSPs: expected several CSNPs, got %d", len(csnps))
	}

	var all packet.LSPID
	for i := range all {
		all[i] = 0xff
	}
	if csnps[0].StartLSP != (packet.LSPID{}) {
		t.Errorf("first CSNP starts at %v, want all-zero", csnps[0].StartLSP)
	}
	if csnps[len(csnps)-1].EndLSP != all {
		t.Errorf("last CSNP ends at %v, want all-0xff", csnps[len(csnps)-1].EndLSP)
	}

	seen := map[packet.LSPID]int{}
	for i, csnp := range csnps {
		if sizes[i] > packet.ReceiveLSPBufferSize {
			t.Errorf("CSNP %d is %d octets, over the %d receive buffer", i, sizes[i], packet.ReceiveLSPBufferSize)
		}
		if i > 0 && csnp.StartLSP != nextLSPID(csnps[i-1].EndLSP) {
			t.Errorf("CSNP %d starts at %v, want previous end %v + 1", i, csnp.StartLSP, csnps[i-1].EndLSP)
		}
		for _, e := range csnpEntries(csnp) {
			if !inRange(e.LSPID, csnp.StartLSP, csnp.EndLSP) {
				t.Errorf("CSNP %d advertises %v outside [%v, %v]", i, e.LSPID, csnp.StartLSP, csnp.EndLSP)
			}
			seen[e.LSPID]++
		}
	}
	for id := range want {
		if seen[id] != 1 {
			t.Errorf("LSP %v advertised %d times, want exactly 1", id, seen[id])
		}
	}
	for id := range seen {
		if !want[id] {
			t.Errorf("CSNPs advertise unknown LSP %v", id)
		}
	}
}

// TestSendCSNPFitsBudgetWhenAuthenticated guarantees the split reserves room
// for the Authentication TLV sendSNP appends, so an authenticated level's
// CSNPs still fit the receive buffer.
func TestSendCSNPFitsBudgetWhenAuthenticated(t *testing.T) {
	now := time.Now()
	cfg := CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg),
		WithDomainPassword("k"),
	)
	fillLSDB(s, 300, now)

	csnps, sizes := collectCSNPs(t, s, s.circuits[0], now)
	if len(csnps) < 2 {
		t.Fatalf("300 LSPs: expected several CSNPs, got %d", len(csnps))
	}
	for i, csnp := range csnps {
		if sizes[i] > packet.ReceiveLSPBufferSize {
			t.Errorf("CSNP %d is %d octets, over the %d receive buffer", i, sizes[i], packet.ReceiveLSPBufferSize)
		}
		authed := false
		for _, tlv := range csnp.TLVs {
			if _, ok := tlv.(*packet.AuthenticationTLV); ok {
				authed = true
			}
		}
		if !authed {
			t.Errorf("CSNP %d carries no Authentication TLV", i)
		}
	}
}

// TestSendCSNPEmptyDatabaseAdvertisesTheWholeRange guarantees an empty database
// still produces one CSNP covering every LSP ID, which is what tells a peer
// holding LSPs we lack to send them.
func TestSendCSNPEmptyDatabaseAdvertisesTheWholeRange(t *testing.T) {
	now := time.Now()
	s, c := snpServer(t, false)

	csnps, _ := collectCSNPs(t, s, c, now)
	if len(csnps) != 1 {
		t.Fatalf("empty database: got %d CSNPs, want 1", len(csnps))
	}
	var all packet.LSPID
	for i := range all {
		all[i] = 0xff
	}
	if csnps[0].StartLSP != (packet.LSPID{}) || csnps[0].EndLSP != all {
		t.Errorf("empty database CSNP covers [%v, %v], want the whole range", csnps[0].StartLSP, csnps[0].EndLSP)
	}
	if n := len(csnpEntries(csnps[0])); n != 0 {
		t.Errorf("empty database CSNP advertises %d entries, want none", n)
	}
}

// TestNextLSPIDCarriesAcrossOctets guarantees the range-boundary increment
// treats the LSP ID as one 8-octet unsigned integer.
func TestNextLSPIDCarriesAcrossOctets(t *testing.T) {
	for _, tc := range []struct {
		in, want packet.LSPID
	}{
		{packet.LSPID{}, packet.LSPID{0, 0, 0, 0, 0, 0, 0, 1}},
		{packet.LSPID{1, 2, 3, 4, 5, 6, 7, 0xff}, packet.LSPID{1, 2, 3, 4, 5, 6, 8, 0}},
		{packet.LSPID{1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, packet.LSPID{2, 0, 0, 0, 0, 0, 0, 0}},
	} {
		if got := nextLSPID(tc.in); got != tc.want {
			t.Errorf("nextLSPID(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// capturePSNPs links a listener onto the circuit's segment and returns a
// function that ends the capture and decodes every PSNP sent since.
func capturePSNPs(t *testing.T, c *circuit) func() []*packet.PSNP {
	t.Helper()
	tr, ok := c.cfg.Transport.(*datalink.MockTransport)
	if !ok {
		t.Fatalf("circuit transport is %T, want *datalink.MockTransport", c.cfg.Transport)
	}
	peer := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xff}, 1500)
	datalink.Link(tr, peer)
	return func() []*packet.PSNP {
		_ = peer.Close()
		var out []*packet.PSNP
		for {
			f, err := peer.Recv()
			if err != nil {
				return out
			}
			pdu, err := packet.DecodePDU(f.PDU)
			if err != nil {
				t.Fatalf("decode captured PDU: %v", err)
			}
			psnp, ok := pdu.(*packet.PSNP)
			if !ok {
				t.Fatalf("captured a %T, want a PSNP", pdu)
			}
			out = append(out, psnp)
		}
	}
}

func psnpEntries(psnp *packet.PSNP) []packet.LSPEntry {
	var out []packet.LSPEntry
	for _, tlv := range psnp.TLVs {
		if le, ok := tlv.(*packet.LSPEntriesTLV); ok {
			out = append(out, le.Entries...)
		}
	}
	return out
}

// TestProcessLSPAcknowledgesUnknownPurgeWithoutStoringIt: on a p2p circuit a
// purge for an LSP ID we do not hold is acknowledged by a PSNP carrying the
// received header, and is never entered into the database (ISO 10589
// 7.3.16.4 a).
func TestProcessLSPAcknowledgesUnknownPurgeWithoutStoringIt(t *testing.T) {
	now := time.Now()
	unknown := lspID(packet.SystemID{9, 9, 9, 9, 9, 9}, 0)

	s, c := snpServer(t, true)                          // p2p
	upP2PAdj(c, packet.SystemID{0, 0, 0, 0, 0, 2}, now) // an LSP only ever arrives over one
	stop := capturePSNPs(t, c)

	purge := &packet.LSP{Level: packet.Level2, RemainingTime: 0, LSPID: unknown, SequenceNumber: 3, ISType: 2}
	raw, err := purge.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, purge, nil, now)

	if e := s.dbs[packet.Level2].get(unknown); e != nil {
		t.Fatalf("purge for an unheld LSP ID was stored: %+v", e)
	}
	if hasSRM(c, unknown) {
		t.Error("purge for an unheld LSP ID was flagged for re-flooding (SRM)")
	}

	s.transmitPSNP(c, packet.Level2, now)
	psnps := stop()
	if len(psnps) != 1 {
		t.Fatalf("sent %d PSNPs, want 1", len(psnps))
	}
	entries := psnpEntries(psnps[0])
	if len(entries) != 1 {
		t.Fatalf("PSNP carried %d entries, want 1: %+v", len(entries), entries)
	}
	if got := entries[0]; got.LSPID != unknown || got.SequenceNumber != 3 || got.RemainingTime != 0 {
		t.Errorf("PSNP entry = %+v, want LSPID %v, seq 3, remaining 0", got, unknown)
	}
	if hasSSN(c, unknown) || len(c.ssnAck[packet.Level2]) != 0 {
		t.Error("acknowledgement flags were not cleared after the PSNP was sent")
	}
}

// TestProcessLSPIgnoresUnknownPurgeOnLAN: on a broadcast circuit a purge for
// an LSP ID we do not hold is discarded silently — not stored, not
// acknowledged, not re-flooded (ISO 10589 7.3.16.4 a).
func TestProcessLSPIgnoresUnknownPurgeOnLAN(t *testing.T) {
	now := time.Now()
	unknown := lspID(packet.SystemID{9, 9, 9, 9, 9, 9}, 0)

	s, c := snpServer(t, false) // LAN
	stop := capturePSNPs(t, c)

	purge := &packet.LSP{Level: packet.Level2, RemainingTime: 0, LSPID: unknown, SequenceNumber: 3, ISType: 2}
	raw, err := purge.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, purge, nil, now)

	if e := s.dbs[packet.Level2].get(unknown); e != nil {
		t.Fatalf("purge for an unheld LSP ID was stored: %+v", e)
	}
	if hasSSN(c, unknown) {
		t.Error("purge for an unheld LSP ID was acknowledged (SSN) on a LAN")
	}
	if hasSRM(c, unknown) {
		t.Error("purge for an unheld LSP ID was flagged for re-flooding (SRM)")
	}

	s.transmitPSNP(c, packet.Level2, now)
	if psnps := stop(); len(psnps) != 0 {
		t.Errorf("sent %d PSNPs, want none", len(psnps))
	}
}

// TestUnknownPurgeDoesNotConsumeLSDBEntryLimit: a purge for an LSP ID we do
// not hold is discarded before the entry-limit check, so purges alone can
// neither fill the database nor trip its once-per-level warning.
func TestUnknownPurgeDoesNotConsumeLSDBEntryLimit(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, P2P: true, Padding: ptrFalse()}),
		WithLSDBEntryLimit(1),
	)
	c := s.circuits[0]
	now := time.Now()
	db := s.dbs[packet.Level2]

	inject := func(lsp *packet.LSP) {
		t.Helper()
		raw, err := lsp.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		s.processLSP(c, raw, lsp, nil, now)
	}

	// Fill the database to the limit.
	live := lspID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	inject(&packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: live, SequenceNumber: 1, ISType: 2})
	if len(db.entries) != 1 {
		t.Fatalf("setup: %d entries, want 1", len(db.entries))
	}

	unknown := lspID(packet.SystemID{9, 9, 9, 9, 9, 9}, 0)
	inject(&packet.LSP{Level: packet.Level2, RemainingTime: 0, LSPID: unknown, SequenceNumber: 3, ISType: 2})
	if len(db.entries) != 1 {
		t.Errorf("%d entries after an unknown purge, want 1", len(db.entries))
	}
	if s.lsdbLimitWarned.fired[packet.Level2] {
		t.Error("an unknown purge reached the entry-limit check instead of being discarded first")
	}
}

// TestSendCSNPFitsANarrowCircuitMTU: the per-PDU budget is
// min(ReceiveLSPBufferSize, MTU-3). At the 1500-octet MTU every other test
// uses, those terms are 1492 and 1497, so the buffer always wins and no test
// can tell a budget derived from the MTU from one that ignored it. A 1000-octet
// circuit inverts them.
func TestSendCSNPFitsANarrowCircuitMTU(t *testing.T) {
	now := time.Now()
	const mtu = 1000
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, mtu),
			Level2: true, Padding: ptrFalse(),
		}),
	)
	fillLSDB(s, 300, now)

	csnps, sizes := collectCSNPs(t, s, s.circuits[0], now)
	if len(csnps) < 2 {
		t.Fatalf("300 LSPs at MTU %d: expected several CSNPs, got %d", mtu, len(csnps))
	}
	for i := range csnps {
		if sizes[i] > mtu-3 { // 3 = LLC header
			t.Errorf("CSNP %d is %d octets, over the %d the MTU leaves", i, sizes[i], mtu-3)
		}
	}
}
