package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func lifetimeServer(t *testing.T) (*IsisServer, *circuit) {
	t.Helper()
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}),
	)
	return s, s.circuits[0]
}

func TestPurgeOwnPOIEncoding(t *testing.T) {
	s, _ := lifetimeServer(t)
	now := time.Now()
	id := lspID(s.systemID, 7)
	s.dbs[packet.Level2].entries[id] = &lspEntry{
		lsp: &packet.LSP{LSPID: id, SequenceNumber: 4}, inserted: now, lifetime: 1000, own: true,
	}
	s.purgeOwn(packet.Level2, id, now)

	e := s.dbs[packet.Level2].get(id)
	if e == nil || e.purgedAt.IsZero() {
		t.Fatal("purge not recorded")
	}
	if e.lsp.RemainingTime != 0 {
		t.Errorf("purge RemainingTime = %d, want 0", e.lsp.RemainingTime)
	}
	// The POI TLV count octet must be 1 (number of system IDs), per RFC 6232,
	// not the system-ID byte length.
	var poi *packet.UnknownTLV
	for _, tlv := range e.lsp.TLVs {
		if u, ok := tlv.(*packet.UnknownTLV); ok && u.Type() == packet.TLVTypePurgeOriginatorID {
			poi = u
		}
	}
	if poi == nil {
		t.Fatal("purge missing POI TLV")
	}
	if len(poi.Value) != 7 || poi.Value[0] != 1 {
		t.Errorf("POI value = % x, want count=1 + 6-octet system ID", poi.Value)
	}
}

// assertHeaderOnlyPurge decodes an entry's wire bytes and asserts they carry a
// purge per ISO 10589 7.3.16.4: remaining lifetime zero, the given LSPID and
// sequence number, and the body removed — only the POI TLV (RFC 6232) and, on
// a keyed level, an Authentication TLV may remain.
func assertHeaderOnlyPurge(t *testing.T, e *lspEntry, id packet.LSPID, seq uint32, now time.Time) {
	t.Helper()
	pdu, err := packet.DecodePDU(e.wire(now))
	if err != nil {
		t.Fatalf("decode purge: %v", err)
	}
	p, ok := pdu.(*packet.LSP)
	if !ok {
		t.Fatalf("purge decoded as %T, want *packet.LSP", pdu)
	}
	if p.RemainingTime != 0 {
		t.Errorf("purge RemainingTime = %d, want 0", p.RemainingTime)
	}
	if p.LSPID != id {
		t.Errorf("purge LSPID = %v, want %v", p.LSPID, id)
	}
	if p.SequenceNumber != seq {
		t.Errorf("purge seq = %d, want %d", p.SequenceNumber, seq)
	}
	poi := false
	for _, tlv := range p.TLVs {
		switch v := tlv.(type) {
		case *packet.UnknownTLV:
			if v.Type() == packet.TLVTypePurgeOriginatorID {
				poi = true
				continue
			}
			t.Errorf("purge carries TLV type %d; the body must be removed", v.Type())
		case *packet.AuthenticationTLV:
			// permitted on a keyed level
		default:
			t.Errorf("purge carries %T; the body must be removed", tlv)
		}
	}
	if !poi {
		t.Error("purge missing POI TLV")
	}
}

// TestExpirePurgeHeaderOnly: a foreign LSP whose remaining lifetime reaches
// zero is re-flooded as a header-only purge (ISO 10589 7.3.16.4) — the
// original reachability body must not survive in the stored/flooded bytes,
// and the foreign originator's sequence number is preserved, not bumped.
func TestExpirePurgeHeaderOnly(t *testing.T) {
	s, c := lifetimeServer(t)
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)
	lsp := &packet.LSP{
		Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 7, ISType: 2,
		TLVs: []packet.TLV{
			&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{
				{NeighborID: nodeID(packet.SystemID{0, 0, 0, 0, 0, 8}, 0), Metric: 10},
			}},
			&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{
				{Metric: 10, Prefix: netip.MustParsePrefix("10.9.0.0/24")},
			}},
		},
	}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, lsp, now)
	e := s.dbs[packet.Level2].get(foreign)
	if e == nil {
		t.Fatal("foreign LSP not installed")
	}

	// Age it past its 1000s lifetime, then run the aging pass.
	e.inserted = now.Add(-1001 * time.Second)
	s.ageLSPs(now)

	if e.purgedAt.IsZero() {
		t.Fatal("expired foreign LSP was not purged")
	}
	if e.own {
		t.Error("foreign purge marked own; refresh logic would reclaim it")
	}
	assertHeaderOnlyPurge(t, e, foreign, 7, now)
}

func TestProcessLSPDropsBadChecksum(t *testing.T) {
	s, c := lifetimeServer(t)
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)
	lsp := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 3, ISType: 2}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt a body byte after the checksum field so the stored checksum no
	// longer matches; re-decode to mimic a corrupted received PDU.
	raw[len(raw)-1] ^= 0xff
	corrupt, err := packet.DecodePDU(raw)
	if err != nil {
		t.Fatalf("decode corrupted: %v", err)
	}
	s.processLSP(c, raw, corrupt.(*packet.LSP), now)
	if s.dbs[packet.Level2].get(foreign) != nil {
		t.Error("LSP with invalid checksum was installed")
	}
}

func TestProcessLSPEqualSeqDifferentChecksumPurges(t *testing.T) {
	s, c := lifetimeServer(t)
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)

	// Install a valid foreign LSP at seq 5.
	a := &packet.LSP{
		Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 5, ISType: 2,
		TLVs: []packet.TLV{&packet.DynamicHostnameTLV{Hostname: "alpha"}},
	}
	araw, err := a.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, araw, a, now)
	if s.dbs[packet.Level2].get(foreign) == nil {
		t.Fatal("first copy not installed")
	}

	// A different body at the SAME sequence number must trigger a purge of
	// the stored copy (ISO 10589 7.3.16.2).
	b := &packet.LSP{
		Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 5, ISType: 2,
		TLVs: []packet.TLV{&packet.DynamicHostnameTLV{Hostname: "bravo"}},
	}
	braw, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, braw, b, now)
	e := s.dbs[packet.Level2].get(foreign)
	if e == nil || e.purgedAt.IsZero() {
		t.Fatalf("equal-seq/different-checksum did not purge stored copy: %+v", e)
	}
	// The purge is header-only (ISO 10589 7.3.16.4) at the foreign
	// originator's sequence number: the true originator, not us, re-originates
	// above it.
	assertHeaderOnlyPurge(t, e, foreign, 5, now)
}
