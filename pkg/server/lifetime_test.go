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
	s.processLSP(c, raw, lsp, nil, now)
	e := s.dbs[packet.Level2].get(foreign)
	if e == nil {
		t.Fatal("foreign LSP not installed")
	}

	// Age it past the lifetime it is stored with — the advertised 1000s is
	// raised to MaxAge on receipt (RFC 7987) — then run the aging pass.
	e.inserted = now.Add(-time.Duration(e.lifetime+1) * time.Second)
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
	s.processLSP(c, raw, corrupt.(*packet.LSP), nil, now)
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
	s.processLSP(c, araw, a, nil, now)
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
	s.processLSP(c, braw, b, nil, now)
	e := s.dbs[packet.Level2].get(foreign)
	if e == nil || e.purgedAt.IsZero() {
		t.Fatalf("equal-seq/different-checksum did not purge stored copy: %+v", e)
	}
	// The purge is header-only (ISO 10589 7.3.16.4) at the foreign
	// originator's sequence number: the true originator, not us, re-originates
	// above it.
	assertHeaderOnlyPurge(t, e, foreign, 5, now)
}

// TestReceivedLSPBelowMaxAgeAgesFromMaxAge: the Remaining Lifetime field lies
// outside the Fletcher checksum, so a value corrupted downward in flight is
// undetectable. A received LSP carrying less than MaxAge is stored as MaxAge
// and is not purged before MaxAge has passed here (RFC 7987 section 2, vi).
func TestReceivedLSPBelowMaxAgeAgesFromMaxAge(t *testing.T) {
	s, c := lifetimeServer(t)
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)
	lsp := &packet.LSP{
		Level: packet.Level2, RemainingTime: 30, LSPID: foreign, SequenceNumber: 7, ISType: 2,
		TLVs: []packet.TLV{&packet.DynamicHostnameTLV{Hostname: "alpha"}},
	}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, lsp, nil, now)

	e := s.dbs[packet.Level2].get(foreign)
	if e == nil {
		t.Fatal("foreign LSP not installed")
	}
	if e.lifetime != maxAgeSeconds {
		t.Errorf("stored lifetime = %d, want %d (the advertised 30s is floored)", e.lifetime, maxAgeSeconds)
	}

	// Long past the corrupted 30 seconds, far short of MaxAge: still live, so
	// neither the purge nor the originator's re-origination storm happens.
	later := now.Add(120 * time.Second)
	s.ageLSPs(later)
	if !e.purgedAt.IsZero() {
		t.Error("LSP purged before it had been held for MaxAge")
	}
	if got := e.remaining(later); got != maxAgeSeconds-120 {
		t.Errorf("remaining after 120s = %d, want %d", got, maxAgeSeconds-120)
	}
}

// TestDuplicateLSPWithSmallerLifetimeKeepsStoredLifetime: a re-flooded copy of
// an LSP we already hold differs only in its remaining lifetime, so it is
// neither newer nor older (ISO 10589 7.3.16.2) and must not be installed —
// otherwise a corrupt lifetime arriving on the second copy would undo the
// RFC 7987 floor applied to the first.
func TestDuplicateLSPWithSmallerLifetimeKeepsStoredLifetime(t *testing.T) {
	s, c := lifetimeServer(t)
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)
	tlvs := []packet.TLV{&packet.DynamicHostnameTLV{Hostname: "alpha"}}

	first := &packet.LSP{Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 7, ISType: 2, TLVs: tlvs}
	firstRaw, err := first.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, firstRaw, first, nil, now)

	// Same sequence number and same body — the checksum does not cover the
	// remaining lifetime, so this is exactly what a corrupted duplicate looks
	// like on the wire.
	dup := &packet.LSP{Level: packet.Level2, RemainingTime: 5, LSPID: foreign, SequenceNumber: 7, ISType: 2, TLVs: tlvs}
	dupRaw, err := dup.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(600 * time.Second)
	s.processLSP(c, dupRaw, dup, nil, later)

	e := s.dbs[packet.Level2].get(foreign)
	if e == nil {
		t.Fatal("LSP no longer held")
	}
	if e.lifetime != maxAgeSeconds {
		t.Errorf("stored lifetime = %d, want %d", e.lifetime, maxAgeSeconds)
	}
	if got := e.remaining(later); got != maxAgeSeconds-600 {
		t.Errorf("remaining = %d, want %d (the duplicate must not restart aging either)", got, maxAgeSeconds-600)
	}
	s.ageLSPs(later)
	if !e.purgedAt.IsZero() {
		t.Error("LSP purged on a duplicate carrying a corrupt lifetime")
	}
}

// TestReceivedLSPAboveMaxAgeKeepsAdvertisedLifetime: RFC 7987 raises a short
// lifetime and never lowers a long one. The originator may run a larger MaxAge
// than we do (RFC 7987 section 3.1) and a lifetime longer than intended is
// harmless (section 1), so clamping down is what would purge that originator's
// LSPs prematurely.
func TestReceivedLSPAboveMaxAgeKeepsAdvertisedLifetime(t *testing.T) {
	s, c := lifetimeServer(t)
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)
	lsp := &packet.LSP{
		Level: packet.Level2, RemainingTime: 2000, LSPID: foreign, SequenceNumber: 7, ISType: 2,
		TLVs: []packet.TLV{&packet.DynamicHostnameTLV{Hostname: "alpha"}},
	}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, raw, lsp, nil, now)

	e := s.dbs[packet.Level2].get(foreign)
	if e == nil {
		t.Fatal("foreign LSP not installed")
	}
	if e.lifetime != 2000 {
		t.Errorf("stored lifetime = %d, want 2000 (a lifetime above MaxAge is kept as advertised)", e.lifetime)
	}
}

// TestReceivedPurgeKeepsZeroLifetime: RFC 7987 changes nothing about purges —
// an LSP received with a zero remaining lifetime is still newer than a live
// copy at the same sequence number (ISO 10589 7.3.15.1 b), and the floor must
// not turn it back into a live LSP for MaxAge.
func TestReceivedPurgeKeepsZeroLifetime(t *testing.T) {
	s, c := lifetimeServer(t)
	now := time.Now()
	foreign := lspID(packet.SystemID{0, 0, 0, 0, 0, 9}, 0)
	live := &packet.LSP{
		Level: packet.Level2, RemainingTime: 1000, LSPID: foreign, SequenceNumber: 7, ISType: 2,
		TLVs: []packet.TLV{&packet.DynamicHostnameTLV{Hostname: "alpha"}},
	}
	liveRaw, err := live.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, liveRaw, live, nil, now)

	purge := &packet.LSP{Level: packet.Level2, RemainingTime: 0, LSPID: foreign, SequenceNumber: 7, ISType: 2}
	purgeRaw, err := purge.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	s.processLSP(c, purgeRaw, purge, nil, now)

	e := s.dbs[packet.Level2].get(foreign)
	if e == nil {
		t.Fatal("purge not installed")
	}
	if e.lifetime != 0 || e.remaining(now) != 0 {
		t.Errorf("purge stored with lifetime %d (remaining %d), want 0", e.lifetime, e.remaining(now))
	}
	if e.purgedAt.IsZero() {
		t.Error("purge not recorded as purged")
	}
}

// TestAnAdjacencyRemembersWhenItCameUp pins the clock RFC 7987 §3.2's
// false-positive filter reads. It starts on the transition into Up and must
// not restart on the hellos that follow: a filter re-armed by every hello
// would read an adjacency of any age as too young to judge, and the event
// would never be raised at all.
func TestAnAdjacencyRemembersWhenItCameUp(t *testing.T) {
	s, c, local := disServer(t, nil)
	id, snpa := packet.SystemID{0, 0, 0, 0, 0, 0x10}, packet.SNPA{0, 0, 0, 0, 0, 0x10}
	other := packet.SNPA{0, 0, 0, 0, 0, 0xee}

	// A hello echoing somebody else's SNPA reaches Init, not Up.
	s.processLANHello(c, snpa, neighborHello(id, 64, packet.NodeID{}, other))
	adj := c.adjs[packet.Level2][id]
	if adj == nil || adj.state != AdjInit || !adj.upSince.IsZero() {
		t.Fatalf("adjacency in Init: %+v, want no upSince yet", adj)
	}

	s.processLANHello(c, snpa, neighborHello(id, 64, packet.NodeID{}, local))
	if adj.state != AdjUp || adj.upSince.IsZero() {
		t.Fatalf("adjacency Up with upSince %v, want it set", adj.upSince)
	}

	came := time.Now().Add(-time.Hour)
	adj.upSince = came
	s.processLANHello(c, snpa, neighborHello(id, 64, packet.NodeID{}, local))
	if !adj.upSince.Equal(came) {
		t.Errorf("a refreshing hello moved upSince to %v, want it left at %v", adj.upSince, came)
	}
}
