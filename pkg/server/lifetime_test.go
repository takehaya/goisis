package server

import (
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
}
