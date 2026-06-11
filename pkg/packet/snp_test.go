package packet

import (
	"testing"
)

func TestCSNPRoundtrip(t *testing.T) {
	in := &CSNP{
		Level:    Level2,
		SourceID: NodeID{0, 0, 0, 0, 0, 1, 0},
		StartLSP: LSPID{0, 0, 0, 0, 0, 0, 0, 0},
		EndLSP:   LSPID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		TLVs: []TLV{
			&LSPEntriesTLV{Entries: []LSPEntry{
				{RemainingTime: 1100, LSPID: LSPID{0, 0, 0, 0, 0, 1, 0, 0}, SequenceNumber: 7, Checksum: 0xabcd},
				{RemainingTime: 1199, LSPID: LSPID{0, 0, 0, 0, 0, 2, 0, 0}, SequenceNumber: 3, Checksum: 0x1234},
			}},
		},
	}
	wire, err := in.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	out := checkPDURoundtrip(t, wire).(*CSNP)
	if out.SourceID != in.SourceID || out.StartLSP != in.StartLSP || out.EndLSP != in.EndLSP {
		t.Errorf("header mismatch: %+v", out)
	}
	entries := out.TLVs[0].(*LSPEntriesTLV).Entries
	if len(entries) != 2 || entries[0].SequenceNumber != 7 || entries[1].Checksum != 0x1234 {
		t.Errorf("LSP entries mismatch: %+v", entries)
	}
}

func TestPSNPRoundtrip(t *testing.T) {
	in := &PSNP{
		Level:    Level1,
		SourceID: NodeID{0, 0, 0, 0, 0, 5, 0},
		TLVs: []TLV{
			&LSPEntriesTLV{Entries: []LSPEntry{
				{RemainingTime: 0, LSPID: LSPID{0, 0, 0, 0, 0, 1, 0, 0}, SequenceNumber: 9, Checksum: 0x4321},
			}},
		},
	}
	wire, err := in.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	out := checkPDURoundtrip(t, wire).(*PSNP)
	if out.SourceID != in.SourceID {
		t.Errorf("SourceID = %v, want %v", out.SourceID, in.SourceID)
	}
}

func TestLSPEntriesTLVTooMany(t *testing.T) {
	tlv := &LSPEntriesTLV{Entries: make([]LSPEntry, MaxLSPEntriesPerTLV+1)}
	if _, err := tlv.Serialize(); err == nil {
		t.Error("expected error serializing too many LSP entries")
	}
}
