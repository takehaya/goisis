package packet

import (
	"net/netip"
	"testing"
)

func TestLSPSerializeChecksumRoundtrip(t *testing.T) {
	in := &LSP{
		Level:          Level2,
		RemainingTime:  1199,
		LSPID:          LSPID{0, 0, 0, 0, 0, 1, 0, 0},
		SequenceNumber: 0x10,
		Overload:       true,
		AttDefault:     true,
		ISType:         3, // L2
		TLVs: []TLV{
			&AreaAddressesTLV{Addresses: []AreaAddress{{0x49, 0x00, 0x01}}},
			&ProtocolsSupportedTLV{NLPIDs: []byte{NLPIDIPv4, NLPIDIPv6}},
			&ExtendedIPReachabilityTLV{Prefixes: []ExtendedIPReachEntry{
				{Metric: 10, Prefix: netip.MustParsePrefix("192.0.2.0/24")},
			}},
		},
	}
	wire, err := in.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	pdu := checkPDURoundtrip(t, wire)
	out, ok := pdu.(*LSP)
	if !ok {
		t.Fatalf("got %T, want *LSP", pdu)
	}
	if out.SequenceNumber != 0x10 || !out.Overload || !out.AttDefault || out.ISType != 3 {
		t.Errorf("decoded flags/seqno mismatch: %+v", out)
	}
	// The serialized checksum must verify.
	valid, err := out.ChecksumValid()
	if err != nil {
		t.Fatalf("ChecksumValid: %v", err)
	}
	if !valid {
		t.Errorf("checksum %04x does not verify", out.Checksum())
	}
}

func TestLSPChecksumDetectsCorruption(t *testing.T) {
	in := &LSP{
		Level:          Level1,
		RemainingTime:  900,
		LSPID:          LSPID{0, 0, 0, 0, 0, 2, 0, 0},
		SequenceNumber: 5,
		ISType:         1,
		TLVs:           []TLV{&DynamicHostnameTLV{Hostname: "r2"}},
	}
	wire, err := in.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// Corrupt a TLV byte (after the checksum field).
	wire[len(wire)-1] ^= 0xff
	pdu, err := DecodePDU(wire)
	if err != nil {
		t.Fatalf("DecodePDU: %v", err)
	}
	valid, err := pdu.(*LSP).ChecksumValid()
	if err != nil {
		t.Fatalf("ChecksumValid: %v", err)
	}
	if valid {
		t.Error("corrupted LSP reported valid checksum")
	}
}

func TestLSPChecksumValidRaw(t *testing.T) {
	in := &LSP{
		Level:          Level2,
		RemainingTime:  1199,
		LSPID:          LSPID{0, 0, 0, 0, 0, 1, 0, 0},
		SequenceNumber: 7,
		ISType:         3,
		TLVs: []TLV{
			&AreaAddressesTLV{Addresses: []AreaAddress{{0x49, 0x00, 0x01}}},
			&ExtendedIPReachabilityTLV{Prefixes: []ExtendedIPReachEntry{
				{Metric: 10, Prefix: netip.MustParsePrefix("192.0.2.0/24")},
			}},
		},
	}
	wire, err := in.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// The receive-path check accepts the bytes exactly as produced on the wire.
	if !LSPChecksumValidRaw(wire) {
		t.Errorf("valid LSP rejected by LSPChecksumValidRaw")
	}
	// Corrupting a TLV byte (after the checksum field) must be detected.
	corrupt := append([]byte(nil), wire...)
	corrupt[len(corrupt)-1] ^= 0xff
	if LSPChecksumValidRaw(corrupt) {
		t.Errorf("corrupted LSP accepted by LSPChecksumValidRaw")
	}
	// Too-short input is rejected, not panicked on (hostile-input guard).
	if LSPChecksumValidRaw(wire[:10]) {
		t.Errorf("truncated buffer accepted by LSPChecksumValidRaw")
	}
	if LSPChecksumValidRaw(nil) {
		t.Errorf("nil accepted by LSPChecksumValidRaw")
	}
}

func TestLSPFlagsAllBits(t *testing.T) {
	in := &LSP{
		Level:          Level2,
		LSPID:          LSPID{0, 0, 0, 0, 0, 9, 0, 0},
		SequenceNumber: 1,
		Partition:      true,
		AttError:       true,
		AttExpense:     true,
		AttDelay:       true,
		AttDefault:     true,
		Overload:       true,
		ISType:         3,
	}
	wire, err := in.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	out := checkPDURoundtrip(t, wire).(*LSP)
	if !out.Partition || !out.AttError || !out.AttExpense || !out.AttDelay || !out.AttDefault || !out.Overload {
		t.Errorf("flag bits lost in roundtrip: %+v", out)
	}
}
