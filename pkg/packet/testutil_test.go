package packet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// mustHex decodes a hex string that may contain spaces and newlines for
// readability.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	clean := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s)
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// checkTLVRoundtrip decodes a TLV area and asserts that re-serializing it
// reproduces the input bytes exactly.
func checkTLVRoundtrip(t *testing.T, wire []byte) []TLV {
	t.Helper()
	tlvs, err := decodeTLVs(wire)
	if err != nil {
		t.Fatalf("decodeTLVs: %v", err)
	}
	out, err := serializeTLVs(tlvs)
	if err != nil {
		t.Fatalf("serializeTLVs: %v", err)
	}
	if !bytes.Equal(out, wire) {
		t.Fatalf("roundtrip mismatch:\n got %x\nwant %x", out, wire)
	}
	return tlvs
}

// checkPDURoundtrip decodes a PDU and asserts that re-serializing it
// reproduces the input bytes exactly.
func checkPDURoundtrip(t *testing.T, wire []byte) PDU {
	t.Helper()
	pdu, err := DecodePDU(wire)
	if err != nil {
		t.Fatalf("DecodePDU: %v", err)
	}
	out, err := pdu.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !bytes.Equal(out, wire) {
		t.Fatalf("roundtrip mismatch:\n got %x\nwant %x", out, wire)
	}
	return pdu
}
