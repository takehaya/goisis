package packet

import "testing"

func TestHMACMD5PatchVerify(t *testing.T) {
	h := &LANHello{
		Level:       Level1,
		SourceID:    SystemID{0, 0, 0, 0, 0, 1},
		HoldingTime: 30,
		TLVs: []TLV{
			&AreaAddressesTLV{Addresses: []AreaAddress{{0x49, 0x00, 0x01}}},
			&AuthenticationTLV{AuthType: AuthTypeHMACMD5, Value: make([]byte, hmacMD5DigestLen)},
		},
	}
	raw, err := h.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	off := HeaderLen(h.PDUType())
	key := []byte("s3cret")

	if err := PatchHMACMD5(raw, off, key, false); err != nil {
		t.Fatalf("PatchHMACMD5: %v", err)
	}
	if !VerifyHMACMD5(raw, off, key, false) {
		t.Error("verify failed for the correct key")
	}
	if VerifyHMACMD5(raw, off, []byte("wrong"), false) {
		t.Error("verify passed for the wrong key")
	}

	// Tampering any covered byte must break verification.
	raw[off]++
	if VerifyHMACMD5(raw, off, key, false) {
		t.Error("verify passed after tampering a covered byte")
	}
}

func TestVerifyHMACMD5IgnoresDataLinkPadding(t *testing.T) {
	// A small authenticated PDU is padded by the NIC to the 60-octet Ethernet
	// minimum on receive. Verification must hash the declared-length PDU, not
	// the padded frame, so callers trim with TrimToPDULength first.
	h := &LANHello{
		Level: Level1, SourceID: SystemID{0, 0, 0, 0, 0, 1}, HoldingTime: 30,
		TLVs: []TLV{
			&AreaAddressesTLV{Addresses: []AreaAddress{{0x49, 0x00, 0x01}}},
			&AuthenticationTLV{AuthType: AuthTypeHMACMD5, Value: make([]byte, hmacMD5DigestLen)},
		},
	}
	raw, err := h.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	off := HeaderLen(h.PDUType())
	key := []byte("k")
	if err := PatchHMACMD5(raw, off, key, false); err != nil {
		t.Fatalf("PatchHMACMD5: %v", err)
	}

	padded := append(append([]byte{}, raw...), make([]byte, 12)...) // NIC padding
	if VerifyHMACMD5(padded, off, key, false) {
		t.Error("verify must not pass over the padded buffer (the digest covers fewer bytes)")
	}
	if !VerifyHMACMD5(TrimToPDULength(padded), off, key, false) {
		t.Error("verify must pass after trimming data-link padding")
	}
}

func TestHMACMD5LSPZeroesVolatileFields(t *testing.T) {
	lsp := &LSP{
		Level: Level2, RemainingTime: 1000, LSPID: LSPID{0, 0, 0, 0, 0, 1, 0, 0}, SequenceNumber: 5, ISType: 2,
		TLVs: []TLV{&AuthenticationTLV{AuthType: AuthTypeHMACMD5, Value: make([]byte, hmacMD5DigestLen)}},
	}
	raw, err := lsp.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	off := HeaderLen(lsp.PDUType())
	key := []byte("k")
	if err := PatchHMACMD5(raw, off, key, true); err != nil {
		t.Fatalf("PatchHMACMD5: %v", err)
	}
	if !VerifyHMACMD5(raw, off, key, true) {
		t.Fatal("verify failed after patch")
	}
	// Changing the remaining lifetime and checksum must NOT invalidate the
	// HMAC (RFC 5304 zeroes them before hashing) — they change in flight.
	raw[10], raw[11] = 0x12, 0x34 // remaining lifetime
	raw[24], raw[25] = 0x56, 0x78 // checksum
	if !VerifyHMACMD5(raw, off, key, true) {
		t.Error("verify must ignore lifetime/checksum changes for an LSP")
	}
}
