package packet

import "testing"

func TestHMACMD5PatchVerify(t *testing.T) {
	h := &LANHello{
		Level:       Level1,
		SourceID:    SystemID{0, 0, 0, 0, 0, 1},
		HoldingTime: 30,
		TLVs: []TLV{
			&AreaAddressesTLV{Addresses: []AreaAddress{{0x49, 0x00, 0x01}}},
			AuthTLV(AuthMD5, 0),
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

func TestHMACSHAPatchVerify(t *testing.T) {
	for _, algo := range []AuthAlgorithm{AuthSHA1, AuthSHA256, AuthSHA384, AuthSHA512} {
		h := &LANHello{
			Level: Level1, SourceID: SystemID{0, 0, 0, 0, 0, 1}, HoldingTime: 30,
			TLVs: []TLV{
				&AreaAddressesTLV{Addresses: []AreaAddress{{0x49, 0x00, 0x01}}},
				AuthTLV(algo, 42),
			},
		}
		raw, err := h.Serialize()
		if err != nil {
			t.Fatalf("algo %d: Serialize: %v", algo, err)
		}
		off := HeaderLen(h.PDUType())
		key := []byte("sharedkey")
		if err := PatchAuth(raw, off, algo, 42, key, false); err != nil {
			t.Fatalf("algo %d: PatchAuth: %v", algo, err)
		}
		if !VerifyAuth(raw, off, algo, 42, key, false) {
			t.Errorf("algo %d: verify failed for the correct key/keyID", algo)
		}
		if VerifyAuth(raw, off, algo, 42, []byte("wrong"), false) {
			t.Errorf("algo %d: verify passed for the wrong key", algo)
		}
		if VerifyAuth(raw, off, algo, 99, key, false) {
			t.Errorf("algo %d: verify passed for the wrong key ID", algo)
		}
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
			AuthTLV(AuthMD5, 0),
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
		TLVs: []TLV{AuthTLV(AuthMD5, 0)},
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

// FuzzVerifyAuth exercises the receive-side authentication parser over hostile
// bytes. VerifyAuth is a second parser over untrusted input (it locates and
// hashes the Authentication TLV), so it must never panic regardless of content.
// Offsets are kept in range because callers always pass a valid header length.
func FuzzVerifyAuth(f *testing.F) {
	seed := func(h PDU, algo AuthAlgorithm, keyID uint16, isLSP bool) {
		raw, err := h.Serialize()
		if err != nil {
			return
		}
		off := HeaderLen(h.PDUType())
		_ = PatchAuth(raw, off, algo, keyID, []byte("seed-key"), isLSP)
		f.Add(raw, off, keyID, isLSP)
	}
	seed(&LANHello{Level: Level1, SourceID: SystemID{0, 0, 0, 0, 0, 1}, HoldingTime: 30, TLVs: []TLV{AuthTLV(AuthMD5, 0)}}, AuthMD5, 0, false)
	seed(&LANHello{Level: Level2, SourceID: SystemID{0, 0, 0, 0, 0, 2}, HoldingTime: 30, TLVs: []TLV{AuthTLV(AuthSHA256, 7)}}, AuthSHA256, 7, false)
	seed(&LSP{Level: Level2, LSPID: LSPID{0, 0, 0, 0, 0, 1, 0, 0}, SequenceNumber: 1, ISType: 2, TLVs: []TLV{AuthTLV(AuthMD5, 0)}}, AuthMD5, 0, true)

	algos := []AuthAlgorithm{AuthMD5, AuthSHA1, AuthSHA256, AuthSHA384, AuthSHA512}
	f.Fuzz(func(t *testing.T, pdu []byte, off int, keyID uint16, isLSP bool) {
		if off < 0 || off > len(pdu) {
			return // callers always pass an in-range header offset
		}
		for _, algo := range algos {
			_ = VerifyAuth(pdu, off, algo, keyID, []byte("k"), isLSP)
		}
	})
}
