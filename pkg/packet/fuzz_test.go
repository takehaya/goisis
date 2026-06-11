package packet

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// addGoldenSeeds seeds a fuzz corpus with the FRR-captured PDUs.
func addGoldenSeeds(f *testing.F) {
	f.Helper()
	matches, _ := filepath.Glob("testdata/frr_pdu_*.bin")
	for _, path := range matches {
		if b, err := os.ReadFile(path); err == nil {
			f.Add(b)
		}
	}
}

// FuzzDecodePDU asserts that DecodePDU never panics and that a successfully
// decoded PDU re-serializes to a stable, self-decodable form (idempotent
// encode). Byte-exact round-tripping is intentionally NOT asserted here:
// the decoder normalizes reserved bits, so re-encoding arbitrary input may
// differ from the input — but encoding must reach a fixed point.
func FuzzDecodePDU(f *testing.F) {
	addGoldenSeeds(f)
	// A few hand-crafted seeds covering shapes the corpus may lack.
	f.Add([]byte{}) // empty
	f.Add([]byte{0x83, 0x1b, 0x01, 0x00, 0x0f, 0x01, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		pdu, err := DecodePDU(data)
		if err != nil {
			return // rejected input is fine; we only require no panic
		}
		enc1, err := pdu.Serialize()
		if err != nil {
			t.Fatalf("decoded PDU failed to re-serialize: %v", err)
		}
		pdu2, err := DecodePDU(enc1)
		if err != nil {
			t.Fatalf("re-serialized PDU failed to decode: %v\nbytes: %x", err, enc1)
		}
		enc2, err := pdu2.Serialize()
		if err != nil {
			t.Fatalf("second serialize failed: %v", err)
		}
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("encode not idempotent:\n first %x\nsecond %x", enc1, enc2)
		}
	})
}

// FuzzDecodeTLVs applies the same idempotence contract to the TLV-area
// decoder, exercising the per-type decoders directly without PDU framing.
func FuzzDecodeTLVs(f *testing.F) {
	f.Add(mustHexNoT("01 06 03 49 00 01 01 49")) // area addresses
	f.Add(mustHexNoT("81 02 cc 8e"))             // protocols supported
	f.Add(mustHexNoT("89 02 72 31"))             // dynamic hostname "r1"
	f.Add(mustHexNoT("87 06 00 00 00 0a 08 0a")) // extended IP reach 10/8

	f.Fuzz(func(t *testing.T, data []byte) {
		tlvs, err := decodeTLVs(data)
		if err != nil {
			return
		}
		enc1, err := serializeTLVs(tlvs)
		if err != nil {
			t.Fatalf("decoded TLVs failed to re-serialize: %v", err)
		}
		tlvs2, err := decodeTLVs(enc1)
		if err != nil {
			t.Fatalf("re-serialized TLVs failed to decode: %v\nbytes: %x", err, enc1)
		}
		enc2, err := serializeTLVs(tlvs2)
		if err != nil {
			t.Fatalf("second serialize failed: %v", err)
		}
		if !bytes.Equal(enc1, enc2) {
			t.Fatalf("encode not idempotent:\n first %x\nsecond %x", enc1, enc2)
		}
	})
}

// mustHexNoT decodes a spaced hex string for use outside a *testing.T.
func mustHexNoT(s string) []byte {
	var out []byte
	hi := -1
	for _, c := range s {
		if c == ' ' {
			continue
		}
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		default:
			panic("bad hex")
		}
		if hi < 0 {
			hi = v
		} else {
			out = append(out, byte(hi<<4|v))
			hi = -1
		}
	}
	return out
}
