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
	// MT IPv6 reach (237), MT #2, 2001:db8::/64 — the MT ID field in front of
	// a TLV 236 entry list is the shape the RFC 5120 decoders add.
	f.Add(mustHexNoT("ed 10 00 02 00 00 00 0a 00 40 20 01 0d b8 00 00 00 00"))
	// The rest of RFC 5120: the other three MT TLVs, which the one seed above
	// does not reach. TLV 229 lists MT #0 and an MT #2 with the O and A bits,
	// TLV 222 is TLV 22's entry list under MT #2, TLV 235 is TLV 135's.
	f.Add(mustHexNoT("e5 04 00 00 c0 02"))
	f.Add(mustHexNoT("de 0d 00 02 00 00 00 00 00 02 00 00 00 0a 00"))
	f.Add(mustHexNoT("eb 09 00 03 00 00 00 05 10 0a 03"))
	// Restart TLV (211) at each of the three lengths RFC 5306 §3.2 defines:
	// the flags alone, the flags plus a Remaining Time, and the full form
	// ending in the acknowledged System ID.
	f.Add(mustHexNoT("d3 01 00"))
	f.Add(mustHexNoT("d3 03 01 00 1e"))
	f.Add(mustHexNoT("d3 09 06 00 1e 00 00 00 00 00 02"))
	// A TLV 22 whose two entries between them reach every accepting path of
	// the link-attribute decoders, in both of the contexts they are registered
	// in. The first entry nests an ASLA (sub-TLV 16, SABM naming Flex-Algo)
	// around an RFC 5305 admin group (3) and an RFC 7308 extended one (14);
	// the second carries an L-flag ASLA with empty bit masks and then the same
	// two code points as legacy sub-TLVs of the neighbor entry itself. A
	// campaign will not assemble this by mutation — four length prefixes nest
	// inside each other — and a seed that only hit the reject paths would now
	// prove less, since decodeSubTLVs keeps a refused value opaque.
	f.Add(mustHexNoT("16 3b" +
		" 00 00 00 00 00 02 00 00 00 0a 15" + // neighbor ..02, metric 10, 21 octets of sub-TLVs
		" 10 13 01 00 10 03 04 00 00 00 05 0e 08 00 00 00 05 80 00 00 00" + // ASLA{admin group, extended admin group}
		" 00 00 00 00 00 03 00 00 00 14 10" + // neighbor ..03, metric 20, 16 octets of sub-TLVs
		" 10 02 80 00 03 04 00 00 00 03 0e 04 00 00 00 03")) // ASLA(L-flag), then both legacy encodings
	// The same families on the other side of the line: one TLV 22 entry whose
	// three sub-TLVs are each refused — an admin group of 3 octets, an ASLA
	// wrapping an extended admin group of 6, and an ASLA with SABM length 9.
	// This is decodeSubTLV's fallback, which the accepting seeds above never
	// reach, and the round trip it must still hold to is the one that carries
	// a refused value out byte for byte.
	f.Add(mustHexNoT("16 21" +
		" 00 00 00 00 00 02 00 00 00 0a 16" + // neighbor ..02, metric 10, 22 octets of sub-TLVs
		" 03 03 00 00 05" + // administrative group, one octet short
		" 10 0b 01 00 10 0e 06 00 00 00 05 00 00" + // ASLA{extended admin group of 6 octets}
		" 10 02 09 00")) // ASLA whose SABM length is 9 (RFC 8919 4.2: ignore it)

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
