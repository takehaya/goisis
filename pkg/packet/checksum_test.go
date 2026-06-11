package packet

import (
	"encoding/binary"
	"testing"
)

func TestFletcherChecksumSelfConsistent(t *testing.T) {
	// An LSP-shaped buffer: data starts at the LSP ID field, checksum
	// field at offset 12.
	data := mustHex(t, `
		00 00 00 00 00 01 00 00
		00 00 00 01
		00 00
		03
		01 04 03 49 00 01
	`)
	const off = 12
	sum := fletcherChecksum(data, off)
	if sum == 0 {
		t.Fatal("checksum must never be zero")
	}
	binary.BigEndian.PutUint16(data[off:], sum)
	if !fletcherValid(data) {
		t.Fatalf("checksum %04x does not verify", sum)
	}
	// Any single-bit corruption must be detected.
	for i := range data {
		data[i] ^= 0x04
		if fletcherValid(data) {
			t.Fatalf("corruption at offset %d not detected", i)
		}
		data[i] ^= 0x04
	}
}

func TestFletcherChecksumPositions(t *testing.T) {
	// The checksum must verify regardless of where the checksum field
	// sits in the buffer.
	for off := 0; off < 30; off++ {
		data := make([]byte, 32)
		for i := range data {
			data[i] = byte(i * 7)
		}
		data[off], data[off+1] = 0, 0
		sum := fletcherChecksum(data, off)
		binary.BigEndian.PutUint16(data[off:], sum)
		if !fletcherValid(data) {
			t.Fatalf("offset %d: checksum %04x does not verify", off, sum)
		}
	}
}
