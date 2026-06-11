// Command fixturegen extracts IS-IS PDUs from a libpcap capture and writes
// one golden fixture per distinct PDU type to an output directory. It is the
// documented provenance of pkg/packet/testdata/*.bin.
//
// Usage:
//
//	go run ./test/fixturegen -out pkg/packet/testdata cap_broadcast.pcap cap_p2p.pcap
//
// IS-IS travels in 802.3 frames with an LLC header (DSAP=SSAP=0xFE, control
// 0x03) and no EtherType, so this tool finds frames whose length field marks
// them as 802.3 and whose LLC header is 0xFEFE03, then carves out the PDU.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", ".", "output directory for fixtures")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: fixturegen -out DIR pcap...")
		os.Exit(2)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}

	// Keep the largest PDU per fixture key, for determinism and richness.
	// Hellos/CSNPs/PSNPs key on type alone; LSPs key on (type, LSP ID) so
	// distinct LSPs (per-router fragment-0 and the DIS pseudonode LSP, which
	// carry different TLV sets) are all captured.
	seen := map[string][]byte{}
	for _, path := range flag.Args() {
		pkts, err := readPcap(path)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", path, err))
		}
		for _, frame := range pkts {
			pdu, ok := isisPDU(frame)
			if !ok {
				continue
			}
			key := fixtureKey(pdu)
			if cur, dup := seen[key]; !dup || len(pdu) > len(cur) {
				seen[key] = pdu
			}
		}
	}

	if len(seen) == 0 {
		fatal(fmt.Errorf("no IS-IS PDUs found in %v", flag.Args()))
	}
	for key, pdu := range seen {
		name := "frr_pdu_" + key + ".bin"
		if err := os.WriteFile(filepath.Join(*out, name), pdu, 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s (%d bytes, PDU type %d)\n", name, len(pdu), pdu[4]&0x1f)
	}
}

// fixtureKey derives a stable fixture name for a PDU. The leading digits are
// always the PDU type so the golden test can recover the expected type.
func fixtureKey(pdu []byte) string {
	t := pdu[4] & 0x1f
	switch t {
	case 18, 20: // L1/L2 LSP: distinguish by LSP ID (PDU offset 12..19)
		var id string
		if len(pdu) >= 20 {
			id = fmt.Sprintf("%x", pdu[12:20])
		}
		// Pseudonode LSPs (non-zero pseudonode octet) get a clear label.
		kind := "frag0"
		if len(pdu) >= 19 && pdu[18] != 0 {
			kind = "pnode"
		}
		return fmt.Sprintf("%02d_%s_%s", t, kind, id)
	default:
		return fmt.Sprintf("%02d", t)
	}
}

// isisPDU returns the IS-IS PDU carried in an Ethernet frame, if any. The
// frame layout is: dst(6) src(6) length(2) LLC(3: FE FE 03) PDU...
func isisPDU(frame []byte) ([]byte, bool) {
	if len(frame) < 17 {
		return nil, false
	}
	etherLen := int(binary.BigEndian.Uint16(frame[12:14]))
	if etherLen >= 0x0600 { // an EtherType, not an 802.3 length
		return nil, false
	}
	if frame[14] != 0xfe || frame[15] != 0xfe || frame[16] != 0x03 {
		return nil, false
	}
	// etherLen counts the LLC header (3) plus the PDU.
	end := 14 + etherLen
	if end > len(frame) || etherLen < 3 {
		return nil, false
	}
	pdu := frame[17:end]
	if len(pdu) < 8 || pdu[0] != 0x83 {
		return nil, false
	}
	return pdu, true
}

// readPcap reads a classic libpcap file and returns the packet frames. Only
// link type 1 (Ethernet) is supported.
func readPcap(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 24 {
		return nil, fmt.Errorf("short pcap header")
	}
	magic := binary.LittleEndian.Uint32(b[0:4])
	var bo binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d: // microsecond / nanosecond, little-endian
		bo = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1: // big-endian variants
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("not a pcap file (magic %08x)", magic)
	}
	linkType := bo.Uint32(b[20:24])
	if linkType != 1 {
		return nil, fmt.Errorf("unsupported link type %d (want Ethernet)", linkType)
	}

	var frames [][]byte
	off := 24
	for off+16 <= len(b) {
		inclLen := int(bo.Uint32(b[off+8 : off+12]))
		off += 16
		if inclLen < 0 || off+inclLen > len(b) {
			return nil, fmt.Errorf("truncated packet record")
		}
		frame := make([]byte, inclLen)
		copy(frame, b[off:off+inclLen])
		frames = append(frames, frame)
		off += inclLen
	}
	return frames, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fixturegen:", err)
	os.Exit(1)
}
