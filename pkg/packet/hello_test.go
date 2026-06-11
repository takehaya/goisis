package packet

import (
	"errors"
	"testing"
)

// lanHelloWire is a handcrafted L1 LAN Hello: circuit type L1/L2, source
// 0000.0000.0001, holding time 30, priority 64, LAN ID 0000.0000.0002.01,
// with an Area Addresses TLV (49.0001) and a Protocols Supported TLV left
// unknown to the framework test (uses raw type 129 with NLPIDs 0xcc 0x8e).
const lanHelloHex = `
	83 1b 01 00 0f 01 00 00
	03
	00 00 00 00 00 01
	00 1e
	00 25
	40
	00 00 00 00 00 02 01
	01 04 03 49 00 01
	81 02 cc 8e
`

func TestLANHelloDecode(t *testing.T) {
	pdu := checkPDURoundtrip(t, mustHex(t, lanHelloHex))
	h, ok := pdu.(*LANHello)
	if !ok {
		t.Fatalf("got %T, want *LANHello", pdu)
	}
	if h.Level != Level1 {
		t.Errorf("Level = %v, want L1", h.Level)
	}
	if h.CircuitType != CircuitTypeLevel12 {
		t.Errorf("CircuitType = %d, want %d", h.CircuitType, CircuitTypeLevel12)
	}
	if got, want := h.SourceID.String(), "0000.0000.0001"; got != want {
		t.Errorf("SourceID = %q, want %q", got, want)
	}
	if h.HoldingTime != 30 {
		t.Errorf("HoldingTime = %d, want 30", h.HoldingTime)
	}
	if h.Priority != 64 {
		t.Errorf("Priority = %d, want 64", h.Priority)
	}
	if got, want := h.LANID.String(), "0000.0000.0002.01"; got != want {
		t.Errorf("LANID = %q, want %q", got, want)
	}
	if len(h.TLVs) != 2 {
		t.Fatalf("got %d TLVs, want 2", len(h.TLVs))
	}
}

func TestLANHelloIgnoresEthernetPadding(t *testing.T) {
	wire := mustHex(t, lanHelloHex)
	padded := append(append([]byte{}, wire...), make([]byte, 17)...)
	pdu, err := DecodePDU(padded)
	if err != nil {
		t.Fatalf("DecodePDU with trailing padding: %v", err)
	}
	out, err := pdu.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(out) != len(wire) {
		t.Errorf("serialized length = %d, want %d", len(out), len(wire))
	}
}

func TestP2PHelloRoundtrip(t *testing.T) {
	in := &P2PHello{
		CircuitType:    CircuitTypeLevel2,
		SourceID:       SystemID{0, 0, 0, 0, 0, 7},
		HoldingTime:    30,
		LocalCircuitID: 0x05,
		TLVs: []TLV{
			&AreaAddressesTLV{Addresses: []AreaAddress{{0x49, 0x00, 0x01}}},
		},
	}
	wire, err := in.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	pdu := checkPDURoundtrip(t, wire)
	out, ok := pdu.(*P2PHello)
	if !ok {
		t.Fatalf("got %T, want *P2PHello", pdu)
	}
	if out.LocalCircuitID != 0x05 || out.HoldingTime != 30 || out.CircuitType != CircuitTypeLevel2 {
		t.Errorf("decoded fields mismatch: %+v", out)
	}
}

func TestDecodePDUErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want error
	}{
		{"empty", "", ErrTruncated},
		{"bad discriminator", "84 1b 01 00 0f 01 00 00", errBadDiscriminator},
		{"bad version", "83 1b 02 00 0f 01 00 00", errBadVersion},
		{"bad id length", "83 1b 01 05 0f 01 00 00", errBadIDLength},
		{"unknown pdu type", "83 08 01 00 1f 01 00 00", ErrUnknownPDUType},
		{"bad length indicator", "83 10 01 00 0f 01 00 00", errBadFixedHeader},
		{
			"pdu length beyond buffer",
			"83 1b 01 00 0f 01 00 00 03 000000000001 001e 0030 40 00000000000201",
			ErrTruncated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodePDU(mustHex(t, tc.wire))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
