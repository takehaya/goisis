package packet

import "testing"

// TestRestartTLVRoundTripsItsThreeLegalLengths guarantees that the three
// shapes RFC 5306 §3.2 allows -- flags alone, flags plus Remaining Time, and
// the full form ending in a System ID -- all decode and re-serialize byte for
// byte. A fixed-length check here would fail decodeTLVs, and with it every
// hello from a restart-capable neighbor.
func TestRestartTLVRoundTripsItsThreeLegalLengths(t *testing.T) {
	cases := []*RestartTLV{
		{},
		{RestartRequest: true},
		{SuppressAdjacency: true},
		{RestartAck: true, HasRemaining: true, RemainingTime: 27},
		{
			RestartAck:       true,
			HasRemaining:     true,
			RemainingTime:    0xfffe,
			HasNeighbor:      true,
			NeighborSystemID: SystemID{0, 0, 0, 0, 0, 2},
		},
	}
	for i, in := range cases {
		wire, err := in.Serialize()
		if err != nil {
			t.Fatalf("case %d: Serialize: %v", i, err)
		}
		if want := 2 + restartValueLen(in); len(wire) != want {
			t.Errorf("case %d: encoded %d octets, want %d", i, len(wire), want)
		}
		decoded := checkTLVRoundtrip(t, wire)[0].(*RestartTLV)
		if *decoded != *in {
			t.Errorf("case %d: decoded %+v, want %+v", i, decoded, in)
		}
	}
}

func restartValueLen(t *RestartTLV) int {
	switch {
	case t.HasNeighbor:
		return 3 + len(SystemID{})
	case t.HasRemaining:
		return 3
	default:
		return 1
	}
}

// TestRestartTLVAcceptsAnAcknowledgementWithoutASystemID guarantees the
// backward-compatibility clause of RFC 5306 §3.2: an implementation predating
// that field sends an RA three octets long, and a LAN receiver reads it as
// directed at itself. Rejecting it would blackhole the neighbor's hellos.
func TestRestartTLVAcceptsAnAcknowledgementWithoutASystemID(t *testing.T) {
	// d3 03: type 211, three octets. Flags 02 = RA, remaining time 30s.
	tlv := checkTLVRoundtrip(t, mustHex(t, "d3 03 02 00 1e"))[0].(*RestartTLV)
	if !tlv.RestartAck || tlv.HasNeighbor {
		t.Fatalf("decoded %+v, want an RA with no Restarting Neighbor System ID", tlv)
	}
	if tlv.RemainingTime != 30 {
		t.Errorf("remaining time = %d, want 30", tlv.RemainingTime)
	}
}

// TestRestartTLVFlagBits pins the on-the-wire flag encoding of RFC 5306 §3.2:
// RR is the least significant bit, then RA, then SA. Getting these the other
// way round is invisible against another goisis and swaps a restart request
// for a suppression request against everyone else.
func TestRestartTLVFlagBits(t *testing.T) {
	for _, tc := range []struct {
		flags byte
		want  RestartTLV
	}{
		{0x01, RestartTLV{RestartRequest: true}},
		{0x02, RestartTLV{RestartAck: true}},
		{0x04, RestartTLV{SuppressAdjacency: true}},
	} {
		wire := []byte{byte(TLVTypeRestart), 1, tc.flags}
		got := checkTLVRoundtrip(t, wire)[0].(*RestartTLV)
		if *got != tc.want {
			t.Errorf("flags %#02x decoded to %+v, want %+v", tc.flags, got, tc.want)
		}
	}
}

// TestRestartTLVRejectsAnUnusableLength guarantees that a value whose length
// matches none of the three shapes is refused rather than half-read: two
// octets would leave the Remaining Time truncated, and eight would leave the
// System ID short.
func TestRestartTLVRejectsAnUnusableLength(t *testing.T) {
	for _, wire := range []string{"d3 02 00 00", "d3 08 00 00 1e 00 00 00 00 00"} {
		if _, err := decodeTLVs(mustHex(t, wire)); err == nil {
			t.Errorf("%s: expected a decode error", wire)
		}
	}
}

// TestRestartTLVRejectsASystemIDWithoutARemainingTime guarantees the encoder
// cannot emit a value no length rule describes; the decoder could not tell the
// two trailing fields apart.
func TestRestartTLVRejectsASystemIDWithoutARemainingTime(t *testing.T) {
	in := &RestartTLV{RestartAck: true, HasNeighbor: true}
	if _, err := in.Serialize(); err == nil {
		t.Error("expected an error: System ID present without a Remaining Time")
	}
}
