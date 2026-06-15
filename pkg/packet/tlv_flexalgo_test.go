package packet

import "testing"

func TestSRAlgorithmRoundtrip(t *testing.T) {
	tlv := &RouterCapabilityTLV{
		SubTLVs: []SubTLV{&SRAlgorithmSubTLV{Algorithms: []uint8{0, 128, 129}}},
	}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*RouterCapabilityTLV)
	if len(decoded.SubTLVs) != 1 {
		t.Fatalf("got %d sub-TLVs", len(decoded.SubTLVs))
	}
	sa, ok := decoded.SubTLVs[0].(*SRAlgorithmSubTLV)
	if !ok {
		t.Fatalf("sub-TLV not SR-Algorithm: %T", decoded.SubTLVs[0])
	}
	if len(sa.Algorithms) != 3 || sa.Algorithms[0] != 0 || sa.Algorithms[1] != 128 || sa.Algorithms[2] != 129 {
		t.Errorf("algorithms = %v", sa.Algorithms)
	}
}

func TestFlexAlgoDefinitionRoundtrip(t *testing.T) {
	tlv := &RouterCapabilityTLV{
		SubTLVs: []SubTLV{&FlexAlgoDefinitionSubTLV{
			FlexAlgo:   128,
			MetricType: FlexAlgoMetricIGP,
			CalcType:   0,
			Priority:   100,
		}},
	}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*RouterCapabilityTLV)
	fad, ok := decoded.SubTLVs[0].(*FlexAlgoDefinitionSubTLV)
	if !ok {
		t.Fatalf("sub-TLV not FAD: %T", decoded.SubTLVs[0])
	}
	if fad.FlexAlgo != 128 || fad.MetricType != FlexAlgoMetricIGP || fad.CalcType != 0 || fad.Priority != 100 {
		t.Errorf("FAD mismatch: %+v", fad)
	}
	if len(fad.SubSubTLVs) != 0 {
		t.Errorf("unexpected sub-sub-TLVs: %+v", fad.SubSubTLVs)
	}
}

func TestFlexAlgoDefinitionSubSubTLVOpaque(t *testing.T) {
	// Constraint sub-sub-TLVs (here: exclude admin group, type 1, with an
	// extended admin-group bitmask) must round-trip byte-exact even though the
	// IGP-only computation does not yet act on them.
	tlv := &RouterCapabilityTLV{
		SubTLVs: []SubTLV{&FlexAlgoDefinitionSubTLV{
			FlexAlgo:   129,
			MetricType: FlexAlgoMetricMinDelay,
			Priority:   200,
			SubSubTLVs: []FlexAlgoSubSubTLV{
				{SubSubTLVType: 1, Value: []byte{0x00, 0x00, 0x00, 0x05}}, // exclude AG
				{SubSubTLVType: 4, Value: []byte{0x80}},                   // definition flags (M-flag)
			},
		}},
	}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*RouterCapabilityTLV)
	fad := decoded.SubTLVs[0].(*FlexAlgoDefinitionSubTLV)
	if len(fad.SubSubTLVs) != 2 {
		t.Fatalf("got %d sub-sub-TLVs", len(fad.SubSubTLVs))
	}
	if fad.SubSubTLVs[0].SubSubTLVType != 1 || len(fad.SubSubTLVs[0].Value) != 4 {
		t.Errorf("exclude-AG sub-sub-TLV mismatch: %+v", fad.SubSubTLVs[0])
	}
	if fad.SubSubTLVs[1].SubSubTLVType != 4 || fad.SubSubTLVs[1].Value[0] != 0x80 {
		t.Errorf("flags sub-sub-TLV mismatch: %+v", fad.SubSubTLVs[1])
	}
}

func TestFlexAlgoDefinitionTruncated(t *testing.T) {
	// A FAD value shorter than the 4-octet fixed header must be rejected, not
	// panic.
	if _, err := decodeFlexAlgoDefinition([]byte{128, 0, 0}); err == nil {
		t.Error("expected error for truncated FAD")
	}
}
