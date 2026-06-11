package packet

import (
	"testing"
)

func TestISNeighborsRoundtrip(t *testing.T) {
	tlv := &ISNeighborsTLV{Neighbors: []SNPA{
		{0x00, 0x1b, 0x21, 0x00, 0x00, 0x01},
		{0x00, 0x1b, 0x21, 0x00, 0x00, 0x02},
	}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*ISNeighborsTLV)
	if len(decoded.Neighbors) != 2 {
		t.Fatalf("got %d neighbors, want 2", len(decoded.Neighbors))
	}
}

func TestPaddingRoundtrip(t *testing.T) {
	for _, n := range []int{0, 1, 255} {
		tlv := &PaddingTLV{Length: n}
		wire, err := tlv.Serialize()
		if err != nil {
			t.Fatalf("Serialize(%d): %v", n, err)
		}
		decoded := checkTLVRoundtrip(t, wire)[0].(*PaddingTLV)
		if decoded.Length != n {
			t.Errorf("Length = %d, want %d", decoded.Length, n)
		}
	}
	if _, err := (&PaddingTLV{Length: 256}).Serialize(); err == nil {
		t.Error("expected error for padding length 256")
	}
}

func TestAuthenticationRoundtrip(t *testing.T) {
	tlv := &AuthenticationTLV{AuthType: AuthTypeCleartext, Value: []byte("secret")}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*AuthenticationTLV)
	if decoded.AuthType != AuthTypeCleartext || string(decoded.Value) != "secret" {
		t.Errorf("auth mismatch: %+v", decoded)
	}
}

func TestProtocolsSupportedRoundtrip(t *testing.T) {
	tlv := &ProtocolsSupportedTLV{NLPIDs: []byte{NLPIDIPv4, NLPIDIPv6}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	checkTLVRoundtrip(t, wire)
}

func TestDynamicHostnameRoundtrip(t *testing.T) {
	tlv := &DynamicHostnameTLV{Hostname: "router-1.example"}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*DynamicHostnameTLV)
	if decoded.Hostname != "router-1.example" {
		t.Errorf("Hostname = %q", decoded.Hostname)
	}
	if _, err := (&DynamicHostnameTLV{}).Serialize(); err == nil {
		t.Error("expected error for empty hostname")
	}
}

func TestExtendedISReachabilityRoundtrip(t *testing.T) {
	tlv := &ExtendedISReachabilityTLV{Neighbors: []ExtendedISReachEntry{
		{NeighborID: NodeID{0, 0, 0, 0, 0, 2, 0}, Metric: 10},
		{
			NeighborID: NodeID{0, 0, 0, 0, 0, 3, 1},
			Metric:     0xffffff,
			SubTLVs:    []SubTLV{&UnknownSubTLV{SubTLVType: 6, Value: []byte{192, 0, 2, 1}}},
		},
	}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedISReachabilityTLV)
	if len(decoded.Neighbors) != 2 {
		t.Fatalf("got %d neighbors, want 2", len(decoded.Neighbors))
	}
	if decoded.Neighbors[1].Metric != 0xffffff {
		t.Errorf("metric = %d, want 0xffffff", decoded.Neighbors[1].Metric)
	}
	if len(decoded.Neighbors[1].SubTLVs) != 1 {
		t.Errorf("sub-TLVs lost: %+v", decoded.Neighbors[1].SubTLVs)
	}
}

func TestExtendedISReachabilityMetricTooLarge(t *testing.T) {
	tlv := &ExtendedISReachabilityTLV{Neighbors: []ExtendedISReachEntry{
		{NeighborID: NodeID{0, 0, 0, 0, 0, 2, 0}, Metric: 0x1000000},
	}}
	if _, err := tlv.Serialize(); err == nil {
		t.Error("expected error for metric exceeding 24 bits")
	}
}
