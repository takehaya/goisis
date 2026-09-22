package packet

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"
)

func TestSRv6EndXSIDRoundtrip(t *testing.T) {
	tlv := &ExtendedISReachabilityTLV{Neighbors: []ExtendedISReachEntry{{
		NeighborID: NodeID{0, 0, 0, 0, 0, 2, 0},
		Metric:     10,
		SubTLVs: []SubTLV{&SRv6EndXSIDSubTLV{
			Flags:     SRv6EndXFlagBackup,
			Algorithm: 128,
			Weight:    7,
			Behavior:  SRv6BehaviorEndX,
			SID:       netip.MustParseAddr("fc00:0:1:1::"),
			Structure: &SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16},
		}},
	}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedISReachabilityTLV)
	sub, ok := decoded.Neighbors[0].SubTLVs[0].(*SRv6EndXSIDSubTLV)
	if !ok {
		t.Fatalf("sub-TLV decoded as %T, want *SRv6EndXSIDSubTLV", decoded.Neighbors[0].SubTLVs[0])
	}
	if sub.Type() != 43 {
		t.Errorf("type = %d, want 43", sub.Type())
	}
	if sub.Flags != SRv6EndXFlagBackup || sub.Algorithm != 128 || sub.Weight != 7 ||
		sub.Behavior != SRv6BehaviorEndX || sub.SID != netip.MustParseAddr("fc00:0:1:1::") {
		t.Errorf("End.X SID mismatch: %+v", sub)
	}
	if s := sub.Structure; s == nil || s.LocatorBlock != 32 || s.LocatorNode != 16 || s.Function != 16 {
		t.Errorf("SID structure mismatch: %+v", s)
	}
}

func TestSRv6LANEndXSIDRoundtrip(t *testing.T) {
	neighbor := SystemID{0, 0, 0, 0, 0, 2}
	tlv := &ExtendedISReachabilityTLV{Neighbors: []ExtendedISReachEntry{{
		NeighborID: NodeID{0, 0, 0, 0, 0, 1, 1}, // the DIS pseudonode
		Metric:     10,
		SubTLVs: []SubTLV{&SRv6LANEndXSIDSubTLV{
			Neighbor: neighbor,
			SRv6EndXSIDSubTLV: SRv6EndXSIDSubTLV{
				Behavior:  SRv6BehaviorEndX,
				SID:       netip.MustParseAddr("fc00:0:1:2::"),
				Structure: &SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16},
			},
		}},
	}}}
	wire, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedISReachabilityTLV)
	sub, ok := decoded.Neighbors[0].SubTLVs[0].(*SRv6LANEndXSIDSubTLV)
	if !ok {
		t.Fatalf("sub-TLV decoded as %T, want *SRv6LANEndXSIDSubTLV", decoded.Neighbors[0].SubTLVs[0])
	}
	if sub.Type() != 44 {
		t.Errorf("type = %d, want 44", sub.Type())
	}
	if sub.Neighbor != neighbor {
		t.Errorf("neighbor = %s, want %s", sub.Neighbor, neighbor)
	}
	if sub.Behavior != SRv6BehaviorEndX || sub.SID != netip.MustParseAddr("fc00:0:1:2::") {
		t.Errorf("LAN End.X SID mismatch: %+v", sub)
	}
}

// TestSRv6EndXSIDUnknownSubSubTLVPreserved checks the opaque-preservation rule
// one level down: a sub-sub-TLV this package does not implement survives a
// decode/encode cycle byte-for-byte.
func TestSRv6EndXSIDUnknownSubSubTLVPreserved(t *testing.T) {
	for _, tc := range []struct {
		name string
		sub  SubTLV
	}{
		{"endx", &SRv6EndXSIDSubTLV{
			Behavior:  SRv6BehaviorEndX,
			SID:       netip.MustParseAddr("fc00:0:1:1::"),
			Structure: &SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16},
			Unknown:   []UnknownSubTLV{{SubTLVType: 200, Value: []byte{0xde, 0xad}}},
		}},
		{"lan", &SRv6LANEndXSIDSubTLV{
			Neighbor: SystemID{0, 0, 0, 0, 0, 2},
			SRv6EndXSIDSubTLV: SRv6EndXSIDSubTLV{
				Behavior: SRv6BehaviorEndX,
				SID:      netip.MustParseAddr("fc00:0:1:2::"),
				Unknown:  []UnknownSubTLV{{SubTLVType: 201, Value: []byte{1, 2, 3}}},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlv := &ExtendedISReachabilityTLV{Neighbors: []ExtendedISReachEntry{
				{NeighborID: NodeID{0, 0, 0, 0, 0, 2, 0}, Metric: 10, SubTLVs: []SubTLV{tc.sub}},
			}}
			wire, err := tlv.Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			decoded := checkTLVRoundtrip(t, wire)[0].(*ExtendedISReachabilityTLV)
			if !reflect.DeepEqual(decoded.Neighbors[0].SubTLVs[0], tc.sub) {
				t.Errorf("decoded = %+v, want %+v", decoded.Neighbors[0].SubTLVs[0], tc.sub)
			}
		})
	}
}

func TestSRv6EndXSIDTruncated(t *testing.T) {
	full := &SRv6EndXSIDSubTLV{
		Behavior:  SRv6BehaviorEndX,
		SID:       netip.MustParseAddr("fc00:0:1:1::"),
		Structure: &SIDStructure{LocatorBlock: 32, LocatorNode: 16, Function: 16},
	}
	body, err := full.body()
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	for _, tc := range []struct {
		name string
		dec  func([]byte) (SubTLV, error)
		v    []byte
	}{
		{"endx fixed part", decodeEndXSID, body[:srv6EndXSIDFixedLen-1]},
		{"endx sub-sub-TLV area", decodeEndXSID, body[:len(body)-1]},
		{"lan neighbor", decodeLANEndXSID, []byte{0, 0, 0}},
		{"lan fixed part", decodeLANEndXSID, append(make([]byte, 6), body[:srv6EndXSIDFixedLen-1]...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.dec(tc.v); !errors.Is(err, ErrTruncated) {
				t.Errorf("error = %v, want ErrTruncated", err)
			}
		})
	}
	// A sub-sub-TLV area that ends mid-header is malformed, not silently dropped.
	short := append(append([]byte(nil), body[:srv6EndXSIDFixedLen-1]...), 1, 0x01)
	if _, err := decodeEndXSID(short); !errors.Is(err, ErrTruncated) {
		t.Errorf("odd sub-sub-TLV area: error = %v, want ErrTruncated", err)
	}
}

// TestGoldenFRREndXSID pins the wire layout against a real FRR isisd LSP: FRR
// advertises the End.X SID for its p2p neighbor as sub-TLV 43 of TLV 22, with
// endpoint behavior End.X (5) and function 1 in the locator's function space.
func TestGoldenFRREndXSID(t *testing.T) {
	wire, err := os.ReadFile("testdata/frr_pdu_18_srv6.bin")
	if err != nil {
		t.Fatal(err)
	}
	lsp, err := DecodePDU(wire)
	if err != nil {
		t.Fatalf("DecodePDU: %v", err)
	}
	var sub *SRv6EndXSIDSubTLV
	for _, tlv := range lsp.(*LSP).TLVs {
		r, ok := tlv.(*ExtendedISReachabilityTLV)
		if !ok {
			continue
		}
		for _, n := range r.Neighbors {
			for _, st := range n.SubTLVs {
				if e, ok := st.(*SRv6EndXSIDSubTLV); ok {
					sub = e
				}
			}
		}
	}
	if sub == nil {
		t.Fatal("no SRv6 End.X SID sub-TLV in the FRR fixture")
	}
	if sub.Behavior != SRv6BehaviorEndX {
		t.Errorf("behavior = %d, want %d (End.X)", sub.Behavior, SRv6BehaviorEndX)
	}
	// The locator is fc00:0:1::/48 with a 16-bit function; FRR allocated
	// function 1 for the adjacency.
	if want := netip.MustParseAddr("fc00:0:1:1::"); sub.SID != want {
		t.Errorf("SID = %s, want %s", sub.SID, want)
	}
	if s := sub.Structure; s == nil || s.LocatorBlock != 32 || s.LocatorNode != 16 || s.Function != 16 {
		t.Errorf("SID structure = %+v, want {32 16 16 0}", s)
	}
}
