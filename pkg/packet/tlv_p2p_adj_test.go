package packet

import (
	"testing"
)

func TestP2PThreeWayAdjacencyLengths(t *testing.T) {
	cases := []*P2PThreeWayAdjacencyTLV{
		{State: P2PAdjStateDown},
		{State: P2PAdjStateInitializing, HasLocal: true, ExtLocalCircuitID: 0x01020304},
		{
			State:                     P2PAdjStateUp,
			HasLocal:                  true,
			ExtLocalCircuitID:         0x01020304,
			HasNeighbor:               true,
			NeighborSystemID:          SystemID{0, 0, 0, 0, 0, 2},
			NeighborExtLocalCircuitID: 0x05060708,
		},
	}
	for i, in := range cases {
		wire, err := in.Serialize()
		if err != nil {
			t.Fatalf("case %d: Serialize: %v", i, err)
		}
		decoded := checkTLVRoundtrip(t, wire)[0].(*P2PThreeWayAdjacencyTLV)
		if decoded.State != in.State || decoded.HasLocal != in.HasLocal || decoded.HasNeighbor != in.HasNeighbor {
			t.Errorf("case %d: mismatch: %+v", i, decoded)
		}
		if decoded.ExtLocalCircuitID != in.ExtLocalCircuitID || decoded.NeighborExtLocalCircuitID != in.NeighborExtLocalCircuitID {
			t.Errorf("case %d: circuit IDs lost: %+v", i, decoded)
		}
	}
}

func TestP2PThreeWayAdjacencyNeighborWithoutLocal(t *testing.T) {
	in := &P2PThreeWayAdjacencyTLV{State: P2PAdjStateUp, HasNeighbor: true}
	if _, err := in.Serialize(); err == nil {
		t.Error("expected error: neighbor present without local circuit ID")
	}
}

func TestP2PThreeWayAdjacencyBadLength(t *testing.T) {
	// Length 3 is not one of {1, 5, 15}.
	if _, err := decodeTLVs(mustHex(t, "f0 03 00 00 00")); err == nil {
		t.Error("expected error for P2P adjacency TLV length 3")
	}
}
