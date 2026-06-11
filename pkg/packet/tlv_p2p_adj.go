package packet

import (
	"encoding/binary"
	"fmt"
)

// P2PAdjState is the adjacency state carried in the P2P Three-Way
// Adjacency TLV (RFC 5303).
type P2PAdjState uint8

// P2P adjacency three-way handshake states.
const (
	P2PAdjStateUp           P2PAdjState = 0
	P2PAdjStateInitializing P2PAdjState = 1
	P2PAdjStateDown         P2PAdjState = 2
)

// P2PThreeWayAdjacencyTLV is the P2P Three-Way Adjacency TLV (type 240, RFC
// 5303). It appears in three valid lengths: state only (1 octet), state +
// local circuit ID (5 octets), or the full form including the neighbor's
// identity (15 octets).
type P2PThreeWayAdjacencyTLV struct {
	State P2PAdjState

	// HasLocal indicates the Extended Local Circuit ID is present.
	HasLocal          bool
	ExtLocalCircuitID uint32

	// HasNeighbor indicates the neighbor identity is present (requires
	// HasLocal).
	HasNeighbor               bool
	NeighborSystemID          SystemID
	NeighborExtLocalCircuitID uint32
}

// Type implements TLV.
func (t *P2PThreeWayAdjacencyTLV) Type() TLVType { return TLVTypeP2PThreeWayAdjacency }

// Serialize implements TLV.
func (t *P2PThreeWayAdjacencyTLV) Serialize() ([]byte, error) {
	if t.HasNeighbor && !t.HasLocal {
		return nil, fmt.Errorf("%w: P2P adjacency neighbor present without local circuit ID", errBadTLV)
	}
	value := []byte{byte(t.State)}
	if t.HasLocal {
		value = binary.BigEndian.AppendUint32(value, t.ExtLocalCircuitID)
	}
	if t.HasNeighbor {
		value = append(value, t.NeighborSystemID[:]...)
		value = binary.BigEndian.AppendUint32(value, t.NeighborExtLocalCircuitID)
	}
	return encodeTLV(TLVTypeP2PThreeWayAdjacency, value)
}

func decodeP2PThreeWayAdjacencyTLV(value []byte) (TLV, error) {
	switch len(value) {
	case 1, 5, 15:
	default:
		return nil, fmt.Errorf("%w: P2P three-way adjacency length %d (want 1, 5, or 15)", errBadTLV, len(value))
	}
	tlv := &P2PThreeWayAdjacencyTLV{State: P2PAdjState(value[0])}
	if len(value) >= 5 {
		tlv.HasLocal = true
		tlv.ExtLocalCircuitID = binary.BigEndian.Uint32(value[1:5])
	}
	if len(value) == 15 {
		tlv.HasNeighbor = true
		tlv.NeighborSystemID = SystemID(value[5:11])
		tlv.NeighborExtLocalCircuitID = binary.BigEndian.Uint32(value[11:15])
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeP2PThreeWayAdjacency, decodeP2PThreeWayAdjacencyTLV)
}
