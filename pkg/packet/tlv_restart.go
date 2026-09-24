package packet

import (
	"encoding/binary"
	"fmt"
)

// Restart TLV flag bits (RFC 5306 §3.2). The diagram numbers bits from the
// most significant, so RR is the least significant bit of the octet.
const (
	restartFlagRR = 0x01 // Restart Request
	restartFlagRA = 0x02 // Restart Acknowledgement
	restartFlagSA = 0x04 // Suppress adjacency advertisement
)

// RestartTLV is the Restart TLV (type 211, RFC 5306 §3.2), carried in every
// IIH sent by a router that implements restart signaling -- its presence with
// every flag clear is the capability advertisement.
//
// It appears in three valid lengths: the flags alone (1 octet), the flags plus
// the Remaining Time (3 octets), or the full form ending in the System ID the
// acknowledgement is for (3 + ID Length). The trailing fields accompany an RA;
// RFC 5306 §3.2 notes that implementations predating the System ID field omit
// it, and that a LAN receiver reads such an RA as directed at itself.
type RestartTLV struct {
	RestartRequest    bool // RR
	RestartAck        bool // RA
	SuppressAdjacency bool // SA

	// HasRemaining reports that the Remaining Time field is present.
	HasRemaining bool
	// RemainingTime is the holding time left on the acknowledged adjacency,
	// in seconds.
	RemainingTime uint16

	// HasNeighbor reports that the Restarting Neighbor System ID is present.
	HasNeighbor      bool
	NeighborSystemID SystemID
}

// Type implements TLV.
func (t *RestartTLV) Type() TLVType { return TLVTypeRestart }

// Serialize implements TLV.
func (t *RestartTLV) Serialize() ([]byte, error) {
	if t.HasNeighbor && !t.HasRemaining {
		return nil, fmt.Errorf("%w: restart neighbor System ID without a remaining time", errBadTLV)
	}
	var flags byte
	if t.RestartRequest {
		flags |= restartFlagRR
	}
	if t.RestartAck {
		flags |= restartFlagRA
	}
	if t.SuppressAdjacency {
		flags |= restartFlagSA
	}
	value := []byte{flags}
	if t.HasRemaining {
		value = binary.BigEndian.AppendUint16(value, t.RemainingTime)
	}
	if t.HasNeighbor {
		value = append(value, t.NeighborSystemID[:]...)
	}
	return encodeTLV(TLVTypeRestart, value)
}

func decodeRestartTLV(value []byte) (TLV, error) {
	switch len(value) {
	case 1, 3, 3 + len(SystemID{}):
	default:
		return nil, fmt.Errorf("%w: restart length %d (want 1, 3, or %d)",
			errBadTLV, len(value), 3+len(SystemID{}))
	}
	tlv := &RestartTLV{
		RestartRequest:    value[0]&restartFlagRR != 0,
		RestartAck:        value[0]&restartFlagRA != 0,
		SuppressAdjacency: value[0]&restartFlagSA != 0,
	}
	if len(value) >= 3 {
		tlv.HasRemaining = true
		tlv.RemainingTime = binary.BigEndian.Uint16(value[1:3])
	}
	if len(value) > 3 {
		tlv.HasNeighbor = true
		tlv.NeighborSystemID = SystemID(value[3:])
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeRestart, decodeRestartTLV)
}
