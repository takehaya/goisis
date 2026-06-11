// Package packet implements encoding and decoding of IS-IS PDUs and TLVs
// (ISO 10589, RFC 1195, and modern extensions).
//
// # Decode policy
//
// DecodePDU is strict about framing: the common header, the PDU-specific
// fixed header, and the PDU length field must all be consistent, and a PDU
// carrying a structurally invalid known TLV fails to decode as a whole —
// callers drop (and should count) such PDUs. TLV types this package does
// not implement are preserved opaquely as UnknownTLV and survive
// re-serialization byte for byte. Narrow-metric TLVs (2, 128, 130) are
// deliberately left unimplemented: goisis parses them opaquely and never
// originates them (wide metrics only).
//
// Serialization is canonical: PDU length and checksum fields are computed
// by Serialize, and reserved fields are emitted as zero.
package packet

import (
	"encoding/binary"
	"fmt"
)

// Architectural constants (ISO 10589).
const (
	// ReceiveLSPBufferSize is the architectural maximum LSP size every IS
	// must be able to receive; goisis never originates PDUs larger than
	// this either.
	ReceiveLSPBufferSize = 1492

	idrpDiscriminator = 0x83 // NLPID assigned to IS-IS
	protocolVersion   = 1
	systemIDLen       = 6

	commonHeaderLen = 8
)

// PDUType identifies an IS-IS PDU (5-bit field in the common header).
type PDUType uint8

// PDU type codes (ISO 10589).
const (
	PDUTypeL1LANHello PDUType = 15
	PDUTypeL2LANHello PDUType = 16
	PDUTypeP2PHello   PDUType = 17
	PDUTypeL1LSP      PDUType = 18
	PDUTypeL2LSP      PDUType = 20
	PDUTypeL1CSNP     PDUType = 24
	PDUTypeL2CSNP     PDUType = 25
	PDUTypeL1PSNP     PDUType = 26
	PDUTypeL2PSNP     PDUType = 27
)

// Level is an IS-IS level.
type Level uint8

// IS-IS levels.
const (
	Level1 Level = 1
	Level2 Level = 2
)

func (l Level) String() string {
	switch l {
	case Level1:
		return "L1"
	case Level2:
		return "L2"
	default:
		return fmt.Sprintf("Level(%d)", uint8(l))
	}
}

// CircuitType is the circuit type field carried in hello PDUs (low 2 bits).
type CircuitType uint8

// Circuit types.
const (
	CircuitTypeLevel1  CircuitType = 1
	CircuitTypeLevel2  CircuitType = 2
	CircuitTypeLevel12 CircuitType = 3
)

// SystemID is a 6-octet IS-IS system identifier.
type SystemID [6]byte

func (s SystemID) String() string {
	return fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x", s[0], s[1], s[2], s[3], s[4], s[5])
}

// NodeID identifies a node in the topology: a system ID plus a pseudonode
// octet (zero for real systems). It is the "LAN ID" of LAN hellos and the
// source ID of SNPs.
type NodeID [7]byte

// SystemID returns the system ID part.
func (n NodeID) SystemID() SystemID { return SystemID(n[:6]) }

// PseudonodeID returns the pseudonode octet (zero for a real system).
func (n NodeID) PseudonodeID() byte { return n[6] }

func (n NodeID) String() string {
	return fmt.Sprintf("%s.%02x", n.SystemID(), n[6])
}

// LSPID identifies an LSP: node ID plus a fragment number.
type LSPID [8]byte

// NodeID returns the originating node (system ID + pseudonode octet).
func (l LSPID) NodeID() NodeID { return NodeID(l[:7]) }

// FragmentID returns the LSP fragment number.
func (l LSPID) FragmentID() byte { return l[7] }

func (l LSPID) String() string {
	return fmt.Sprintf("%s-%02x", l.NodeID(), l[7])
}

// PDU is a decoded IS-IS PDU.
type PDU interface {
	// PDUType returns the PDU type code.
	PDUType() PDUType
	// Serialize renders the complete PDU including the common header.
	Serialize() ([]byte, error)
}

// commonHeader is the fixed 8-octet header shared by all PDUs.
type commonHeader struct {
	LengthIndicator  uint8
	PDUType          PDUType
	MaxAreaAddresses uint8
}

func decodeCommonHeader(b []byte) (commonHeader, error) {
	var h commonHeader
	if len(b) < commonHeaderLen {
		return h, fmt.Errorf("common header: %w", ErrTruncated)
	}
	if b[0] != idrpDiscriminator {
		return h, fmt.Errorf("%w: 0x%02x", errBadDiscriminator, b[0])
	}
	if b[2] != protocolVersion {
		return h, fmt.Errorf("%w: version/protocol ID extension %d", errBadVersion, b[2])
	}
	if b[3] != 0 && b[3] != systemIDLen {
		return h, fmt.Errorf("%w: %d", errBadIDLength, b[3])
	}
	if b[5] != protocolVersion {
		return h, fmt.Errorf("%w: version %d", errBadVersion, b[5])
	}
	h.LengthIndicator = b[1]
	h.PDUType = PDUType(b[4] & 0x1f)
	h.MaxAreaAddresses = b[7]
	return h, nil
}

// putCommonHeader writes the canonical common header (ID length 0 meaning 6,
// maximum area addresses 0 meaning 3) into b[:8].
func putCommonHeader(b []byte, t PDUType, lengthIndicator uint8) {
	b[0] = idrpDiscriminator
	b[1] = lengthIndicator
	b[2] = protocolVersion
	b[3] = 0 // ID length: 6 octets
	b[4] = byte(t)
	b[5] = protocolVersion
	b[6] = 0 // reserved
	b[7] = 0 // maximum area addresses: 3
}

type pduDecoder func(h commonHeader, b []byte) (PDU, error)

var pduDecoders = map[PDUType]pduDecoder{}

// registerPDUDecoder registers the decoder for a PDU type. It is meant to be
// called from init functions and panics on duplicate registration.
func registerPDUDecoder(t PDUType, dec pduDecoder) {
	if _, dup := pduDecoders[t]; dup {
		panic(fmt.Sprintf("duplicate PDU decoder for type %d", t))
	}
	pduDecoders[t] = dec
}

// DecodePDU decodes one IS-IS PDU. b must start at the common header (i.e.
// after any data-link framing); trailing bytes beyond the PDU length field
// (such as Ethernet padding) are ignored.
func DecodePDU(b []byte) (PDU, error) {
	h, err := decodeCommonHeader(b)
	if err != nil {
		return nil, err
	}
	dec, ok := pduDecoders[h.PDUType]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownPDUType, h.PDUType)
	}
	pdu, err := dec(h, b)
	if err != nil {
		return nil, fmt.Errorf("%v PDU: %w", h.PDUType, err)
	}
	return pdu, nil
}

// checkFixedHeader validates the length indicator and reads the PDU length
// field at pduLenOff, returning the PDU trimmed to its declared length.
// minLen is the length of common plus PDU-specific fixed header.
func checkFixedHeader(h commonHeader, b []byte, minLen, pduLenOff int) ([]byte, error) {
	if int(h.LengthIndicator) != minLen {
		return nil, fmt.Errorf("%w: length indicator %d, want %d", errBadFixedHeader, h.LengthIndicator, minLen)
	}
	if len(b) < minLen {
		return nil, fmt.Errorf("fixed header: %w", ErrTruncated)
	}
	pduLen := int(binary.BigEndian.Uint16(b[pduLenOff:]))
	if pduLen < minLen {
		return nil, fmt.Errorf("%w: PDU length %d shorter than headers (%d)", errBadFixedHeader, pduLen, minLen)
	}
	if pduLen > len(b) {
		return nil, fmt.Errorf("%w: PDU length %d exceeds buffer (%d)", ErrTruncated, pduLen, len(b))
	}
	return b[:pduLen], nil
}

func (t PDUType) String() string {
	switch t {
	case PDUTypeL1LANHello:
		return "L1 LAN Hello"
	case PDUTypeL2LANHello:
		return "L2 LAN Hello"
	case PDUTypeP2PHello:
		return "P2P Hello"
	case PDUTypeL1LSP:
		return "L1 LSP"
	case PDUTypeL2LSP:
		return "L2 LSP"
	case PDUTypeL1CSNP:
		return "L1 CSNP"
	case PDUTypeL2CSNP:
		return "L2 CSNP"
	case PDUTypeL1PSNP:
		return "L1 PSNP"
	case PDUTypeL2PSNP:
		return "L2 PSNP"
	default:
		return fmt.Sprintf("PDUType(%d)", uint8(t))
	}
}
