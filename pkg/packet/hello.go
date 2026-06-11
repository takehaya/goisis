package packet

import (
	"encoding/binary"
)

const (
	lanHelloHeaderLen = commonHeaderLen + 19 // 27
	p2pHelloHeaderLen = commonHeaderLen + 12 // 20
)

// LANHello is a Level 1 or Level 2 LAN IS-IS Hello PDU (types 15 and 16).
type LANHello struct {
	Level       Level
	CircuitType CircuitType
	SourceID    SystemID
	HoldingTime uint16
	Priority    uint8 // 0-127
	LANID       NodeID
	TLVs        []TLV
}

// PDUType implements PDU.
func (p *LANHello) PDUType() PDUType {
	if p.Level == Level2 {
		return PDUTypeL2LANHello
	}
	return PDUTypeL1LANHello
}

// Serialize implements PDU.
func (p *LANHello) Serialize() ([]byte, error) {
	tlvs, err := serializeTLVs(p.TLVs)
	if err != nil {
		return nil, err
	}
	b := make([]byte, lanHelloHeaderLen, lanHelloHeaderLen+len(tlvs))
	putCommonHeader(b, p.PDUType(), lanHelloHeaderLen)
	b[8] = byte(p.CircuitType & 0x03)
	copy(b[9:15], p.SourceID[:])
	binary.BigEndian.PutUint16(b[15:17], p.HoldingTime)
	b = append(b, tlvs...)
	binary.BigEndian.PutUint16(b[17:19], uint16(len(b))) //nolint:gosec // capped by TLV area size
	b[19] = p.Priority & 0x7f
	copy(b[20:27], p.LANID[:])
	return b, nil
}

func decodeLANHello(level Level, h commonHeader, b []byte) (PDU, error) {
	b, err := checkFixedHeader(h, b, lanHelloHeaderLen, 17)
	if err != nil {
		return nil, err
	}
	p := &LANHello{
		Level:       level,
		CircuitType: CircuitType(b[8] & 0x03),
		SourceID:    SystemID(b[9:15]),
		HoldingTime: binary.BigEndian.Uint16(b[15:17]),
		Priority:    b[19] & 0x7f,
		LANID:       NodeID(b[20:27]),
	}
	if p.TLVs, err = decodeTLVs(b[lanHelloHeaderLen:]); err != nil {
		return nil, err
	}
	return p, nil
}

// P2PHello is a point-to-point IS-IS Hello PDU (type 17).
type P2PHello struct {
	CircuitType    CircuitType
	SourceID       SystemID
	HoldingTime    uint16
	LocalCircuitID uint8
	TLVs           []TLV
}

// PDUType implements PDU.
func (p *P2PHello) PDUType() PDUType { return PDUTypeP2PHello }

// Serialize implements PDU.
func (p *P2PHello) Serialize() ([]byte, error) {
	tlvs, err := serializeTLVs(p.TLVs)
	if err != nil {
		return nil, err
	}
	b := make([]byte, p2pHelloHeaderLen, p2pHelloHeaderLen+len(tlvs))
	putCommonHeader(b, p.PDUType(), p2pHelloHeaderLen)
	b[8] = byte(p.CircuitType & 0x03)
	copy(b[9:15], p.SourceID[:])
	binary.BigEndian.PutUint16(b[15:17], p.HoldingTime)
	b = append(b, tlvs...)
	binary.BigEndian.PutUint16(b[17:19], uint16(len(b))) //nolint:gosec // capped by TLV area size
	b[19] = p.LocalCircuitID
	return b, nil
}

func decodeP2PHello(h commonHeader, b []byte) (PDU, error) {
	b, err := checkFixedHeader(h, b, p2pHelloHeaderLen, 17)
	if err != nil {
		return nil, err
	}
	p := &P2PHello{
		CircuitType:    CircuitType(b[8] & 0x03),
		SourceID:       SystemID(b[9:15]),
		HoldingTime:    binary.BigEndian.Uint16(b[15:17]),
		LocalCircuitID: b[19],
	}
	if p.TLVs, err = decodeTLVs(b[p2pHelloHeaderLen:]); err != nil {
		return nil, err
	}
	return p, nil
}

func init() {
	registerPDUDecoder(PDUTypeL1LANHello, func(h commonHeader, b []byte) (PDU, error) {
		return decodeLANHello(Level1, h, b)
	})
	registerPDUDecoder(PDUTypeL2LANHello, func(h commonHeader, b []byte) (PDU, error) {
		return decodeLANHello(Level2, h, b)
	})
	registerPDUDecoder(PDUTypeP2PHello, decodeP2PHello)
}
