package packet

import (
	"encoding/binary"
)

const (
	csnpHeaderLen = commonHeaderLen + 25 // 33
	psnpHeaderLen = commonHeaderLen + 9  // 17
)

// CSNP is a Complete Sequence Numbers PDU (types 24 and 25). It advertises
// the sender's view of an LSP-ID range (typically the full database) via
// LSP Entries TLVs (type 9).
type CSNP struct {
	Level    Level
	SourceID NodeID // system ID + circuit octet
	StartLSP LSPID
	EndLSP   LSPID
	TLVs     []TLV
}

// PDUType implements PDU.
func (p *CSNP) PDUType() PDUType {
	if p.Level == Level2 {
		return PDUTypeL2CSNP
	}
	return PDUTypeL1CSNP
}

// Serialize implements PDU.
func (p *CSNP) Serialize() ([]byte, error) {
	tlvs, err := serializeTLVs(p.TLVs)
	if err != nil {
		return nil, err
	}
	b := make([]byte, csnpHeaderLen, csnpHeaderLen+len(tlvs))
	putCommonHeader(b, p.PDUType(), csnpHeaderLen)
	copy(b[10:17], p.SourceID[:])
	copy(b[17:25], p.StartLSP[:])
	copy(b[25:33], p.EndLSP[:])
	b = append(b, tlvs...)
	binary.BigEndian.PutUint16(b[8:10], uint16(len(b))) //nolint:gosec // capped by TLV area size
	return b, nil
}

func decodeCSNP(level Level, h commonHeader, b []byte) (PDU, error) {
	b, err := checkFixedHeader(h, b, csnpHeaderLen, 8)
	if err != nil {
		return nil, err
	}
	p := &CSNP{
		Level:    level,
		SourceID: NodeID(b[10:17]),
		StartLSP: LSPID(b[17:25]),
		EndLSP:   LSPID(b[25:33]),
	}
	if p.TLVs, err = decodeTLVs(b[csnpHeaderLen:]); err != nil {
		return nil, err
	}
	return p, nil
}

// PSNP is a Partial Sequence Numbers PDU (types 26 and 27): a request for
// (on a LAN) or acknowledgement of (on P2P) specific LSPs, carried in LSP
// Entries TLVs (type 9).
type PSNP struct {
	Level    Level
	SourceID NodeID
	TLVs     []TLV
}

// PDUType implements PDU.
func (p *PSNP) PDUType() PDUType {
	if p.Level == Level2 {
		return PDUTypeL2PSNP
	}
	return PDUTypeL1PSNP
}

// Serialize implements PDU.
func (p *PSNP) Serialize() ([]byte, error) {
	tlvs, err := serializeTLVs(p.TLVs)
	if err != nil {
		return nil, err
	}
	b := make([]byte, psnpHeaderLen, psnpHeaderLen+len(tlvs))
	putCommonHeader(b, p.PDUType(), psnpHeaderLen)
	copy(b[10:17], p.SourceID[:])
	b = append(b, tlvs...)
	binary.BigEndian.PutUint16(b[8:10], uint16(len(b))) //nolint:gosec // capped by TLV area size
	return b, nil
}

func decodePSNP(level Level, h commonHeader, b []byte) (PDU, error) {
	b, err := checkFixedHeader(h, b, psnpHeaderLen, 8)
	if err != nil {
		return nil, err
	}
	p := &PSNP{
		Level:    level,
		SourceID: NodeID(b[10:17]),
	}
	if p.TLVs, err = decodeTLVs(b[psnpHeaderLen:]); err != nil {
		return nil, err
	}
	return p, nil
}

func init() {
	registerPDUDecoder(PDUTypeL1CSNP, func(h commonHeader, b []byte) (PDU, error) {
		return decodeCSNP(Level1, h, b)
	})
	registerPDUDecoder(PDUTypeL2CSNP, func(h commonHeader, b []byte) (PDU, error) {
		return decodeCSNP(Level2, h, b)
	})
	registerPDUDecoder(PDUTypeL1PSNP, func(h commonHeader, b []byte) (PDU, error) {
		return decodePSNP(Level1, h, b)
	})
	registerPDUDecoder(PDUTypeL2PSNP, func(h commonHeader, b []byte) (PDU, error) {
		return decodePSNP(Level2, h, b)
	})
}
