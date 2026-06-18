package packet

import (
	"encoding/binary"
)

const lspHeaderLen = commonHeaderLen + 19 // 27

// LSP flag octet bits (ISO 10589 9.8, the octet at PDU offset 26).
const (
	lspFlagPartition  = 0x80 // P: partition repair supported
	lspFlagAttError   = 0x40 // ATT: error metric
	lspFlagAttExpense = 0x20 // ATT: expense metric
	lspFlagAttDelay   = 0x10 // ATT: delay metric
	lspFlagAttDefault = 0x08 // ATT: default metric
	lspFlagOverload   = 0x04 // OL: LSP database overload
	lspISTypeMask     = 0x03 // IS-Type: 1=L1, 3=L2
)

// LSP is a Link State PDU (types 18 and 20). The checksum field is computed
// by Serialize; ChecksumValid reports whether a decoded LSP's checksum
// verifies.
type LSP struct {
	Level          Level
	RemainingTime  uint16 // seconds
	LSPID          LSPID
	SequenceNumber uint32
	checksum       uint16 // as decoded; recomputed on Serialize
	Partition      bool
	AttError       bool
	AttExpense     bool
	AttDelay       bool
	AttDefault     bool
	Overload       bool
	ISType         uint8 // low 2 bits: 1=L1, 3=L2
	TLVs           []TLV
}

// PDUType implements PDU.
func (p *LSP) PDUType() PDUType {
	if p.Level == Level2 {
		return PDUTypeL2LSP
	}
	return PDUTypeL1LSP
}

// Checksum returns the checksum as decoded from the wire. It is only
// meaningful for a decoded LSP; Serialize always recomputes.
func (p *LSP) Checksum() uint16 { return p.checksum }

func (p *LSP) flagsOctet() byte {
	var f byte
	if p.Partition {
		f |= lspFlagPartition
	}
	if p.AttError {
		f |= lspFlagAttError
	}
	if p.AttExpense {
		f |= lspFlagAttExpense
	}
	if p.AttDelay {
		f |= lspFlagAttDelay
	}
	if p.AttDefault {
		f |= lspFlagAttDefault
	}
	if p.Overload {
		f |= lspFlagOverload
	}
	f |= p.ISType & lspISTypeMask
	return f
}

// Serialize implements PDU. The Fletcher checksum is computed over the LSP
// from the LSP ID field to the end (ISO 10589 7.3.11).
func (p *LSP) Serialize() ([]byte, error) {
	tlvs, err := serializeTLVs(p.TLVs)
	if err != nil {
		return nil, err
	}
	b := make([]byte, lspHeaderLen, lspHeaderLen+len(tlvs))
	putCommonHeader(b, p.PDUType(), lspHeaderLen)
	binary.BigEndian.PutUint16(b[10:12], p.RemainingTime)
	copy(b[12:20], p.LSPID[:])
	binary.BigEndian.PutUint32(b[20:24], p.SequenceNumber)
	// b[24:26] checksum: left zero until computed below.
	b[26] = p.flagsOctet()
	b = append(b, tlvs...)
	binary.BigEndian.PutUint16(b[8:10], uint16(len(b))) //nolint:gosec // capped by TLV area size

	// Checksum covers from the LSP ID (offset 12) onward; the field itself
	// (offset 24, i.e. relative offset 12) must be zero while computing.
	sum := fletcherChecksum(b[12:], 12)
	binary.BigEndian.PutUint16(b[24:26], sum)
	p.checksum = sum
	return b, nil
}

func decodeLSP(level Level, h commonHeader, b []byte) (PDU, error) {
	b, err := checkFixedHeader(h, b, lspHeaderLen)
	if err != nil {
		return nil, err
	}
	flags := b[26]
	p := &LSP{
		Level:          level,
		RemainingTime:  binary.BigEndian.Uint16(b[10:12]),
		LSPID:          LSPID(b[12:20]),
		SequenceNumber: binary.BigEndian.Uint32(b[20:24]),
		checksum:       binary.BigEndian.Uint16(b[24:26]),
		Partition:      flags&lspFlagPartition != 0,
		AttError:       flags&lspFlagAttError != 0,
		AttExpense:     flags&lspFlagAttExpense != 0,
		AttDelay:       flags&lspFlagAttDelay != 0,
		AttDefault:     flags&lspFlagAttDefault != 0,
		Overload:       flags&lspFlagOverload != 0,
		ISType:         flags & lspISTypeMask,
	}
	if p.TLVs, err = decodeTLVs(b[lspHeaderLen:]); err != nil {
		return nil, err
	}
	return p, nil
}

// LSPChecksumValidRaw reports whether a received LSP's Fletcher checksum
// verifies against its on-wire bytes. Unlike (*LSP).ChecksumValid — which
// re-serializes the decoded TLVs and so couples validity to byte-exact
// round-trip — this checks the bytes exactly as received. The receive path MUST
// use this: re-serialization can reject a peer's valid-but-non-canonical
// encoding, or pass a corrupt-but-decodable TLV area. raw is the full LSP PDU
// trimmed to its declared length. A purge (zero remaining lifetime) carries a
// zero checksum and must be exempted by the caller.
func LSPChecksumValidRaw(raw []byte) bool {
	if len(raw) < lspHeaderLen {
		return false
	}
	// The checksum covers from the LSP ID (PDU offset 12) to the end, with the
	// checksum octets (offset 24:26) in place.
	return fletcherValid(raw[12:])
}

// ChecksumValid reports whether the LSP's on-wire checksum verifies. A purge
// (remaining lifetime zero, body stripped) carries a zero checksum and is
// not subject to this check by the caller.
//
// This re-serializes the decoded TLVs, so it is only meaningful for an LSP
// goisis itself built or that round-trips byte-exactly. For the receive path,
// use LSPChecksumValidRaw against the wire bytes instead.
func (p *LSP) ChecksumValid() (bool, error) {
	b, err := p.serializeWithChecksum(p.checksum)
	if err != nil {
		return false, err
	}
	return fletcherValid(b[12:]), nil
}

// serializeWithChecksum renders the LSP but writes the given checksum
// verbatim instead of recomputing, used to validate a decoded checksum.
func (p *LSP) serializeWithChecksum(sum uint16) ([]byte, error) {
	tlvs, err := serializeTLVs(p.TLVs)
	if err != nil {
		return nil, err
	}
	b := make([]byte, lspHeaderLen, lspHeaderLen+len(tlvs))
	putCommonHeader(b, p.PDUType(), lspHeaderLen)
	binary.BigEndian.PutUint16(b[10:12], p.RemainingTime)
	copy(b[12:20], p.LSPID[:])
	binary.BigEndian.PutUint32(b[20:24], p.SequenceNumber)
	binary.BigEndian.PutUint16(b[24:26], sum)
	b[26] = p.flagsOctet()
	b = append(b, tlvs...)
	binary.BigEndian.PutUint16(b[8:10], uint16(len(b))) //nolint:gosec // capped by TLV area size
	return b, nil
}

func init() {
	registerPDUDecoder(PDUTypeL1LSP, func(h commonHeader, b []byte) (PDU, error) {
		return decodeLSP(Level1, h, b)
	})
	registerPDUDecoder(PDUTypeL2LSP, func(h commonHeader, b []byte) (PDU, error) {
		return decodeLSP(Level2, h, b)
	})
}
