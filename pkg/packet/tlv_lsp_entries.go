package packet

import (
	"encoding/binary"
	"fmt"
)

const lspEntrySize = 16 // remaining lifetime(2) + LSP ID(8) + seqno(4) + checksum(2)

// MaxLSPEntriesPerTLV is the number of LSP entries that fit in one TLV
// (255 / 16, floored). A producer with more entries emits multiple TLVs.
const MaxLSPEntriesPerTLV = 255 / lspEntrySize // 15

// LSPEntry is one entry of an LSP Entries TLV: a digest of an LSP used for
// database synchronization in CSNPs and PSNPs.
type LSPEntry struct {
	RemainingTime  uint16
	LSPID          LSPID
	SequenceNumber uint32
	Checksum       uint16
}

// LSPEntriesTLV is the LSP Entries TLV (type 9), carried in CSNPs and PSNPs.
type LSPEntriesTLV struct {
	Entries []LSPEntry
}

// Type implements TLV.
func (t *LSPEntriesTLV) Type() TLVType { return TLVTypeLSPEntries }

// Serialize implements TLV.
func (t *LSPEntriesTLV) Serialize() ([]byte, error) {
	if len(t.Entries) > MaxLSPEntriesPerTLV {
		return nil, fmt.Errorf("%w: %d LSP entries exceed %d per TLV", ErrTooLong, len(t.Entries), MaxLSPEntriesPerTLV)
	}
	value := make([]byte, 0, len(t.Entries)*lspEntrySize)
	for _, e := range t.Entries {
		var buf [lspEntrySize]byte
		binary.BigEndian.PutUint16(buf[0:2], e.RemainingTime)
		copy(buf[2:10], e.LSPID[:])
		binary.BigEndian.PutUint32(buf[10:14], e.SequenceNumber)
		binary.BigEndian.PutUint16(buf[14:16], e.Checksum)
		value = append(value, buf[:]...)
	}
	return encodeTLV(TLVTypeLSPEntries, value)
}

func decodeLSPEntriesTLV(value []byte) (TLV, error) {
	if len(value)%lspEntrySize != 0 {
		return nil, fmt.Errorf("%w: LSP entries length %d not a multiple of %d", errBadTLV, len(value), lspEntrySize)
	}
	tlv := &LSPEntriesTLV{}
	for len(value) > 0 {
		tlv.Entries = append(tlv.Entries, LSPEntry{
			RemainingTime:  binary.BigEndian.Uint16(value[0:2]),
			LSPID:          LSPID(value[2:10]),
			SequenceNumber: binary.BigEndian.Uint32(value[10:14]),
			Checksum:       binary.BigEndian.Uint16(value[14:16]),
		})
		value = value[lspEntrySize:]
	}
	return tlv, nil
}

func init() {
	registerTLVDecoder(TLVTypeLSPEntries, decodeLSPEntriesTLV)
}
