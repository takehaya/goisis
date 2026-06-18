package server

import (
	"encoding/binary"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// LSP lifetime constants (ISO 10589 architectural defaults).
//
// goisis deliberately does not apply an RFC 7987 minimum-remaining-lifetime
// floor to received LSPs; aging follows the advertised remaining lifetime.
const (
	maxAgeSeconds  = 1200 // MaxAge
	refreshSeconds = 900  // maximumLSPGenerationInterval
	zeroAgeSeconds = 60   // ZeroAgeLifetime: hold a purge this long
)

// lspEntry is one LSP in the database, owned by the Serve loop.
type lspEntry struct {
	lsp      *packet.LSP
	raw      []byte    // serialized PDU; remaining-lifetime field patched on send
	inserted time.Time // when received or (re)originated
	lifetime uint16    // remaining lifetime at insertion, in seconds
	own      bool      // self-originated
	purgedAt time.Time // nonzero once purged; entry held until +ZeroAgeLifetime
}

// remaining returns the current remaining lifetime in seconds, aged from
// insertion.
func (e *lspEntry) remaining(now time.Time) uint16 {
	elapsed := int(now.Sub(e.inserted).Seconds())
	rem := int(e.lifetime) - elapsed
	if rem < 0 {
		return 0
	}
	return uint16(rem) //nolint:gosec // rem is in [0, lifetime<=0xffff]
}

// wire returns the LSP bytes with the remaining-lifetime field updated to the
// current value. The Fletcher checksum does not cover remaining lifetime, so
// patching those two octets keeps the checksum valid.
func (e *lspEntry) wire(now time.Time) []byte {
	b := make([]byte, len(e.raw))
	copy(b, e.raw)
	if len(b) >= 12 {
		binary.BigEndian.PutUint16(b[10:12], e.remaining(now))
	}
	return b
}

// lsdb is the per-level link-state database.
type lsdb struct {
	level   packet.Level
	entries map[packet.LSPID]*lspEntry
}

func newLSDB(level packet.Level) *lsdb {
	return &lsdb{level: level, entries: map[packet.LSPID]*lspEntry{}}
}

func (db *lsdb) get(id packet.LSPID) *lspEntry { return db.entries[id] }

// newer reports whether candidate supersedes existing for the same LSP ID
// (ISO 10589 7.3.16.2): higher sequence number wins; on a tie a purge
// (remaining lifetime 0) supersedes a live copy.
func newer(candSeq uint32, candRemaining uint16, ex *lspEntry, now time.Time) bool {
	if ex == nil {
		return true
	}
	if candSeq != ex.lsp.SequenceNumber {
		return candSeq > ex.lsp.SequenceNumber
	}
	candZero := candRemaining == 0
	exZero := ex.remaining(now) == 0
	if candZero != exZero {
		return candZero
	}
	return false
}

// LSPInfo is an exported snapshot of one LSDB entry.
type LSPInfo struct {
	Level          packet.Level
	LSPID          packet.LSPID
	SequenceNumber uint32
	Remaining      uint16
	Checksum       uint16
	Own            bool
}

func (db *lsdb) snapshot(now time.Time) []LSPInfo {
	out := make([]LSPInfo, 0, len(db.entries))
	for id, e := range db.entries {
		out = append(out, LSPInfo{
			Level:          db.level,
			LSPID:          id,
			SequenceNumber: e.lsp.SequenceNumber,
			Remaining:      e.remaining(now),
			Checksum:       e.lsp.Checksum(),
			Own:            e.own,
		})
	}
	return out
}
