package server

import (
	"encoding/binary"
	"math"
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

// maxLSPSeq is the highest sequence number an LSP can carry. Reaching it
// exhausts the ID's sequence number space (ISO 10589 7.3.16.1); see exhaustSeq.
const maxLSPSeq = uint32(math.MaxUint32)

// seqWrapHold is how long an exhausted LSP ID stays un-originated before it
// restarts at sequence number 1: ZeroAgeLifetime, after which every node has
// dropped the purge, plus a margin for the purge to reach them.
const seqWrapHold = (zeroAgeSeconds + 5) * time.Second

// lspKey identifies one LSP across the per-level databases.
type lspKey struct {
	level packet.Level
	id    packet.LSPID
}

// lspEntry is one LSP in the database, owned by the Serve loop.
type lspEntry struct {
	lsp       *packet.LSP
	raw       []byte    // serialized PDU; remaining-lifetime field patched on send
	inserted  time.Time // when received or (re)originated
	lifetime  uint16    // remaining lifetime at insertion, in seconds
	own       bool      // self-originated
	purgedAt  time.Time // nonzero once purged; entry held until +ZeroAgeLifetime
	refreshAt time.Time // own LSPs: when to re-originate (see refreshDeadline)
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
//
// Sequence numbers are assumed monotonic. Natural refreshes never wrap — at
// the 900s refresh rate, exhausting 2^32 increments takes ~120k years — but a
// single hostile LSP can jump one of ours to maxLSPSeq, so exhaustion is
// handled by the 7.3.16.1 procedure in exhaustSeq rather than ignored.
// Consequently a peer that crash-restarts at seq 1 is ignored until its stale
// LSP ages out (ties into the deferred RFC 5306).
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
	// Hostname is the originator's dynamic hostname (TLV 137), empty when it
	// advertises none.
	Hostname string
	// TLVs renders the LSP's TLVs in wire order for display; a TLV carrying a
	// list renders one line per entry, so there are usually more lines than
	// TLVs. Only ListLSDBDetail fills it in — see renderTLVs.
	TLVs []string
	// tlvs is the stored TLV list, carried out of the management operation so
	// renderTLVs can format it off the Serve loop. Sharing the slice rather
	// than copying the TLVs is safe because an installed entry is replaced,
	// never edited: the only write to one in place swaps e.lsp for a freshly
	// built purge (expirePurge), so nothing appends to or mutates the TLVs a
	// snapshot captured.
	tlvs []packet.TLV
}

// snapshot copies the entries out for a management read. It only copies: the
// TLV text is rendered by renderTLVs, after the management operation returns.
func (db *lsdb) snapshot(now time.Time, hostnames map[packet.SystemID]string) []LSPInfo {
	out := make([]LSPInfo, 0, len(db.entries))
	for id, e := range db.entries {
		out = append(out, LSPInfo{
			Level:          db.level,
			LSPID:          id,
			SequenceNumber: e.lsp.SequenceNumber,
			Remaining:      e.remaining(now),
			Checksum:       e.lsp.Checksum(),
			Own:            e.own,
			Hostname:       hostnames[id.NodeID().SystemID()],
			tlvs:           e.lsp.TLVs,
		})
	}
	return out
}

// renderTLVs fills in the TLVs field of a snapshot. It must run off the Serve
// loop (the stored TLVs stay readable there, see LSPInfo.tlvs): a database of
// a few thousand LSPs renders six figures of lines, which is far more than a
// management read may take from the goroutine that also sends hellos, floods
// and expires adjacencies.
func renderTLVs(infos []LSPInfo) {
	for i := range infos {
		infos[i].TLVs = tlvSummaries(infos[i].tlvs)
	}
}
