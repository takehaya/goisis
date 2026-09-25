package server

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// LSP lifetime constants (ISO 10589 architectural defaults).
const (
	maxAgeSeconds  = 1200 // MaxAge
	refreshSeconds = 900  // maximumLSPGenerationInterval
	zeroAgeSeconds = 60   // ZeroAgeLifetime: hold a purge this long
)

// receivedLifetime returns the lifetime a received LSP is aged from.
//
// The Remaining Lifetime field sits outside the Fletcher checksum (see
// LSP.Serialize) and outside the authentication hash, so corruption of it in
// flight — or a man in the middle rewriting it under authentication — is
// undetectable. Corrupted downward, it makes every receiver purge the LSP
// before its originator refreshes it, and the originator's re-origination
// floods the area again: the storm RFC 7987 exists to stop. Its remedy is one
// added action on the ISO 10589 7.3.15.1 e) 1) install path: a lifetime below
// MaxAge is stored as MaxAge (RFC 7987 section 2, vi), so a node other than the
// originator never purges an LSP it has held for less than MaxAge. The stored
// value is what we flood on (lspEntry.wire patches the field), so the floor
// reaches downstream neighbors as well.
//
// Two values are deliberately left alone:
//   - Zero. A purge stays a purge: RFC 7987 changes nothing in 7.3.15.1 b), and
//     flooring here would resurrect every purge as a live LSP for MaxAge.
//   - Above MaxAge. The originator may run a larger MaxAge than we do (section
//     3.1) and a lifetime longer than intended is benign (section 1), so
//     clamping down is precisely what would purge that originator's LSPs
//     prematurely. RFC 7987 raises a short lifetime; it never lowers a long one.
//
// The floor is fixed at our own MaxAge rather than configurable (section 3.1
// permits a configurable value but requires it to be at least the local
// MaxAge), because goisis does not make MaxAge configurable either.
func receivedLifetime(remaining uint16) uint16 {
	if remaining == 0 {
		return 0
	}
	return max(remaining, maxAgeSeconds)
}

// corruptLifetime reports whether a received Remaining Lifetime should raise
// RFC 7987 §3.2's CorruptRemainingLifetime event. §3.2 lists four conditions;
// two of them are settled by where this is called from, on the install path of
// processLSP:
//
//   - the LSP has passed the ISO 10589 7.3.15.1 acceptance tests — handleRx
//     has authenticated it and the adjacency gate has admitted it, and
//     processLSP has validated its checksum;
//   - it is newer than the copy in the local LSPDB — processLSP returns above
//     on anything that is not, the absent copy included.
//
// The two tested here are the ones a caller cannot settle. A lifetime below
// ZeroAgeLifetime is the symptom; §3.2's fourth condition is the
// false-positive filter, and it is what makes the count worth alerting on. An
// adjacency in the middle of a whole-database exchange is being handed a
// database whose LSPs may genuinely have aged that far, in bulk.
//
// Why that condition is read off syncSince and not off when the adjacency came
// Up, which is how §3.2 words it: the wording is a proxy. In an implementation
// with no restart helper the only thing that starts a whole-database exchange
// is an adjacency coming Up, so the two are the same field. RFC 5306 §3.2.1c
// adds a second one — a neighbor restarting under the helper is handed the
// complete database over an adjacency that deliberately never left Up, which
// is the exact traffic this filter exists to exclude, arriving with the filter
// reading the adjacency as arbitrarily old. Taking §3.2 literally there counts
// every helped restart in the area as corruption and costs the counter the
// zero baseline that is the whole reason it can be alerted on, so what is
// measured is the exchange rather than the adjacency. The two differ only
// while a restart is being helped: the other writer is syncCircuitLevel, which
// opens the window where it actually begins handing a neighbor the database
// and is itself held down to one run per syncHoldDown per circuit and level.
//
// What stops a neighbor holding the window open is not §3.2.1a. That clause
// bounds lastHeard, and its own "an IIH with the RR bit reset will clear the
// Restart mode state" is what re-arms the next request, so a peer that
// interleaves ordinary hellos keeps the adjacency alive by the normal path and
// can ask again for as long as it likes. The bound is maxSyncSuppression: the
// budget openSyncWindow spends from, which nothing refills before the
// adjacency next comes Up.
//
// A purge is not a corrupt lifetime, however far below ZeroAgeLifetime zero
// is: §2 leaves the handling of purged LSPs alone, and every purge in the area
// would otherwise bury the event this exists to make legible. nil adj is the
// fourth condition unsatisfiable rather than satisfied: with no adjacency there
// is no exchange to have finished.
func corruptLifetime(adj *adjacency, remaining uint16, now time.Time) bool {
	if remaining == 0 || remaining >= zeroAgeSeconds {
		return false
	}
	return adj != nil && now.Sub(adj.syncSince) >= zeroAgeSeconds*time.Second
}

// maxSyncSuppression is how much of RFC 7987 §3.2's report one neighbor may
// suppress between one transition of its adjacency into Up and the next.
//
// The window corruptLifetime reads is reopened by every database exchange this
// node starts, and RFC 5306 §3.2.1c makes a neighbor's restart request one of
// the things that starts one. Without a budget a peer asking again inside
// every ZeroAgeLifetime holds the filter open for as long as it keeps that up,
// and the party that can switch the detector off is the party whose LSPs it
// watches. §3.2's fourth condition is worded as the adjacency's own age
// precisely because that is monotone; measuring the exchange instead buys the
// helped restart at the cost of that monotonicity, and this is what is put
// back in its place.
//
// Five minutes, measured against what an exchange actually costs: one helped
// restart spends roughly its own duration (see openSyncWindow's charge), and
// RFC 5306 §3.3 bounds a restart by "the minimum holding time of the
// neighbors" — 30s in ISO 10589's architectural defaults — so the budget
// covers on the order of ten consecutive restarts over one Up episode, on an
// adjacency that never went Down between them. What it caps is the other side:
// a neighbor holding the window open costs the counter at most
// maxSyncSuppression plus the ZeroAgeLifetime of the last window, under a
// tenth of the hour docs/configuration.md's alert evaluates over.
const maxSyncSuppression = 5 * zeroAgeSeconds * time.Second

// resetSyncWindow starts a fresh Up episode on an adjacency that has just
// reached state Up. The transition is where the exchange RFC 7987 §3.2 words
// its fourth condition around begins, so the window opens with it, and the
// suppression budget starts over — the one thing here a neighbor cannot help
// itself to quietly, since reaching Up again means having gone Down first.
func (adj *adjacency) resetSyncWindow(now time.Time) {
	adj.upSince, adj.syncSince, adj.syncSpent = now, now, 0
}

// openSyncWindow reopens RFC 7987 §3.2's window for an exchange beginning now
// and charges what that adds to the Up episode's budget. syncCircuitLevel is
// the only caller: the window follows the exchange, not the request that asked
// for one.
//
// The charge is the suppressed time the reopening actually adds — the gap
// since the window last opened, never more than the one ZeroAgeLifetime a
// single window covers — so a restarter that asks on every IIH pays for the
// seconds it is quiet rather than for the number of times it asked, and the
// total suppressed over an Up episode is syncSpent plus one final window. Once
// the budget is gone the window is never reopened on this adjacency again.
func (s *IsisServer) openSyncWindow(c *circuit, adj *adjacency, now time.Time) {
	add := now.Sub(adj.syncSince)
	if add <= 0 {
		// The open window already covers now: the transition into Up opened it
		// at this same instant, or another level's exchange did.
		return
	}
	if adj.syncSpent >= maxSyncSuppression {
		return
	}
	adj.syncSpent += min(add, zeroAgeSeconds*time.Second)
	adj.syncSince = now
	if adj.syncSpent >= maxSyncSuppression {
		// On the edge, so it is one line per Up episode however long the
		// neighbor keeps asking. It is what an operator reading a silent
		// lsp_lifetime_corrupt against a busy restart_requests needs told:
		// from here the filter is armed for this neighbor whatever it sends.
		s.logger.Warn("restart resync suppression budget spent", "circuit", c.cfg.Name,
			"neighbor", adj.systemID, "up", now.Sub(adj.upSince).Truncate(time.Second))
	}
}

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
