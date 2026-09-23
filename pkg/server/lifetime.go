package server

import (
	"math/rand/v2"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// makePurge builds the header-only purge for an LSP (ISO 10589 7.3.16.4): a
// purge is flooded with the body removed, so only a Purge Originator
// Identification TLV (RFC 6232/8918) naming this node — and, when the level
// is keyed, an Authentication TLV — remain. The caller picks the sequence
// number: purgeOwn bumps ours, expirePurge keeps the foreign originator's.
func (s *IsisServer) makePurge(level packet.Level, id packet.LSPID, seq uint32) (*packet.LSP, []byte, error) {
	lsp := &packet.LSP{
		Level:          level,
		RemainingTime:  0,
		LSPID:          id,
		SequenceNumber: seq,
		ISType:         s.isType(),
		TLVs: []packet.TLV{
			// POI (RFC 6232): a 1-octet count of system IDs (1 or 2) then the
			// IDs. We carry one: ourselves.
			&packet.UnknownTLV{TLVType: packet.TLVTypePurgeOriginatorID, Value: append([]byte{1}, s.systemID[:]...)},
		},
	}
	if spec := s.authKey(level); spec.on() {
		lsp.TLVs = append(lsp.TLVs, authTLVPlaceholder(spec))
	}
	raw, err := s.serializeLSP(lsp)
	if err != nil {
		return nil, nil, err
	}
	return lsp, raw, nil
}

// purgeOwn floods a purge for one of our own LSPs: a header-only LSP with
// remaining lifetime zero and a Purge Originator Identification TLV (RFC
// 6232/8918). The entry is held for ZeroAgeLifetime so the purge propagates.
func (s *IsisServer) purgeOwn(level packet.Level, id packet.LSPID, now time.Time) {
	db := s.dbs[level]
	ex := db.get(id)
	// The LSP is ours, so bump the sequence number to supersede every live
	// copy — unless that would wrap, which calls for the exhaustion procedure
	// instead (ISO 10589 7.3.16.1).
	seq := uint32(1)
	if ex != nil {
		if ex.lsp.SequenceNumber == maxLSPSeq {
			s.exhaustSeq(level, id, now)
			return
		}
		seq = ex.lsp.SequenceNumber + 1
	}
	lsp, raw, err := s.makePurge(level, id, seq)
	if err != nil {
		s.logger.Error("serialize purge", "lsp", id, "error", err)
		return
	}
	db.entries[id] = &lspEntry{lsp: lsp, raw: raw, inserted: now, lifetime: 0, own: true, purgedAt: now}
	s.logger.Info("purge LSP", "level", level, "lsp", id, "seq", seq)
	s.markDirty()
	s.floodLSP(level, id, nil, now)
}

// exhaustSeq runs the ISO 10589 7.3.16.1 sequence-number exhaustion procedure
// for one of our own LSPs: flood a purge at maxLSPSeq — which supersedes the
// live copy at equal sequence under 7.3.16.2, so no higher number is needed —
// and leave the ID alone until every node has dropped that purge, after which
// refreshOwnLSPs re-originates it from 1. Sequence number 0 is never
// serialized: peers read it as older than whatever forced the wrap and would
// flood that copy back at us, so our own LSP would never be accepted again.
//
// Natural refreshes cannot reach maxLSPSeq (see newer in lsdb.go); one forged
// LSP can, so the hold-down is a bounded, area-wide outage of this LSP ID that
// buys back a correct sequence number space. Authentication is what keeps the
// forgery off the wire in the first place.
func (s *IsisServer) exhaustSeq(level packet.Level, id packet.LSPID, now time.Time) {
	k := lspKey{level: level, id: id}
	if _, held := s.seqWrapUntil[k]; !held {
		// Once per exhaustion, not once per received copy: an attacker can
		// repeat the PDU, and an unthrottled Warn would turn this defense into
		// log amplification on the management loop.
		s.logger.Warn("LSP sequence number space exhausted; purging and holding the ID down",
			"level", level, "lsp", id, "hold", seqWrapHold)
	}
	s.seqWrapUntil[k] = now.Add(seqWrapHold)

	lsp, raw, err := s.makePurge(level, id, maxLSPSeq)
	if err != nil {
		s.logger.Error("serialize purge", "lsp", id, "error", err)
		return
	}
	s.dbs[level].entries[id] = &lspEntry{lsp: lsp, raw: raw, inserted: now, lifetime: 0, own: true, purgedAt: now}
	s.markDirty()
	s.floodLSP(level, id, nil, now)
}

// ageLSPs ages the database: live LSPs that reach zero remaining lifetime are
// purged, and purged LSPs are removed once held for ZeroAgeLifetime. Own LSPs
// are refreshed before they expire.
func (s *IsisServer) ageLSPs(now time.Time) {
	for level, db := range s.dbs {
		for id, e := range db.entries {
			switch {
			case !e.purgedAt.IsZero():
				if now.Sub(e.purgedAt) >= zeroAgeSeconds*time.Second {
					delete(db.entries, id)
					s.markDirty()
				}
			case e.own && !now.Before(e.refreshAt):
				// handled by refreshOwnLSPs to keep aging side-effect-free
			case e.remaining(now) == 0:
				if e.own {
					// Our own LSP should never naturally expire; refresh it.
					continue
				}
				s.expirePurge(level, id, e, now)
			}
		}
	}
}

// expirePurge converts an expired (or equal-seq conflicting) foreign LSP into
// a purge we flood, so the rest of the network drops it too (ISO 10589
// 7.3.16.4). The stored entry is rewritten header-only via makePurge — a purge
// must not carry the original body — keeping the originator's current sequence
// number (only the originator may advance it; a purge supersedes a live copy
// at equal seq per 7.3.16.2) and own=false so refresh never treats it as ours.
func (s *IsisServer) expirePurge(level packet.Level, id packet.LSPID, e *lspEntry, now time.Time) {
	lsp, raw, err := s.makePurge(level, id, e.lsp.SequenceNumber)
	if err != nil {
		s.logger.Error("serialize purge", "lsp", id, "error", err)
		return
	}
	e.lsp = lsp
	e.raw = raw
	e.purgedAt = now
	e.lifetime = 0
	e.inserted = now
	s.logger.Info("expire LSP", "level", level, "lsp", id)
	s.markDirty()
	s.floodLSP(level, id, nil, now)
}

// refreshDeadline returns when an own LSP originated at now must be
// re-originated: maximumLSPGenerationInterval less a jitter of up to 25 % (ISO
// 10589 10.1). Without the jitter, nodes that booted together refresh — and
// flood — in lockstep for as long as they run.
func refreshDeadline(now time.Time) time.Time {
	return now.Add(refreshSeconds*time.Second - rand.N(refreshSeconds/4*time.Second))
}

// refreshOwnLSPs re-originates own LSPs that reached their refresh deadline so
// their lifetime never reaches zero, and releases LSP IDs whose sequence-number
// hold-down has elapsed.
func (s *IsisServer) refreshOwnLSPs(now time.Time) {
	// An exhausted LSP ID whose hold-down elapsed: ageLSPs has already dropped
	// its purge here and every other node has dropped theirs, so the ID may be
	// originated again — originate restarts it at 1 (ISO 10589 7.3.16.1).
	released := false
	for k, until := range s.seqWrapUntil {
		if !now.Before(until) {
			delete(s.seqWrapUntil, k)
			released = true
		}
	}
	if released {
		s.regenerateLSPs(false, now)
	}
	for _, db := range s.dbs {
		for _, e := range db.entries {
			if e.own && e.purgedAt.IsZero() && !now.Before(e.refreshAt) {
				s.regenerateLSPs(true, now)
				return
			}
		}
	}
}
