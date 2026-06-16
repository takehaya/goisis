package server

import (
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// purgeOwn floods a purge for one of our own LSPs: a header-only LSP with
// remaining lifetime zero and a Purge Originator Identification TLV (RFC
// 6232/8918). The entry is held for ZeroAgeLifetime so the purge propagates.
func (s *IsisServer) purgeOwn(level packet.Level, id packet.LSPID, now time.Time) {
	db := s.dbs[level]
	ex := db.get(id)
	seq := uint32(1)
	if ex != nil {
		seq = ex.lsp.SequenceNumber + 1
	}
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
	if s.authKey(level) != nil {
		lsp.TLVs = append(lsp.TLVs, authTLVPlaceholder())
	}
	raw, err := s.serializeLSP(lsp)
	if err != nil {
		s.logger.Error("serialize purge", "lsp", id, "error", err)
		return
	}
	db.entries[id] = &lspEntry{lsp: lsp, raw: raw, inserted: now, lifetime: 0, own: true, purgedAt: now}
	s.logger.Info("purge LSP", "level", level, "lsp", id, "seq", seq)
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
			case e.own && now.Sub(e.inserted) >= refreshSeconds*time.Second:
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

// expirePurge converts an expired foreign LSP into a purge we flood, so the
// rest of the network drops it too (ISO 10589 7.3.16.4).
func (s *IsisServer) expirePurge(level packet.Level, id packet.LSPID, e *lspEntry, now time.Time) {
	e.purgedAt = now
	e.lifetime = 0
	e.inserted = now
	s.logger.Info("expire LSP", "level", level, "lsp", id)
	s.markDirty()
	s.floodLSP(level, id, nil, now)
}

// refreshOwnLSPs re-originates own LSPs that are within the refresh window so
// their lifetime never reaches zero.
func (s *IsisServer) refreshOwnLSPs(now time.Time) {
	for _, db := range s.dbs {
		for _, e := range db.entries {
			if e.own && e.purgedAt.IsZero() && now.Sub(e.inserted) >= refreshSeconds*time.Second {
				s.regenerateLSPs(true, now)
				return
			}
		}
	}
}
