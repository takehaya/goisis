package server

import (
	"bytes"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// minLSPTransmissionInterval rate-limits LSP retransmission on p2p circuits
// (ISO 10589 minimumLSPTransmissionInterval).
const minLSPTransmissionInterval = 5 * time.Second

// csnpInterval is how often a DIS multicasts CSNPs on a LAN.
const csnpInterval = 10 * time.Second

// dest returns the multicast destination for control PDUs at a level.
func (c *circuit) dest(level packet.Level) packet.SNPA {
	if c.cfg.P2P {
		return datalink.AllISs
	}
	return datalink.DestForLevel(level)
}

// ownsLSP reports whether this node is the current originator of an LSP ID:
// always for its own node LSP, and for a pseudonode LSP only while it is the
// DIS of the matching circuit.
func (s *IsisServer) ownsLSP(level packet.Level, id packet.LSPID) bool {
	if id.NodeID().SystemID() != s.systemID {
		return false
	}
	pn := id.NodeID().PseudonodeID()
	if pn == 0 {
		return true // node LSP
	}
	for _, c := range s.circuits {
		if c.pseudonodeID == pn && c.isDIS(level, s.systemID) {
			return true
		}
	}
	return false
}

// processLSP applies the ISO 10589 7.3 update process to a received LSP.
func (s *IsisServer) processLSP(c *circuit, raw []byte, lsp *packet.LSP, now time.Time) {
	level := lsp.Level
	db := s.dbs[level]
	if db == nil {
		return // level not enabled on this circuit
	}
	id := lsp.LSPID

	// Discard a corrupted-but-decodable LSP rather than store or forward it
	// (ISO 10589 7.3.14.2). Validate the Fletcher checksum over the bytes as
	// received — not a re-serialization of the decoded TLVs, which would couple
	// validity to byte-exact round-trip. A purge legitimately carries a zero
	// checksum and is exempt.
	if lsp.RemainingTime != 0 && !packet.LSPChecksumValidRaw(raw) {
		s.logger.Debug("drop LSP with invalid checksum", "circuit", c.cfg.Name, "lsp", id)
		return
	}

	ex := db.get(id)

	if !newer(lsp.SequenceNumber, lsp.RemainingTime, ex, now) {
		// Received copy is not newer than ours.
		switch {
		case ex != nil && lsp.SequenceNumber < ex.lsp.SequenceNumber:
			// We hold a newer copy: send it, and do not acknowledge theirs.
			c.setSRM(level, id, now)
			c.clearSSN(level, id)
		case ex != nil && lsp.SequenceNumber == ex.lsp.SequenceNumber &&
			ex.remaining(now) == 0 && lsp.RemainingTime != 0:
			// We hold a purge at this sequence number and the peer still has a
			// live copy: a purge supersedes a live LSP at equal sequence (ISO
			// 10589 7.3.16.2), so re-flood our purge instead of acknowledging.
			c.setSRM(level, id, now)
			c.clearSSN(level, id)
		case ex != nil && lsp.SequenceNumber == ex.lsp.SequenceNumber &&
			lsp.RemainingTime != 0 && ex.remaining(now) != 0 &&
			lsp.Checksum() != ex.lsp.Checksum():
			// Same sequence number, different content (ISO 10589 7.3.16.2):
			// purge our stored copy so the true originator re-originates with
			// a higher sequence number.
			if !ex.own {
				s.expirePurge(level, id, ex, now)
			} else {
				s.reoriginateOwn(level, id, lsp.SequenceNumber, now)
			}
		case c.cfg.P2P:
			// Equal and identical: acknowledge on p2p so the sender stops
			// retransmitting.
			c.setSSN(level, id)
		}
		return
	}

	if s.ownsLSP(level, id) {
		// Someone advanced (or purged) one of our own LSPs; re-originate
		// with a higher sequence number to reclaim it.
		s.reoriginateOwn(level, id, lsp.SequenceNumber, now)
		return
	}

	// Install the newer copy.
	stored := make([]byte, len(raw))
	copy(stored, raw)
	purgedAt := time.Time{}
	if lsp.RemainingTime == 0 {
		purgedAt = now
	}
	db.entries[id] = &lspEntry{
		lsp:      lsp,
		raw:      stored,
		inserted: now,
		lifetime: lsp.RemainingTime,
		purgedAt: purgedAt,
	}
	s.markDirty()

	// Flood to all other circuits; on the arrival circuit clear SRM and, on
	// p2p, acknowledge.
	s.floodLSP(level, id, c, now)
	c.clearSRM(level, id)
	if c.cfg.P2P {
		c.setSSN(level, id)
	}
}

// reoriginateOwn rebuilds one of our own LSPs with a sequence number above
// the one just seen on the wire, then re-floods it.
func (s *IsisServer) reoriginateOwn(level packet.Level, id packet.LSPID, seenSeq uint32, now time.Time) {
	db := s.dbs[level]
	ex := db.get(id)
	if ex == nil {
		return
	}
	lsp := *ex.lsp
	lsp.SequenceNumber = seenSeq + 1
	lsp.RemainingTime = maxAgeSeconds
	raw, err := s.serializeLSP(&lsp)
	if err != nil {
		s.logger.Error("re-originate own LSP", "lsp", id, "error", err)
		return
	}
	db.entries[id] = &lspEntry{lsp: &lsp, raw: raw, inserted: now, lifetime: maxAgeSeconds, own: true}
	s.logger.Info("re-originate LSP", "level", level, "lsp", id, "seq", lsp.SequenceNumber)
	s.markDirty()
	s.floodLSP(level, id, nil, now)
}

// floodTransmit sends pending LSPs (SRM) and PSNPs (SSN), and emits periodic
// CSNPs where this node is the DIS. Called from housekeeping.
func (s *IsisServer) floodTransmit(now time.Time) {
	for _, c := range s.circuits {
		for _, level := range c.cfg.levels() {
			s.transmitSRM(c, level, now)
			s.transmitPSNP(c, level, now)
			if c.isDIS(level, s.systemID) && !now.Before(c.nextCSNP[level]) {
				s.sendCSNP(c, level, now)
				c.nextCSNP[level] = now.Add(csnpInterval)
			}
		}
	}
}

// transmitSRM sends every LSP flagged for this circuit whose send time has
// arrived. On a LAN the flag is cleared after one send (the DIS CSNP provides
// reliability); on p2p it is rescheduled until a PSNP acknowledges it.
func (s *IsisServer) transmitSRM(c *circuit, level packet.Level, now time.Time) {
	db := s.dbs[level]
	for id, when := range c.srm[level] {
		if now.Before(when) {
			continue
		}
		e := db.get(id)
		if e == nil {
			c.clearSRM(level, id)
			continue
		}
		if err := c.cfg.Transport.Send(c.dest(level), e.wire(now)); err != nil {
			s.logger.Error("send LSP", "circuit", c.cfg.Name, "lsp", id, "error", err)
			continue
		}
		s.metrics.FloodTx(c.cfg.Name)
		if c.cfg.P2P {
			c.srm[level][id] = now.Add(minLSPTransmissionInterval)
		} else {
			c.clearSRM(level, id)
		}
	}
}

// transmitPSNP sends one PSNP describing every LSP flagged SSN on the circuit
// (acknowledgements on p2p, requests on a LAN), then clears the flags.
func (s *IsisServer) transmitPSNP(c *circuit, level packet.Level, now time.Time) {
	if len(c.ssn[level]) == 0 {
		return
	}
	db := s.dbs[level]
	var entries []packet.LSPEntry
	for id := range c.ssn[level] {
		e := db.get(id)
		entry := packet.LSPEntry{LSPID: id}
		if e != nil {
			entry.RemainingTime = e.remaining(now)
			entry.SequenceNumber = e.lsp.SequenceNumber
			entry.Checksum = e.lsp.Checksum()
		}
		entries = append(entries, entry)
		c.clearSSN(level, id)
	}
	for _, chunk := range chunkEntries(entries) {
		psnp := &packet.PSNP{
			Level:    level,
			SourceID: nodeID(s.systemID, 0),
			TLVs:     []packet.TLV{&packet.LSPEntriesTLV{Entries: chunk}},
		}
		s.sendSNP(c, level, psnp)
	}
}

// sendCSNP multicasts the DIS's view of the database for a level as one or
// more CSNPs spanning the whole LSP-ID range.
func (s *IsisServer) sendCSNP(c *circuit, level packet.Level, now time.Time) {
	db := s.dbs[level]
	var entries []packet.LSPEntry
	for id, e := range db.entries {
		entries = append(entries, packet.LSPEntry{
			RemainingTime:  e.remaining(now),
			LSPID:          id,
			SequenceNumber: e.lsp.SequenceNumber,
			Checksum:       e.lsp.Checksum(),
		})
	}
	var start, end packet.LSPID
	for i := range end {
		end[i] = 0xff
	}
	csnp := &packet.CSNP{
		Level:    level,
		SourceID: nodeID(s.systemID, c.pseudonodeID),
		StartLSP: start,
		EndLSP:   end,
		TLVs:     []packet.TLV{},
	}
	for _, chunk := range chunkEntries(entries) {
		csnp.TLVs = append(csnp.TLVs, &packet.LSPEntriesTLV{Entries: chunk})
	}
	s.sendSNP(c, level, csnp)
}

func (s *IsisServer) sendSNP(c *circuit, level packet.Level, pdu packet.PDU) {
	spec := s.authKey(level)
	if spec.on() {
		// Append an Authentication TLV (filled after serialization).
		switch p := pdu.(type) {
		case *packet.CSNP:
			p.TLVs = append(p.TLVs, authTLVPlaceholder(spec))
		case *packet.PSNP:
			p.TLVs = append(p.TLVs, authTLVPlaceholder(spec))
		}
	}
	wire, err := pdu.Serialize()
	if err != nil {
		s.logger.Error("serialize SNP", "circuit", c.cfg.Name, "error", err)
		return
	}
	if spec.on() {
		if err := packet.PatchAuth(wire, packet.HeaderLen(pdu.PDUType()), spec.algo, spec.keyID, spec.key, false); err != nil {
			s.logger.Error("authenticate SNP", "circuit", c.cfg.Name, "error", err)
			return
		}
	}
	if err := c.cfg.Transport.Send(c.dest(level), wire); err != nil {
		s.logger.Error("send SNP", "circuit", c.cfg.Name, "error", err)
	}
}

// processCSNP reconciles the database against a CSNP: request LSPs we lack or
// that are newer at the sender (SSN), and re-send LSPs we hold that are newer
// or that the sender omitted from the covered range (SRM).
func (s *IsisServer) processCSNP(c *circuit, csnp *packet.CSNP, now time.Time) {
	level := csnp.Level
	db := s.dbs[level]
	if db == nil {
		return
	}
	listed := map[packet.LSPID]packet.LSPEntry{}
	for _, tlv := range csnp.TLVs {
		le, ok := tlv.(*packet.LSPEntriesTLV)
		if !ok {
			continue
		}
		for _, e := range le.Entries {
			listed[e.LSPID] = e
			local := db.get(e.LSPID)
			switch {
			case local == nil || newer(e.SequenceNumber, e.RemainingTime, local, now):
				c.setSSN(level, e.LSPID) // request it
			case local.lsp.SequenceNumber > e.SequenceNumber:
				c.setSRM(level, e.LSPID, now) // we have newer
			case local.lsp.SequenceNumber == e.SequenceNumber &&
				local.remaining(now) != 0 && e.RemainingTime != 0 &&
				local.lsp.Checksum() != e.Checksum:
				// Equal sequence, different content (ISO 10589 7.3.15): re-flood
				// our copy so the conflict surfaces on the full-LSP path, which
				// purges and lets the originator re-originate at a higher seq.
				c.setSRM(level, e.LSPID, now)
			default:
				c.clearSRM(level, e.LSPID)
			}
		}
	}
	// LSPs we hold within the CSNP range that the sender did not list: it is
	// missing them, so send them.
	for id := range db.entries {
		if _, ok := listed[id]; ok {
			continue
		}
		if inRange(id, csnp.StartLSP, csnp.EndLSP) {
			c.setSRM(level, id, now)
		}
	}
}

// processPSNP handles a PSNP: on p2p it acknowledges our LSPs (clearing SRM);
// on a LAN the DIS treats listed entries as requests and re-sends newer copies.
func (s *IsisServer) processPSNP(c *circuit, psnp *packet.PSNP, now time.Time) {
	level := psnp.Level
	db := s.dbs[level]
	if db == nil {
		return
	}
	for _, tlv := range psnp.TLVs {
		le, ok := tlv.(*packet.LSPEntriesTLV)
		if !ok {
			continue
		}
		for _, e := range le.Entries {
			local := db.get(e.LSPID)
			if c.cfg.P2P {
				// Acknowledgement: stop retransmitting if they confirm a
				// copy at least as new as ours.
				if local != nil && e.SequenceNumber >= local.lsp.SequenceNumber {
					c.clearSRM(level, e.LSPID)
				}
			} else if local != nil && (local.lsp.SequenceNumber > e.SequenceNumber ||
				(local.lsp.SequenceNumber == e.SequenceNumber &&
					local.remaining(now) != 0 && e.RemainingTime != 0 &&
					local.lsp.Checksum() != e.Checksum)) {
				// LAN request: we hold a newer copy, or an equal-sequence copy
				// with conflicting content (ISO 10589 7.3.15), so send it.
				c.setSRM(level, e.LSPID, now)
			}
		}
	}
}

// chunkEntries splits LSP entries into groups that fit one LSP Entries TLV.
func chunkEntries(entries []packet.LSPEntry) [][]packet.LSPEntry {
	if len(entries) == 0 {
		return nil
	}
	var out [][]packet.LSPEntry
	for i := 0; i < len(entries); i += packet.MaxLSPEntriesPerTLV {
		end := i + packet.MaxLSPEntriesPerTLV
		if end > len(entries) {
			end = len(entries)
		}
		out = append(out, entries[i:end])
	}
	return out
}

// inRange reports whether id lies within [start, end] inclusive.
func inRange(id, start, end packet.LSPID) bool {
	return bytes.Compare(id[:], start[:]) >= 0 && bytes.Compare(id[:], end[:]) <= 0
}
