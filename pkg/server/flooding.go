package server

import (
	"bytes"
	"sort"
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
		s.metrics.PDUDrop(c.cfg.Name, dropChecksum)
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

	if ex == nil && lsp.RemainingTime == 0 {
		// A purge for an LSP ID we do not hold is never entered into the
		// database (ISO 10589 7.3.16.4 a): on p2p acknowledge it so the sender
		// stops retransmitting, on a LAN ignore it. Storing it would let an
		// attacker fill the database (see WithLSDBEntryLimit) with purges for
		// LSPs that never existed.
		s.logger.Debug("ignore purge for unknown LSP", "circuit", c.cfg.Name, "level", level, "lsp", id)
		s.metrics.PDUDrop(c.cfg.Name, dropUnknownPurge)
		if c.cfg.P2P {
			c.setSSNAck(level, packet.LSPEntry{
				LSPID:          id,
				SequenceNumber: lsp.SequenceNumber,
				RemainingTime:  0,
				Checksum:       lsp.Checksum(),
			})
		}
		return
	}

	// Cap the database size against an attacker flooding fabricated LSP IDs
	// on an unauthenticated segment (see WithLSDBEntryLimit). Only new IDs
	// count: updates to known IDs never grow the map. Warn once per level
	// (re-armed when a new ID installs below the limit) — an unthrottled log
	// per attack PDU would turn the memory defense into log amplification on
	// the management loop.
	if ex == nil && s.lsdbEntryLimit > 0 && len(db.entries) >= s.lsdbEntryLimit {
		if !s.lsdbLimitWarned[level] {
			s.lsdbLimitWarned[level] = true
			s.logger.Warn("drop LSP: database at entry limit; suppressing repeats",
				"circuit", c.cfg.Name, "level", level, "lsp", id, "limit", s.lsdbEntryLimit)
		}
		s.metrics.PDUDrop(c.cfg.Name, dropLSDBLimit)
		return
	}
	if ex == nil {
		delete(s.lsdbLimitWarned, level) // headroom again: re-arm the warning
	}

	// An LSP carrying our own System ID is handled apart from foreign ones.
	// Placed after the entry-limit check so forged LSPs naming us cannot grow
	// the database past the cap.
	if s.handleOwnSystemID(c, lsp, ex, now) {
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

	// A neighbor's fragment 0 carries its interface addresses (TLV 232), which
	// is where a peer that lists only link-locals in its hellos (FRR, per RFC
	// 5308 3) publishes the global on-link address an End.X SID towards it
	// needs. Re-originate so the SID appears once that fragment arrives.
	if id.FragmentID() == 0 && id.IsNodeLSP() {
		if adj, _ := s.findAdjacency(id.NodeID().SystemID()); adj != nil {
			s.requestLSPRegen()
		}
	}

	// Flood to all other circuits; on the arrival circuit clear SRM and, on
	// p2p, acknowledge.
	s.floodLSP(level, id, c, now)
	c.clearSRM(level, id)
	if c.cfg.P2P {
		c.setSSN(level, id)
	}
}

// handleOwnSystemID applies the update process to a newer received LSP that
// carries our own System ID, and reports whether it consumed it (ISO 10589
// 7.3.16.4 b and c). A purge for an ID we do not hold never reaches here:
// processLSP drops it earlier under a).
func (s *IsisServer) handleOwnSystemID(c *circuit, lsp *packet.LSP, ex *lspEntry, now time.Time) bool {
	level, id := lsp.Level, lsp.LSPID
	if id.NodeID().SystemID() != s.systemID {
		return false
	}
	switch {
	case s.ownsLSP(level, id) && ex != nil && ex.own && ex.purgedAt.IsZero():
		// Someone advanced (or purged) an LSP we are currently originating;
		// re-originate with a higher sequence number to reclaim it (b).
		if lsp.SequenceNumber == maxLSPSeq {
			s.metrics.PDUDrop(c.cfg.Name, dropOwnSeqWrap)
		} else {
			s.metrics.PDUDrop(c.cfg.Name, dropOwnLSPReclaimed)
		}
		s.reoriginateOwn(level, id, lsp.SequenceNumber, now)
	case lsp.RemainingTime == 0:
		// A purge of an LSP we do not originate is already dead: let the
		// install path propagate and acknowledge it as for any foreign LSP.
		return false
	default:
		// Our System ID, but an LSP we do not originate: a fragment of our node
		// LSP we never built, a pseudonode LSP for a circuit where we are not
		// (or no longer) the DIS, or a pseudonode number matching none of our
		// circuits. Purge it rather than keep a stranger's claim about us alive
		// (b and c); there is nothing of ours to reclaim, so re-origination
		// would only lend our name to the forged body.
		reason := dropOwnSysIDPurge
		if id.IsNodeLSP() {
			reason = dropOwnFragmentPurge
		}
		s.metrics.PDUDrop(c.cfg.Name, reason)
		e := &lspEntry{lsp: lsp}
		s.dbs[level].entries[id] = e
		s.expirePurge(level, id, e, now)
	}
	return true
}

// reoriginateOwn rebuilds one of our own LSPs with a sequence number above
// the one just seen on the wire, then re-floods it.
func (s *IsisServer) reoriginateOwn(level packet.Level, id packet.LSPID, seenSeq uint32, now time.Time) {
	db := s.dbs[level]
	ex := db.get(id)
	if ex == nil {
		return
	}
	if seenSeq == maxLSPSeq {
		// seenSeq + 1 would wrap to 0, which every peer reads as older than
		// the copy that forced the wrap: it would flood that copy back and our
		// own LSP would never be accepted again. Run the exhaustion procedure
		// instead (ISO 10589 7.3.16.1).
		s.exhaustSeq(level, id, now)
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
	db.entries[id] = &lspEntry{lsp: &lsp, raw: raw, inserted: now, lifetime: maxAgeSeconds, own: true, refreshAt: refreshDeadline(now)}
	s.logger.Info("re-originate LSP", "level", level, "lsp", id, "seq", lsp.SequenceNumber)
	s.markDirty()
	s.floodLSP(level, id, nil, now)
}

// floodTransmit sends pending LSPs (SRM) and PSNPs (SSN), and emits periodic
// CSNPs where this node is the DIS. Called from housekeeping.
func (s *IsisServer) floodTransmit(now time.Time) {
	for _, c := range s.circuits {
		// A circuit whose link is down cannot carry anything; its SRM/SSN flags
		// keep waiting, and the neighbor resynchronizes when the link returns.
		// Without this every tick would log a send error per flagged LSP.
		if c.linkDown {
			continue
		}
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
	if !c.floodReady(level) {
		return // p2p with no Up adjacency: the flags are re-armed when one comes Up
	}
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
		wire := e.wire(now)
		// Our own LSPs are sized to fit every circuit (see WithLSPMTU), but a
		// foreign one is re-flooded from the octets we received and a transit
		// node may not re-fragment it (ISO 10589 7.3.3). One that overruns this
		// circuit can therefore never be sent here: drop the flag instead of
		// retrying it every second forever, and log once per circuit so the
		// repeat does not amplify into the management loop.
		if maxSize := c.cfg.Transport.MTU() - 3; len(wire) > maxSize { // 3 = LLC header
			if !c.oversizeWarned {
				c.oversizeWarned = true
				s.logger.Warn("LSP exceeds the circuit MTU; not flooded here; suppressing repeats",
					"circuit", c.cfg.Name, "lsp", id, "size", len(wire), "max", maxSize)
			}
			c.clearSRM(level, id)
			continue
		}
		if err := c.cfg.Transport.Send(c.dest(level), wire); err != nil {
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
	if len(c.ssn[level]) == 0 || !c.floodReady(level) {
		return // p2p with no Up adjacency: an acknowledgement to nobody
	}
	db := s.dbs[level]
	var entries []packet.LSPEntry
	for id := range c.ssn[level] {
		entry := packet.LSPEntry{LSPID: id}
		if e := db.get(id); e != nil {
			entry.RemainingTime = e.remaining(now)
			entry.SequenceNumber = e.lsp.SequenceNumber
			entry.Checksum = e.lsp.Checksum()
		} else if ack, ok := c.ssnAck[level][id]; ok {
			entry = ack
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
// more CSNPs spanning the whole LSP-ID range. One CSNP per database would
// exceed the receive buffer and the MTU past roughly 90 LSPs and fail to
// send, taking the LAN's only resynchronization mechanism with it (see
// transmitSRM), so the database is cut into consecutive ranges that each fit
// one PDU.
func (s *IsisServer) sendCSNP(c *circuit, level packet.Level, now time.Time) {
	db := s.dbs[level]
	entries := make([]packet.LSPEntry, 0, len(db.entries))
	for id, e := range db.entries {
		entries = append(entries, packet.LSPEntry{
			RemainingTime:  e.remaining(now),
			LSPID:          id,
			SequenceNumber: e.lsp.SequenceNumber,
			Checksum:       e.lsp.Checksum(),
		})
	}
	// A receiver treats LSP IDs as unsigned octet strings when testing them
	// against [StartLSP, EndLSP] (ISO 10589 7.3.15.2, see inRange), so sorting
	// that way is what makes each PDU's range contiguous.
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].LSPID[:], entries[j].LSPID[:]) < 0
	})

	budget := packet.ReceiveLSPBufferSize
	if mtu := c.cfg.Transport.MTU() - 3; mtu < budget { // 3 = LLC header
		budget = mtu
	}
	budget -= packet.HeaderLen(packet.PDUTypeL1CSNP) // both levels: 33 octets
	if spec := s.authKey(level); spec.on() {
		budget -= tlvLen(authTLVPlaceholder(spec)) // sendSNP appends it
	}

	var (
		tlvs  []packet.TLV
		size  int
		start packet.LSPID // the first CSNP starts at 00...00
		last  packet.LSPID // last LSP ID packed so far
	)
	flush := func(end packet.LSPID) {
		s.sendSNP(c, level, &packet.CSNP{
			Level:    level,
			SourceID: nodeID(s.systemID, c.pseudonodeID),
			StartLSP: start,
			EndLSP:   end,
			TLVs:     tlvs,
		})
		start = nextLSPID(end)
		tlvs, size = nil, 0
	}
	for _, chunk := range chunkEntries(entries) {
		n := tlvLen(&packet.LSPEntriesTLV{Entries: chunk})
		if size+n > budget && len(tlvs) > 0 {
			flush(last)
		}
		tlvs = append(tlvs, &packet.LSPEntriesTLV{Entries: chunk})
		size += n
		last = chunk[len(chunk)-1].LSPID
	}
	var end packet.LSPID
	for i := range end {
		end[i] = 0xff
	}
	flush(end) // the last CSNP ends at ff...ff, so the ranges cover everything
}

// syncCircuitLevel hands the whole database at a level to the neighbor of a
// point-to-point circuit that has just become usable there: SRM for every LSP
// we hold (ISO 10589 7.3.17) plus a CSNP describing the database (7.3.15.1),
// which also draws out LSPs the neighbor holds and we do not. A p2p circuit
// has no periodic CSNP — only the DIS of a LAN sends one, see floodTransmit —
// so without this an LSP already in the database when the link came up would
// never reach that neighbor.
func (s *IsisServer) syncCircuitLevel(c *circuit, level packet.Level, now time.Time) {
	for id := range s.dbs[level].entries {
		// Purged entries included: a neighbor that missed the purge would
		// otherwise keep the dead LSP until it aged out.
		c.setSRM(level, id, now)
	}
	s.sendCSNP(c, level, now)
}

// nextLSPID returns id + 1 read as an 8-octet unsigned integer: the start of
// the range following one that ends at id. Overflow at ff...ff cannot happen,
// because that value only ever ends the final range.
func nextLSPID(id packet.LSPID) packet.LSPID {
	for i := len(id) - 1; i >= 0; i-- {
		id[i]++
		if id[i] != 0 {
			break
		}
	}
	return id
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
// on a LAN only the DIS treats listed entries as requests and re-sends newer
// copies.
func (s *IsisServer) processPSNP(c *circuit, psnp *packet.PSNP, now time.Time) {
	level := psnp.Level
	// ISO 10589 7.3.15.2 b): on a broadcast circuit a PSNP is a request aimed
	// at the DIS, whose CSNPs carry the reliability. Were every system to act
	// on it, one request would draw a retransmission from each holder of a
	// newer copy.
	if !c.cfg.P2P && !c.isDIS(level, s.systemID) {
		return
	}
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
