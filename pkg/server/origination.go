package server

import (
	"bytes"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// isType returns this router's IS-Type field for its LSPs (1=L1, 2=L2,
// 3=L1L2), the union of the configured circuit levels.
func (s *IsisServer) isType() uint8 {
	var t uint8
	if s.levelCap.has(packet.Level1) {
		t |= 1
	}
	if s.levelCap.has(packet.Level2) {
		t |= 2
	}
	return t
}

// regenerateLSPs rebuilds this node's own LSPs for every level and floods any
// that changed. forceRefresh re-originates even when content is unchanged, to
// reset the remaining lifetime.
func (s *IsisServer) regenerateLSPs(forceRefresh bool, now time.Time) {
	// Reconcile the adjacency-scoped SRv6 SIDs first, so the TLV 22 entries
	// built below advertise the set that is (being) programmed.
	s.syncEndXSIDs(now)
	for _, l := range s.levelCap.levels() {
		s.regenerateNodeLSP(l, forceRefresh, now)
		s.regeneratePseudonodeLSPs(l, forceRefresh, now)
	}
}

// minLSPGenInterval is ISO 10589's minimumLSPGenerationInterval: the shortest
// spacing between two event-driven re-originations. Without it a flapping
// adjacency bumps our sequence number and floods a new LSP per flap. One
// second, not the standard's 30 s default, because modern deployments expect
// to converge in about that long — and it is the housekeeping tick, so a
// pending request is drained there even when no further event arrives.
const minLSPGenInterval = time.Second

// requestLSPRegen asks for a regeneration at the next drain. Every change to
// what our own LSPs say goes through here — protocol events and operator
// mutations alike — so minLSPGenInterval really bounds how often we
// re-originate. Only origination itself stays direct: startup, the refresh and
// reclaim in refreshOwnLSPs, and the startup-overload clear, none of which is a
// content change an interval should hold back. Regenerating directly would not
// show an operator their change any sooner: mgmtOperation replies from inside
// the loop iteration that ran the mutation, and that iteration drains before
// the next operation is dequeued, so the next RPC sees it — unless the
// preceding re-origination is less than minLSPGenInterval old, which is the
// throttle doing its job. The SPF flag is set right away: an adjacency loss
// must withdraw routes through the dead neighbor now, not when the coalesced
// LSP is finally built.
func (s *IsisServer) requestLSPRegen() {
	s.lspGenPending = true
	s.markDirty()
}

// drainLSPGen runs a pending regeneration once minLSPGenInterval has elapsed
// since the last one, so a burst of events costs one LSP rather than one each.
func (s *IsisServer) drainLSPGen(now time.Time) {
	if !s.lspGenPending || now.Before(s.nextLSPGen) {
		return
	}
	s.lspGenPending = false
	s.regenerateLSPs(false, now)
	s.nextLSPGen = now.Add(minLSPGenInterval)
}

// maxSubTLVArea is the sub-TLV area of one Extended IS Reachability entry: a
// single length octet.
const maxSubTLVArea = 255

// appendISReach appends one Extended IS Reachability entry for a neighbor,
// splitting it into several entries when its sub-TLVs overflow the sub-TLV
// area (many locators times many LAN neighbors). RFC 5305 §3 lets a neighbor
// appear in more than one entry, and receivers merge them; tlvChunks then
// packs the entries into TLVs.
func appendISReach(entries []packet.ExtendedISReachEntry, id packet.NodeID, metric uint32, subs []packet.SubTLV) []packet.ExtendedISReachEntry {
	for {
		e := packet.ExtendedISReachEntry{NeighborID: id, Metric: metric}
		size := 0
		for _, sub := range subs {
			n := subTLVLen(sub)
			if size+n > maxSubTLVArea && len(e.SubTLVs) > 0 {
				break
			}
			e.SubTLVs = append(e.SubTLVs, sub)
			size += n
		}
		entries = append(entries, e)
		subs = subs[len(e.SubTLVs):]
		if len(subs) == 0 {
			return entries
		}
	}
}

func subTLVLen(sub packet.SubTLV) int {
	b, err := sub.Serialize()
	if err != nil {
		return maxSubTLVArea + 1 // force it onto its own entry; Serialize then reports it
	}
	return len(b)
}

// tlvChunks splits entries into the fewest TLVs whose serialized form each
// fits the 255-octet TLV value limit (ISO 10589; the TLV interface contract
// requires producers to split). mk builds one TLV from a sub-slice. Without
// this, a reachability list that overflows a single TLV would make
// MarshalTLVs/Serialize fail and the node would originate nothing — a silent
// black hole. Returns nil for no entries.
func tlvChunks[E any](entries []E, mk func([]E) packet.TLV) []packet.TLV {
	var out []packet.TLV
	start := 0
	for i := 0; i < len(entries); i++ {
		// encodeTLV (via Serialize) fails once the value exceeds 255 octets.
		if _, err := mk(entries[start : i+1]).Serialize(); err == nil {
			continue // still fits; keep growing the chunk
		}
		if i == start {
			// A single entry overflows a TLV by itself; emit it alone and let
			// the LSP-size guard surface any resulting over-size LSP.
			out = append(out, mk(entries[start:i+1]))
			start = i + 1
			continue
		}
		out = append(out, mk(entries[start:i])) // entries[start:i] is the largest that fit
		start = i
		i-- // reconsider entries[i] as the first of the next chunk
	}
	if start < len(entries) {
		out = append(out, mk(entries[start:]))
	}
	return out
}

// originatedPrefixes derives the prefixes this node advertises from the two
// owners of that fact: the prefixes an option or AddPrefix named (with their
// metric) and the connected subnets each circuit contributes (at that circuit's
// metric). One entry per masked prefix — an operator naming a prefix outranks
// the circuit that happens to have it connected, and a subnet connected on two
// circuits takes the better of their metrics — and sorted, so a regeneration
// that changed nothing marshals identically and does not re-flood.
func (s *IsisServer) originatedPrefixes() []AdvertisedPrefix {
	metrics := make(map[netip.Prefix]uint32, len(s.optionPrefixes)+len(s.circuitPrefixes))
	for _, c := range s.circuits {
		for _, p := range s.circuitPrefixes[c.cfg.Name] {
			if m, ok := metrics[p]; !ok || c.cfg.Metric < m {
				metrics[p] = c.cfg.Metric
			}
		}
	}
	for p, ap := range s.optionPrefixes {
		metrics[p] = ap.Metric
	}
	out := make([]AdvertisedPrefix, 0, len(metrics))
	for p, m := range metrics {
		out = append(out, AdvertisedPrefix{Prefix: p, Metric: m})
	}
	slices.SortFunc(out, func(a, b AdvertisedPrefix) int { return a.Prefix.Compare(b.Prefix) })
	return out
}

// regenerateNodeLSP builds this node's own LSP at a level, fragmenting it
// across fragment numbers 1..255 when the TLVs exceed one LSP.
func (s *IsisServer) regenerateNodeLSP(level packet.Level, forceRefresh bool, now time.Time) {
	// Fixed TLVs stay in fragment 0: area addresses, supported protocols, the
	// dynamic hostname, and the Router Capability TLV (SRv6 / Flex-Algo).
	fixed := []packet.TLV{
		&packet.AreaAddressesTLV{Addresses: s.areaAddrs},
		&packet.ProtocolsSupportedTLV{NLPIDs: []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}},
	}
	if s.hostname != "" {
		fixed = append(fixed, &packet.DynamicHostnameTLV{Hostname: s.hostname})
	}
	if caps := s.routerCapabilitySubTLVs(); len(caps) > 0 {
		fixed = append(fixed, &packet.RouterCapabilityTLV{RouterID: s.routerID(), SubTLVs: caps})
	}
	// Our non-link-local IPv6 addresses (TLV 232). They belong in fragment 0
	// because that is the one fragment a peer looks in for them (endXNexthop):
	// an End.X SID towards us has to forward to a global address of ours that
	// is on its link, and the hello cannot publish one (RFC 5308 3 keeps the
	// IIH link-local).
	fixed = append(fixed, tlvChunks(s.lspIPv6Addrs(), func(a []netip.Addr) packet.TLV {
		return &packet.IPv6InterfaceAddressesTLV{Addresses: a}
	})...)

	// Variable TLVs may spill into fragments 1..255.
	var variable []packet.TLV

	// IS reachability: on a broadcast circuit point at the DIS pseudonode;
	// on p2p point directly at the neighbor.
	var neighbors []packet.ExtendedISReachEntry
	for _, c := range s.circuits {
		if c.cfg.P2P {
			if adj := c.p2pAdj; adj != nil && adj.state == AdjUp && adj.levels.has(level) {
				neighbors = appendISReach(neighbors, nodeID(adj.systemID, 0), c.cfg.Metric,
					s.endXSubTLVs(c, adj))
			}
			continue
		}
		if _, ok := c.adjs[level]; !ok {
			continue
		}
		dis := c.dis[level]
		if dis == (packet.NodeID{}) || len(c.upAdjacencies(level)) == 0 {
			continue // no usable pseudonode yet
		}
		neighbors = appendISReach(neighbors, dis, c.cfg.Metric, s.lanEndXSubTLVs(c, level))
	}
	variable = append(variable, tlvChunks(neighbors, func(n []packet.ExtendedISReachEntry) packet.TLV {
		return &packet.ExtendedISReachabilityTLV{Neighbors: n}
	})...)

	// IP reachability: prefixes this node originates (TLV 135 for IPv4, 236
	// for IPv6).
	var v4 []packet.ExtendedIPReachEntry
	var v6 []packet.IPv6ReachEntry
	for _, p := range s.originatedPrefixes() {
		// Export policy: suppress prefixes the filter rejects. Flooding and the
		// LSDB are untouched — we simply originate fewer reachability entries.
		if s.advertiseFilter != nil && !s.advertiseFilter(p) {
			continue
		}
		if p.Prefix.Addr().Is4() {
			v4 = append(v4, packet.ExtendedIPReachEntry{Metric: p.Metric, Prefix: p.Prefix})
		} else {
			v6 = append(v6, packet.IPv6ReachEntry{Metric: p.Metric, Prefix: p.Prefix})
		}
	}
	// Mirror algorithm-0 SRv6 locators into IPv6 reachability (TLV 236, metric
	// 0) so peers that don't parse the SRv6 Locator TLV still install a route
	// (RFC 9352 SHOULD). Flex-Algo locators are NOT mirrored: a 236 entry is
	// algorithm-0 reachability and would let algorithm-0 SPF install the
	// locator, defeating the per-algorithm path (no-fallback).
	for _, lc := range s.locators {
		if lc.Algo == 0 {
			v6 = append(v6, packet.IPv6ReachEntry{Metric: 0, Prefix: lc.Prefix.Masked()})
		}
	}
	// ISO 10589 7.2.9 / RFC 1195 §3.1: the Level-2 LSP of an L1L2 IS also
	// carries what is reachable inside its Level-1 area (updateRIB's l1Export).
	// Sorted, because originate compares the marshalled body and a map's range
	// order would re-flood the LSP on every regeneration. The up/down bit stays
	// clear: this is the upward direction (RFC 5305 §4.1).
	if level == packet.Level2 && s.levelCap.has(packet.Level1) {
		for _, p := range slices.SortedFunc(maps.Keys(s.l1Export), netip.Prefix.Compare) {
			m := min(s.l1Export[p], maxPathMetric-1)
			// Export policy again: these entries are originated by this node
			// too. l1ExportSet has already dropped what we advertise ourselves,
			// so no prefix is put to the filter twice.
			if s.advertiseFilter != nil && !s.advertiseFilter(AdvertisedPrefix{Prefix: p, Metric: m}) {
				continue
			}
			if p.Addr().Is4() {
				v4 = append(v4, packet.ExtendedIPReachEntry{Metric: m, Prefix: p})
			} else {
				v6 = append(v6, packet.IPv6ReachEntry{Metric: m, Prefix: p})
			}
		}
	}
	// The other direction (ISO 10589 7.2.9 / RFC 5305 §4.1 / RFC 5308 §2): the
	// Level-1 LSP of an L1L2 IS carries the Level-2 prefixes an operator asked
	// it to leak down (updateRIB's l2Leak), each with the up/down bit set so no
	// L1L2 IS sends it back up. The leak policy has already decided the set and
	// clamped the metric; the advertise policy is deliberately not applied on
	// top, so an allowlist of this node's own prefixes does not silently empty
	// the leak as well.
	if level == packet.Level1 && s.levelCap.has(packet.Level2) {
		for _, p := range slices.SortedFunc(maps.Keys(s.l2Leak), netip.Prefix.Compare) {
			if p.Addr().Is4() {
				v4 = append(v4, packet.ExtendedIPReachEntry{Metric: s.l2Leak[p], Prefix: p, Down: true})
			} else {
				v6 = append(v6, packet.IPv6ReachEntry{Metric: s.l2Leak[p], Prefix: p, Down: true})
			}
		}
	}
	variable = append(variable, tlvChunks(v4, func(e []packet.ExtendedIPReachEntry) packet.TLV {
		return &packet.ExtendedIPReachabilityTLV{Prefixes: e}
	})...)
	variable = append(variable, tlvChunks(v6, func(e []packet.IPv6ReachEntry) packet.TLV {
		return &packet.IPv6ReachabilityTLV{Prefixes: e}
	})...)

	// SRv6 Locator TLV (27): the locators with their local End SIDs.
	if len(s.locators) > 0 {
		locs := make([]packet.SRv6Locator, 0, len(s.locators))
		for _, lc := range s.locators {
			locs = append(locs, lc.locatorEntry())
		}
		variable = append(variable, tlvChunks(locs, func(l []packet.SRv6Locator) packet.TLV {
			return &packet.SRv6LocatorTLV{Locators: l}
		})...)
	}

	att := level == packet.Level1 && s.levelCap.has(packet.Level2)
	s.originateFragmented(level, 0, fixed, variable, att, forceRefresh, now)
}

// regeneratePseudonodeLSPs originates (or purges) this node's pseudonode LSPs
// for the broadcast circuits where it is DIS.
func (s *IsisServer) regeneratePseudonodeLSPs(level packet.Level, forceRefresh bool, now time.Time) {
	for _, c := range s.circuits {
		if c.cfg.P2P {
			continue
		}
		if !c.isDIS(level, s.systemID) {
			// We are not DIS here: purge every pseudonode LSP fragment we own.
			s.purgeStaleFragments(level, c.pseudonodeID, 0, now)
			continue
		}
		// Members: ourselves plus every Up adjacency, all at metric 0. Sort
		// by neighbor ID so the encoding is deterministic (upAdjacencies
		// ranges a map); otherwise the content-unchanged check spuriously
		// fails and bumps the sequence number.
		neighbors := []packet.ExtendedISReachEntry{{NeighborID: nodeID(s.systemID, 0)}}
		for _, adj := range c.upAdjacencies(level) {
			neighbors = append(neighbors, packet.ExtendedISReachEntry{NeighborID: nodeID(adj.systemID, 0)})
		}
		sort.Slice(neighbors, func(i, j int) bool {
			return bytes.Compare(neighbors[i].NeighborID[:], neighbors[j].NeighborID[:]) < 0
		})
		variable := tlvChunks(neighbors, func(n []packet.ExtendedISReachEntry) packet.TLV {
			return &packet.ExtendedISReachabilityTLV{Neighbors: n}
		})
		s.originateFragmented(level, c.pseudonodeID, nil, variable, false, forceRefresh, now)
	}
}

// originateFragmented splits a node's (or pseudonode's) TLV set across LSP
// fragments so each fragment fits this node's LSP buffer, originates each, and
// purges any higher-numbered fragments left over from a larger prior
// origination. The fixed TLVs stay in fragment 0; att and the overload bit
// apply to fragment 0 only.
func (s *IsisServer) originateFragmented(level packet.Level, pseudonode uint8, fixed, variable []packet.TLV, att, forceRefresh bool, now time.Time) {
	// Reserve the LSP header and, when the level is authenticated, the
	// Authentication TLV that originate appends to each fragment.
	budget := s.lspBufferSize - packet.HeaderLen(packet.PDUTypeL2LSP)
	if spec := s.authKey(level); spec.on() {
		budget -= tlvLen(authTLVPlaceholder(spec))
	}

	frags := packLSPFragments(fixed, variable, budget)
	for n, ftlvs := range frags {
		if n > 255 {
			s.logger.Error("LSP needs more than 256 fragments; truncating",
				"system_id", s.systemID, "pseudonode", pseudonode)
			break
		}
		id := lspIDFrag(s.systemID, pseudonode, uint8(n)) //nolint:gosec // bounded by the n > 255 guard
		s.originate(level, id, ftlvs, att && n == 0, forceRefresh, now)
	}
	count := len(frags)
	if count > 256 {
		count = 256
	}
	s.purgeStaleFragments(level, pseudonode, count, now)
}

// packLSPFragments distributes TLVs across fragments whose serialized TLV area
// each fits budget. fixed TLVs occupy fragment 0; variable TLVs fill fragment 0
// and spill into further fragments in order. Always returns at least one
// fragment.
func packLSPFragments(fixed, variable []packet.TLV, budget int) [][]packet.TLV {
	frags := [][]packet.TLV{append([]packet.TLV(nil), fixed...)}
	size := tlvsLen(fixed)
	cur := 0
	for _, t := range variable {
		ts := tlvLen(t)
		if size+ts > budget && len(frags[cur]) > 0 {
			frags = append(frags, nil)
			cur++
			size = 0
		}
		frags[cur] = append(frags[cur], t)
		size += ts
	}
	return frags
}

func tlvLen(t packet.TLV) int {
	b, err := t.Serialize()
	if err != nil {
		return packet.ReceiveLSPBufferSize // force it onto its own fragment
	}
	return len(b)
}

func tlvsLen(tlvs []packet.TLV) int {
	n := 0
	for _, t := range tlvs {
		n += tlvLen(t)
	}
	return n
}

// purgeStaleFragments purges this node's own LSP fragments numbered >= keep for
// the given pseudonode — fragments left behind when the TLV set shrank, or all
// fragments (keep == 0) when relinquishing a pseudonode.
func (s *IsisServer) purgeStaleFragments(level packet.Level, pseudonode uint8, keep int, now time.Time) {
	db := s.dbs[level]
	for id, e := range db.entries {
		if !e.own || !e.purgedAt.IsZero() {
			continue
		}
		nid := id.NodeID()
		if nid.SystemID() != s.systemID || nid.PseudonodeID() != pseudonode {
			continue
		}
		if int(id.FragmentID()) >= keep {
			s.purgeOwn(level, id, now)
		}
	}
}

// originate installs a self-originated LSP, bumping its sequence number when
// the content changed (or on a forced refresh), and floods it on every
// circuit at the level.
func (s *IsisServer) originate(level packet.Level, id packet.LSPID, tlvs []packet.TLV, att, forceRefresh bool, now time.Time) {
	db := s.dbs[level]
	ex := db.get(id)
	// An ID whose sequence number space was exhausted stays un-originated until
	// its purge has aged out area-wide, then restarts at 1 (ISO 10589 7.3.16.1;
	// see exhaustSeq). refreshOwnLSPs clears the hold-down.
	if until, held := s.seqWrapUntil[lspKey{level: level, id: id}]; held && now.Before(until) {
		return
	}
	// The overload bit applies to fragment 0 of this node's own LSP, not to
	// pseudonode LSPs or higher fragments (SPF reads it from fragment 0).
	overload := id.IsNodeLSP() && id.FragmentID() == 0 && s.overloaded(now)

	// Carry an HMAC-MD5 Authentication TLV (zeroed; filled by serializeLSP) when
	// the level is authenticated. It is part of the content-unchanged check, so
	// it stays stable across refreshes.
	if spec := s.authKey(level); spec.on() {
		tlvs = append(tlvs, authTLVPlaceholder(spec))
	}

	newBody, err := packet.MarshalTLVs(tlvs)
	if err != nil {
		s.logger.Error("serialize own LSP body", "lsp", id, "error", err)
		return
	}
	// Unchanged only if the header flags match too: an OL/ATT flip with
	// identical TLVs must still re-originate (e.g. clearing the startup OL bit).
	if ex != nil && ex.own && ex.purgedAt.IsZero() && !forceRefresh &&
		ex.lsp.Overload == overload && ex.lsp.AttDefault == att {
		if exBody, err := packet.MarshalTLVs(ex.lsp.TLVs); err == nil && bytes.Equal(newBody, exBody) {
			return // unchanged
		}
	}

	seq := uint32(1)
	if ex != nil {
		if ex.lsp.SequenceNumber == maxLSPSeq {
			// Bumping would serialize 0; run the exhaustion procedure instead
			// (ISO 10589 7.3.16.1).
			s.exhaustSeq(level, id, now)
			return
		}
		seq = ex.lsp.SequenceNumber + 1
	}
	lsp := &packet.LSP{
		Level:          level,
		RemainingTime:  maxAgeSeconds,
		LSPID:          id,
		SequenceNumber: seq,
		AttDefault:     att,
		Overload:       overload,
		ISType:         s.isType(),
		TLVs:           tlvs,
	}
	raw, err := s.serializeLSP(lsp)
	if err != nil {
		s.logger.Error("serialize own LSP", "lsp", id, "error", err)
		return
	}
	// originateFragmented keeps each fragment within the buffer; reaching here
	// means a single fragment's fixed TLVs plus one variable TLV still overflow
	// (pathological). Surface it loudly and drop the fragment rather than
	// storing and flooding an LSP peers discard (see WithLSPMTU).
	if len(raw) > s.lspBufferSize {
		s.logger.Error("own LSP fragment exceeds the maximum size; not originated",
			"lsp", id, "size", len(raw), "max", s.lspBufferSize)
		return
	}
	db.entries[id] = &lspEntry{lsp: lsp, raw: raw, inserted: now, lifetime: maxAgeSeconds, own: true, refreshAt: refreshDeadline(now)}
	s.logger.Info("originate LSP", "level", level, "lsp", id, "seq", seq)
	s.markDirty()
	s.floodLSP(level, id, nil, now)
}

// floodLSP sets SRM for an LSP on every circuit at the level, optionally
// excluding the circuit it arrived on (split horizon).
func (s *IsisServer) floodLSP(level packet.Level, id packet.LSPID, except *circuit, now time.Time) {
	for _, c := range s.circuits {
		if c == except {
			continue
		}
		if _, ok := c.srm[level]; !ok {
			continue
		}
		c.setSRM(level, id, now)
		c.clearSSN(level, id)
	}
}

// routerCapabilitySubTLVs builds the sub-TLVs of this node's Router Capability
// TLV (242): the SRv6 Capabilities sub-TLV when locators are configured, and —
// when Flex-Algos are configured — the SR-Algorithm sub-TLV (algo 0 plus every
// participated algorithm) followed by a FAD sub-TLV per advertised definition.
func (s *IsisServer) routerCapabilitySubTLVs() []packet.SubTLV {
	var caps []packet.SubTLV
	if len(s.locators) > 0 {
		caps = append(caps, &packet.SRv6CapabilitiesSubTLV{})
	}
	if len(s.flexAlgos) > 0 {
		algos := []uint8{0} // algorithm 0 (normal SPF) is always supported
		for _, fa := range s.flexAlgos {
			algos = append(algos, fa.Algo)
		}
		caps = append(caps, &packet.SRAlgorithmSubTLV{Algorithms: algos})
		for _, fa := range s.flexAlgos {
			if fa.AdvertiseDefinition {
				caps = append(caps, &packet.FlexAlgoDefinitionSubTLV{
					FlexAlgo:   fa.Algo,
					MetricType: fa.MetricType,
					CalcType:   0,
					Priority:   fa.Priority,
				})
			}
		}
	}
	return caps
}

// routerID returns the IPv4 router ID advertised in the Router Capability TLV:
// the first configured IPv4 interface address, or the zero address if none.
func (s *IsisServer) routerID() netip.Addr {
	for _, c := range s.circuits {
		for _, a := range c.cfg.IPv4Addrs {
			if a.Is4() {
				return a
			}
		}
	}
	return netip.Addr{}
}

// lspIPv6Addrs returns the node's non-link-local IPv6 interface addresses, in
// circuit order and without repeats (an address may sit on two circuits).
// Sorting is unnecessary and unwanted: the circuit order is already stable, and
// originate compares the marshalled body, so any reshuffle would re-flood.
func (s *IsisServer) lspIPv6Addrs() []netip.Addr {
	var out []netip.Addr
	for _, c := range s.circuits {
		for _, a := range c.cfg.IPv6Addrs {
			// IsGlobalUnicast is the same test onLinkAddr applies to a peer's
			// addresses: whatever we advertise here must be usable there.
			if !a.Is6() || a.Is4In6() || !a.IsGlobalUnicast() || slices.Contains(out, a) {
				continue
			}
			out = append(out, a)
		}
	}
	return out
}

// lspID builds a fragment-0 LSP ID from a system ID and pseudonode octet.
func lspID(id packet.SystemID, pseudonode uint8) packet.LSPID {
	return lspIDFrag(id, pseudonode, 0)
}

// lspIDFrag builds an LSP ID for a specific fragment number.
func lspIDFrag(id packet.SystemID, pseudonode, fragment uint8) packet.LSPID {
	var l packet.LSPID
	copy(l[:6], id[:])
	l[6] = pseudonode
	l[7] = fragment
	return l
}
