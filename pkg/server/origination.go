package server

import (
	"bytes"
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
	for _, l := range s.levelCap.levels() {
		s.regenerateNodeLSP(l, forceRefresh, now)
		s.regeneratePseudonodeLSPs(l, forceRefresh, now)
	}
	// A topology/adjacency change warrants an SPF recompute even when our own
	// LSP content is unchanged (e.g. a redundant next hop was lost).
	s.markDirty()
}

// regenerateNodeLSP builds fragment 0 of this node's own LSP at a level.
func (s *IsisServer) regenerateNodeLSP(level packet.Level, forceRefresh bool, now time.Time) {
	tlvs := []packet.TLV{
		&packet.AreaAddressesTLV{Addresses: s.areaAddrs},
		&packet.ProtocolsSupportedTLV{NLPIDs: []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}},
	}
	if s.hostname != "" {
		tlvs = append(tlvs, &packet.DynamicHostnameTLV{Hostname: s.hostname})
	}

	// IS reachability: on a broadcast circuit point at the DIS pseudonode;
	// on p2p point directly at the neighbor.
	var neighbors []packet.ExtendedISReachEntry
	for _, c := range s.circuits {
		if c.cfg.P2P {
			if adj := c.p2pAdj; adj != nil && adj.state == AdjUp && adj.levels.has(level) {
				neighbors = append(neighbors, packet.ExtendedISReachEntry{
					NeighborID: nodeID(adj.systemID, 0),
					Metric:     c.cfg.Metric,
				})
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
		neighbors = append(neighbors, packet.ExtendedISReachEntry{
			NeighborID: dis,
			Metric:     c.cfg.Metric,
		})
	}
	if len(neighbors) > 0 {
		tlvs = append(tlvs, &packet.ExtendedISReachabilityTLV{Neighbors: neighbors})
	}

	// IP reachability: prefixes this node originates (TLV 135 for IPv4, 236
	// for IPv6).
	var v4 []packet.ExtendedIPReachEntry
	var v6 []packet.IPv6ReachEntry
	for _, p := range s.prefixes {
		if p.Prefix.Addr().Is4() {
			v4 = append(v4, packet.ExtendedIPReachEntry{Metric: p.Metric, Prefix: p.Prefix})
		} else {
			v6 = append(v6, packet.IPv6ReachEntry{Metric: p.Metric, Prefix: p.Prefix})
		}
	}
	if len(v4) > 0 {
		tlvs = append(tlvs, &packet.ExtendedIPReachabilityTLV{Prefixes: v4})
	}
	if len(v6) > 0 {
		tlvs = append(tlvs, &packet.IPv6ReachabilityTLV{Prefixes: v6})
	}

	att := level == packet.Level1 && s.levelCap.has(packet.Level2)
	s.originate(level, lspID(s.systemID, 0), tlvs, att, forceRefresh, now)
}

// regeneratePseudonodeLSPs originates (or purges) this node's pseudonode LSPs
// for the broadcast circuits where it is DIS.
func (s *IsisServer) regeneratePseudonodeLSPs(level packet.Level, forceRefresh bool, now time.Time) {
	for _, c := range s.circuits {
		if c.cfg.P2P {
			continue
		}
		id := lspID(s.systemID, c.pseudonodeID)
		if !c.isDIS(level, s.systemID) {
			// We are not DIS here: purge any pseudonode LSP we own.
			if e := s.dbs[level].get(id); e != nil && e.own && e.purgedAt.IsZero() {
				s.purgeOwn(level, id, now)
			}
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
		tlvs := []packet.TLV{&packet.ExtendedISReachabilityTLV{Neighbors: neighbors}}
		s.originate(level, id, tlvs, false, forceRefresh, now)
	}
}

// originate installs a self-originated LSP, bumping its sequence number when
// the content changed (or on a forced refresh), and floods it on every
// circuit at the level.
func (s *IsisServer) originate(level packet.Level, id packet.LSPID, tlvs []packet.TLV, att, forceRefresh bool, now time.Time) {
	db := s.dbs[level]
	ex := db.get(id)

	newBody, err := packet.MarshalTLVs(tlvs)
	if err != nil {
		s.logger.Error("serialize own LSP body", "lsp", id, "error", err)
		return
	}
	if ex != nil && ex.own && ex.purgedAt.IsZero() && !forceRefresh {
		if exBody, err := packet.MarshalTLVs(ex.lsp.TLVs); err == nil && bytes.Equal(newBody, exBody) {
			return // unchanged
		}
	}

	seq := uint32(1)
	if ex != nil {
		seq = ex.lsp.SequenceNumber + 1
	}
	lsp := &packet.LSP{
		Level:          level,
		RemainingTime:  maxAgeSeconds,
		LSPID:          id,
		SequenceNumber: seq,
		AttDefault:     att,
		ISType:         s.isType(),
		TLVs:           tlvs,
	}
	raw, err := lsp.Serialize()
	if err != nil {
		s.logger.Error("serialize own LSP", "lsp", id, "error", err)
		return
	}
	db.entries[id] = &lspEntry{lsp: lsp, raw: raw, inserted: now, lifetime: maxAgeSeconds, own: true}
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

// lspID builds a fragment-0 LSP ID from a system ID and pseudonode octet.
// goisis originates only fragment 0 today; LSP fragmentation is future work.
func lspID(id packet.SystemID, pseudonode uint8) packet.LSPID {
	var l packet.LSPID
	copy(l[:6], id[:])
	l[6] = pseudonode
	return l
}
