package server

import (
	"bytes"
	"cmp"
	"maps"
	"net/netip"
	"slices"

	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// endXKey identifies one End.X SID. It is keyed on the adjacency — a locator,
// the circuit and the neighbor on it — and deliberately not on the level: the
// SID forwards to a link, so an L1L2 neighbor gets one SID advertised at both
// levels rather than two SIDs for the same link.
type endXKey struct {
	locator  netip.Prefix
	circuit  string
	neighbor packet.SystemID
}

// endXSID is an allocated End.X SID and the next hop it forwards to.
type endXSID struct {
	sid      netip.Addr
	function uint32     // position in the locator's function space (0 is the End SID)
	nexthop  netip.Addr // the neighbor's global on-link address (see endXNexthop)
}

// endXAdjKey names one adjacency, without the locator: the granularity at
// which the "no usable next hop" warning is edge-triggered.
type endXAdjKey struct {
	circuit  string
	neighbor packet.SystemID
}

// endXAdj pairs an adjacency with the circuit it is on.
type endXAdj struct {
	circuit *circuit
	adj     *adjacency
}

// endXAdjs returns the Up adjacencies that get End.X SIDs, one per (circuit,
// neighbor), ordered by circuit and then system ID. The order is fixed because
// it decides which function value each adjacency gets: an unstable order would
// reshuffle the SIDs and re-flood our LSP on every regeneration.
func (s *IsisServer) endXAdjs() []endXAdj {
	var out []endXAdj
	for _, c := range s.circuits {
		if c.cfg.P2P {
			if adj := c.p2pAdj; adj != nil && adj.state == AdjUp {
				out = append(out, endXAdj{circuit: c, adj: adj})
			}
			continue
		}
		seen := map[packet.SystemID]*adjacency{}
		for _, l := range c.cfg.levels() {
			for _, adj := range c.upAdjacencies(l) {
				seen[adj.systemID] = adj
			}
		}
		for _, id := range sortedSystemIDs(seen) {
			out = append(out, endXAdj{circuit: c, adj: seen[id]})
		}
	}
	return out
}

func sortedSystemIDs[V any](m map[packet.SystemID]V) []packet.SystemID {
	ids := make([]packet.SystemID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b packet.SystemID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

// syncEndXSIDs reconciles the End.X SIDs with the current adjacency set:
// it releases the SIDs of adjacencies (or locators) that are gone, allocates
// one per (locator, adjacency) that is new, and reprograms the FIB. It runs
// from the LSP regeneration path — every adjacency change already converges
// there — so the adjacency state machine needs no hook of its own.
func (s *IsisServer) syncEndXSIDs() {
	if len(s.locators) == 0 && len(s.endXSIDs) == 0 {
		clear(s.endXNoNexthop) // nothing to warn about without a locator
		return
	}
	type want struct {
		key     endXKey
		locator SRv6LocatorConfig
		nexthop netip.Addr
	}
	wanted := make([]want, 0, len(s.endXSIDs))
	live := make(map[endXKey]bool, len(s.endXSIDs))
	eas := s.endXAdjs()
	adjs := make(map[endXAdjKey]bool, len(eas))
	for _, ea := range eas {
		ak := endXAdjKey{circuit: ea.circuit.cfg.Name, neighbor: ea.adj.systemID}
		adjs[ak] = true
		nh := s.endXNexthop(ea.circuit, ea.adj)
		if !nh.IsValid() {
			// Nothing to allocate, advertise or program: an End.X SID with no
			// routable next hop is a black hole that pulls traffic in (see
			// endXNexthop). Warn once, re-armed when the address appears.
			if !s.endXNoNexthop[ak] {
				s.endXNoNexthop[ak] = true
				s.logger.Warn("no on-link global IPv6 address for neighbor; no End.X SID advertised",
					"circuit", ak.circuit, "neighbor", ak.neighbor)
			}
			continue
		}
		delete(s.endXNoNexthop, ak)
		for _, lc := range s.locators {
			k := endXKey{locator: lc.Prefix.Masked(), circuit: ak.circuit, neighbor: ak.neighbor}
			live[k] = true
			wanted = append(wanted, want{key: k, locator: lc, nexthop: nh})
		}
	}
	maps.DeleteFunc(s.endXNoNexthop, func(k endXAdjKey, _ bool) bool { return !adjs[k] })
	// Release first, so a function freed by an adjacency that just went down
	// is available to one that just came up.
	for k, e := range s.endXSIDs {
		if live[k] {
			continue
		}
		s.unprogramSID(e.sid, "neighbor", k.neighbor)
		delete(s.endXSIDs, k)
	}
	for _, w := range wanted {
		e, ok := s.endXSIDs[w.key]
		if !ok {
			if e, ok = s.allocEndXSID(w.locator); !ok {
				continue
			}
			s.logger.Info("allocate End.X SID", "sid", e.sid, "circuit", w.key.circuit, "neighbor", w.key.neighbor)
		}
		e.nexthop = w.nexthop
		s.endXSIDs[w.key] = e
	}
	s.installEndXSIDs()
}

// endXNexthop returns the address an End.X SID towards this adjacency must
// forward to: a global neighbor address that lies inside one of the circuit's
// directly-connected IPv6 prefixes. An invalid Addr means there is none.
//
// Why not the link-local next hop RFC 5308 3 reserves for IS-IS, and that the
// RIB uses: Linux resolves an End.X next hop with seg6_lookup_any_nexthop,
// which sets flowi6_iif and, for a link-local destination, RT6_LOOKUP_F_IFACE
// — so the lookup is confined to the interface the packet arrived on and the
// seg6local route's own device plays no part. A link-local next hop therefore
// only forwards a packet that entered on the egress link (a hairpin) and drops
// every transit packet, which is the case the SID exists for. A global address
// on the circuit's own subnet resolves through that connected route from any
// ingress interface.
//
// The peer's fragment-0 LSP is where the address normally comes from: TLV 232
// of a hello carries link-locals (RFC 5308 3 — goisis and FRR both send only
// those), TLV 232 of an LSP carries the global ones. Hellos are still consulted
// first, for a peer that does list a global address there.
func (s *IsisServer) endXNexthop(c *circuit, adj *adjacency) netip.Addr {
	if a := s.onLinkAddr(c, adj.neighborIPv6); a.IsValid() {
		return a
	}
	for _, l := range adj.levels.levels() {
		db := s.dbs[l]
		if db == nil {
			continue
		}
		e := db.get(lspID(adj.systemID, 0))
		if e == nil || !e.purgedAt.IsZero() {
			continue
		}
		for _, tlv := range e.lsp.TLVs {
			t, ok := tlv.(*packet.IPv6InterfaceAddressesTLV)
			if !ok {
				continue
			}
			if a := s.onLinkAddr(c, t.Addresses); a.IsValid() {
				return a
			}
		}
	}
	return netip.Addr{}
}

// onLinkAddr returns the first global IPv6 address in addrs that falls inside
// one of the circuit's directly-connected prefixes, or an invalid Addr.
func (s *IsisServer) onLinkAddr(c *circuit, addrs []netip.Addr) netip.Addr {
	for _, a := range addrs {
		if !a.Is6() || a.Is4In6() || !a.IsGlobalUnicast() {
			continue
		}
		for _, p := range s.circuitPrefixes[c.cfg.Name] {
			if p.Contains(a) {
				return a
			}
		}
		// A prefix from WithConnectedPrefix says a subnet is connected without
		// saying on which circuit (unlike CircuitConfig.ConnectedPrefixes);
		// accept it anywhere rather than withhold a SID the addressing
		// supports.
		for p := range s.optionConnected {
			if p.Contains(a) {
				return a
			}
		}
	}
	return netip.Addr{}
}

// allocEndXSID picks the smallest unused function value in a locator's
// function space and returns the SID it names. Function 0 is the locator's own
// End SID, so End.X functions start at 1 — which is also what FRR allocates.
func (s *IsisServer) allocEndXSID(lc SRv6LocatorConfig) (endXSID, bool) {
	loc := lc.Prefix.Masked()
	// sidStructure caps the function at 16 bits, so both the scan below and
	// the shift are bounded.
	bits := int(lc.sidStructure().Function)
	if bits == 0 {
		s.logger.Warn("SRv6 locator leaves no function bits for End.X SIDs", "locator", loc)
		return endXSID{}, false
	}
	used := map[uint32]bool{}
	for k, e := range s.endXSIDs {
		if k.locator == loc {
			used[e.function] = true
		}
	}
	for fn := uint32(1); fn < 1<<bits; fn++ {
		if !used[fn] {
			return endXSID{sid: locatorSID(loc, bits, fn), function: fn}, true
		}
	}
	s.logger.Warn("SRv6 locator function space exhausted; no End.X SID allocated",
		"locator", loc, "functions", len(used))
	return endXSID{}, false
}

// locatorSID places a function value in the bits immediately after a locator
// prefix, the layout the SID Structure sub-sub-TLV advertises.
func locatorSID(loc netip.Prefix, fnBits int, fn uint32) netip.Addr {
	b := loc.Addr().As16()
	for i := range fnBits {
		if fn>>(fnBits-1-i)&1 == 0 {
			continue
		}
		pos := loc.Bits() + i
		b[pos/8] |= 1 << (7 - pos%8)
	}
	return netip.AddrFrom16(b)
}

// installEndXSIDs (re-)programs every allocated End.X SID. Like the End SIDs
// it is re-asserted from housekeeping, so a SID whose install failed or that
// was removed out-of-band is repaired without a restart.
func (s *IsisServer) installEndXSIDs() {
	for k, e := range s.endXSIDs {
		s.programSID(fib.LocalSID{SID: e.sid, Behavior: fib.BehaviorEndX, Nexthop: e.nexthop, Interface: k.circuit},
			"neighbor", k.neighbor)
	}
}

// endXSubTLVs returns one SRv6 End.X SID sub-TLV per locator for a
// point-to-point adjacency (RFC 9352 §8.1). Algorithm is the locator's: an
// End.X SID is bound to the algorithm its locator is advertised for.
func (s *IsisServer) endXSubTLVs(c *circuit, adj *adjacency) []packet.SubTLV {
	var out []packet.SubTLV
	for _, lc := range s.locators {
		if body, ok := s.endXSubTLV(lc, c, adj); ok {
			out = append(out, &body)
		}
	}
	return out
}

// lanEndXSubTLVs returns the SRv6 LAN End.X SID sub-TLVs (RFC 9352 §8.2) for
// every Up neighbor on a broadcast circuit at a level. The IS reachability
// entry points at the pseudonode, so each sub-TLV names its neighbor.
func (s *IsisServer) lanEndXSubTLVs(c *circuit, level packet.Level) []packet.SubTLV {
	adjs := map[packet.SystemID]*adjacency{}
	for _, adj := range c.upAdjacencies(level) {
		adjs[adj.systemID] = adj
	}
	var out []packet.SubTLV
	// Sorted, because originate compares the marshalled body and a map's range
	// order would re-flood the LSP on every regeneration.
	for _, id := range sortedSystemIDs(adjs) {
		for _, lc := range s.locators {
			if body, ok := s.endXSubTLV(lc, c, adjs[id]); ok {
				out = append(out, &packet.SRv6LANEndXSIDSubTLV{Neighbor: id, SRv6EndXSIDSubTLV: body})
			}
		}
	}
	return out
}

func (s *IsisServer) endXSubTLV(lc SRv6LocatorConfig, c *circuit, adj *adjacency) (packet.SRv6EndXSIDSubTLV, bool) {
	e, ok := s.endXSIDs[endXKey{locator: lc.Prefix.Masked(), circuit: c.cfg.Name, neighbor: adj.systemID}]
	if !ok {
		return packet.SRv6EndXSIDSubTLV{}, false
	}
	return packet.SRv6EndXSIDSubTLV{
		Algorithm: lc.Algo,
		Behavior:  packet.SRv6BehaviorEndX,
		SID:       e.sid,
		Structure: lc.sidStructure(),
	}, true
}

// EndXSIDInfo describes one adjacency-scoped End.X SID.
type EndXSIDInfo struct {
	SID       netip.Addr
	Neighbor  packet.SystemID
	Interface string
}

// endXSIDInfos returns the End.X SIDs allocated from a locator, ordered by
// circuit then neighbor.
func (s *IsisServer) endXSIDInfos(locator netip.Prefix) []EndXSIDInfo {
	var out []EndXSIDInfo
	for k, e := range s.endXSIDs {
		if k.locator == locator {
			out = append(out, EndXSIDInfo{SID: e.sid, Neighbor: k.neighbor, Interface: k.circuit})
		}
	}
	slices.SortFunc(out, func(a, b EndXSIDInfo) int {
		if a.Interface != b.Interface {
			return cmp.Compare(a.Interface, b.Interface)
		}
		return bytes.Compare(a.Neighbor[:], b.Neighbor[:])
	})
	return out
}
