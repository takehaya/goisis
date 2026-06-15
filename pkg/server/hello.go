package server

import (
	"bytes"
	"net/netip"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// sendHellos transmits the circuit's hellos and schedules the next send.
func (s *IsisServer) sendHellos(c *circuit, now time.Time) {
	c.nextHello = now.Add(c.cfg.HelloInterval)
	if c.cfg.P2P {
		s.sendOne(c, datalink.AllISs, s.buildP2PHello(c))
		return
	}
	for _, l := range c.cfg.levels() {
		s.sendOne(c, datalink.DestForLevel(l), s.buildLANHello(c, l))
	}
}

func (s *IsisServer) sendOne(c *circuit, dst packet.SNPA, pdu packet.PDU) {
	wire, err := pdu.Serialize()
	if err != nil {
		s.logger.Error("serialize hello", "circuit", c.cfg.Name, "error", err)
		return
	}
	if err := c.cfg.Transport.Send(dst, wire); err != nil {
		s.logger.Error("send hello", "circuit", c.cfg.Name, "error", err)
	}
}

// commonHelloTLVs are the area/protocol/address TLVs shared by LAN and p2p
// hellos.
func (s *IsisServer) commonHelloTLVs() []packet.TLV {
	tlvs := []packet.TLV{
		&packet.AreaAddressesTLV{Addresses: s.areaAddrs},
		&packet.ProtocolsSupportedTLV{NLPIDs: []byte{packet.NLPIDIPv4, packet.NLPIDIPv6}},
	}
	return tlvs
}

func addrTLVs(c *circuit) []packet.TLV {
	var tlvs []packet.TLV
	if len(c.cfg.IPv4Addrs) > 0 {
		tlvs = append(tlvs, &packet.IPInterfaceAddressesTLV{Addresses: c.cfg.IPv4Addrs})
	}
	if len(c.cfg.IPv6Addrs) > 0 {
		tlvs = append(tlvs, &packet.IPv6InterfaceAddressesTLV{Addresses: c.cfg.IPv6Addrs})
	}
	return tlvs
}

func (s *IsisServer) buildLANHello(c *circuit, level packet.Level) *packet.LANHello {
	tlvs := s.commonHelloTLVs()
	// IS Neighbors (TLV 6): echo the SNPAs of neighbors heard at this level
	// so they can complete the three-way handshake.
	var snpas []packet.SNPA
	for _, adj := range c.adjs[level] {
		snpas = append(snpas, adj.snpa)
	}
	if len(snpas) > 0 {
		tlvs = append(tlvs, &packet.ISNeighborsTLV{Neighbors: snpas})
	}
	tlvs = append(tlvs, addrTLVs(c)...)

	h := &packet.LANHello{
		Level:       level,
		CircuitType: c.cfg.circuitType(),
		SourceID:    s.systemID,
		HoldingTime: c.cfg.holdingTime(),
		Priority:    c.cfg.priority(),
		LANID:       c.dis[level], // zero until a DIS is elected
		TLVs:        tlvs,
	}
	s.padHello(c, h, &h.TLVs)
	return h
}

func (s *IsisServer) buildP2PHello(c *circuit) *packet.P2PHello {
	tlvs := s.commonHelloTLVs()

	// P2P Three-Way Adjacency (TLV 240, RFC 5303): advertise our state and,
	// once we know the neighbor, echo their identity so they reach Up.
	adjTLV := &packet.P2PThreeWayAdjacencyTLV{
		State:             packet.P2PAdjStateDown,
		HasLocal:          true,
		ExtLocalCircuitID: c.extCircID,
	}
	if c.p2pAdj != nil {
		adjTLV.State = p2pStateTLV(c.p2pAdj.state)
		adjTLV.HasNeighbor = true
		adjTLV.NeighborSystemID = c.p2pAdj.systemID
		adjTLV.NeighborExtLocalCircuitID = c.p2pAdj.neighborExtCircID
	}
	tlvs = append(tlvs, adjTLV)
	tlvs = append(tlvs, addrTLVs(c)...)

	h := &packet.P2PHello{
		CircuitType:    c.cfg.circuitType(),
		SourceID:       s.systemID,
		HoldingTime:    c.cfg.holdingTime(),
		LocalCircuitID: c.pseudonodeID,
		TLVs:           tlvs,
	}
	s.padHello(c, h, &h.TLVs)
	return h
}

// p2pStateTLV maps an adjacency state to the RFC 5303 TLV 240 state code.
func p2pStateTLV(s AdjState) packet.P2PAdjState {
	switch s {
	case AdjUp:
		return packet.P2PAdjStateUp
	case AdjInit:
		return packet.P2PAdjStateInitializing
	default:
		return packet.P2PAdjStateDown
	}
}

// padHello appends Padding TLVs so the serialized PDU reaches the circuit
// MTU (less the 3-octet LLC header), per ISO 10589. This makes an MTU
// mismatch break adjacency formation rather than silently truncate.
func (s *IsisServer) padHello(c *circuit, pdu packet.PDU, tlvs *[]packet.TLV) {
	if !c.cfg.padding() {
		return
	}
	target := c.cfg.Transport.MTU() - 3 // LLC header
	for {
		wire, err := pdu.Serialize()
		if err != nil {
			return
		}
		room := target - len(wire)
		if room < 2 { // need at least a TLV header
			return
		}
		pad := room - 2
		if pad > 255 {
			pad = 255
		}
		*tlvs = append(*tlvs, &packet.PaddingTLV{Length: pad})
	}
}

// handleEvent dispatches one event on the Serve loop.
func (s *IsisServer) handleEvent(ev event) {
	switch e := ev.(type) {
	case *rxEvent:
		s.handleRx(e.circuit, e.frame)
	}
}

// handleRx decodes and processes a received frame. Decode failures are
// logged and dropped (the malformed-PDU policy for M2).
func (s *IsisServer) handleRx(c *circuit, frame datalink.Frame) {
	pdu, err := packet.DecodePDU(frame.PDU)
	if err != nil {
		s.logger.Debug("drop undecodable PDU", "circuit", c.cfg.Name, "src", frame.Src, "error", err)
		return
	}
	switch h := pdu.(type) {
	case *packet.LANHello:
		s.processLANHello(c, frame.Src, h)
	case *packet.P2PHello:
		s.processP2PHello(c, frame.Src, h)
	case *packet.LSP:
		s.processLSP(c, frame.PDU, h, time.Now())
	case *packet.CSNP:
		s.processCSNP(c, h, time.Now())
	case *packet.PSNP:
		s.processPSNP(c, h, time.Now())
	}
}

// processLANHello runs the broadcast adjacency state machine for one hello.
func (s *IsisServer) processLANHello(c *circuit, src packet.SNPA, h *packet.LANHello) {
	if c.cfg.P2P {
		return // wrong circuit type for this PDU
	}
	if h.HoldingTime == 0 {
		return // a zero holding time would expire the adjacency immediately
	}
	level := h.Level
	if _, ok := c.adjs[level]; !ok {
		return // level not enabled on this circuit
	}
	areas := areaAddressesOf(h.TLVs)
	if level == packet.Level1 && !areasOverlap(s.areaAddrs, areas) {
		return // L1 requires a common area
	}

	// Three-way: we may declare Up only once the neighbor echoes our SNPA.
	newState := AdjInit
	if snpaListed(h.TLVs, c.cfg.Transport.LocalSNPA()) {
		newState = AdjUp
	}

	adj, existed := c.adjs[level][h.SourceID]
	if !existed {
		adj = &adjacency{systemID: h.SourceID}
		c.adjs[level][h.SourceID] = adj
	}
	prev := adj.state
	// Detect changes to election-relevant fields on an established adjacency
	// so a preemption or a newly-learned DIS LAN ID triggers re-election.
	electionChanged := existed && (adj.priority != h.Priority || adj.snpa != src || adj.lanID != h.LANID)
	adj.snpa = src
	adj.priority = h.Priority
	adj.areaAddrs = areas
	adj.lanID = h.LANID
	adj.holding = h.HoldingTime
	adj.lastHeard = time.Now()
	adj.state = newState
	adj.levels.add(level)
	adj.neighborIPv4 = ipv4AddrsOf(h.TLVs)
	adj.neighborIPv6 = ipv6AddrsOf(h.TLVs)

	if prev != newState {
		s.logger.Info("adjacency state change", "circuit", c.cfg.Name, "level", level,
			"neighbor", h.SourceID, "from", prev, "to", newState)
		s.metrics.AdjacencyTransition(c.cfg.Name, levelLabel(level), newState.String())
		s.emitAdjacency(c.infoFor(adj, level))
		// Triggered hello so the neighbor sees our echo promptly (speeds the
		// three-way handshake); harmless even when no DIS decision changes.
		s.sendOne(c, datalink.DestForLevel(level), s.buildLANHello(c, level))
	}
	// Re-run DIS election only when the set of Up adjacencies changes, or an
	// Up neighbor's election attributes change. Electing while a neighbor is
	// still in Init would have us briefly claim DIS (no Up neighbors yet) and
	// then retract it, churning the LAN.
	upChanged := (prev == AdjUp) != (newState == AdjUp)
	if upChanged || (newState == AdjUp && electionChanged) {
		s.electDIS(c, level)
		s.regenerateLSPs(false, time.Now())
	}
}

// processP2PHello runs the point-to-point adjacency state machine (RFC 5303).
func (s *IsisServer) processP2PHello(c *circuit, src packet.SNPA, h *packet.P2PHello) {
	if !c.cfg.P2P {
		return
	}
	if h.HoldingTime == 0 {
		return // a zero holding time would expire the adjacency immediately
	}
	common := commonLevels(c, h.CircuitType)
	areas := areaAddressesOf(h.TLVs)
	if common.has(packet.Level1) && !areasOverlap(s.areaAddrs, areas) {
		common = clearLevel(common, packet.Level1)
	}
	if common == 0 {
		return // no common level
	}

	three := threeWayTLV(h.TLVs)
	// We reach Up only when the neighbor echoes our system ID + circuit ID.
	newState := AdjInit
	if three != nil && three.HasNeighbor &&
		three.NeighborSystemID == s.systemID &&
		three.NeighborExtLocalCircuitID == c.extCircID {
		newState = AdjUp
	}

	adj := c.p2pAdj
	if adj == nil || adj.systemID != h.SourceID {
		adj = &adjacency{systemID: h.SourceID}
		c.p2pAdj = adj
	}
	prev := adj.state
	adj.snpa = src
	adj.areaAddrs = areas
	adj.holding = h.HoldingTime
	adj.lastHeard = time.Now()
	adj.levels = common
	adj.state = newState
	adj.neighborIPv4 = ipv4AddrsOf(h.TLVs)
	adj.neighborIPv6 = ipv6AddrsOf(h.TLVs)
	if three != nil && three.HasLocal {
		adj.neighborExtCircID = three.ExtLocalCircuitID
	}

	if prev != newState {
		s.logger.Info("p2p adjacency state change", "circuit", c.cfg.Name,
			"neighbor", h.SourceID, "from", prev, "to", newState)
		for _, l := range adj.levels.levels() {
			s.metrics.AdjacencyTransition(c.cfg.Name, levelLabel(l), newState.String())
			s.emitAdjacency(c.infoFor(adj, l))
		}
		s.sendOne(c, datalink.AllISs, s.buildP2PHello(c))
		s.regenerateLSPs(false, time.Now())
	}
}

// expireAdjacencies tears down adjacencies whose holding time has elapsed.
func (s *IsisServer) expireAdjacencies(c *circuit, now time.Time) {
	if c.cfg.P2P {
		if adj := c.p2pAdj; adj != nil && expired(adj, now) {
			s.logger.Info("p2p adjacency expired", "circuit", c.cfg.Name, "neighbor", adj.systemID)
			for _, l := range adj.levels.levels() {
				s.emitAdjacencyDown(c, adj, l)
			}
			c.p2pAdj = nil
			s.regenerateLSPs(false, now)
		}
		return
	}
	changed := false
	for _, level := range c.cfg.levels() {
		for id, adj := range c.adjs[level] {
			if expired(adj, now) {
				s.logger.Info("adjacency expired", "circuit", c.cfg.Name, "level", level, "neighbor", id)
				s.emitAdjacencyDown(c, adj, level)
				delete(c.adjs[level], id)
				s.electDIS(c, level)
				changed = true
			}
		}
	}
	if changed {
		s.regenerateLSPs(false, now)
	}
}

func expired(adj *adjacency, now time.Time) bool {
	hold := time.Duration(adj.holding) * time.Second
	return now.Sub(adj.lastHeard) > hold
}

// --- TLV helpers ---

func ipv4AddrsOf(tlvs []packet.TLV) []netip.Addr {
	for _, t := range tlvs {
		if a, ok := t.(*packet.IPInterfaceAddressesTLV); ok {
			return a.Addresses
		}
	}
	return nil
}

func ipv6AddrsOf(tlvs []packet.TLV) []netip.Addr {
	for _, t := range tlvs {
		if a, ok := t.(*packet.IPv6InterfaceAddressesTLV); ok {
			return a.Addresses
		}
	}
	return nil
}

func areaAddressesOf(tlvs []packet.TLV) []packet.AreaAddress {
	for _, t := range tlvs {
		if a, ok := t.(*packet.AreaAddressesTLV); ok {
			return a.Addresses
		}
	}
	return nil
}

func snpaListed(tlvs []packet.TLV, want packet.SNPA) bool {
	for _, t := range tlvs {
		if n, ok := t.(*packet.ISNeighborsTLV); ok {
			for _, s := range n.Neighbors {
				if s == want {
					return true
				}
			}
		}
	}
	return false
}

func threeWayTLV(tlvs []packet.TLV) *packet.P2PThreeWayAdjacencyTLV {
	for _, t := range tlvs {
		if a, ok := t.(*packet.P2PThreeWayAdjacencyTLV); ok {
			return a
		}
	}
	return nil
}

func areasOverlap(a, b []packet.AreaAddress) bool {
	for _, x := range a {
		for _, y := range b {
			if bytes.Equal(x, y) {
				return true
			}
		}
	}
	return false
}

func commonLevels(c *circuit, neighbor packet.CircuitType) levelSet {
	var ls levelSet
	if c.cfg.Level1 && neighbor&packet.CircuitTypeLevel1 != 0 {
		ls.add(packet.Level1)
	}
	if c.cfg.Level2 && neighbor&packet.CircuitTypeLevel2 != 0 {
		ls.add(packet.Level2)
	}
	return ls
}

func clearLevel(s levelSet, l packet.Level) levelSet {
	return s &^ (1 << l)
}
