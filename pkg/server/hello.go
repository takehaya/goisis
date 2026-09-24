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
	// A circuit whose link is down keeps its schedule but stays silent: the
	// frames would be dropped anyway, and on a link that is only reported down
	// (a one-way carrier loss) they would keep the neighbor's adjacency to us
	// alive after we tore ours down.
	if c.linkDown {
		return
	}
	if c.cfg.P2P {
		s.sendOne(c, datalink.AllISs, s.buildP2PHello(c, nil))
		return
	}
	for _, l := range c.cfg.levels() {
		s.sendOne(c, datalink.DestForLevel(l), s.buildLANHello(c, l, nil))
	}
}

func (s *IsisServer) sendOne(c *circuit, dst packet.SNPA, pdu packet.PDU) {
	wire, err := pdu.Serialize()
	if err != nil {
		s.txFailed(c, txErrSerialize, err, "pdu", pdu.PDUType())
		return
	}
	if spec := c.helloSpec(); spec.on() {
		if err := packet.PatchAuth(wire, packet.HeaderLen(pdu.PDUType()), spec.algo, spec.keyID, spec.key, false); err != nil {
			s.txFailed(c, txErrAuth, err, "pdu", pdu.PDUType())
			return
		}
	}
	if err := c.cfg.Transport.Send(dst, wire); err != nil {
		s.txFailed(c, txErrSend, err, "pdu", pdu.PDUType())
		return
	}
	s.txSucceeded(c)
}

// finalizeHello appends an HMAC-MD5 authentication TLV when a hello password is
// configured (padding is skipped then; the digest is filled at send time),
// otherwise pads the hello toward the MTU.
func (s *IsisServer) finalizeHello(c *circuit, pdu packet.PDU, tlvs *[]packet.TLV) {
	if spec := c.helloSpec(); spec.on() {
		*tlvs = append(*tlvs, authTLVPlaceholder(spec))
		return
	}
	s.padHello(c, pdu, tlvs)
}

// helloAuthOK reports whether a received hello satisfies this circuit's hello
// authentication. With no password configured every hello passes.
func (s *IsisServer) helloAuthOK(c *circuit, raw []byte, pt packet.PDUType) bool {
	spec := c.helloSpec()
	if !spec.on() {
		return true
	}
	if !spec.verify(raw, packet.HeaderLen(pt), false) {
		s.logger.Debug("drop hello failing authentication", "circuit", c.cfg.Name)
		s.metrics.PDUDrop(c.cfg.Name, dropAuth)
		return false
	}
	return true
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
	if v6 := helloIPv6Addrs(c.cfg.IPv6Addrs); len(v6) > 0 {
		tlvs = append(tlvs, &packet.IPv6InterfaceAddressesTLV{Addresses: v6})
	}
	return tlvs
}

// helloIPv6Addrs picks the addresses a hello's TLV 232 carries out of a
// circuit's IPv6 addresses: the link-local ones, which is what RFC 5308 3
// requires of an IIH and what a neighbor takes as its IPv6 next hop. The rest
// are published in the node's own LSP instead (lspIPv6Addrs).
//
// Why not filter unconditionally: a circuit with no link-local address at all
// would then send no TLV 232, costing the neighbor every IPv6 route through
// us. Listing what the circuit has beats saying nothing.
func helloIPv6Addrs(addrs []netip.Addr) []netip.Addr {
	var ll []netip.Addr
	for _, a := range addrs {
		if a.IsLinkLocalUnicast() {
			ll = append(ll, a)
		}
	}
	if len(ll) == 0 {
		return addrs
	}
	return ll
}

func (s *IsisServer) buildLANHello(c *circuit, level packet.Level, ack *packet.RestartTLV) *packet.LANHello {
	tlvs := s.commonHelloTLVs()
	// IS Neighbors (TLV 6): echo the SNPAs of neighbors heard at this level
	// so they can complete the three-way handshake.
	var snpas []packet.SNPA
	for _, adj := range c.adjs[level] {
		snpas = append(snpas, adj.snpa)
	}
	// Split across several TLVs: one holds 42 SNPAs before its value passes
	// 255 octets, and a hello that fails to serialize is never sent at all,
	// silencing the circuit. ISO 10589 8.4.5 permits repeated TLV 6.
	tlvs = append(tlvs, tlvChunks(snpas, func(chunk []packet.SNPA) packet.TLV {
		return &packet.ISNeighborsTLV{Neighbors: chunk}
	})...)
	tlvs = append(tlvs, addrTLVs(c)...)
	// Before finalizeHello, which measures what is left of the MTU: the
	// Restart TLV comes out of the padding budget, not on top of it.
	tlvs = append(tlvs, helloRestartTLV(ack))

	h := &packet.LANHello{
		Level:       level,
		CircuitType: c.cfg.circuitType(),
		SourceID:    s.systemID,
		HoldingTime: c.cfg.holdingTime(),
		Priority:    c.cfg.priority(),
		LANID:       c.dis[level], // zero until a DIS is elected
		TLVs:        tlvs,
	}
	s.finalizeHello(c, h, &h.TLVs)
	return h
}

func (s *IsisServer) buildP2PHello(c *circuit, ack *packet.RestartTLV) *packet.P2PHello {
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
	// See buildLANHello on the ordering.
	tlvs = append(tlvs, helloRestartTLV(ack))

	h := &packet.P2PHello{
		CircuitType:    c.cfg.circuitType(),
		SourceID:       s.systemID,
		HoldingTime:    c.cfg.holdingTime(),
		LocalCircuitID: c.pseudonodeID,
		TLVs:           tlvs,
	}
	s.finalizeHello(c, h, &h.TLVs)
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
	// A deleted circuit is no longer ours, but its reader goroutine outlives
	// DeleteCircuit by up to readerRetryDelay and has queued events already.
	// The guard belongs here and not in handleRx: this is the one point both
	// event kinds pass, and it must not touch Metrics — the delete has just
	// dropped this circuit's label series, and counting the drop would build
	// them again.
	if ev.on().detached {
		return
	}
	switch e := ev.(type) {
	case *rxEvent:
		s.handleRx(e.circuit, e.frame)
	case *rxErrEvent:
		s.metrics.PDURxError(e.circuit.cfg.Name)
	}
}

// handleRx decodes and processes a received frame. Decode failures are
// logged and dropped (the malformed-PDU policy for M2).
func (s *IsisServer) handleRx(c *circuit, frame datalink.Frame) {
	// A circuit whose link is down is deaf as well as mute: acting on a frame
	// that raced the link-down event would re-form an adjacency we no longer
	// send hellos on, and advertise reachability over a link we cannot use.
	// Counted rather than dropped in silence: the frame is neither received
	// nor handled, and a link reported down while frames keep arriving is
	// exactly the one-way state an operator needs to see.
	if c.linkDown {
		s.metrics.PDUDrop(c.cfg.Name, dropLinkDown)
		return
	}
	// Trim any data-link padding to the declared PDU length first: authentication
	// must hash the exact PDU the sender signed, and a stored/re-flooded LSP must
	// not carry padding.
	raw := packet.TrimToPDULength(frame.PDU)
	pdu, err := packet.DecodePDU(raw)
	if err != nil {
		s.logger.Debug("drop undecodable PDU", "circuit", c.cfg.Name, "src", frame.Src, "error", err)
		s.metrics.PDUDrop(c.cfg.Name, dropDecode)
		return
	}
	s.metrics.PDURx(c.cfg.Name, pduLabel(pdu.PDUType()))
	switch h := pdu.(type) {
	case *packet.LANHello:
		if s.helloAuthOK(c, raw, h.PDUType()) {
			s.processLANHello(c, frame.Src, h)
		}
	case *packet.P2PHello:
		if s.helloAuthOK(c, raw, h.PDUType()) {
			s.processP2PHello(c, frame.Src, h)
		}
	case *packet.LSP:
		if s.pduAuthOK(c, raw, h.PDUType(), h.Level, true) {
			if adj := s.adjacencyGate(c, h.PDUType(), h.Level, frame.Src); adj != nil {
				s.processLSP(c, raw, h, adj, s.clock.Now())
			}
		}
	case *packet.CSNP:
		if s.pduAuthOK(c, raw, h.PDUType(), h.Level, false) && s.adjacencyGate(c, h.PDUType(), h.Level, frame.Src) != nil {
			s.processCSNP(c, h, s.clock.Now())
		}
	case *packet.PSNP:
		if s.pduAuthOK(c, raw, h.PDUType(), h.Level, false) && s.adjacencyGate(c, h.PDUType(), h.Level, frame.Src) != nil {
			s.processPSNP(c, h, s.clock.Now())
		}
	}
}

// adjacencyGate admits an LSP or SNP only from a source with an Up adjacency
// at that level (ISO 10589 7.3.15.1/7.3.15.2), and returns that adjacency so
// the caller need not resolve the source a second time. Hellos are exempt:
// they are how adjacencies form in the first place.
func (s *IsisServer) adjacencyGate(c *circuit, pt packet.PDUType, level packet.Level, src packet.SNPA) *adjacency {
	if adj := c.upAdjacencyFrom(level, src); adj != nil {
		return adj
	}
	s.logger.Debug("drop PDU from a source without an Up adjacency",
		"circuit", c.cfg.Name, "pdu", pt, "level", level, "src", src)
	s.metrics.PDUDrop(c.cfg.Name, dropNoAdjacency)
	return nil
}

// dropHello counts one hello the adjacency state machine cannot use and logs
// which branch refused it. reason is the closed set the metric label carries
// (hello_invalid / hello_mismatch); why names the branch, which is what an
// operator chasing an adjacency that will not come up actually needs and is
// too fine-grained to be a label.
func (s *IsisServer) dropHello(c *circuit, reason, why string) {
	s.logger.Debug("drop hello", "circuit", c.cfg.Name, "reason", reason, "why", why)
	s.metrics.PDUDrop(c.cfg.Name, reason)
}

// processLANHello runs the broadcast adjacency state machine for one hello.
func (s *IsisServer) processLANHello(c *circuit, src packet.SNPA, h *packet.LANHello) {
	if c.cfg.P2P {
		s.dropHello(c, dropHelloInvalid, "LAN hello on a point-to-point circuit")
		return
	}
	if h.HoldingTime == 0 {
		// A zero holding time would expire the adjacency immediately.
		s.dropHello(c, dropHelloInvalid, "zero holding time")
		return
	}
	if s.helloFromSelf(c, h.SourceID) {
		return
	}
	level := h.Level
	if _, ok := c.adjs[level]; !ok {
		s.dropHello(c, dropHelloInvalid, "level not enabled on this circuit")
		return
	}
	areas := areaAddressesOf(h.TLVs)
	if level == packet.Level1 && !areasOverlap(s.areaAddrs, areas) {
		// ISO 10589 8.4.2: a Level-1 adjacency requires a common area address.
		s.dropHello(c, dropHelloMismatch, "no area address in common")
		return
	}

	// Three-way: we may declare Up only once the neighbor echoes our SNPA.
	newState := AdjInit
	if snpaListed(h.TLVs, c.cfg.Transport.LocalSNPA()) {
		newState = AdjUp
	}

	adj, existed := c.adjs[level][h.SourceID]
	if !existed && s.adjacencyLimited(c, h.SourceID) {
		return
	}
	if !existed {
		adj = &adjacency{systemID: h.SourceID}
		c.adjs[level][h.SourceID] = adj
	}
	now := s.clock.Now()
	prev := adj.state
	rt := restartTLVOf(h.TLVs)
	// RFC 5306 §3.2.1's precondition: an adjacency already in state Up to this
	// System ID on this circuit, from the same source LAN address. Under it an
	// IIH with the RR bit set leaves the adjacency state alone "irrespective of
	// the other contents of the Intermediate System Neighbors option" — a
	// restarting router has no adjacency database left to echo us from, and
	// reading that silence as a lost handshake is what turns a neighbor's
	// planned maintenance into an area-wide outage.
	holdForRestart := rt != nil && rt.RestartRequest && existed && prev == AdjUp && adj.snpa == src
	if holdForRestart {
		newState = AdjUp
	}
	// Detect changes to election-relevant fields on an established adjacency
	// so a preemption or a newly-learned DIS LAN ID triggers re-election.
	electionChanged := existed && (adj.priority != h.Priority || adj.snpa != src || adj.lanID != h.LANID)
	wasSuppressed := adj.suppressed
	adj.snpa = src
	adj.priority = h.Priority
	adj.areaAddrs = areas
	adj.lanID = h.LANID
	adj.holding = h.HoldingTime
	if noteRestart(adj, rt) {
		adj.lastHeard = now
	}
	if prev != AdjUp && newState == AdjUp {
		// Only the transition starts the clock RFC 7987 §3.2 reads; every
		// later hello re-assigns the same state.
		adj.upSince = now
	}
	adj.state = newState
	adj.levels.add(level)
	addrsChanged := adj.setNeighborAddrs(ipv4AddrsOf(h.TLVs), ipv6AddrsOf(h.TLVs))
	adj.nlpids = nlpidsOf(h.TLVs)

	// §3.2.1b, and its "Otherwise" clause: every IIH with RR set is answered,
	// whether or not there was an Up adjacency to hold.
	var ack *packet.RestartTLV
	if rt != nil && rt.RestartRequest {
		ack = restartAck(c, adj, now)
	}
	if prev != newState {
		s.logger.Info("adjacency state change", "circuit", c.cfg.Name, "level", level,
			"neighbor", h.SourceID, "from", prev, "to", newState)
		s.metrics.AdjacencyTransition(c.cfg.Name, levelLabel(level), newState.String())
		s.emitAdjacency(c.infoFor(adj, level))
	}
	// A triggered hello when the state moved, so the neighbor sees our echo
	// promptly (it speeds the three-way handshake); and §3.2.1b's "immediately"
	// when there is an acknowledgement to carry, which is exactly the case
	// where the state deliberately did not move.
	if prev != newState || ack != nil {
		s.sendOne(c, datalink.DestForLevel(level), s.buildLANHello(c, level, ack))
	}
	// Re-run DIS election only when the set of Up adjacencies changes, or an
	// Up neighbor's election attributes change. Electing while a neighbor is
	// still in Init would have us briefly claim DIS (no Up neighbors yet) and
	// then retract it, churning the LAN.
	upChanged := (prev == AdjUp) != (newState == AdjUp)
	if upChanged || (newState == AdjUp && electionChanged) {
		s.electDIS(c, level)
		s.requestLSPRegen()
	}
	// §3.2.1c, after the acknowledgement has gone out: hand the restarter the
	// database it asked for, from the one router the clause elects for the job.
	if holdForRestart && s.restartSyncEligible(c, level) {
		s.syncCircuitLevel(c, level, now)
	}
	// Suppression changes what our LSP may advertise (§3.2.2) without anything
	// about the adjacency's state having moved.
	if newState == AdjUp && (addrsChanged || adj.suppressed != wasSuppressed) {
		s.requestLSPRegen()
	}
}

// processP2PHello runs the point-to-point adjacency state machine (RFC 5303).
func (s *IsisServer) processP2PHello(c *circuit, src packet.SNPA, h *packet.P2PHello) {
	if !c.cfg.P2P {
		s.dropHello(c, dropHelloInvalid, "point-to-point hello on a LAN circuit")
		return
	}
	if h.HoldingTime == 0 {
		// A zero holding time would expire the adjacency immediately.
		s.dropHello(c, dropHelloInvalid, "zero holding time")
		return
	}
	if s.helloFromSelf(c, h.SourceID) {
		return
	}
	common := commonLevels(c, h.CircuitType)
	areas := areaAddressesOf(h.TLVs)
	if common.has(packet.Level1) && !areasOverlap(s.areaAddrs, areas) {
		common = clearLevel(common, packet.Level1)
	}
	if common == 0 {
		// Either the circuit types do not overlap, or the only level they
		// shared was Level 1 and the areas differ (ISO 10589 8.4.2).
		s.dropHello(c, dropHelloMismatch, "no level in common")
		return
	}

	three := threeWayTLV(h.TLVs)
	rt := restartTLVOf(h.TLVs)
	// RFC 5306 §3.2.1's precondition on a point-to-point circuit: an adjacency
	// already in state Up to this System ID. Under it an IIH with the RR bit
	// set holds that adjacency "irrespective of the other contents of the
	// Point-to-Point Three-Way Adjacency option". A restarting router has lost
	// its adjacency database, so a TLV 240 that echoes nobody — or a stale
	// circuit ID from its previous incarnation, which §3.3.1 says to ignore
	// while a restart is in progress — is the restart itself, not a peer that
	// has moved on to some other router.
	held := c.p2pAdj
	holdForRestart := rt != nil && rt.RestartRequest &&
		held != nil && held.systemID == h.SourceID && held.state == AdjUp
	// RFC 5303 3.2: a TLV 240 echoing someone other than us describes a
	// different adjacency, which puts ours in Down — not Init. Staying in Init
	// would leave a stale Up adjacency to a peer now talking to another router
	// alive until the hold timer expires.
	if !holdForRestart && three != nil && three.HasNeighbor &&
		(three.NeighborSystemID != s.systemID || three.NeighborExtLocalCircuitID != c.extCircID) {
		// Only the current neighbor can take our adjacency down this way; a
		// third router's hello on a misconfigured shared segment is ignored.
		if adj := c.p2pAdj; adj != nil && adj.systemID == h.SourceID {
			s.teardownP2PAdj(c, adj, "p2p adjacency down: neighbor handshakes with another router")
		}
		return
	}
	// We reach Up only when the neighbor echoes our system ID + circuit ID.
	newState := AdjInit
	if holdForRestart || (three != nil && three.HasNeighbor &&
		three.NeighborSystemID == s.systemID &&
		three.NeighborExtLocalCircuitID == c.extCircID) {
		newState = AdjUp
	}

	adj := c.p2pAdj
	if adj != nil && adj.systemID != h.SourceID {
		// A different neighbor replaced the old one (system-ID change or the
		// link recabled to another router): tear the old one down first so
		// observers see it go away, rather than silently overwriting it.
		s.teardownP2PAdj(c, adj, "p2p adjacency replaced")
		adj = nil
	}
	if adj == nil {
		adj = &adjacency{systemID: h.SourceID}
		c.p2pAdj = adj
	}
	now := s.clock.Now()
	prev := adj.state
	prevLevels := adj.levels
	wasSuppressed := adj.suppressed
	adj.snpa = src
	adj.areaAddrs = areas
	adj.holding = h.HoldingTime
	if noteRestart(adj, rt) {
		adj.lastHeard = now
	}
	adj.levels = common
	if prev != AdjUp && newState == AdjUp {
		// See processLANHello: the transition, not every hello.
		adj.upSince = now
	}
	adj.state = newState
	addrsChanged := adj.setNeighborAddrs(ipv4AddrsOf(h.TLVs), ipv6AddrsOf(h.TLVs))
	adj.nlpids = nlpidsOf(h.TLVs)
	if three != nil && three.HasLocal {
		adj.neighborExtCircID = three.ExtLocalCircuitID
	}

	// React to a state change, or to the common-level set changing while Up
	// (e.g. the neighbor reconfigured its circuit type): otherwise our own LSP
	// would keep advertising IS reachability for a level the peer dropped.
	changed := prev != newState || (newState == AdjUp && prevLevels != common)
	if changed {
		s.logger.Info("p2p adjacency state change", "circuit", c.cfg.Name,
			"neighbor", h.SourceID, "from", prev, "to", newState)
		for _, l := range adj.levels.levels() {
			s.metrics.AdjacencyTransition(c.cfg.Name, levelLabel(l), newState.String())
			s.emitAdjacency(c.infoFor(adj, l))
		}
		// Levels that dropped while the adjacency stayed Up must be reported
		// down so consumers and the RIB stop using them.
		if newState == AdjUp {
			for _, l := range prevLevels.levels() {
				if !common.has(l) {
					s.emitAdjacencyDown(c, adj, l)
				}
			}
		}
		s.requestLSPRegen()
	}
	// §3.2.1b, and its "Otherwise" clause: every IIH with RR set is answered.
	// §3.2.1b also wants the IIH updated to reflect the new values the
	// restarter just sent, which buildP2PHello reads back off the adjacency.
	var ack *packet.RestartTLV
	if rt != nil && rt.RestartRequest {
		ack = restartAck(c, adj, now)
	}
	if changed || ack != nil {
		s.sendOne(c, datalink.AllISs, s.buildP2PHello(c, ack))
	}
	// Every level that just became usable is synchronized from scratch
	// (ISO 10589 7.3.17); a level already Up keeps the flags it has. Our own
	// regeneration is still pending, so the CSNP may describe a stale copy of
	// our LSP; the fresh one is flooded via SRM as soon as it is generated.
	if changed && newState == AdjUp {
		for _, l := range common.levels() {
			if prev != AdjUp || !prevLevels.has(l) {
				s.syncCircuitLevel(c, l, now)
			}
		}
	}
	// §3.2.1c: on a point-to-point circuit the one neighbor's request is the
	// whole election, and §3.3.3 keeps the two LSPDBs' synchronizations
	// separate even though a single IIH covers both.
	if holdForRestart {
		for _, l := range adj.levels.levels() {
			s.syncCircuitLevel(c, l, now)
		}
	}
	// See processLANHello: suppression changes what our LSP may advertise.
	if newState == AdjUp && (addrsChanged || adj.suppressed != wasSuppressed) {
		s.requestLSPRegen()
	}
}

// teardownP2PAdj detaches a point-to-point neighbor from its circuit, reports
// it down for the given reason, drops the flooding flags aimed at it, and asks
// for a re-origination so our LSP drops its stale IS reachability. adj is
// always c.p2pAdj; a caller with a replacement installs it afterwards.
func (s *IsisServer) teardownP2PAdj(c *circuit, adj *adjacency, reason string) {
	s.logger.Info(reason, "circuit", c.cfg.Name, "neighbor", adj.systemID)
	c.p2pAdj = nil
	for _, l := range adj.levels.levels() {
		s.emitAdjacencyDown(c, adj, l)
	}
	c.clearFlags()
	s.requestLSPRegen()
}

// helloFromSelf reports whether a hello carries our own system ID. Such a
// hello means a duplicate system ID on the segment (a misconfiguration or a
// cloned VM); forming an adjacency "to ourselves" would corrupt DIS election
// and SPF, so the caller drops it without touching adjacency state. Hellos
// arrive every few seconds, so the warning is edge-triggered per circuit and
// re-armed when the link returns (SetCircuitLinkState); the counter is not, so
// a duplicate that outlives its one log line still shows a rate.
func (s *IsisServer) helloFromSelf(c *circuit, src packet.SystemID) bool {
	if src != s.systemID {
		return false
	}
	s.metrics.PDUDrop(c.cfg.Name, dropDuplicateSystemID)
	s.dupSystemIDWarned.warn(c.cfg.Name, func() {
		s.logger.Warn("drop hello carrying our own system ID: duplicate system ID on the circuit; suppressing repeats",
			"circuit", c.cfg.Name, "systemID", src)
	})
	return true
}

// adjacencyLimited reports whether the circuit is at its adjacency limit and
// this station is not one of the neighbors it already has, dropping and
// counting the hello if so. The station is turned away rather than replacing
// anyone: an adjacency that formed keeps working, and what the cap bounds is
// the per-neighbor state (an End.X SID, an IS reachability entry, a route)
// that a segment without hello authentication can otherwise make us allocate
// at will. Hellos repeat every few seconds, so the warning is edge-triggered
// per circuit, re-armed when an adjacency goes away (dropAdjacencies).
func (s *IsisServer) adjacencyLimited(c *circuit, src packet.SystemID) bool {
	if !c.atAdjacencyLimit(src) {
		return false
	}
	s.metrics.PDUDrop(c.cfg.Name, dropAdjacencyLimit)
	s.adjLimitWarned.warn(c.cfg.Name, func() {
		s.logger.Warn("drop hello from a new neighbor: circuit is at its adjacency limit; suppressing repeats",
			"circuit", c.cfg.Name, "limit", c.cfg.adjacencyLimit(), "systemID", src)
	})
	return true
}

// expireAdjacencies tears down adjacencies whose holding time has elapsed.
func (s *IsisServer) expireAdjacencies(c *circuit, now time.Time) {
	s.dropAdjacencies(c, "adjacency expired", func(adj *adjacency) bool { return expired(adj, now) })
}

// dropAdjacencies tears down every adjacency on the circuit that drop selects,
// reporting each one down, re-electing the DIS, and re-originating so our LSP
// loses the stale IS reachability. reason is the log message.
func (s *IsisServer) dropAdjacencies(c *circuit, reason string, drop func(*adjacency) bool) {
	if c.cfg.P2P {
		if adj := c.p2pAdj; adj != nil && drop(adj) {
			s.teardownP2PAdj(c, adj, reason)
		}
		return
	}
	changed := false
	for _, level := range c.cfg.levels() {
		for id, adj := range c.adjs[level] {
			if !drop(adj) {
				continue
			}
			s.logger.Info(reason, "circuit", c.cfg.Name, "level", level, "neighbor", id)
			s.emitAdjacencyDown(c, adj, level)
			delete(c.adjs[level], id)
			s.electDIS(c, level)
			changed = true
		}
	}
	if changed {
		// The circuit has room again, so the next station it turns away is news.
		s.adjLimitWarned.clear(c.cfg.Name)
		s.requestLSPRegen()
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

// nlpidsOf returns the NLPIDs the sender routes, or nil when the hello omits
// TLV 129. RFC 1195 3.1 makes it mandatory, but a missing TLV is treated as
// "unknown" rather than "routes nothing" so a lax peer still gets next hops.
func nlpidsOf(tlvs []packet.TLV) []byte {
	for _, t := range tlvs {
		if p, ok := t.(*packet.ProtocolsSupportedTLV); ok {
			return p.NLPIDs
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
