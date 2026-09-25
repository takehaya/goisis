package server

import (
	"slices"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// circuit is the runtime state of one IS-IS circuit, owned by the Serve
// loop. Broadcast adjacencies live in adjs[level][systemID]; a p2p circuit
// keeps its single neighbor in p2pAdj.
type circuit struct {
	cfg          CircuitConfig
	pseudonodeID uint8  // nonzero, unique per box (broadcast pseudonode octet)
	extCircID    uint32 // our extended local circuit ID (p2p TLV 240)

	adjs   map[packet.Level]map[packet.SystemID]*adjacency
	p2pAdj *adjacency

	dis       map[packet.Level]packet.NodeID // elected DIS LAN ID per level
	nextHello time.Time

	// linkDown is set while the interface has no carrier (SetCircuitLinkState).
	// Hellos are suppressed and adjacencies are torn down at once, instead of
	// waiting out the neighbor's holding time.
	linkDown bool

	// detached is set by DeleteCircuit once the circuit is no longer ours. Its
	// reader goroutine outlives that call by up to readerRetryDelay, so events
	// it has already queued still name this circuit; handleEvent refuses them
	// on this flag. It is deliberately not linkDown, which means the carrier is
	// down and the circuit is still ours: reusing it would let
	// SetCircuitLinkState(up) resurrect a deleted circuit.
	detached bool

	// Flooding flags per level (ISO 10589 7.3): srm[level][lspid] holds the
	// earliest time to (re)send that LSP on this circuit; ssn[level][lspid]
	// marks an LSP to report in the next PSNP. ssnAck holds the header to
	// report for an SSN entry the database has no copy of; it is a subset of
	// ssn. nextCSNP drives periodic CSNP transmission when this circuit is
	// the DIS.
	srm      map[packet.Level]map[packet.LSPID]time.Time
	ssn      map[packet.Level]map[packet.LSPID]bool
	ssnAck   map[packet.Level]map[packet.LSPID]packet.LSPEntry
	nextCSNP map[packet.Level]time.Time

	// syncHold is the earliest time a whole-database synchronization may run
	// again at a level, and syncDeferred records that one was asked for while
	// the hold-down was in force and still owes the neighbor the database.
	// See syncCircuitLevel.
	syncHold     map[packet.Level]time.Time
	syncDeferred map[packet.Level]bool
}

func newCircuit(cfg CircuitConfig, pseudonodeID uint8, extCircID uint32) *circuit {
	c := &circuit{
		cfg:          cfg,
		pseudonodeID: pseudonodeID,
		extCircID:    extCircID,
		adjs:         map[packet.Level]map[packet.SystemID]*adjacency{},
		dis:          map[packet.Level]packet.NodeID{},
		srm:          map[packet.Level]map[packet.LSPID]time.Time{},
		ssn:          map[packet.Level]map[packet.LSPID]bool{},
		ssnAck:       map[packet.Level]map[packet.LSPID]packet.LSPEntry{},
		nextCSNP:     map[packet.Level]time.Time{},
		syncHold:     map[packet.Level]time.Time{},
		syncDeferred: map[packet.Level]bool{},
	}
	for _, l := range cfg.levels() {
		c.adjs[l] = map[packet.SystemID]*adjacency{}
		c.srm[l] = map[packet.LSPID]time.Time{}
		c.ssn[l] = map[packet.LSPID]bool{}
		c.ssnAck[l] = map[packet.LSPID]packet.LSPEntry{}
	}
	return c
}

// setSRM marks an LSP for transmission on this circuit at the given level.
func (c *circuit) setSRM(level packet.Level, id packet.LSPID, when time.Time) {
	if m := c.srm[level]; m != nil {
		m[id] = when
	}
}

// clearSRM stops retransmitting an LSP on this circuit.
func (c *circuit) clearSRM(level packet.Level, id packet.LSPID) {
	if m := c.srm[level]; m != nil {
		delete(m, id)
	}
}

// setSSN marks an LSP to be reported in the next PSNP on this circuit.
func (c *circuit) setSSN(level packet.Level, id packet.LSPID) {
	if m := c.ssn[level]; m != nil {
		m[id] = true
	}
}

// setSSNAck marks an LSP to be reported in the next PSNP with the given
// header verbatim, for an LSP the database does not hold and so cannot
// describe.
func (c *circuit) setSSNAck(level packet.Level, e packet.LSPEntry) {
	if m := c.ssnAck[level]; m != nil {
		m[e.LSPID] = e
		c.setSSN(level, e.LSPID)
	}
}

func (c *circuit) clearSSN(level packet.Level, id packet.LSPID) {
	if m := c.ssn[level]; m != nil {
		delete(m, id)
	}
	// ssnAck is a subset of ssn, so the two are always cleared together.
	if m := c.ssnAck[level]; m != nil {
		delete(m, id)
	}
}

// clearFlags drops every flooding flag on the circuit. Called when a p2p
// adjacency leaves Up: the flags describe what to send to a neighbor that is
// gone, and ISO 10589 7.3.17 re-arms them for the whole database when an
// adjacency comes Up, so nothing kept across a Down is of any use. LAN flags
// are not cleared on adjacency expiry: they are per circuit, not per neighbor,
// and the DIS's CSNPs govern them.
func (c *circuit) clearFlags() {
	for _, l := range c.cfg.levels() {
		clear(c.srm[l])
		clear(c.ssn[l])
		clear(c.ssnAck[l])
	}
}

// floodReady reports whether flooding may transmit on this circuit at a level.
// A p2p circuit needs an Up adjacency covering the level: an LSP or a PSNP
// sent without one reaches nobody, and retrying it every
// minLSPTransmissionInterval forever is pure waste. A LAN circuit is always
// ready (see clearFlags).
func (c *circuit) floodReady(level packet.Level) bool {
	if !c.cfg.P2P {
		return true
	}
	adj := c.p2pAdj
	return adj != nil && adj.state == AdjUp && adj.levels.has(level)
}

// isDIS reports whether we are the elected DIS at a level on this broadcast
// circuit.
func (c *circuit) isDIS(level packet.Level, self packet.SystemID) bool {
	return !c.cfg.P2P && c.dis[level].SystemID() == self && c.dis[level].PseudonodeID() != 0
}

// aslaSubTLVs returns the circuit's Application-Specific Link Attributes
// sub-TLV (RFC 8919 §4.2) naming the Flex-Algorithm application, or nil when
// no admin group is configured.
//
// A node that prunes on its peers' colors while advertising none of its own is
// incoherent: RFC 9350 §12 lets a Flex-Algorithm read colors from ASLA only,
// so under an include rule every link goisis owns would fail the test and the
// algorithm would go dark on exactly those links. The L-flag stays clear —
// goisis originates no legacy link attributes to send a receiver to.
//
// It hangs off the configuration rather than the circuit so that
// CircuitConfig.validate can measure what a circuit would advertise before one
// exists (maxLinkAttrArea).
func (c *CircuitConfig) aslaSubTLVs() []packet.SubTLV {
	if len(c.AdminGroup) == 0 {
		return nil
	}
	// RFC 9350 §12 takes either encoding. Colors that fit the single 32-bit
	// word of RFC 5305 §3.1 go out in it, because a receiver that predates RFC
	// 7308's extended group still reads that one.
	g := &packet.AdminGroupSubTLV{Extended: len(c.AdminGroup) > 1, Groups: c.AdminGroup}
	return []packet.SubTLV{&packet.ASLASubTLV{
		SABM:       []byte{packet.ASLAAppFlexAlgo},
		SubSubTLVs: []packet.SubTLV{g},
	}}
}

// CircuitInfo is an exported snapshot of a circuit's configuration.
type CircuitInfo struct {
	Interface string
	P2P       bool
	Level1    bool
	Level2    bool
	Priority  uint8
	Metric    uint32
	LinkUp    bool
}

func (c *circuit) info() CircuitInfo {
	return CircuitInfo{
		Interface: c.cfg.Name,
		P2P:       c.cfg.P2P,
		Level1:    c.cfg.Level1,
		Level2:    c.cfg.Level2,
		Priority:  c.cfg.priority(),
		Metric:    c.cfg.Metric,
		LinkUp:    !c.linkDown,
	}
}

// adjacencyInfos returns snapshots of all adjacencies on the circuit.
func (c *circuit) adjacencyInfos() []AdjacencyInfo {
	var out []AdjacencyInfo
	if c.cfg.P2P {
		if c.p2pAdj != nil {
			for _, l := range c.p2pAdj.levels.levels() {
				out = append(out, c.infoFor(c.p2pAdj, l))
			}
		}
		return out
	}
	for _, l := range c.cfg.levels() {
		for _, adj := range c.adjs[l] {
			out = append(out, c.infoFor(adj, l))
		}
	}
	return out
}

func (c *circuit) infoFor(adj *adjacency, l packet.Level) AdjacencyInfo {
	return AdjacencyInfo{
		Interface:  c.cfg.Name,
		Level:      l,
		SystemID:   adj.systemID,
		SNPA:       adj.snpa,
		State:      adj.state,
		Priority:   adj.priority,
		Holding:    adj.holding,
		Restarting: adj.restartMode,
		Suppressed: adj.suppressed,
	}
}

// upAdjacencyFrom returns the adjacency that is Up at this level on the
// circuit and has src as its SNPA, or nil if there is none. ISO 10589
// 7.3.15.1/7.3.15.2 accept an LSP or an SNP only from such a source: a station
// that never sent a hello must not be able to reach the update process. The
// adjacency itself and not a bool, because the update process needs how long
// it has been Up (RFC 7987 §3.2, see corruptLifetime).
func (c *circuit) upAdjacencyFrom(level packet.Level, src packet.SNPA) *adjacency {
	if c.cfg.P2P {
		adj := c.p2pAdj
		if adj != nil && adj.state == AdjUp && adj.levels.has(level) && adj.snpa == src {
			return adj
		}
		return nil
	}
	for _, adj := range c.adjs[level] {
		if adj.snpa == src && adj.state == AdjUp {
			return adj
		}
	}
	return nil
}

// atAdjacencyLimit reports whether admitting id as a new neighbor would take
// the circuit past its adjacency limit. A System ID the circuit already knows
// at some level is the same station, so it is admitted even at the cap: the
// limit bounds how many neighbors the circuit takes on, never one it has.
// A p2p circuit keeps a single neighbor and so cannot grow past anything.
func (c *circuit) atAdjacencyLimit(id packet.SystemID) bool {
	limit := c.cfg.adjacencyLimit()
	if limit <= 0 || c.cfg.P2P {
		return false
	}
	seen := map[packet.SystemID]bool{}
	for _, l := range c.cfg.levels() {
		for other := range c.adjs[l] {
			seen[other] = true
		}
	}
	return !seen[id] && len(seen) >= limit
}

// upAdjacencyCount returns the number of Up adjacencies at a level, counting
// the single neighbor a p2p circuit keeps outside c.adjs.
func (c *circuit) upAdjacencyCount(l packet.Level) int {
	if c.cfg.P2P {
		if adj := c.p2pAdj; adj != nil && adj.state == AdjUp && adj.levels.has(l) {
			return 1
		}
		return 0
	}
	return len(c.upAdjacencies(l))
}

// suppressedAdjacencyCount returns how many of the Up adjacencies at a level
// RFC 5306 §3.2.2 keeps out of this node's LSPs and out of SPF. It is what
// makes upAdjacencyCount readable: an adjacency that is Up and carries nothing
// is counted there and absent from the topology, and this is exactly the
// difference between the two.
func (c *circuit) suppressedAdjacencyCount(l packet.Level) int {
	if c.cfg.P2P {
		if adj := c.p2pAdj; adj != nil && adj.state == AdjUp && adj.levels.has(l) && adj.suppressed {
			return 1
		}
		return 0
	}
	return len(c.upAdjacencies(l)) - len(c.advertisedAdjacencies(l))
}

// upAdjacencies returns the Up adjacencies at a level (broadcast).
func (c *circuit) upAdjacencies(l packet.Level) []*adjacency {
	var out []*adjacency
	for _, adj := range c.adjs[l] {
		if adj.state == AdjUp {
			out = append(out, adj)
		}
	}
	return out
}

// advertisedAdjacencies returns the Up adjacencies at a level that this node's
// LSPs may carry and SPF may cross: RFC 5306 §3.2.2 keeps one whose neighbor
// set the SA bit out of both until an IIH with SA clear arrives.
//
// DIS election and the holding timer deliberately keep reading upAdjacencies
// instead: §3.2.2 suppresses the advertisement of an adjacency, not the
// adjacency, and a starting router that loses the election as well would have
// to be re-elected once it finished, churning the LAN a second time.
func (c *circuit) advertisedAdjacencies(l packet.Level) []*adjacency {
	return slices.DeleteFunc(c.upAdjacencies(l), func(adj *adjacency) bool { return adj.suppressed })
}
