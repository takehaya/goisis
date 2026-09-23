package server

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// countingMetrics records what the server reported. It embeds NoopMetrics so
// only the methods under test need an implementation, and guards its maps
// because a served instance reports from the management goroutine while the
// test reads from another.
type countingMetrics struct {
	NoopMetrics
	mu     sync.Mutex
	counts map[string]int
	gauges map[string]int
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{counts: map[string]int{}, gauges: map[string]int{}}
}

func (m *countingMetrics) PDURx(circuit, pduType string)  { m.inc("pdu_rx", circuit, pduType) }
func (m *countingMetrics) PDUDrop(circuit, reason string) { m.inc("pdu_drop", circuit, reason) }
func (m *countingMetrics) FIBError(op string)             { m.inc("fib_error", op) }

func (m *countingMetrics) AdjacencyCount(circuit, level string, n int) {
	m.set(n, "adjacencies", circuit, level)
}

func (m *countingMetrics) RouteCount(level, algo string, n int) { m.set(n, "routes", level, algo) }
func (m *countingMetrics) EventQueueDepth(n int)                { m.set(n, "event_queue") }

func (m *countingMetrics) inc(parts ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[strings.Join(parts, "|")]++
}

func (m *countingMetrics) set(n int, parts ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[strings.Join(parts, "|")] = n
}

func (m *countingMetrics) count(parts ...string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[strings.Join(parts, "|")]
}

func (m *countingMetrics) gauge(parts ...string) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.gauges[strings.Join(parts, "|")]
	return n, ok
}

var (
	metricsSelfID   = packet.SystemID{0, 0, 0, 0, 0, 1}
	metricsPeerID   = packet.SystemID{0, 0, 0, 0, 0, 2}
	metricsPeerSNPA = packet.SNPA{0, 0, 0, 0, 0, 2}
)

// metricsServer is a one-circuit L2 instance that is never served: the tests
// call the loop's own methods directly, so every report they observe comes
// from the call they made.
func metricsServer(t *testing.T, p2p bool, opts ...ServerOption) (*IsisServer, *circuit, *countingMetrics) {
	t.Helper()
	m := newCountingMetrics()
	s := mustServer(t, append([]ServerOption{
		WithSystemID(metricsSelfID),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level2:    true,
			P2P:       p2p,
			Padding:   ptrFalse(),
		}),
		WithMetrics(m),
	}, opts...)...)
	return s, s.circuits[0], m
}

// addUpAdjacency attaches an Up L2 adjacency to the peer, heard just now so
// housekeeping does not expire it.
func addUpAdjacency(c *circuit, now time.Time) {
	adj := &adjacency{
		systemID:  metricsPeerID,
		snpa:      metricsPeerSNPA,
		state:     AdjUp,
		holding:   30,
		lastHeard: now,
	}
	adj.levels.add(packet.Level2)
	if c.cfg.P2P {
		c.p2pAdj = adj
		return
	}
	c.adjs[packet.Level2][metricsPeerID] = adj
}

func serialize(t *testing.T, pdu packet.PDU) []byte {
	t.Helper()
	wire, err := pdu.Serialize()
	if err != nil {
		t.Fatalf("serialize %T: %v", pdu, err)
	}
	return wire
}

func peerLSP(remaining uint16) *packet.LSP {
	return &packet.LSP{
		Level:          packet.Level2,
		RemainingTime:  remaining,
		LSPID:          lspID(metricsPeerID, 0),
		SequenceNumber: 7,
		ISType:         3,
	}
}

// TestMetricsCountsReceivedAndDroppedPDUs walks handleRx through each point at
// which a PDU is discarded and checks the reason reported is the one that
// applies, so an operator can tell a misconfiguration from a dead link.
func TestMetricsCountsReceivedAndDroppedPDUs(t *testing.T) {
	now := time.Now()

	t.Run("undecodable bytes are dropped as decode", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		s.handleRx(c, datalink.Frame{PDU: []byte{0x83, 0xff, 0xde, 0xad}, Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "decode"); got != 1 {
			t.Errorf("decode drops = %d, want 1", got)
		}
		if got := m.count("pdu_rx", "c", "lsp"); got != 0 {
			t.Errorf("a PDU that never decoded was counted as received %d times", got)
		}
	})

	t.Run("a decoded hello is counted as received", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		hello := &packet.LANHello{
			Level:       packet.Level2,
			CircuitType: packet.CircuitTypeLevel2,
			SourceID:    metricsPeerID,
			HoldingTime: 30,
			Priority:    64,
			TLVs: []packet.TLV{
				&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{{0x49, 0x00, 0x01}}},
			},
		}
		s.handleRx(c, datalink.Frame{PDU: serialize(t, hello), Src: metricsPeerSNPA})
		if got := m.count("pdu_rx", "c", "lan_hello_l2"); got != 1 {
			t.Errorf("lan_hello_l2 received = %d, want 1", got)
		}
	})

	t.Run("an LSP from a source with no adjacency is dropped as no_adjacency", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, peerLSP(1000)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "no_adjacency"); got != 1 {
			t.Errorf("no_adjacency drops = %d, want 1", got)
		}
		// The gate runs after decoding, so the PDU still counts as received.
		if got := m.count("pdu_rx", "c", "lsp"); got != 1 {
			t.Errorf("lsp received = %d, want 1", got)
		}
	})

	t.Run("a corrupted checksum is dropped as checksum", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		addUpAdjacency(c, now)
		raw := serialize(t, peerLSP(1000))
		raw[24] ^= 0x01 // the first checksum octet (PDU offset 24)
		s.handleRx(c, datalink.Frame{PDU: raw, Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "checksum"); got != 1 {
			t.Errorf("checksum drops = %d, want 1", got)
		}
	})

	t.Run("a purge for an unheld LSP is dropped as unknown_purge", func(t *testing.T) {
		s, c, m := metricsServer(t, true)
		addUpAdjacency(c, now)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, peerLSP(0)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "unknown_purge"); got != 1 {
			t.Errorf("unknown_purge drops = %d, want 1", got)
		}
	})

	t.Run("an unsigned LSP into an authenticated level is dropped as auth", func(t *testing.T) {
		s, c, m := metricsServer(t, false, WithDomainAuth(AuthConfig{Secret: "k"}))
		addUpAdjacency(c, now)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, peerLSP(1000)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "auth"); got != 1 {
			t.Errorf("auth drops = %d, want 1", got)
		}
		if e := s.dbs[packet.Level2].get(lspID(metricsPeerID, 0)); e != nil {
			t.Error("an LSP that failed authentication was stored")
		}
	})

	t.Run("an LSP beyond the entry limit is dropped as lsdb_limit", func(t *testing.T) {
		s, c, m := metricsServer(t, false, WithLSDBEntryLimit(1))
		addUpAdjacency(c, now)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, peerLSP(1000)), Src: metricsPeerSNPA})
		second := peerLSP(1000)
		second.LSPID = lspID(packet.SystemID{0, 0, 0, 0, 0, 0x33}, 0)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, second), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "lsdb_limit"); got != 1 {
			t.Errorf("lsdb_limit drops = %d, want 1", got)
		}
		if n := len(s.dbs[packet.Level2].entries); n != 1 {
			t.Errorf("database holds %d entries, want the 1 the limit allows", n)
		}
	})

	t.Run("a copy of an LSP we originate is counted as own_lsp_reclaimed", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		addUpAdjacency(c, now)
		s.regenerateLSPs(false, now)
		id := lspID(s.systemID, 0)
		ex := s.dbs[packet.Level2].get(id)
		if ex == nil {
			t.Fatal("our own LSP was not originated")
		}
		forged := &packet.LSP{
			Level: packet.Level2, RemainingTime: 1000, LSPID: id,
			SequenceNumber: ex.lsp.SequenceNumber + 5, ISType: 3,
		}
		s.handleRx(c, datalink.Frame{PDU: serialize(t, forged), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "own_lsp_reclaimed"); got != 1 {
			t.Errorf("own_lsp_reclaimed drops = %d, want 1", got)
		}
	})

	t.Run("an LSP for a pseudonode we do not own is counted as own_sysid_purge", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		addUpAdjacency(c, now)
		// Pseudonode 0x7f matches none of our circuits, so we can never be its DIS.
		forged := &packet.LSP{
			Level: packet.Level2, RemainingTime: 1000, LSPID: lspID(s.systemID, 0x7f),
			SequenceNumber: 4, ISType: 2,
		}
		s.handleRx(c, datalink.Frame{PDU: serialize(t, forged), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "own_sysid_purge"); got != 1 {
			t.Errorf("own_sysid_purge drops = %d, want 1", got)
		}
	})
}

// TestForgedOwnSystemIDLSPsCannotGrowTheDatabasePastTheLimit pins the ordering
// processLSP documents: the own-System-ID handling sits after the entry-limit
// check, so an attacker flooding LSP IDs that name us cannot use the purge path
// to push the database past the cap an operator configured.
func TestForgedOwnSystemIDLSPsCannotGrowTheDatabasePastTheLimit(t *testing.T) {
	now := time.Now()
	s, c, m := metricsServer(t, false, WithLSDBEntryLimit(1))
	addUpAdjacency(c, now)
	s.handleRx(c, datalink.Frame{PDU: serialize(t, peerLSP(1000)), Src: metricsPeerSNPA})

	for pseudonode := 0x70; pseudonode < 0x78; pseudonode++ {
		forged := &packet.LSP{
			Level: packet.Level2, RemainingTime: 1000, LSPID: lspID(s.systemID, uint8(pseudonode)),
			SequenceNumber: 4, ISType: 2,
		}
		s.handleRx(c, datalink.Frame{PDU: serialize(t, forged), Src: metricsPeerSNPA})
	}

	if n := len(s.dbs[packet.Level2].entries); n != 1 {
		t.Errorf("database holds %d entries, want the 1 the limit allows", n)
	}
	if got := m.count("pdu_drop", "c", "lsdb_limit"); got != 8 {
		t.Errorf("lsdb_limit drops = %d, want 8 (one per forged LSP)", got)
	}
	if got := m.count("pdu_drop", "c", "own_sysid_purge"); got != 0 {
		t.Errorf("own_sysid_purge drops = %d: the limit must be applied first", got)
	}
}

// TestMetricsReportsGaugesOnHousekeeping: the adjacency gauge is reported for a
// configured circuit and level whether or not it holds an adjacency, so losing
// the last neighbor reads as 0 rather than as a gauge that stopped moving.
func TestMetricsReportsGaugesOnHousekeeping(t *testing.T) {
	s, c, m := metricsServer(t, false)
	now := time.Now()
	addUpAdjacency(c, now)

	s.housekeeping(now)
	if n, ok := m.gauge("adjacencies", "c", "L2"); !ok || n != 1 {
		t.Errorf("adjacencies{c,L2} = %d (reported %v), want 1", n, ok)
	}
	if n, ok := m.gauge("event_queue"); !ok || n != 0 {
		t.Errorf("event queue depth = %d (reported %v), want 0", n, ok)
	}

	delete(c.adjs[packet.Level2], metricsPeerID)
	s.housekeeping(now)
	if n, ok := m.gauge("adjacencies", "c", "L2"); !ok || n != 0 {
		t.Errorf("adjacencies{c,L2} after the neighbor left = %d (reported %v), want 0", n, ok)
	}
}

// TestMetricsReportsRouteCount: the route gauge follows the RIB down to zero
// for a level and algorithm that computed routes and then stopped.
func TestMetricsReportsRouteCount(t *testing.T) {
	m := newCountingMetrics()
	s := ribServer(t, false, WithMetrics(m))
	now := time.Now()
	self, peer := packet.SystemID{0, 0, 0, 0, 0, 1}, packet.SystemID{0, 0, 0, 0, 0, 2}

	injectLSPAt(s, packet.Level2, self, []packet.TLV{isReach(peer)}, now)
	injectLSPAt(s, packet.Level2, peer, []packet.TLV{isReach(self),
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4("10.55.0.0/24", 10)}}}, now)
	s.updateRIB(now)
	if n, ok := m.gauge("routes", "L2", "0"); !ok || n != 1 {
		t.Errorf("routes{L2,0} = %d (reported %v), want 1", n, ok)
	}

	injectLSPAt(s, packet.Level2, peer, []packet.TLV{isReach(self)}, now)
	s.updateRIB(now)
	if n, ok := m.gauge("routes", "L2", "0"); !ok || n != 0 {
		t.Errorf("routes{L2,0} after the prefix was withdrawn = %d (reported %v), want 0", n, ok)
	}
}

// TestMetricsCountsFIBWriteErrors: a rejected kernel write is reported by
// operation, separately from the pending-retry gauge that follows it.
func TestMetricsCountsFIBWriteErrors(t *testing.T) {
	ff := newFailFIB()
	ff.failNext = true
	m := newCountingMetrics()
	s := ribServer(t, false, WithFIB(ff), WithMetrics(m))
	now := time.Now()
	self, peer := packet.SystemID{0, 0, 0, 0, 0, 1}, packet.SystemID{0, 0, 0, 0, 0, 2}

	injectLSPAt(s, packet.Level2, self, []packet.TLV{isReach(peer)}, now)
	injectLSPAt(s, packet.Level2, peer, []packet.TLV{isReach(self),
		&packet.ExtendedIPReachabilityTLV{Prefixes: []packet.ExtendedIPReachEntry{v4("10.56.0.0/24", 10)}}}, now)
	s.updateRIB(now)

	if got := m.count("fib_error", "update"); got != 1 {
		t.Errorf("fib update errors = %d, want 1", got)
	}
	if _, ok := s.rib[netip.MustParsePrefix("10.56.0.0/24")]; !ok {
		t.Error("a route the FIB rejected left the RIB; the error count would then be unreachable on retry")
	}
}
