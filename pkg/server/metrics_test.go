package server

import (
	"bytes"
	"errors"
	"log/slog"
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
	// reports counts every report made, and reportsAtForget the value it held
	// when ForgetCircuit ran. The two are what tell a retirement made last
	// from one made half way through: a sink keys its series on the circuit
	// name, so anything reported afterwards builds them again.
	reports         int
	reportsAtForget int
	forgotten       []string
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{counts: map[string]int{}, gauges: map[string]int{}}
}

func (m *countingMetrics) PDURx(circuit, pduType string)  { m.inc("pdu_rx", circuit, pduType) }
func (m *countingMetrics) PDUDrop(circuit, reason string) { m.inc("pdu_drop", circuit, reason) }
func (m *countingMetrics) FIBError(op string)             { m.inc("fib_error", op) }

func (m *countingMetrics) PDUTxError(circuit, reason string) { m.inc("pdu_tx_error", circuit, reason) }
func (m *countingMetrics) PDURxError(circuit string)         { m.inc("pdu_rx_error", circuit) }

func (m *countingMetrics) FloodDrop(circuit, reason string) { m.inc("flood_drop", circuit, reason) }

func (m *countingMetrics) LSPLifetimeFloored(circuit string) { m.inc("lsp_lifetime_floored", circuit) }

func (m *countingMetrics) InterLevelPrefixes(direction string, n int) {
	m.set(n, "inter_level_prefixes", direction)
}

func (m *countingMetrics) AdjacencyCount(circuit, level string, n int) {
	m.set(n, "adjacencies", circuit, level)
}

func (m *countingMetrics) RouteCount(level, algo string, n int) { m.set(n, "routes", level, algo) }
func (m *countingMetrics) EventQueueDepth(n int)                { m.set(n, "event_queue") }

func (m *countingMetrics) inc(parts ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[strings.Join(parts, "|")]++
	m.reports++
}

func (m *countingMetrics) set(n int, parts ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[strings.Join(parts, "|")] = n
	m.reports++
}

func (m *countingMetrics) ForgetCircuit(circuit string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forgotten = append(m.forgotten, circuit)
	m.reportsAtForget = m.reports
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

// metricsServerWith is a one-circuit instance that is never served: the tests
// call the loop's own methods directly, so every report they observe comes
// from the call they made.
func metricsServerWith(t *testing.T, cfg CircuitConfig, opts ...ServerOption) (*IsisServer, *circuit, *countingMetrics) {
	t.Helper()
	m := newCountingMetrics()
	s := mustServer(t, append([]ServerOption{
		WithSystemID(metricsSelfID),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg),
		WithMetrics(m),
	}, opts...)...)
	return s, s.circuits[0], m
}

// metricsServer is metricsServerWith over the default L2 circuit "c".
func metricsServer(t *testing.T, p2p bool, opts ...ServerOption) (*IsisServer, *circuit, *countingMetrics) {
	t.Helper()
	return metricsServerWith(t, CircuitConfig{
		Name:      "c",
		Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
		Level2:    true,
		P2P:       p2p,
		Padding:   ptrFalse(),
	}, opts...)
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

	t.Run("a frame that raced the link going down is dropped as link_down", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		c.linkDown = true
		s.handleRx(c, datalink.Frame{PDU: serialize(t, peerLSP(1000)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", "link_down"); got != 1 {
			t.Errorf("link_down drops = %d, want 1", got)
		}
		if got := m.count("pdu_rx", "c", "lsp"); got != 0 {
			t.Errorf("a frame on a down circuit was counted as received %d times", got)
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

// metricsArea is the area every hello below shares with metricsServer.
var metricsArea = packet.AreaAddress{0x49, 0x00, 0x01}

// metricsLANHello builds a LAN hello from the peer at a level, carrying area.
func metricsLANHello(level packet.Level, holding uint16, area packet.AreaAddress) *packet.LANHello {
	return &packet.LANHello{
		Level:       level,
		CircuitType: packet.CircuitTypeLevel1 | packet.CircuitTypeLevel2,
		SourceID:    metricsPeerID,
		HoldingTime: holding,
		Priority:    64,
		TLVs:        []packet.TLV{&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{area}}},
	}
}

// metricsP2PHello builds a point-to-point hello from the peer advertising ct.
func metricsP2PHello(ct packet.CircuitType, area packet.AreaAddress) *packet.P2PHello {
	return &packet.P2PHello{
		CircuitType:    ct,
		SourceID:       metricsPeerID,
		HoldingTime:    30,
		LocalCircuitID: 1,
		TLVs:           []packet.TLV{&packet.AreaAddressesTLV{Addresses: []packet.AreaAddress{area}}},
	}
}

// TestMetricsCountsHellosTheAdjacencyFSMRefuses walks every point at which a
// hello is thrown away before it can form an adjacency. Each one is a routine
// "why won't this adjacency come up" cause, so each must leave a counter with
// the reason behind: hello_invalid for a hello this circuit cannot use at all,
// hello_mismatch for one whose area or level set does not meet ours, and
// duplicate_system_id for one carrying our own System ID.
func TestMetricsCountsHellosTheAdjacencyFSMRefuses(t *testing.T) {
	lanCircuit := func(name string) CircuitConfig {
		return CircuitConfig{Name: name, Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
			Level1: true, Padding: ptrFalse()}
	}

	t.Run("a LAN hello on a point-to-point circuit is hello_invalid", func(t *testing.T) {
		s, c, m := metricsServer(t, true)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, metricsLANHello(packet.Level2, 30, metricsArea)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", dropHelloInvalid); got != 1 {
			t.Errorf("hello_invalid drops = %d, want 1", got)
		}
	})

	t.Run("a point-to-point hello on a LAN circuit is hello_invalid", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, metricsP2PHello(packet.CircuitTypeLevel2, metricsArea)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", dropHelloInvalid); got != 1 {
			t.Errorf("hello_invalid drops = %d, want 1", got)
		}
	})

	t.Run("a zero holding time is hello_invalid", func(t *testing.T) {
		s, c, m := metricsServer(t, false)
		s.handleRx(c, datalink.Frame{PDU: serialize(t, metricsLANHello(packet.Level2, 0, metricsArea)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", dropHelloInvalid); got != 1 {
			t.Errorf("hello_invalid drops = %d, want 1", got)
		}
	})

	t.Run("a hello for a level the circuit does not run is hello_invalid", func(t *testing.T) {
		s, c, m := metricsServer(t, false) // Level 2 only
		s.handleRx(c, datalink.Frame{PDU: serialize(t, metricsLANHello(packet.Level1, 30, metricsArea)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", dropHelloInvalid); got != 1 {
			t.Errorf("hello_invalid drops = %d, want 1", got)
		}
	})

	t.Run("a Level-1 hello from another area is hello_mismatch", func(t *testing.T) {
		s, c, m := metricsServerWith(t, lanCircuit("c"))
		other := packet.AreaAddress{0x49, 0x00, 0x02}
		s.handleRx(c, datalink.Frame{PDU: serialize(t, metricsLANHello(packet.Level1, 30, other)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", dropHelloMismatch); got != 1 {
			t.Errorf("hello_mismatch drops = %d, want 1", got)
		}
		if _, ok := c.adjs[packet.Level1][metricsPeerID]; ok {
			t.Error("a Level-1 hello from another area formed an adjacency")
		}
	})

	t.Run("a point-to-point hello with no common level is hello_mismatch", func(t *testing.T) {
		s, c, m := metricsServer(t, true) // Level 2 only; the peer offers Level 1
		s.handleRx(c, datalink.Frame{PDU: serialize(t, metricsP2PHello(packet.CircuitTypeLevel1, metricsArea)), Src: metricsPeerSNPA})
		if got := m.count("pdu_drop", "c", dropHelloMismatch); got != 1 {
			t.Errorf("hello_mismatch drops = %d, want 1", got)
		}
	})

	t.Run("a hello carrying our own System ID is duplicate_system_id", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			p2p  bool
			pdu  func() packet.PDU
		}{
			{"lan", false, func() packet.PDU {
				h := metricsLANHello(packet.Level2, 30, metricsArea)
				h.SourceID = metricsSelfID
				return h
			}},
			{"p2p", true, func() packet.PDU {
				h := metricsP2PHello(packet.CircuitTypeLevel2, metricsArea)
				h.SourceID = metricsSelfID
				return h
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s, c, m := metricsServer(t, tc.p2p)
				// Twice: the warning is edge-triggered, the counter is not.
				for range 2 {
					s.handleRx(c, datalink.Frame{PDU: serialize(t, tc.pdu()), Src: metricsPeerSNPA})
				}
				if got := m.count("pdu_drop", "c", dropDuplicateSystemID); got != 2 {
					t.Errorf("duplicate_system_id drops = %d, want 2", got)
				}
			})
		}
	})
}

// failingSendTransport fails every Send, as a socket does under ENOBUFS or
// when the interface goes away between the link-state event and the write.
type failingSendTransport struct {
	*datalink.MockTransport
}

func (failingSendTransport) Send(packet.SNPA, []byte) error {
	return errors.New("datalink: send: no buffer space available")
}

// TestMetricsCountsTransmitFailures: a PDU that never reaches the wire is
// counted per circuit with the step that failed, and logged on the edge of the
// outage rather than once per PDU per tick. Hellos, SNPs and flooded LSPs all
// report through the same counter: to an operator they are one fault, "this
// circuit cannot transmit".
func TestMetricsCountsTransmitFailures(t *testing.T) {
	now := time.Now()
	newServer := func(t *testing.T, logs *bytes.Buffer) (*IsisServer, *circuit, *countingMetrics) {
		t.Helper()
		return metricsServerWith(t, CircuitConfig{
			Name:      "c",
			Transport: failingSendTransport{datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)},
			Level2:    true,
			Padding:   ptrFalse(),
		}, WithLogger(slog.New(slog.NewTextHandler(logs, nil))))
	}

	t.Run("a hello that cannot be sent is counted", func(t *testing.T) {
		var logs bytes.Buffer
		s, c, m := newServer(t, &logs)
		s.sendHellos(c, now)
		s.sendHellos(c, now)
		if got := m.count("pdu_tx_error", "c", txErrSend); got != 2 {
			t.Errorf("send errors = %d, want 2 (one per hello)", got)
		}
		if n := strings.Count(logs.String(), "circuit cannot transmit"); n != 1 {
			t.Errorf("transmit-failure logs for 2 failed hellos = %d, want 1: the log is edge-triggered", n)
		}
	})

	t.Run("an SNP that cannot be sent is counted", func(t *testing.T) {
		var logs bytes.Buffer
		s, c, m := newServer(t, &logs)
		s.sendCSNP(c, packet.Level2, now)
		if got := m.count("pdu_tx_error", "c", txErrSend); got != 1 {
			t.Errorf("send errors = %d, want 1", got)
		}
	})

	t.Run("an LSP that cannot be flooded is counted as a send error, not a flood drop", func(t *testing.T) {
		var logs bytes.Buffer
		s, c, m := newServer(t, &logs)
		id := lspID(metricsPeerID, 0)
		putEntry(s, id, 7, 1000, now)
		c.setSRM(packet.Level2, id, now)
		s.transmitSRM(c, packet.Level2, now)

		if got := m.count("pdu_tx_error", "c", txErrSend); got != 1 {
			t.Errorf("send errors = %d, want 1", got)
		}
		// A transient write failure is not the permanent "this LSP can never
		// go out here" that FloodDrop reports, and the flag stays set so the
		// next tick retries.
		if got := m.count("flood_drop", "c", floodDropOversize); got != 0 {
			t.Errorf("flood drops = %d, want 0: the LSP fits, the socket failed", got)
		}
		if _, ok := c.srm[packet.Level2][id]; !ok {
			t.Error("the SRM flag was cleared by a transient send failure; the LSP would never be retried")
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

func (m *countingMetrics) FloodTx(circuit string) { m.inc("flood_tx", circuit) }

func (m *countingMetrics) AdjacencyTransition(circuit, level, state string) {
	m.inc("adj_transition", circuit, level, state)
}

// TestAFlooredLifetimeIsCountedPerCircuit pins what the counter counts, which
// is every lifetime the RFC 7987 floor raises and not corruption: an ordinary
// aged value is indistinguishable here, because separating the two needs how
// long the receiving adjacency has been Up (§3.2's false-positive filter) and
// the update process does not carry that down to the LSP it installs. So the
// baseline is normal flooding, no absolute value means anything, and the
// counter is read as one circuit's rate against the others -- which is why it
// is counted and never logged.
func TestAFlooredLifetimeIsCountedPerCircuit(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		remaining uint16
		want      int
	}{
		{"any lifetime below MaxAge is raised, and counted, corrupt or merely aged", 30, 1},
		{"MaxAge itself is not raised", maxAgeSeconds, 0},
		{"a lifetime above MaxAge is kept as advertised", maxAgeSeconds + 100, 0},
		{"a purge is never a floored lifetime", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c, m := metricsServer(t, true)
			addUpAdjacency(c, now)
			s.handleRx(c, datalink.Frame{PDU: serialize(t, peerLSP(tc.remaining)), Src: metricsPeerSNPA})
			if got := m.count("lsp_lifetime_floored", "c"); got != tc.want {
				t.Errorf("floored lifetimes on c = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestADeletedCircuitIsRetiredFromTheSinkLast pins the one call that keeps a
// removed circuit's series from standing forever. Every per-circuit gauge is
// re-set on the housekeeping tick, which walks the configured circuits, so a
// circuit that is gone is never visited again and its last value is what a
// scrape keeps reading.
//
// "Last" is half the guarantee: the sink keys on the circuit name, so a report
// made after the retirement builds the series again. The removal itself owes
// several (the adjacencies going down, the flush onto the departing segment),
// and its reader goroutine outlives it with events already queued -- which is
// why the guard that refuses those sits in handleEvent and not in handleRx.
func TestADeletedCircuitIsRetiredFromTheSinkLast(t *testing.T) {
	m := newCountingMetrics()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(lanCircuit("a", 0xa1, 1500)), WithCircuit(lanCircuit("b", 0xb1, 1500)),
		WithMetrics(m),
	)
	now := time.Now()
	c := s.circuits[0]
	addUpAdjacency(c, now)
	s.regenerateLSPs(false, now)

	if err := s.deleteCircuit("a", now); err != nil {
		t.Fatalf("deleteCircuit: %v", err)
	}

	if got := m.forgets(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("circuits retired from the sink = %v, want exactly [a]", got)
	}
	if made, atForget := m.reportCounts(); made != atForget {
		t.Errorf("%d reports were made after the circuit was retired, so its series are back", made-atForget)
	}
	// The reader's queued failure must not put them back either.
	s.handleEvent(&rxErrEvent{circuit: c})
	if got := m.count("pdu_rx_error", "a"); got != 0 {
		t.Errorf("receive errors recorded for a deleted circuit = %d, want 0", got)
	}
}

func (m *countingMetrics) forgets() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.forgotten...)
}

func (m *countingMetrics) reportCounts() (made, atForget int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reports, m.reportsAtForget
}
