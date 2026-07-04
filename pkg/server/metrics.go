package server

import (
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// Metrics receives observability events from the IS-IS instance. The server
// calls every method from its single management goroutine, so the write side
// needs no synchronization; only concurrent reads (a scraper on another
// goroutine) must be synchronized, which Prometheus collectors already are.
// The default is NoopMetrics; the daemon wires a Prometheus implementation
// (see pkg/metrics) and library consumers can supply their own telemetry sink.
// Implementations can embed NoopMetrics to stay forward-compatible when
// methods are added to this interface.
type Metrics interface {
	// AdjacencyTransition records an adjacency entering a new state ("Up",
	// "Init", "Down") on a circuit at a level ("L1"/"L2").
	AdjacencyTransition(circuit, level, state string)
	// SPFRun records one shortest-path computation for a level and its duration.
	SPFRun(level string, d time.Duration)
	// LSDBSize reports the current number of LSPs held for a level.
	LSDBSize(level string, n int)
	// FloodTx records one LSP transmitted (flooded) on a circuit.
	FloodTx(circuit string)
	// FIBPending reports the number of routes whose last FIB write failed and
	// are awaiting retry.
	FIBPending(n int)
}

// NoopMetrics discards every event. It is the default when no Metrics sink is
// configured.
type NoopMetrics struct{}

// AdjacencyTransition implements Metrics.
func (NoopMetrics) AdjacencyTransition(string, string, string) {}

// SPFRun implements Metrics.
func (NoopMetrics) SPFRun(string, time.Duration) {}

// LSDBSize implements Metrics.
func (NoopMetrics) LSDBSize(string, int) {}

// FloodTx implements Metrics.
func (NoopMetrics) FloodTx(string) {}

// FIBPending implements Metrics.
func (NoopMetrics) FIBPending(int) {}

// levelLabel renders a level as a short metric label.
func levelLabel(l packet.Level) string {
	switch l {
	case packet.Level1:
		return "L1"
	case packet.Level2:
		return "L2"
	default:
		return "?"
	}
}
