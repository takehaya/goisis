// Package metrics provides a Prometheus implementation of server.Metrics. It
// is an optional, separately-imported adapter so library consumers that do not
// want Prometheus never link client_golang.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/takehaya/goisis/pkg/server"
)

// Prometheus implements server.Metrics by recording into Prometheus collectors.
type Prometheus struct {
	adjTransitions *prometheus.CounterVec
	spfDuration    *prometheus.HistogramVec
	lsdbSize       *prometheus.GaugeVec
	floodTx        *prometheus.CounterVec
	floodDrops     *prometheus.CounterVec
	fibPending     prometheus.Gauge
	pduRx          *prometheus.CounterVec
	pduDrops       *prometheus.CounterVec
	adjacencies    *prometheus.GaugeVec
	routes         *prometheus.GaugeVec
	fibErrors      *prometheus.CounterVec
	eventQueue     prometheus.Gauge
}

// NewPrometheus creates the collectors and registers them in reg (e.g.
// prometheus.DefaultRegisterer or a custom registry). It panics if a collector
// is already registered, matching prometheus.MustRegister.
func NewPrometheus(reg prometheus.Registerer) *Prometheus {
	p := &Prometheus{
		adjTransitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "goisis_adjacency_transitions_total",
			Help: "Count of IS-IS adjacency state transitions.",
		}, []string{"circuit", "level", "state"}),
		spfDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "goisis_spf_duration_seconds",
			Help:    "Shortest-path computation duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"level"}),
		lsdbSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "goisis_lsdb_lsps",
			Help: "Number of LSPs currently in the link-state database.",
		}, []string{"level"}),
		floodTx: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "goisis_flooding_lsp_tx_total",
			Help: "Count of LSPs transmitted during flooding.",
		}, []string{"circuit"}),
		floodDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "goisis_flooding_lsp_drops_total",
			Help: "Count of LSPs that could not be flooded on a circuit, by reason.",
		}, []string{"circuit", "reason"}),
		fibPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "goisis_fib_pending",
			Help: "Number of routes whose last FIB write failed and are awaiting retry.",
		}),
		pduRx: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "goisis_pdu_rx_total",
			Help: "Count of IS-IS PDUs received and successfully decoded.",
		}, []string{"circuit", "type"}),
		pduDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "goisis_pdu_drops_total",
			Help: "Count of received IS-IS PDUs discarded, by reason.",
		}, []string{"circuit", "reason"}),
		adjacencies: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "goisis_adjacencies",
			Help: "Number of adjacencies currently Up.",
		}, []string{"circuit", "level"}),
		routes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "goisis_routes",
			Help: "Number of routes currently in the RIB.",
		}, []string{"level", "algorithm"}),
		fibErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "goisis_fib_errors_total",
			Help: "Count of failed FIB writes, by operation.",
		}, []string{"op"}),
		eventQueue: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "goisis_event_queue_depth",
			Help: "Number of received frames waiting to be handled by the management loop.",
		}),
	}
	reg.MustRegister(p.adjTransitions, p.spfDuration, p.lsdbSize, p.floodTx, p.floodDrops,
		p.fibPending, p.pduRx, p.pduDrops, p.adjacencies, p.routes, p.fibErrors, p.eventQueue)
	return p
}

// AdjacencyTransition implements server.Metrics.
func (p *Prometheus) AdjacencyTransition(circuit, level, state string) {
	p.adjTransitions.WithLabelValues(circuit, level, state).Inc()
}

// SPFRun implements server.Metrics.
func (p *Prometheus) SPFRun(level string, d time.Duration) {
	p.spfDuration.WithLabelValues(level).Observe(d.Seconds())
}

// LSDBSize implements server.Metrics.
func (p *Prometheus) LSDBSize(level string, n int) {
	p.lsdbSize.WithLabelValues(level).Set(float64(n))
}

// FloodTx implements server.Metrics.
func (p *Prometheus) FloodTx(circuit string) {
	p.floodTx.WithLabelValues(circuit).Inc()
}

// FloodDrop implements server.Metrics.
func (p *Prometheus) FloodDrop(circuit, reason string) {
	p.floodDrops.WithLabelValues(circuit, reason).Inc()
}

// FIBPending implements server.Metrics.
func (p *Prometheus) FIBPending(n int) {
	p.fibPending.Set(float64(n))
}

// PDURx implements server.Metrics.
func (p *Prometheus) PDURx(circuit, pduType string) {
	p.pduRx.WithLabelValues(circuit, pduType).Inc()
}

// PDUDrop implements server.Metrics.
func (p *Prometheus) PDUDrop(circuit, reason string) {
	p.pduDrops.WithLabelValues(circuit, reason).Inc()
}

// AdjacencyCount implements server.Metrics.
func (p *Prometheus) AdjacencyCount(circuit, level string, n int) {
	p.adjacencies.WithLabelValues(circuit, level).Set(float64(n))
}

// RouteCount implements server.Metrics.
func (p *Prometheus) RouteCount(level, algo string, n int) {
	p.routes.WithLabelValues(level, algo).Set(float64(n))
}

// FIBError implements server.Metrics.
func (p *Prometheus) FIBError(op string) {
	p.fibErrors.WithLabelValues(op).Inc()
}

// EventQueueDepth implements server.Metrics.
func (p *Prometheus) EventQueueDepth(n int) {
	p.eventQueue.Set(float64(n))
}

var _ server.Metrics = (*Prometheus)(nil)
