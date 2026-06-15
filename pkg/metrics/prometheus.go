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
	}
	reg.MustRegister(p.adjTransitions, p.spfDuration, p.lsdbSize, p.floodTx)
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

var _ server.Metrics = (*Prometheus)(nil)
