package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestPrometheusRecords(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheus(reg)
	m.AdjacencyTransition("eth0", "L2", "Up")
	m.SPFRun("L2", 5*time.Millisecond)
	m.LSDBSize("L2", 3)
	m.FloodTx("eth0")
	m.FIBPending(2)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]bool{}
	for _, mf := range mfs {
		got[mf.GetName()] = true
	}
	for _, want := range []string{
		"goisis_adjacency_transitions_total",
		"goisis_spf_duration_seconds",
		"goisis_lsdb_lsps",
		"goisis_flooding_lsp_tx_total",
		"goisis_fib_pending",
	} {
		if !got[want] {
			t.Errorf("metric %q not registered/emitted", want)
		}
	}
	// The gauge carries the reported value, not just its registration.
	for _, mf := range mfs {
		if mf.GetName() != "goisis_fib_pending" {
			continue
		}
		if ms := mf.GetMetric(); len(ms) != 1 || ms[0].GetGauge().GetValue() != 2 {
			t.Errorf("goisis_fib_pending = %+v, want a single gauge with value 2", ms)
		}
	}
}
