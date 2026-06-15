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
	} {
		if !got[want] {
			t.Errorf("metric %q not registered/emitted", want)
		}
	}
}
