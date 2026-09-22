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
	m.PDURx("eth0", "lsp")
	m.PDUDrop("eth0", "auth")
	m.AdjacencyCount("eth0", "L2", 1)
	m.RouteCount("L2", "0", 4)
	m.FIBError("update")
	m.EventQueueDepth(7)

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
		"goisis_pdu_rx_total",
		"goisis_pdu_drops_total",
		"goisis_adjacencies",
		"goisis_routes",
		"goisis_fib_errors_total",
		"goisis_event_queue_depth",
	} {
		if !got[want] {
			t.Errorf("metric %q not registered/emitted", want)
		}
	}
	// singleValue reads back a metric family that carries exactly one series,
	// whether it is a counter or a gauge.
	singleValue := func(name string) (float64, bool) {
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			ms := mf.GetMetric()
			if len(ms) != 1 {
				return 0, false
			}
			if c := ms[0].GetCounter(); c != nil {
				return c.GetValue(), true
			}
			return ms[0].GetGauge().GetValue(), true
		}
		return 0, false
	}

	// The series carry the reported values, not just their registration.
	for _, tc := range []struct {
		name string
		want float64
	}{
		{"goisis_fib_pending", 2},
		{"goisis_pdu_rx_total", 1},
		{"goisis_pdu_drops_total", 1},
		{"goisis_adjacencies", 1},
		{"goisis_routes", 4},
		{"goisis_fib_errors_total", 1},
		{"goisis_event_queue_depth", 7},
	} {
		if v, ok := singleValue(tc.name); !ok || v != tc.want {
			t.Errorf("%s = %v (single series %v), want %v", tc.name, v, ok, tc.want)
		}
	}
}
