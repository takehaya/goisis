package metrics

import (
	"reflect"
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
	m.FloodDrop("eth0", "oversize")
	m.FIBPending(2)
	m.PDURx("eth0", "lsp")
	m.PDUDrop("eth0", "auth")
	m.AdjacencyCount("eth0", "L2", 1)
	m.RouteCount("L2", "0", 4)
	m.FIBError("update")
	m.EventQueueDepth(7)
	m.PDUTxError("eth0", "send")
	m.PDURxError("eth0")
	m.ConfigReload("partial")
	m.ConfigReloadUnapplied(2)
	m.LSPLifetimeFloored("eth0")
	m.InterLevelPrefixes("l2_to_l1", 3)

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
		"goisis_flooding_lsp_drops_total",
		"goisis_fib_pending",
		"goisis_pdu_rx_total",
		"goisis_pdu_drops_total",
		"goisis_adjacencies",
		"goisis_routes",
		"goisis_fib_errors_total",
		"goisis_event_queue_depth",
		"goisis_pdu_tx_errors_total",
		"goisis_pdu_rx_errors_total",
		"goisis_config_reloads_total",
		"goisis_config_reload_unapplied",
		"goisis_lsp_lifetime_floored_total",
		"goisis_inter_level_prefixes",
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
		{"goisis_flooding_lsp_drops_total", 1},
		{"goisis_fib_pending", 2},
		{"goisis_pdu_rx_total", 1},
		{"goisis_pdu_drops_total", 1},
		{"goisis_adjacencies", 1},
		{"goisis_routes", 4},
		{"goisis_fib_errors_total", 1},
		{"goisis_event_queue_depth", 7},
		{"goisis_pdu_tx_errors_total", 1},
		{"goisis_pdu_rx_errors_total", 1},
		{"goisis_config_reloads_total", 1},
		{"goisis_config_reload_unapplied", 2},
		{"goisis_lsp_lifetime_floored_total", 1},
		{"goisis_inter_level_prefixes", 3},
	} {
		if v, ok := singleValue(tc.name); !ok || v != tc.want {
			t.Errorf("%s = %v (single series %v), want %v", tc.name, v, ok, tc.want)
		}
	}
}

// circuitSeries groups every gathered series carrying a "circuit" label by that
// label's value, as the names of the families it appears in.
func circuitSeries(t *testing.T, reg *prometheus.Registry) map[string][]string {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string][]string{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "circuit" {
					out[l.GetValue()] = append(out[l.GetValue()], mf.GetName())
				}
			}
		}
	}
	return out
}

// TestForgetCircuitDropsEverySeriesThatNamesIt reads the retirement back out of
// the registry rather than trusting the call. A deleted circuit's series are
// otherwise permanent -- nothing re-sets a gauge for a circuit the housekeeping
// tick no longer walks -- and the obvious implementation, DeleteLabelValues,
// wants the complete label tuple in declaration order and silently deletes
// nothing when it is given anything else.
func TestForgetCircuitDropsEverySeriesThatNamesIt(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheus(reg)
	for _, c := range []string{"eth0", "eth1"} {
		m.AdjacencyTransition(c, "L2", "Up")
		m.FloodTx(c)
		m.FloodDrop(c, "oversize")
		m.PDURx(c, "lsp")
		m.PDUDrop(c, "auth")
		m.AdjacencyCount(c, "L2", 1)
		m.PDUTxError(c, "send")
		m.PDURxError(c)
		m.LSPLifetimeFloored(c)
	}

	before := circuitSeries(t, reg)
	// Every collector that carries a circuit label has to be in the fixture,
	// or this proves the retirement only of the ones that are.
	for _, c := range []string{"eth0", "eth1"} {
		if n := len(before[c]); n != 9 {
			t.Fatalf("%s has %d circuit-labelled series (%v), want the 9 collectors that carry the label: a collector was added without a line in this fixture or in ForgetCircuit", c, n, before[c])
		}
	}

	m.ForgetCircuit("eth0")

	after := circuitSeries(t, reg)
	if n := len(after["eth0"]); n != 0 {
		t.Errorf("%d series still name the deleted circuit: %v", n, after["eth0"])
	}
	if !reflect.DeepEqual(after["eth1"], before["eth1"]) {
		t.Errorf("retiring one circuit took another's series with it:\n got %v\nwant %v", after["eth1"], before["eth1"])
	}
}
