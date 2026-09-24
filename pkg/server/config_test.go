package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func TestHoldingTimeCeil(t *testing.T) {
	for _, tc := range []struct {
		interval time.Duration
		mult     int
		want     uint16
	}{
		{3 * time.Second, 10, 30},
		{1500 * time.Millisecond, 10, 15}, // must not truncate to 10
		{500 * time.Millisecond, 10, 5},
		{900 * time.Millisecond, 3, 3}, // ceil(2.7) = 3
	} {
		c := CircuitConfig{HelloInterval: tc.interval, HoldingMultiplier: tc.mult}
		if got := c.holdingTime(); got != tc.want {
			t.Errorf("holdingTime(%v*%d) = %d, want %d", tc.interval, tc.mult, got, tc.want)
		}
	}
}

func TestPriorityValidation(t *testing.T) {
	mock := func() *datalink.MockTransport {
		return datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	}
	// Priority above 127 is rejected.
	if _, err := NewIsisServer(WithCircuit(CircuitConfig{Name: "c", Transport: mock(), Priority: u8(200)})); err == nil {
		t.Error("priority 200 should be rejected")
	}
	// Priority 0 is honored, not silently replaced by the default.
	cfg := CircuitConfig{Name: "c", Transport: mock(), Priority: u8(0)}
	if err := cfg.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	if cfg.priority() != 0 {
		t.Errorf("priority() = %d, want 0", cfg.priority())
	}
	// Unset priority defaults to DefaultPriority.
	def := CircuitConfig{Name: "c", Transport: mock()}
	if def.priority() != DefaultPriority {
		t.Errorf("default priority() = %d, want %d", def.priority(), DefaultPriority)
	}
}

func TestCircuitLimit(t *testing.T) {
	var opts []ServerOption
	for i := 0; i < 256; i++ {
		opts = append(opts, WithCircuit(CircuitConfig{
			Name:      "c",
			Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500),
		}))
	}
	if _, err := NewIsisServer(opts...); err == nil {
		t.Error("256 circuits should exceed the pseudonode limit")
	}
}

// TestValidateOptionsRunsEveryCircuitCheckThatNeedsNoTransport pins the line
// ValidateOptions' doc draws. A reload validates through it and opens no
// socket (pkg/config.Diff), and it rebuilds a changed circuit as a delete and
// an add, so a circuit check only NewIsisServer reaches is one the reload runs
// with the circuit already deleted. The MTU checks are the deliberate
// exception: a circuit's MTU comes from its transport, and only a restart has
// one to ask.
func TestValidateOptionsRunsEveryCircuitCheckThatNeedsNoTransport(t *testing.T) {
	circuits := func(cfgs ...CircuitConfig) []ServerOption {
		opts := make([]ServerOption, 0, len(cfgs))
		for _, c := range cfgs {
			c.Transport = datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
			opts = append(opts, WithCircuit(c))
		}
		return opts
	}
	// One more than the pseudonode space holds, which allocCircuitIDs refuses
	// on the last circuit and ValidateOptions refuses on the count.
	many := make([]CircuitConfig, 256)
	for i := range many {
		many[i] = CircuitConfig{Name: fmt.Sprintf("c%d", i)}
	}

	for name, tc := range map[string]struct {
		opts []ServerOption
		ok   bool
	}{
		"an ordinary circuit":                    {circuits(CircuitConfig{Name: "c"}), true},
		"no interface name":                      {circuits(CircuitConfig{}), false},
		"priority above the 127 ceiling":         {circuits(CircuitConfig{Name: "c", Priority: u8(200)}), false},
		"priority at the ceiling":                {circuits(CircuitConfig{Name: "c", Priority: u8(127)}), true},
		"hello accept passwords with no primary": {circuits(CircuitConfig{Name: "c", HelloAcceptPasswords: []string{"old"}}), false},
		"a hello key rotation that keeps one":    {circuits(CircuitConfig{Name: "c", HelloPassword: "new", HelloAcceptPasswords: []string{"old"}}), true},
		"more circuits than pseudonode octets":   {circuits(many...), false},
		"the same interface named twice":         {circuits(CircuitConfig{Name: "c"}, CircuitConfig{Name: "c"}), false},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateOptions(tc.opts...); (err == nil) != tc.ok {
				t.Errorf("ValidateOptions err = %v, want ok=%v", err, tc.ok)
			}
			if _, err := NewIsisServer(tc.opts...); (err == nil) != tc.ok {
				t.Errorf("NewIsisServer err = %v, want ok=%v: the two paths disagree on the same file", err, tc.ok)
			}
		})
	}
}

func TestServeClosesTransportsOnShutdown(t *testing.T) {
	tr := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500)
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithCircuit(CircuitConfig{Name: "c", Transport: tr, Level2: true, Padding: ptrFalse()}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}

	// Serve must have closed the transport, so its reader goroutine exited
	// rather than leaking: Recv now reports ErrClosed.
	if _, err := tr.Recv(); err != datalink.ErrClosed {
		t.Errorf("transport not closed on shutdown: Recv err = %v, want ErrClosed", err)
	}
}
