package server

import (
	"context"
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
