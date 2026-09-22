package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// spfCounter counts SPF runs. The fixture below configures a single L2
// circuit, so one recompute records exactly one run. The Serve loop records
// from its own goroutine while the test reads from another, hence the mutex.
type spfCounter struct {
	NoopMetrics
	mu   sync.Mutex
	runs int
}

func (c *spfCounter) SPFRun(string, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runs++
}

func (c *spfCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs
}

// spfBackoffServer runs a one-circuit L2 instance with an SPF counter. It
// returns once startup origination's own recompute and its hold have elapsed,
// so a test measures only the changes it makes itself.
func spfBackoffServer(t *testing.T) (*IsisServer, *spfCounter) {
	t.Helper()
	c := &spfCounter{}
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithMetrics(c),
	)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx
	if err := s.mgmtOperation(ctx, func() error { return nil }); err != nil {
		t.Fatalf("waiting for the loop to start: %v", err)
	}
	time.Sleep(2 * spfHold)
	return s, c
}

// markDirty on the loop, the way a protocol event would.
func dirty(t *testing.T, s *IsisServer) {
	t.Helper()
	if err := s.mgmtOperation(t.Context(), func() error {
		s.markDirty()
		return nil
	}); err != nil {
		t.Fatalf("markDirty: %v", err)
	}
}

func TestSPFRunsPromptlyOnFirstChange(t *testing.T) {
	s, c := spfBackoffServer(t)
	base := c.count()

	dirty(t, s)

	// The recompute happens at the end of the same loop iteration, so it lands
	// well inside a hold interval; only scheduling separates us from it.
	deadline := time.Now().Add(100 * time.Millisecond)
	for c.count() == base && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.count() - base; got == 0 {
		t.Errorf("SPF runs within 100ms of the first change = 0, want at least 1")
	}
}

func TestSPFCoalescesChangesDuringHold(t *testing.T) {
	s, c := spfBackoffServer(t)
	base := c.count()

	// Ten changes spread over 200ms: one immediate recompute, then at most one
	// per hold window — and never zero for the trailing change.
	start := time.Now()
	for range 10 {
		dirty(t, s)
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(time.Until(start.Add(time.Second)))

	if got := c.count() - base; got < 2 || got > 3 {
		t.Errorf("SPF runs for 10 changes over 200ms = %d, want 2 or 3", got)
	}
}

func TestSPFHoldDoesNotDelayIdleLoop(t *testing.T) {
	s, c := spfBackoffServer(t)
	base := c.count()

	time.Sleep(3 * spfHold)

	// An idle loop neither recomputes nor wedges: the hold timer fires with
	// nothing dirty, and management operations are still served.
	if err := s.mgmtOperation(t.Context(), func() error { return nil }); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	if got := c.count() - base; got != 0 {
		t.Errorf("SPF runs while idle = %d, want 0", got)
	}
}
