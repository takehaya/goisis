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

// spfBackoffServer runs a one-circuit L2 instance with an SPF counter, on a
// clock the test drives. It returns once startup origination's own recompute
// and its hold have elapsed, so a test measures only the changes it makes
// itself, and with the loop idle at a known instant: no peer, no tick due, so
// every recompute that follows is one the test asked for.
func spfBackoffServer(t *testing.T) (*IsisServer, *spfCounter, *fakeClock) {
	t.Helper()
	c := &spfCounter{}
	clk := newFakeClock()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithMetrics(c),
		WithClock(clk),
	)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx
	// loopSync before the first Advance, not only as a barrier: the loop arms
	// its ticker and its hold timer before it serves anything, so this is also
	// what guarantees the clock has them to fire.
	loopSync(t, s)
	clk.Advance(2 * spfHold)
	loopSync(t, s)
	return s, c, clk
}

// dirty marks SPF dirty on the loop, the way a protocol event would, and
// returns once the loop has run the tail of that iteration — so the back-off
// has already decided what to do with the change, and the count the test
// reads next cannot be one recompute behind.
func dirty(t *testing.T, s *IsisServer) {
	t.Helper()
	if err := s.mgmtOperation(t.Context(), func() error {
		s.markDirty()
		return nil
	}); err != nil {
		t.Fatalf("markDirty: %v", err)
	}
	loopSync(t, s)
}

func TestSPFRunsPromptlyOnFirstChange(t *testing.T) {
	s, c, _ := spfBackoffServer(t)
	base := c.count()

	dirty(t, s)

	// Promptly means in the tail of the very iteration that took the change,
	// before any timer: dirty returns at the end of that iteration and the
	// clock has not moved, so one run here is the whole claim.
	if got := c.count() - base; got != 1 {
		t.Errorf("SPF runs in the iteration that took the first change = %d, want 1", got)
	}
}

func TestSPFCoalescesChangesDuringHold(t *testing.T) {
	s, c, clk := spfBackoffServer(t)
	base := c.count()

	// Ten changes, one every 20ms of the server's own time against a 200ms
	// hold. The first recomputes at once and arms the hold; the other nine all
	// fall inside it and cost one recompute between them, at its end. Two, and
	// which change landed where is not a matter of how the run was scheduled:
	// dirty leaves the loop idle at a known instant and only Advance moves it.
	for range 10 {
		dirty(t, s)
		clk.Advance(20 * time.Millisecond)
	}
	loopSync(t, s)

	if got := c.count() - base; got != 2 {
		t.Errorf("SPF runs for 10 changes over one hold = %d, want 2", got)
	}
}

func TestSPFHoldDoesNotDelayIdleLoop(t *testing.T) {
	s, c, clk := spfBackoffServer(t)

	// One change arms the hold and nothing changes while it runs, so it is an
	// idle loop the timer fires on. That loop neither recomputes nor wedges:
	// management operations are still served afterwards.
	dirty(t, s)
	base := c.count()
	clk.Advance(3 * spfHold)
	loopSync(t, s)

	if err := s.mgmtOperation(t.Context(), func() error { return nil }); err != nil {
		t.Fatalf("mgmtOperation: %v", err)
	}
	if got := c.count() - base; got != 0 {
		t.Errorf("SPF runs while idle = %d, want 0", got)
	}
}
