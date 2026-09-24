package server

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeClock is a Clock a test drives by hand. Nothing ages, ticks or fires
// until Advance says so, which buys two things: a test that would otherwise
// wait out a 200ms hold or a 10s CSNP interval costs no wall time, and it
// lands on an exact instant rather than somewhere inside a window, so its
// assertion can be a count instead of a range.
//
// It is unexported on purpose. The packages above this one (pkg/config,
// cmd/goisisd) wait on convergence, which is frames crossing transports and
// not time passing, so nothing outside this package needs it yet; a consumer
// that does implements Clock itself, which is four small methods.
//
// A Serve loop parked in its select on a ticker that has not fired is the
// normal case here, and it is what Advance is built around: every tick goes
// out on an unbuffered channel and Advance waits for it to be taken, so when
// Advance returns the loop has the tick in hand. It has not finished acting on
// it — that is what loopSync is for. The waiting is also why a timer that is
// stopped has to leave the waiter list: a send nobody selects on would never
// return. Stop takes a timer off the list, and so does firing a one-shot, so
// only an armed timer is ever sent to.
//
// The cost of that is that advancing a clock whose Serve loop has already
// exited blocks until the test binary's own timeout dumps the goroutines. That
// is a test bug, and the dump names it.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*fakeWaiter
}

// fakeWaiter is one armed ticker or timer; period is zero for a one-shot.
type fakeWaiter struct {
	ch     chan time.Time
	at     time.Time
	period time.Duration
}

// newFakeClock starts at a fixed instant, far from the zero Time so the
// server's "has this been set" checks on a time.Time stay honest.
func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTicker(d time.Duration) Ticker {
	ch := make(chan time.Time)
	return &fakeTicker{c: c, ch: ch, w: c.arm(ch, d, d)}
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	ch := make(chan time.Time)
	return &fakeTimer{c: c, ch: ch, w: c.arm(ch, d, 0)}
}

func (c *fakeClock) arm(ch chan time.Time, d, period time.Duration) *fakeWaiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := &fakeWaiter{ch: ch, at: c.now.Add(d), period: period}
	c.waiters = append(c.waiters, w)
	return w
}

func (c *fakeClock) disarm(w *fakeWaiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waiters = slices.DeleteFunc(c.waiters, func(x *fakeWaiter) bool { return x == w })
}

// Advance moves the clock on by d, firing every timer it passes one at a time
// and in order. Ten seconds with a one-second ticker are ten housekeeping
// passes, each at its own instant — a test that skips a window this way skips
// the waiting and not the work.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()
	for {
		w, at := c.nextDue(target)
		if w == nil {
			break
		}
		w.ch <- at
	}
	c.mu.Lock()
	c.now = target
	c.mu.Unlock()
}

// nextDue moves the clock onto the earliest waiter due at or before target and
// hands it back, rearming it if it is a ticker and dropping it if it is not.
// It reports nil once nothing more is due.
func (c *fakeClock) nextDue(target time.Time) (*fakeWaiter, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var due *fakeWaiter
	for _, w := range c.waiters {
		if w.at.After(target) {
			continue
		}
		if due == nil || w.at.Before(due.at) {
			due = w
		}
	}
	if due == nil {
		return nil, time.Time{}
	}
	at := due.at
	// The clock reads as the firing instant for the whole of the handling, so
	// whatever the receiver asks it while it works agrees with the tick it was
	// handed.
	c.now = at
	if due.period > 0 {
		due.at = at.Add(due.period)
	} else {
		c.waiters = slices.DeleteFunc(c.waiters, func(x *fakeWaiter) bool { return x == due })
	}
	return due, at
}

type fakeTicker struct {
	c  *fakeClock
	ch chan time.Time
	w  *fakeWaiter
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }
func (t *fakeTicker) Stop()               { t.c.disarm(t.w) }

// fakeTimer keeps one channel across arms, so a Reset does not invalidate a
// C() the caller is already selecting on. Its waiter may have fired and been
// dropped already; disarming it again does nothing, which is what time.Timer
// promises too.
type fakeTimer struct {
	c  *fakeClock
	ch chan time.Time
	w  *fakeWaiter
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }
func (t *fakeTimer) Stop()               { t.c.disarm(t.w) }

func (t *fakeTimer) Reset(d time.Duration) {
	t.c.disarm(t.w)
	t.w = t.c.arm(t.ch, d, 0)
}

// loopSync returns once the Serve loop has finished the iteration it was in.
// Two operations are what it takes: the first is served at the top of an
// iteration, so the second cannot be until the tail of that iteration — the
// pending LSP generation and the SPF back-off check — has run and the loop is
// back at its select. It is the barrier to follow an Advance with when the
// assertion is about what the tick did rather than that it was delivered.
func loopSync(t *testing.T, s *IsisServer) {
	t.Helper()
	for range 2 {
		if err := s.mgmtOperation(context.Background(), func() error { return nil }); err != nil {
			t.Fatalf("syncing with the Serve loop: %v", err)
		}
	}
}

// stepDelay is how long waitClock lets the frames one advance produced cross
// the mock transports and the reader goroutines, which happens in real time
// however the clock is driven. A stall only costs another simulated tick.
const stepDelay = 2 * time.Millisecond

// waitClock is waitFor for instances on a fake clock: the condition still says
// when to stop, but the protocol's seconds pass only because this advances
// them, a housekeeping tick at a time — which is the cadence hellos, aging and
// flooding actually run at (housekeeping). The bound is in simulated ticks,
// not wall time, so a loaded runner makes it slower and not flakier.
func waitClock(t *testing.T, clk *fakeClock, what string, fn func() bool) {
	t.Helper()
	for range 120 {
		if fn() {
			return
		}
		clk.Advance(housekeepInterval)
		time.Sleep(stepDelay)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// stopped waits for a Serve loop to exit, which a test on a fake clock must do
// before it advances again: the loop disarms its ticker and its hold on the
// way out, and until it has, an advance would sit forever sending a tick into
// a select nobody is in any more.
func stopped(t *testing.T, s *IsisServer) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the Serve loop did not exit")
	}
}

// waitDrops advances the clock until a circuit has turned away n PDUs for
// this reason. It is what a test whose claim is that nothing happened wants in
// place of a window chosen to be comfortably long: the clock makes the peer
// send, the counter says its frames arrived and were rejected, and the test
// stops there instead of at the end of the window.
func waitDrops(t *testing.T, clk *fakeClock, m *countingMetrics, circuit, reason string, n int) {
	t.Helper()
	waitClock(t, clk, fmt.Sprintf("circuit %s to reject %d PDUs (%s)", circuit, n, reason),
		func() bool { return m.count("pdu_drop", circuit, reason) >= n })
}

// TestRealClockDoesNotAllocate pins the claim realClock's comment makes: the
// default Clock is the time package with a wrapper that Go stores in the
// interface value itself, so putting one in an interface costs nothing. A
// wrapper that grew a second field would start allocating per tick.
func TestRealClockDoesNotAllocate(t *testing.T) {
	var c Clock = realClock{}
	if n := testing.AllocsPerRun(100, func() { _ = c.Now() }); n != 0 {
		t.Errorf("allocations per Clock.Now = %v, want 0", n)
	}
	tk := c.NewTicker(time.Hour)
	defer tk.Stop()
	if n := testing.AllocsPerRun(100, func() { _ = tk.C() }); n != 0 {
		t.Errorf("allocations per Ticker.C = %v, want 0", n)
	}
}
