package server

import "time"

// Clock is where the server reads time. Every timer the Serve loop arms and
// every instant the server takes on its own behalf comes from here, so a test
// can drive a running instance through a hold, a housekeeping tick or a CSNP
// interval instead of waiting out real seconds (WithClock). The default is the
// time package itself and costs nothing extra.
//
// Two readings deliberately stay on the wall clock and are not routed here.
// The reader goroutines' retry delay is one: readLoop runs per circuit and not
// on the management loop, so a clock a test steps would have to be stepped
// from a goroutine that knows nothing about those readers, for a delay no
// assertion is about (see readerRetryDelay). The other is the stopwatch around
// an SPF run, which measures how long the computation took and not when it
// happened (computeSPF).
type Clock interface {
	// Now is the server's idea of the current instant. The Serve loop reads it
	// once per unit of work and passes it down, so everything decided in that
	// unit agrees on when it happened.
	Now() time.Time
	// NewTicker and NewTimer mirror time.NewTicker and time.NewTimer.
	NewTicker(d time.Duration) Ticker
	NewTimer(d time.Duration) Timer
}

// Ticker is a Clock's periodic timer: time.Ticker with its channel behind a
// method, because an interface cannot carry a field.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// Timer is a Clock's one-shot timer. Stop and Reset report nothing, unlike
// time.Timer's: the Serve loop tracks whether its timer is armed in a variable
// of its own and never consults the return, and a bool that says whether a
// timer was armed a moment ago is the classic way to get timer code wrong.
type Timer interface {
	C() <-chan time.Time
	Stop()
	Reset(d time.Duration)
}

// realClock is the default Clock: the time package, unadorned. Each wrapper is
// a single pointer, which Go stores in an interface value directly, so none of
// this allocates beyond what time itself allocates.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }

func (realClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTicker struct{ t *time.Ticker }

func (r realTicker) C() <-chan time.Time { return r.t.C }
func (r realTicker) Stop()               { r.t.Stop() }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time   { return r.t.C }
func (r realTimer) Stop()                 { r.t.Stop() }
func (r realTimer) Reset(d time.Duration) { r.t.Reset(d) }
