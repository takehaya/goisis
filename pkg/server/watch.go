package server

import (
	"context"

	"github.com/takehaya/goisis/pkg/packet"
)

// watcherBuffer is the per-subscriber event queue depth. A subscriber that
// falls this far behind is dropped rather than stalling the Serve loop.
const watcherBuffer = 64

// Event is a protocol change delivered to WatchEvent subscribers. Exactly one
// of Adjacency or Route is set.
type Event struct {
	// Adjacency, if set, reports an adjacency state change.
	Adjacency *AdjacencyInfo
	// Route, if set, reports a route change; Withdrawn distinguishes removal
	// from addition/update.
	Route     *RouteInfo
	Withdrawn bool
}

// watcher is one subscription's delivery channel.
type watcher struct {
	ch     chan Event
	closed bool
	lagged bool // dropped for falling behind (vs. unsubscribed/shutdown)
}

// Subscription is a handle to a WatchEvent stream.
type Subscription struct {
	// Events delivers protocol changes. It is closed when the subscription
	// ends (unsubscribed, server stopped, or dropped for lagging — see
	// Lagged).
	Events <-chan Event
	s      *IsisServer
	w      *watcher
}

// Lagged reports whether the subscription was dropped because the consumer
// fell too far behind (as opposed to a normal unsubscribe or server stop). A
// lagging consumer has missed events and should resubscribe.
func (sub *Subscription) Lagged() bool {
	lagged := false
	_ = sub.s.mgmtOperation(context.Background(), func() error {
		lagged = sub.w.lagged
		return nil
	})
	return lagged
}

// Unsubscribe ends the subscription.
func (sub *Subscription) Unsubscribe() {
	_ = sub.s.mgmtOperation(context.Background(), func() error {
		sub.s.dropWatcher(sub.w)
		return nil
	})
}

// Subscribe registers an event subscriber.
func (s *IsisServer) Subscribe(ctx context.Context) (*Subscription, error) {
	w := &watcher{ch: make(chan Event, watcherBuffer)}
	if err := s.mgmtOperation(ctx, func() error {
		s.watchers[w] = struct{}{}
		return nil
	}); err != nil {
		return nil, err
	}
	return &Subscription{Events: w.ch, s: s, w: w}, nil
}

// emit delivers an event to all subscribers without blocking the Serve loop:
// a subscriber whose buffer is full is dropped (its channel is closed).
// Called only on the Serve goroutine.
func (s *IsisServer) emit(ev Event) {
	for w := range s.watchers {
		select {
		case w.ch <- ev:
		default:
			s.logger.Warn("dropping lagging watch subscriber")
			w.lagged = true
			s.dropWatcher(w)
		}
	}
}

func (s *IsisServer) dropWatcher(w *watcher) {
	if !w.closed {
		w.closed = true
		close(w.ch)
		delete(s.watchers, w)
	}
}

// emitAdjacency reports an adjacency state change to subscribers.
func (s *IsisServer) emitAdjacency(info AdjacencyInfo) {
	if len(s.watchers) > 0 {
		s.emit(Event{Adjacency: &info})
	}
}

// emitAdjacencyDown reports that an adjacency went down (its info with the
// state overridden to Down, since the adjacency is about to be removed).
func (s *IsisServer) emitAdjacencyDown(c *circuit, adj *adjacency, level packet.Level) {
	if len(s.watchers) == 0 {
		return
	}
	info := c.infoFor(adj, level)
	info.State = AdjDown
	s.emit(Event{Adjacency: &info})
}

// closeWatchers drops all subscribers (used on shutdown).
func (s *IsisServer) closeWatchers() {
	for w := range s.watchers {
		s.dropWatcher(w)
	}
}
