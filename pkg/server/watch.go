package server

import (
	"bytes"
	"context"
	"sort"
	"sync/atomic"

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
	// lagged is set (before ch is closed) when the subscriber is dropped for
	// falling behind, vs. a normal unsubscribe/shutdown. It is atomic because
	// Subscription.Lagged may read it from the consumer goroutine.
	lagged atomic.Bool
}

// Subscription is a handle to a WatchEvent stream.
type Subscription struct {
	// Initial is a snapshot of state as of the instant the subscription was
	// registered: one event per adjacency (the same content as
	// ListAdjacencies, hostnames included), then one per RIB entry (the same
	// as ListRoutes).
	// Because it is captured in the very management operation that registers
	// the watcher, Initial followed by Events is a gap-free view — no change
	// can fall between the two, as it can between a separate List call and a
	// Subscribe. It is a plain slice rather than pre-queued events, so a large
	// snapshot cannot fill the buffer and get the subscriber dropped.
	Initial []Event
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
	// lagged is an atomic.Bool set before the channel is closed, so the consumer
	// can read it directly once it observes the close — no serialization onto
	// the Serve loop is required.
	return sub.w.lagged.Load()
}

// Unsubscribe ends the subscription.
func (sub *Subscription) Unsubscribe() {
	_ = sub.s.mgmtOperation(context.Background(), func() error {
		sub.s.dropWatcher(sub.w)
		return nil
	})
}

// Subscribe registers an event subscriber and snapshots current state into
// the subscription (see Subscription.Initial).
func (s *IsisServer) Subscribe(ctx context.Context) (*Subscription, error) {
	w := &watcher{ch: make(chan Event, watcherBuffer)}
	sub := &Subscription{Events: w.ch, s: s, w: w}
	var adjs []AdjacencyInfo
	var routes []RouteInfo
	if err := s.mgmtOperation(ctx, func() error {
		s.watchers[w] = struct{}{}
		adjs, routes = s.snapshotState()
		return nil
	}); err != nil {
		return nil, err
	}
	// Ordering the snapshot is pure work on a private copy, so it runs here
	// rather than in the management operation: a full RIB costs far more to
	// sort than the Serve loop can give a read (a lag-dropped monitor that
	// resubscribes pays it again every time).
	sub.Initial = initialEvents(adjs, routes)
	return sub, nil
}

// snapshotState copies the current adjacencies and routes for a subscriber's
// initial snapshot. Called only on the Serve goroutine; it only copies, and
// leaves ordering to initialEvents.
func (s *IsisServer) snapshotState() ([]AdjacencyInfo, []RouteInfo) {
	// Resolve hostnames once for the whole snapshot, so Initial really carries
	// the same content as ListAdjacencies. Live events do not: the index is
	// O(LSDB) and an adjacency change is not worth rebuilding it (see the
	// Hostname field's doc).
	hostnames := s.hostnameIndex(s.clock.Now())
	var adjs []AdjacencyInfo
	for _, c := range s.circuits {
		adjs = append(adjs, c.adjacencyInfos()...)
	}
	for i := range adjs {
		adjs[i].Hostname = hostnames[adjs[i].SystemID]
	}
	routes := make([]RouteInfo, 0, len(s.rib))
	for _, r := range s.rib {
		routes = append(routes, r)
	}
	return adjs, routes
}

// initialEvents renders a snapshot as the events that would have reported it,
// adjacencies first and each group ordered so two subscribers see the same
// sequence. It works on the caller's own copies, off the Serve loop.
func initialEvents(adjs []AdjacencyInfo, routes []RouteInfo) []Event {
	sort.Slice(adjs, func(i, j int) bool {
		if adjs[i].Interface != adjs[j].Interface {
			return adjs[i].Interface < adjs[j].Interface
		}
		if adjs[i].Level != adjs[j].Level {
			return adjs[i].Level < adjs[j].Level
		}
		return bytes.Compare(adjs[i].SystemID[:], adjs[j].SystemID[:]) < 0
	})
	sort.Slice(routes, func(i, j int) bool {
		// Compare the prefixes, not their text: Prefix.String formats both
		// operands afresh on every one of the O(n log n) comparisons, which is
		// most of what sorting a large RIB costs.
		return routes[i].Prefix.Compare(routes[j].Prefix) < 0
	})

	out := make([]Event, 0, len(adjs)+len(routes))
	for i := range adjs {
		out = append(out, Event{Adjacency: &adjs[i]})
	}
	for i := range routes {
		out = append(out, Event{Route: &routes[i]})
	}
	return out
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
			w.lagged.Store(true)
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
	s.metrics.AdjacencyTransition(c.cfg.Name, levelLabel(level), AdjDown.String())
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
