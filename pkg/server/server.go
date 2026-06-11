// Package server provides IsisServer, the embeddable IS-IS instance that
// backs both goisisd and library consumers.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/packet"
)

// ErrServerStopped is returned by management operations issued after the
// Serve loop has exited.
var ErrServerStopped = errors.New("goisis: server stopped")

// IsisServer is the top-level IS-IS instance. Every management operation and
// protocol event is serialized onto the Serve loop, so there is exactly one
// goroutine that mutates protocol state (circuits, adjacencies, the LSDB).
type IsisServer struct {
	logger    *slog.Logger
	systemID  packet.SystemID
	areaAddrs []packet.AreaAddress
	hostname  string

	mgmtCh  chan *mgmtOp
	eventCh chan event
	done    chan struct{}

	// circuits is owned by the Serve loop after Serve starts.
	circuits []*circuit
}

type mgmtOp struct {
	f     func() error
	errCh chan error
}

// NewIsisServer returns a stopped IS-IS instance. Call Serve to run it.
func NewIsisServer(opts ...ServerOption) (*IsisServer, error) {
	o := options{logger: slog.Default()}
	for _, opt := range opts {
		opt(&o)
	}
	s := &IsisServer{
		logger:    o.logger,
		systemID:  o.systemID,
		areaAddrs: o.areaAddrs,
		hostname:  o.hostname,
		mgmtCh:    make(chan *mgmtOp, 1),
		eventCh:   make(chan event, 256),
		done:      make(chan struct{}),
	}
	// Pseudonode octets are a single byte and must be nonzero and unique
	// per box, so at most 255 circuits can be assigned distinct octets.
	if len(o.circuits) > 255 {
		return nil, fmt.Errorf("goisis: %d circuits exceeds the 255 pseudonode limit", len(o.circuits))
	}
	for i := range o.circuits {
		cfg := o.circuits[i]
		if err := cfg.applyDefaults(); err != nil {
			return nil, err
		}
		// Pseudonode / extended-circuit IDs must be nonzero and unique
		// per box; the 1-based circuit index serves both.
		s.circuits = append(s.circuits, newCircuit(cfg, uint8(i+1), uint32(i+1))) //nolint:gosec // bounded by the 255 check above
	}
	return s, nil
}

// Serve runs the management and protocol event loop until ctx is cancelled.
// It may be called at most once per IsisServer. On exit Serve closes every
// circuit's transport (taking ownership of the injected transports) and
// waits for the reader goroutines to finish, so a cancelled Serve leaks
// neither goroutines nor sockets.
func (s *IsisServer) Serve(ctx context.Context) error {
	defer close(s.done)
	s.logger.Info("goisis server started",
		"net", s.netString(), "circuits", len(s.circuits))

	// One reader goroutine per circuit feeds decoded frames to the loop.
	var readers sync.WaitGroup
	for _, c := range s.circuits {
		readers.Add(1)
		go func(c *circuit) {
			defer readers.Done()
			s.readLoop(ctx, c)
		}(c)
	}

	// Send an initial hello burst so adjacencies form promptly.
	now := time.Now()
	for _, c := range s.circuits {
		s.sendHellos(c, now)
	}

	ticker := time.NewTicker(housekeepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.shutdown(&readers)
			return nil
		case op := <-s.mgmtCh:
			op.errCh <- op.f()
		case ev := <-s.eventCh:
			s.handleEvent(ev)
		case t := <-ticker.C:
			s.housekeeping(t)
		}
	}
}

// shutdown closes transports (unblocking the reader goroutines' Recv),
// waits for the readers to exit, and fails any queued management ops.
func (s *IsisServer) shutdown(readers *sync.WaitGroup) {
	for _, c := range s.circuits {
		_ = c.cfg.Transport.Close()
	}
	readers.Wait()
	for {
		select {
		case op := <-s.mgmtCh:
			op.errCh <- ErrServerStopped
		default:
			s.logger.Info("goisis server stopped")
			return
		}
	}
}

// readLoop receives frames on a circuit and forwards them to the event loop
// until the transport closes or the context is cancelled.
func (s *IsisServer) readLoop(ctx context.Context, c *circuit) {
	for {
		frame, err := c.cfg.Transport.Recv()
		if err != nil {
			return
		}
		select {
		case s.eventCh <- &rxEvent{circuit: c, frame: frame}:
		case <-ctx.Done():
			return
		}
	}
}

// housekeeping runs periodic per-circuit maintenance: hello transmission and
// holding-time expiry.
func (s *IsisServer) housekeeping(now time.Time) {
	for _, c := range s.circuits {
		if !now.Before(c.nextHello) {
			s.sendHellos(c, now)
		}
		s.expireAdjacencies(c, now)
	}
}

// mgmtOperation runs f on the Serve loop and waits for its result. State
// owned by the loop must only be touched from inside f.
func (s *IsisServer) mgmtOperation(ctx context.Context, f func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	errCh := make(chan error, 1)
	select {
	case s.mgmtCh <- &mgmtOp{f: f, errCh: errCh}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrServerStopped
	}
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		select {
		case err := <-errCh:
			return err
		default:
			return ErrServerStopped
		}
	}
}

// Global is a snapshot of instance-wide state.
type Global struct {
	Version  string
	SystemID packet.SystemID
}

// GetGlobal returns a snapshot of instance-wide state.
func (s *IsisServer) GetGlobal(ctx context.Context) (Global, error) {
	var g Global
	err := s.mgmtOperation(ctx, func() error {
		g = Global{Version: version.Version, SystemID: s.systemID}
		return nil
	})
	return g, err
}

// ListAdjacencies returns a snapshot of all adjacencies across all circuits.
func (s *IsisServer) ListAdjacencies(ctx context.Context) ([]AdjacencyInfo, error) {
	var out []AdjacencyInfo
	err := s.mgmtOperation(ctx, func() error {
		for _, c := range s.circuits {
			out = append(out, c.adjacencyInfos()...)
		}
		return nil
	})
	return out, err
}

// netString renders the server's NET for diagnostics.
func (s *IsisServer) netString() string {
	if len(s.areaAddrs) == 0 {
		return fmt.Sprintf("(no area).%s.00", s.systemID)
	}
	return fmt.Sprintf("%s.%s.00", s.areaAddrs[0], s.systemID)
}
