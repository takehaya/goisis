// Package server provides IsisServer, the embeddable IS-IS instance that
// backs both goisisd and library consumers.
package server

import (
	"context"
	"errors"
	"log/slog"

	"github.com/takehaya/goisis/internal/version"
)

// ErrServerStopped is returned by management operations issued after the
// Serve loop has exited.
var ErrServerStopped = errors.New("goisis: server stopped")

// IsisServer is the top-level IS-IS instance. Every management operation is
// serialized onto the Serve loop through mgmtCh, so there is exactly one
// mutation path for protocol state (LSDB, adjacencies, configuration).
type IsisServer struct {
	logger *slog.Logger
	mgmtCh chan *mgmtOp
	done   chan struct{}
}

type mgmtOp struct {
	f     func() error
	errCh chan error
}

type options struct {
	logger *slog.Logger
}

// ServerOption configures an IsisServer.
type ServerOption func(*options)

// WithLogger sets the logger used by the server. Defaults to slog.Default().
func WithLogger(l *slog.Logger) ServerOption {
	return func(o *options) { o.logger = l }
}

// NewIsisServer returns a stopped IS-IS instance. Call Serve to run it.
func NewIsisServer(opts ...ServerOption) *IsisServer {
	o := options{logger: slog.Default()}
	for _, opt := range opts {
		opt(&o)
	}
	return &IsisServer{
		logger: o.logger,
		mgmtCh: make(chan *mgmtOp, 1),
		done:   make(chan struct{}),
	}
}

// Serve runs the management event loop until ctx is cancelled. It may be
// called at most once per IsisServer.
func (s *IsisServer) Serve(ctx context.Context) error {
	defer close(s.done)
	s.logger.Info("goisis server started")
	for {
		select {
		case <-ctx.Done():
			// Fail queued ops so callers blocked in mgmtOperation don't
			// have to wait for their own deadlines.
			for {
				select {
				case op := <-s.mgmtCh:
					op.errCh <- ErrServerStopped
				default:
					s.logger.Info("goisis server stopped")
					return nil
				}
			}
		case op := <-s.mgmtCh:
			op.errCh <- op.f()
		}
	}
}

// mgmtOperation runs f on the Serve loop and waits for its result. State
// owned by the loop must only be touched from inside f.
func (s *IsisServer) mgmtOperation(ctx context.Context, f func() error) error {
	// Never enqueue on a context that is already cancelled: select would
	// otherwise pick the ready send at random and run f anyway.
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
		// An op answered just before shutdown still wins over the stop error.
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
	Version string
}

// GetGlobal returns a snapshot of instance-wide state.
func (s *IsisServer) GetGlobal(ctx context.Context) (Global, error) {
	var g Global
	err := s.mgmtOperation(ctx, func() error {
		g = Global{Version: version.Version}
		return nil
	})
	return g, err
}
