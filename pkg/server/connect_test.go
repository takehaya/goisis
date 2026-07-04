package server

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	goisisv1 "github.com/takehaya/goisis/gen/goisis/v1"
	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// TestToConnectError pins the error-code mapping for the mutating handlers:
// lifecycle errors get their canonical codes, already-coded errors pass
// through, and everything else is a validation failure.
func TestToConnectError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want connect.Code
	}{
		{"server stopped", ErrServerStopped, connect.CodeUnavailable},
		{"context canceled", context.Canceled, connect.CodeCanceled},
		{"deadline exceeded", context.DeadlineExceeded, connect.CodeDeadlineExceeded},
		{"coded error passes through", connect.NewError(connect.CodeAlreadyExists, errors.New("dup")), connect.CodeAlreadyExists},
		{"validation error", errors.New("locator overlaps"), connect.CodeInvalidArgument},
	} {
		if got := connect.CodeOf(toConnectError(tc.err)); got != tc.want {
			t.Errorf("%s: code = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestConnectMutatorsOnStoppedServer asserts a mutation issued after Serve has
// returned is reported as Unavailable, not InvalidArgument, so clients can
// tell a dead daemon from a bad request.
func TestConnectMutatorsOnStoppedServer(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	ctx, cancel := context.WithCancel(t.Context())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = s.Serve(ctx)
	}()
	cancel()
	<-serveDone

	h := &connectHandler{s: s}
	_, err := h.AddLocator(context.Background(), connect.NewRequest(&goisisv1.AddLocatorRequest{Prefix: "fc00:0:1::/48"}))
	if got := connect.CodeOf(err); got != connect.CodeUnavailable {
		t.Errorf("AddLocator on stopped server: code = %v (%v), want Unavailable", got, err)
	}
	_, err = h.DeleteFlexAlgo(context.Background(), connect.NewRequest(&goisisv1.DeleteFlexAlgoRequest{Algorithm: 128}))
	if got := connect.CodeOf(err); got != connect.CodeUnavailable {
		t.Errorf("DeleteFlexAlgo on stopped server: code = %v (%v), want Unavailable", got, err)
	}
}

// TestConnectMutatorOnCancelledContext asserts a caller-side cancellation is
// reported as Canceled.
func TestConnectMutatorOnCancelledContext(t *testing.T) {
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	// No Serve loop: mgmtOperation fails fast on the dead context.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h := &connectHandler{s: s}
	_, err := h.DeleteLocator(ctx, connect.NewRequest(&goisisv1.DeleteLocatorRequest{Prefix: "fc00:0:1::/48"}))
	if got := connect.CodeOf(err); got != connect.CodeCanceled {
		t.Errorf("DeleteLocator on cancelled ctx: code = %v (%v), want Canceled", got, err)
	}
}
