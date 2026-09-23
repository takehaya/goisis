package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	goisisv1 "github.com/takehaya/goisis/gen/goisis/v1"
	"github.com/takehaya/goisis/gen/goisis/v1/goisisv1connect"
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

// TestConnectAddPrefixInvalid asserts an unparsable prefix is rejected by the
// handler as InvalidArgument, before it reaches the Serve loop.
func TestConnectAddPrefixInvalid(t *testing.T) {
	h := &connectHandler{s: mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)}
	_, err := h.AddPrefix(context.Background(), connect.NewRequest(&goisisv1.AddPrefixRequest{Prefix: "10.9.9.0"}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("AddPrefix with a bad prefix: code = %v (%v), want InvalidArgument", got, err)
	}
}

// TestConnectClearAdjacencyInvalidSystemID asserts a malformed system ID is
// rejected as InvalidArgument.
func TestConnectClearAdjacencyInvalidSystemID(t *testing.T) {
	h := &connectHandler{s: mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)}
	_, err := h.ClearAdjacency(context.Background(), connect.NewRequest(&goisisv1.ClearAdjacencyRequest{
		Interface: "c",
		SystemId:  "0000.0000.01",
	}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("ClearAdjacency with a bad system ID: code = %v (%v), want InvalidArgument", got, err)
	}
}

func TestParseSystemID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want packet.SystemID
		ok   bool
	}{
		{"0000.0000.0001", packet.SystemID{0, 0, 0, 0, 0, 1}, true},
		{"1921.6800.1001", packet.SystemID{0x19, 0x21, 0x68, 0x00, 0x10, 0x01}, true},
		{"000000000001", packet.SystemID{0, 0, 0, 0, 0, 1}, true},
		{"0000.0000.01", packet.SystemID{}, false},      // too short
		{"0000.0000.0001.00", packet.SystemID{}, false}, // too long
		{"zzzz.0000.0001", packet.SystemID{}, false},    // not hex
	} {
		got, err := parseSystemID(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("parseSystemID(%q) ok=%v, want %v (err=%v)", tc.in, err == nil, tc.ok, err)
		}
		if tc.ok && got != tc.want {
			t.Errorf("parseSystemID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestWatchEventIncludeInitialOverConnect asserts a client that asks for the
// snapshot receives it before any live event, so it can prime itself from the
// stream alone.
func TestWatchEventIncludeInitialOverConnect(t *testing.T) {
	dst := netip.MustParsePrefix("10.9.9.0/24")
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	// There is no peer to converge with, so seed the RIB with what SPF would
	// have computed. Seeding in the same operation that finds no recompute
	// pending is what keeps it: a pending one would replace the whole map.
	waitFor(t, "startup SPF to settle", func() bool {
		seeded := false
		_ = s.mgmtOperation(ctx, func() error {
			if !s.spfDirty {
				s.rib[dst] = RouteInfo{Prefix: dst, Metric: 10, Level: packet.Level2}
				seeded = true
			}
			return nil
		})
		return seeded
	})

	mux := http.NewServeMux()
	mux.Handle(NewConnectHandler(s))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	client := goisisv1connect.NewIsisServiceClient(ts.Client(), ts.URL)

	stream, err := client.WatchEvent(ctx, connect.NewRequest(&goisisv1.WatchEventRequest{IncludeInitial: true}))
	if err != nil {
		t.Fatalf("WatchEvent: %v", err)
	}
	defer func() { _ = stream.Close() }()
	if !stream.Receive() {
		t.Fatalf("Receive: %v", stream.Err())
	}
	if got := stream.Msg().GetRoute().GetRoute().GetPrefix(); got != dst.String() {
		t.Errorf("first event = %+v, want snapshot route %s", stream.Msg(), dst)
	}
}

// TestGetLsdbSurvivesInvalidUTF8Hostname: a peer that advertises a TLV 137
// whose bytes are not valid UTF-8 must not break the management API. proto3
// string fields must hold valid UTF-8, so an unsanitized hostname makes
// Marshal fail and takes `goisis database`/`goisis neighbor` down for every
// operator until the LSP ages out.
func TestGetLsdbSurvivesInvalidUTF8Hostname(t *testing.T) {
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	// The LSP and the adjacency both have to exist for the hostname to reach
	// the two RPCs: GetLsdb renders it from the LSDB, ListAdjacencies resolves
	// it per neighbor.
	if err := s.mgmtOperation(ctx, func() error {
		injectLSPAt(s, packet.Level2, peer,
			[]packet.TLV{&packet.DynamicHostnameTLV{Hostname: "\xff\xfe"}}, time.Now())
		var l2 levelSet
		l2.add(packet.Level2)
		s.circuits[0].adjs[packet.Level2][peer] = &adjacency{
			systemID: peer, snpa: packet.SNPA{0, 0, 0, 0, 0, 2}, state: AdjUp, levels: l2,
		}
		return nil
	}); err != nil {
		t.Fatalf("seed LSDB: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(NewConnectHandler(s))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	client := goisisv1connect.NewIsisServiceClient(ts.Client(), ts.URL)

	lsdb, err := client.GetLsdb(ctx, connect.NewRequest(&goisisv1.GetLsdbRequest{}))
	if err != nil {
		t.Fatalf("GetLsdb: %v", err)
	}
	for _, l := range lsdb.Msg.GetLsps() {
		if !utf8.ValidString(l.GetHostname()) {
			t.Errorf("LSP %s hostname %q is not valid UTF-8", l.GetLspId(), l.GetHostname())
		}
		for _, tlv := range l.GetTlvs() {
			if !utf8.ValidString(tlv) {
				t.Errorf("LSP %s TLV line %q is not valid UTF-8", l.GetLspId(), tlv)
			}
		}
	}

	adjs, err := client.ListAdjacencies(ctx, connect.NewRequest(&goisisv1.ListAdjacenciesRequest{}))
	if err != nil {
		t.Fatalf("ListAdjacencies: %v", err)
	}
	for _, a := range adjs.Msg.GetAdjacencies() {
		if !utf8.ValidString(a.GetHostname()) {
			t.Errorf("adjacency %s hostname %q is not valid UTF-8", a.GetSystemId(), a.GetHostname())
		}
	}
}
