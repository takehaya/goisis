package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
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

// TestConnectAddPrefixUnroutable asserts a syntactically valid but unroutable
// prefix is refused by the server and reaches the client as InvalidArgument,
// not as an internal failure.
func TestConnectAddPrefixUnroutable(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()

	h := &connectHandler{s: s}
	_, err := h.AddPrefix(context.Background(), connect.NewRequest(&goisisv1.AddPrefixRequest{Prefix: "224.0.0.0/4"}))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("AddPrefix with a multicast prefix: code = %v (%v), want InvalidArgument", got, err)
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

	lsdb, err := client.GetLsdb(ctx, connect.NewRequest(&goisisv1.GetLsdbRequest{Detail: true}))
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

// TestGetLsdbSendsTLVTextOnlyWhenAsked: rendering an LSP's TLVs costs more
// than the rest of the response put together, so GetLsdb renders them only for
// a client that asks. `goisis database` without --detail never displays them.
func TestGetLsdbSendsTLVTextOnlyWhenAsked(t *testing.T) {
	peer := packet.SystemID{0, 0, 0, 0, 0, 2}
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	if err := s.mgmtOperation(ctx, func() error {
		injectLSPAt(s, packet.Level2, peer,
			[]packet.TLV{&packet.DynamicHostnameTLV{Hostname: "r2"}}, time.Now())
		return nil
	}); err != nil {
		t.Fatalf("seed LSDB: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(NewConnectHandler(s))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	client := goisisv1connect.NewIsisServiceClient(ts.Client(), ts.URL)

	for _, tc := range []struct {
		detail bool
		want   []string
	}{
		{detail: false, want: nil},
		{detail: true, want: []string{"Dynamic Hostname: r2"}},
	} {
		res, err := client.GetLsdb(ctx, connect.NewRequest(&goisisv1.GetLsdbRequest{Detail: tc.detail}))
		if err != nil {
			t.Fatalf("GetLsdb(detail=%t): %v", tc.detail, err)
		}
		var found bool
		for _, l := range res.Msg.GetLsps() {
			if l.GetHostname() != "r2" {
				continue
			}
			found = true
			if got := l.GetTlvs(); !slices.Equal(got, tc.want) {
				t.Errorf("GetLsdb(detail=%t) tlvs = %q, want %q", tc.detail, got, tc.want)
			}
		}
		if !found {
			t.Fatalf("GetLsdb(detail=%t): the injected peer LSP is missing", tc.detail)
		}
	}
}

// connectClient serves s over an httptest server and returns a client for it.
func connectClient(t *testing.T, s *IsisServer) goisisv1connect.IsisServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(NewConnectHandler(s))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return goisisv1connect.NewIsisServiceClient(ts.Client(), ts.URL)
}

// TestConnectPrefixLifecycleReachesTheOwnLSP: the in-process mutators are
// pinned elsewhere; what this asserts is the wire contract between them —
// AddPrefix over Connect puts the prefix in the node's own LSP as GetLsdb
// renders it, and DeletePrefix takes it out again.
func TestConnectPrefixLifecycleReachesTheOwnLSP(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	client := connectClient(t, s)
	ctx := context.Background()
	const prefix = "10.9.9.0/24"

	advertised := func() bool {
		res, err := client.GetLsdb(ctx, connect.NewRequest(&goisisv1.GetLsdbRequest{Detail: true}))
		if err != nil {
			t.Fatalf("GetLsdb: %v", err)
		}
		for _, l := range res.Msg.GetLsps() {
			if !l.GetOwn() {
				continue
			}
			for _, tlv := range l.GetTlvs() {
				if strings.Contains(tlv, prefix) {
					return true
				}
			}
		}
		return false
	}

	if _, err := client.AddPrefix(ctx, connect.NewRequest(&goisisv1.AddPrefixRequest{Prefix: prefix, Metric: 10})); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	waitFor(t, "GetLsdb shows the added prefix", advertised)

	if _, err := client.DeletePrefix(ctx, connect.NewRequest(&goisisv1.DeletePrefixRequest{Prefix: prefix})); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}
	waitFor(t, "GetLsdb drops the deleted prefix", func() bool { return !advertised() })
}

// TestConnectSetOverloadIsReportedByGetIsis pins the round trip an operator
// running `goisis overload set` then `goisis show` makes: the mutator's effect
// has to be visible in Global.overload, in both directions.
func TestConnectSetOverloadIsReportedByGetIsis(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	client := connectClient(t, s)
	ctx := context.Background()

	overloaded := func() bool {
		res, err := client.GetIsis(ctx, connect.NewRequest(&goisisv1.GetIsisRequest{}))
		if err != nil {
			t.Fatalf("GetIsis: %v", err)
		}
		return res.Msg.GetGlobal().GetOverload()
	}
	if overloaded() {
		t.Fatal("Global.overload is set before anything asked for it")
	}
	if _, err := client.SetOverload(ctx, connect.NewRequest(&goisisv1.SetOverloadRequest{Overload: true})); err != nil {
		t.Fatalf("SetOverload(true): %v", err)
	}
	if !overloaded() {
		t.Error("Global.overload = false after SetOverload(true)")
	}
	if _, err := client.SetOverload(ctx, connect.NewRequest(&goisisv1.SetOverloadRequest{Overload: false})); err != nil {
		t.Fatalf("SetOverload(false): %v", err)
	}
	if overloaded() {
		t.Error("Global.overload = true after SetOverload(false)")
	}
}

// TestConnectListAdjacenciesRendersEveryAdjacencyField pins adjacencyToProto,
// the mapping `goisis neighbor` and every WatchEvent adjacency event go
// through, against a converged pair. ClearAdjacency then proves the mutator's
// success path over the wire: the adjacency re-forms from hellos alone.
func TestConnectListAdjacenciesRendersEveryAdjacencyField(t *testing.T) {
	a, _, clk, cancel := mutatePair(t, false)
	defer cancel()
	client := connectClient(t, a)
	ctx := context.Background()

	list := func() []*goisisv1.Adjacency {
		res, err := client.ListAdjacencies(ctx, connect.NewRequest(&goisisv1.ListAdjacenciesRequest{}))
		if err != nil {
			t.Fatalf("ListAdjacencies: %v", err)
		}
		return res.Msg.GetAdjacencies()
	}
	adjs := list()
	if len(adjs) != 1 {
		t.Fatalf("ListAdjacencies returned %d adjacencies, want 1", len(adjs))
	}
	got := adjs[0]
	for _, tc := range []struct{ field, got, want string }{
		{"interface", got.GetInterface(), "a"},
		{"system_id", got.GetSystemId(), "0000.0000.0002"},
		{"snpa", got.GetSnpa(), packet.SNPA{0, 0, 0, 0, 0, 0xb2}.String()},
		{"state", got.GetState(), AdjUp.String()},
	} {
		if tc.got != tc.want {
			t.Errorf("Adjacency.%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
	if got.GetLevel() != goisisv1.Level_LEVEL_2 {
		t.Errorf("Adjacency.level = %v, want LEVEL_2", got.GetLevel())
	}
	if got.GetPriority() != uint32(DefaultPriority) {
		t.Errorf("Adjacency.priority = %d, want %d", got.GetPriority(), DefaultPriority)
	}
	if got.GetHoldingTime() == 0 {
		t.Error("Adjacency.holding_time = 0, want the neighbor's advertised holding time")
	}

	if _, err := client.ClearAdjacency(ctx, connect.NewRequest(&goisisv1.ClearAdjacencyRequest{Interface: "a"})); err != nil {
		t.Fatalf("ClearAdjacency: %v", err)
	}
	waitClock(t, clk, "the cleared adjacency re-forms", func() bool {
		adjs := list()
		return len(adjs) == 1 && adjs[0].GetState() == AdjUp.String()
	})
}

// TestConnectListLocatorsRendersEndXSids pins the SRv6 half of the wire
// contract: a locator's per-adjacency End.X SIDs reach the client with the
// neighbor, the interface and the locator's algorithm, which is the only place
// EndXSid.algorithm is filled in (from the parent locator, not the SID).
func TestConnectListLocatorsRendersEndXSids(t *testing.T) {
	ta := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500)
	tb := datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xb2}, 1500)
	datalink.Link(ta, tb)

	area := packet.AreaAddress{0x49, 0x00, 0x01}
	loc := netip.MustParsePrefix("fc00:0:1::/48")
	subnet := netip.MustParsePrefix("2001:db8::/64")
	// End.X forwards to the neighbor's global on-link address, so both ends
	// carry one on the link's /64 (see endXNexthop).
	cfg := func(name string, tr *datalink.MockTransport, ll, global string) CircuitConfig {
		c := CircuitConfig{Name: name, Transport: tr, P2P: true, Level2: true, Padding: ptrFalse(),
			IPv6Addrs:         []netip.Addr{netip.MustParseAddr(ll), netip.MustParseAddr(global)},
			ConnectedPrefixes: []netip.Prefix{subnet}}
		fastHello(&c)
		return c
	}
	a := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}), WithAreaAddresses(area),
		WithCircuit(cfg("a", ta, "fe80::a1", "2001:db8::a1")), WithSRv6Locator(loc),
	)
	b := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 2}), WithAreaAddresses(area),
		WithCircuit(cfg("b", tb, "fe80::b2", "2001:db8::b2")),
	)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go a.Serve(ctx) //nolint:errcheck // ctx shutdown
	go b.Serve(ctx) //nolint:errcheck // ctx shutdown

	client := connectClient(t, a)
	var sid *goisisv1.EndXSid
	waitFor(t, "the locator reports an End.X SID for the p2p neighbor", func() bool {
		res, err := client.ListLocators(context.Background(), connect.NewRequest(&goisisv1.ListLocatorsRequest{}))
		if err != nil {
			return false
		}
		for _, l := range res.Msg.GetLocators() {
			if l.GetPrefix() != loc.String() || len(l.GetEndXSids()) == 0 {
				continue
			}
			if got := l.GetEndSid(); got != "fc00:0:1::" {
				t.Errorf("Locator.end_sid = %q, want fc00:0:1::", got)
			}
			sid = l.GetEndXSids()[0]
			return true
		}
		return false
	})
	if got := sid.GetNeighbor(); got != "0000.0000.0002" {
		t.Errorf("EndXSid.neighbor = %q, want 0000.0000.0002", got)
	}
	if got := sid.GetInterface(); got != "a" {
		t.Errorf("EndXSid.interface = %q, want a", got)
	}
	// Function 1 of the locator: function 0 is the locator's own End SID.
	if got := sid.GetSid(); got != "fc00:0:1:1::" {
		t.Errorf("EndXSid.sid = %q, want fc00:0:1:1::", got)
	}
	if got := sid.GetAlgorithm(); got != 0 {
		t.Errorf("EndXSid.algorithm = %d, want the parent locator's 0", got)
	}
}

// TestConnectListCircuitsReportsLinkState: a circuit whose link went down keeps
// its configuration and its flooding flags but carries nothing, so `goisis
// circuit` has to say so — otherwise the only symptom an operator sees is an
// adjacency that will not form.
func TestConnectListCircuitsReportsLinkState(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	client := connectClient(t, s)
	ctx := context.Background()

	linkUp := func() bool {
		res, err := client.ListCircuits(ctx, connect.NewRequest(&goisisv1.ListCircuitsRequest{}))
		if err != nil {
			t.Fatalf("ListCircuits: %v", err)
		}
		cs := res.Msg.GetCircuits()
		if len(cs) != 1 {
			t.Fatalf("ListCircuits returned %d circuits, want 1", len(cs))
		}
		return cs[0].GetLinkUp()
	}
	if !linkUp() {
		t.Error("Circuit.link_up = false on a circuit nothing took down")
	}
	if err := s.SetCircuitLinkState(ctx, "c", false); err != nil {
		t.Fatalf("SetCircuitLinkState(down): %v", err)
	}
	if linkUp() {
		t.Error("Circuit.link_up = true after the link went down")
	}
	if err := s.SetCircuitLinkState(ctx, "c", true); err != nil {
		t.Fatalf("SetCircuitLinkState(up): %v", err)
	}
	if !linkUp() {
		t.Error("Circuit.link_up = false after the link came back")
	}
}
