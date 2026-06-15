package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"connectrpc.com/connect"

	goisisv1alpha1 "github.com/takehaya/goisis/gen/goisis/v1alpha1"
	"github.com/takehaya/goisis/gen/goisis/v1alpha1/goisisv1alpha1connect"
	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

func mustServer(t *testing.T, opts ...ServerOption) *IsisServer {
	t.Helper()
	s, err := NewIsisServer(opts...)
	if err != nil {
		t.Fatalf("NewIsisServer: %v", err)
	}
	return s
}

func TestGetGlobal(t *testing.T) {
	s := mustServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	g, err := s.GetGlobal(ctx)
	if err != nil {
		t.Fatalf("GetGlobal: %v", err)
	}
	if g.Version != version.Version {
		t.Errorf("Version = %q, want %q", g.Version, version.Version)
	}
}

func TestGetIsisOverConnect(t *testing.T) {
	s := mustServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	mux := http.NewServeMux()
	mux.Handle(NewConnectHandler(s))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := goisisv1alpha1connect.NewIsisServiceClient(ts.Client(), ts.URL)
	res, err := client.GetIsis(ctx, connect.NewRequest(&goisisv1alpha1.GetIsisRequest{}))
	if err != nil {
		t.Fatalf("GetIsis: %v", err)
	}
	if got := res.Msg.GetGlobal().GetVersion(); got != version.Version {
		t.Errorf("version = %q, want %q", got, version.Version)
	}
}

func TestListLocatorsAndFlexAlgosOverConnect(t *testing.T) {
	loc := netip.MustParsePrefix("fc00:0:1::/48")
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
		WithSRv6Locator(loc),
		WithFlexAlgo(FlexAlgoConfig{Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100, AdvertiseDefinition: true}),
	)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.Serve(ctx) //nolint:errcheck // shut down via ctx

	mux := http.NewServeMux()
	mux.Handle(NewConnectHandler(s))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	client := goisisv1alpha1connect.NewIsisServiceClient(ts.Client(), ts.URL)

	lres, err := client.ListLocators(ctx, connect.NewRequest(&goisisv1alpha1.ListLocatorsRequest{}))
	if err != nil {
		t.Fatalf("ListLocators: %v", err)
	}
	locs := lres.Msg.GetLocators()
	if len(locs) != 1 || locs[0].GetPrefix() != "fc00:0:1::/48" || locs[0].GetEndSid() != "fc00:0:1::" {
		t.Errorf("locators = %+v", locs)
	}

	fres, err := client.ListFlexAlgos(ctx, connect.NewRequest(&goisisv1alpha1.ListFlexAlgosRequest{}))
	if err != nil {
		t.Fatalf("ListFlexAlgos: %v", err)
	}
	found := false
	for _, fa := range fres.Msg.GetFlexAlgos() {
		if fa.GetAlgorithm() != 128 {
			continue
		}
		found = true
		d := fa.GetDefinition()
		if d == nil || d.GetPriority() != 100 || d.GetAdvertiser() != "0000.0000.0001" {
			t.Errorf("flex-algo 128 definition = %+v", d)
		}
	}
	if !found {
		t.Error("flex-algo 128 not listed over Connect")
	}
}

func TestMgmtOperationAfterServeStopped(t *testing.T) {
	s := mustServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = s.Serve(ctx)
	}()
	cancel()
	<-serveDone

	// Must fail fast even with a background context instead of blocking on
	// the dead management loop.
	if _, err := s.GetGlobal(context.Background()); !errors.Is(err, ErrServerStopped) {
		t.Fatalf("GetGlobal after stop = %v, want ErrServerStopped", err)
	}
}

func TestMgmtOperationCancelled(t *testing.T) {
	s := mustServer(t)
	// No Serve loop running: a cancelled context must not deadlock.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.mgmtOperation(ctx, func() error { return nil }); err == nil {
		t.Error("mgmtOperation on cancelled ctx: want error, got nil")
	}
}
