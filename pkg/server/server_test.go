package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	goisisv1alpha1 "github.com/takehaya/goisis/gen/goisis/v1alpha1"
	"github.com/takehaya/goisis/gen/goisis/v1alpha1/goisisv1alpha1connect"
	"github.com/takehaya/goisis/internal/version"
)

func TestGetGlobal(t *testing.T) {
	s := NewIsisServer()
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
	s := NewIsisServer()
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

func TestMgmtOperationAfterServeStopped(t *testing.T) {
	s := NewIsisServer()
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
	s := NewIsisServer()
	// No Serve loop running: a cancelled context must not deadlock.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.mgmtOperation(ctx, func() error { return nil }); err == nil {
		t.Error("mgmtOperation on cancelled ctx: want error, got nil")
	}
}
