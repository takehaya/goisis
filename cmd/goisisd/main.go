// Command goisisd is the goisis IS-IS daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"golang.org/x/sync/errgroup"

	"github.com/takehaya/goisis/gen/goisis/v1alpha1/goisisv1alpha1connect"
	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/server"
)

func main() {
	apiListen := flag.String("api-listen", "127.0.0.1:50051", "listen address for the Connect/gRPC API")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(logger, *apiListen); err != nil {
		logger.Error("goisisd exited with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, apiListen string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	isis, err := server.NewIsisServer(server.WithLogger(logger))
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(server.NewConnectHandler(isis))
	reflector := grpcreflect.NewStaticReflector(goisisv1alpha1connect.IsisServiceName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	// Many tools (grpcurl among them) still speak the v1alpha reflection API.
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	mux.Handle(grpchealth.NewHandler(grpchealth.NewStaticChecker(goisisv1alpha1connect.IsisServiceName)))

	// Plaintext HTTP/2 (h2c) so gRPC clients work without TLS.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	httpServer := &http.Server{
		Addr:      apiListen,
		Handler:   mux,
		Protocols: protocols,
	}

	logger.Info("starting goisisd", "version", version.Version, "api", apiListen)

	g, gctx := errgroup.WithContext(ctx)
	// The management loop runs on its own context and is stopped only after
	// the HTTP server has shut down, so RPCs draining during Shutdown can
	// still reach it instead of hanging on a dead loop.
	serveCtx, stopServe := context.WithCancel(context.Background())
	defer stopServe()
	g.Go(func() error {
		return isis.Serve(serveCtx)
	})
	g.Go(func() error {
		if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-gctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		stopServe()
		return err
	})
	return g.Wait()
}
