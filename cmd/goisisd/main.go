// Command goisisd is the goisis IS-IS daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/takehaya/goisis/gen/goisis/v1alpha1/goisisv1alpha1connect"
	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/config"
	"github.com/takehaya/goisis/pkg/metrics"
	"github.com/takehaya/goisis/pkg/server"
)

func main() {
	apiListen := flag.String("api-listen", "127.0.0.1:50051", "listen address for the Connect/gRPC API")
	configFile := flag.String("f", "", "path to the configuration file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(logger, *apiListen, *configFile); err != nil {
		logger.Error("goisisd exited with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, apiListen, configFile string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	opts := []server.ServerOption{
		server.WithLogger(logger),
		server.WithMetrics(metrics.NewPrometheus(reg)),
	}
	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err != nil {
			return err
		}
		cfgOpts, err := cfg.Options()
		if err != nil {
			return err
		}
		opts = append(opts, cfgOpts...)
	}

	isis, err := server.NewIsisServer(opts...)
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
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	// Plaintext HTTP/2 (h2c) so gRPC clients work without TLS.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	// Request contexts derive from reqCtx; cancelling it on shutdown unblocks
	// long-lived streaming handlers (WatchEvent / `goisis monitor`) that would
	// otherwise keep Shutdown waiting for its full timeout.
	reqCtx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	httpServer := &http.Server{
		Addr:        apiListen,
		Handler:     mux,
		Protocols:   protocols,
		BaseContext: func(net.Listener) context.Context { return reqCtx },
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
		cancelReq() // unblock streaming handlers so Shutdown drains promptly
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			// A slow drain shouldn't fail the process exit; force-close any
			// lingering connections instead.
			logger.Warn("http server did not drain cleanly; forcing close", "error", err)
			_ = httpServer.Close()
		}
		stopServe()
		return nil
	})
	return g.Wait()
}
