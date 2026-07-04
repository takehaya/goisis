// Command goisisd is the goisis IS-IS daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
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

	"github.com/takehaya/goisis/gen/goisis/v1/goisisv1connect"
	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/config"
	"github.com/takehaya/goisis/pkg/metrics"
	"github.com/takehaya/goisis/pkg/server"
)

func main() {
	apiListen := flag.String("api-listen", "127.0.0.1:50051", "listen address for the Connect/gRPC API")
	apiAllowRemote := flag.Bool("api-allow-remote", false, "allow binding the API beyond loopback; the API has no authentication or TLS, so it must be protected externally (firewall, network isolation)")
	configFile := flag.String("f", "", "path to the configuration file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(logger, *apiListen, *apiAllowRemote, *configFile); err != nil {
		logger.Error("goisisd exited with error", "error", err)
		os.Exit(1)
	}
}

// nonLoopbackAPI reports whether the API listen address is reachable from off
// the host. The Connect/gRPC API is unauthenticated plaintext h2c, so binding
// it beyond loopback (a specific external IP, or 0.0.0.0/:: for all interfaces)
// exposes routing state and requires the explicit -api-allow-remote opt-in. A
// hostname or an unparseable address is left to the operator's judgment.
func nonLoopbackAPI(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return !ip.IsLoopback()
}

func run(logger *slog.Logger, apiListen string, apiAllowRemote bool, configFile string) error {
	if nonLoopbackAPI(apiListen) && !apiAllowRemote {
		return fmt.Errorf("refusing to bind the unauthenticated management API beyond loopback (%s); pass -api-allow-remote to accept the exposure", apiListen)
	}

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
	reflector := grpcreflect.NewStaticReflector(goisisv1connect.IsisServiceName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	// Many tools (grpcurl among them) still speak the v1alpha reflection API.
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	mux.Handle(grpchealth.NewHandler(grpchealth.NewStaticChecker(goisisv1connect.IsisServiceName)))
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

	if nonLoopbackAPI(apiListen) {
		logger.Warn("the management API is unauthenticated plaintext but is bound beyond loopback; anyone who can reach it can read and modify routing state",
			"api", apiListen)
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
