package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetadapter "github.com/kabirnarang39/wardline/internal/features/budget/adapter"
	budgetusecase "github.com/kabirnarang39/wardline/internal/features/budget/usecase"
	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	opaadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/opa"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/kabirnarang39/wardline/internal/platform/tracing"
)

// Server-level timeouts, chosen to stop an unauthenticated caller from
// holding a connection open before the policy layer ever gets a say. Not
// yet exposed in the YAML config — v0.1 doesn't need per-deployment tuning.
//
// writeTimeout must stay comfortably above proxy/adapter's
// upstreamResponseHeaderTimeout (30s): a slow-but-connected upstream fires
// the Transport timeout at 30s, and the handler still needs time after that
// to write the 502 response back to the client. Equal values race — the
// server can close the connection for exceeding its own write deadline at
// the same instant the error response is being written, so the client sees
// a dropped connection instead of a clean 502.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 45 * time.Second
	idleTimeout       = 60 * time.Second

	// tracingShutdownTimeout bounds how long we wait for the tracer
	// provider to flush buffered spans on exit. If the OTLP collector is
	// unreachable, the SDK's batch span processor can otherwise block up
	// to its export timeout (default 30s, with retry) — well past what a
	// container orchestrator's SIGTERM-to-SIGKILL grace period allows
	// (Kubernetes defaults to 30s, Docker to 10s). Paired with the 10s
	// HTTP drain above, the 15s total comfortably fits inside a 30s grace
	// period with headroom.
	tracingShutdownTimeout = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if len(os.Args) < 2 {
		logger.Error("usage: wardline <serve|validate-policy|validate-config> [flags]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(logger, os.Args[2:])
	case "validate-policy":
		runValidatePolicy(logger, os.Args[2:])
	case "validate-config":
		runValidateConfig(logger, os.Args[2:])
	default:
		logger.Error("unknown command", "command", os.Args[1])
		os.Exit(1)
	}
}

func runServe(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "wardline.yaml", "path to config file")
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// A budget block with no flag to enforce it is very likely an operator
	// mistake (forgot to flip the flag, or forgot to remove the block) —
	// surface it instead of silently no-op'ing enforcement.
	if (cfg.Budget.RequestsPerWindow > 0 || cfg.Budget.WindowSeconds > 0) && !cfg.Features["budget_enforcement"] {
		logger.Info("budget config is set but features.budget_enforcement is off; budget is not being enforced",
			"requests_per_window", cfg.Budget.RequestsPerWindow, "window_seconds", cfg.Budget.WindowSeconds)
	}

	engine, err := loadPolicyEngine(cfg.PolicyBackend, cfg.PolicyFile)
	if err != nil {
		logger.Error("failed to load policy", "error", err)
		os.Exit(1)
	}

	writer := buildAuditWriter(logger, cfg.Audit.Output)
	recorder := auditusecase.NewRecorder(writer, func(err error) {
		logger.Error("audit write failed", "error", err)
	})

	decider := proxyusecase.NewDecider(engine)

	featureFlags := flags.NewStaticProvider(cfg.Features)
	limiter := budgetadapter.NewInMemoryLimiter(cfg.Budget.RequestsPerWindow, time.Duration(cfg.Budget.WindowSeconds)*time.Second)
	budgetChecker := budgetusecase.NewChecker(featureFlags, limiter)

	tracingProvider, err := buildTracingProvider(logger, featureFlags, cfg.Tracing)
	if err != nil {
		logger.Error("failed to initialize tracing", "error", err)
		os.Exit(1)
	}

	handler := proxyadapter.NewHandler(decider, recorder, cfg.UpstreamURL, budgetChecker, tracingProvider.Tracer())

	// Log what the operator has toggled on so a flag isn't silently ignored.
	for name := range cfg.Features {
		if featureFlags.Enabled(name) {
			logger.Info("feature enabled", "feature", name)
		}
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("wardline listening", "addr", cfg.Listen, "upstream", cfg.Upstream)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited", "error", err)
			tracingShutdownCtx, tracingCancel := context.WithTimeout(context.Background(), tracingShutdownTimeout)
			if err := tracingProvider.Shutdown(tracingShutdownCtx); err != nil {
				logger.Error("tracing shutdown failed", "error", err)
			}
			tracingCancel()
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}

	tracingShutdownCtx, tracingCancel := context.WithTimeout(context.Background(), tracingShutdownTimeout)
	defer tracingCancel()
	if err := tracingProvider.Shutdown(tracingShutdownCtx); err != nil {
		logger.Error("tracing shutdown failed", "error", err)
	}
}

// buildTracingProvider returns a disabled (no-op) Provider unless
// otel_tracing is on, in which case it builds a real OTLP/HTTP-exporting
// one from cfg.
func buildTracingProvider(logger *slog.Logger, featureFlags flags.Provider, cfg config.TracingConfig) (*tracing.Provider, error) {
	if !featureFlags.Enabled("otel_tracing") {
		return tracing.NewDisabled(), nil
	}
	logger.Info("otel tracing enabled", "otlp_endpoint", cfg.OTLPEndpoint, "service_name", cfg.ServiceName)
	return tracing.NewOTLPHTTP(context.Background(), cfg.ServiceName, cfg.OTLPEndpoint)
}

func runValidatePolicy(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("validate-policy", flag.ExitOnError)
	path := fs.String("file", "policy.yaml", "path to policy file")
	backend := fs.String("backend", "yaml", `policy backend: "yaml" or "opa"`)
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	if _, err := loadPolicyEngine(*backend, *path); err != nil {
		logger.Error("failed to load policy", "error", err)
		os.Exit(1)
	}
	fmt.Println("policy file is valid")
}

// loadPolicyEngine picks the policy.Engine implementation named by
// backend ("yaml" or "opa"; "" defaults to "yaml"). runServe only ever
// passes a value config.Load has already validated, but runValidatePolicy
// passes its raw, unvalidated -backend flag straight through, so any other
// value is rejected explicitly here rather than silently falling back to
// the YAML loader.
func loadPolicyEngine(backend, path string) (policydomain.Engine, error) {
	switch backend {
	case "opa":
		return opaadapter.LoadRegoFile(path)
	case "yaml", "":
		return policyadapter.LoadFile(path)
	default:
		return nil, fmt.Errorf("unknown policy backend %q (want \"yaml\" or \"opa\")", backend)
	}
}

func runValidateConfig(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
	path := fs.String("config", "wardline.yaml", "path to config file")
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	if _, err := config.Load(*path); err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	fmt.Println("config file is valid")
}

func buildAuditWriter(logger *slog.Logger, output string) *auditadapter.JSONLWriter {
	if output == "stdout" {
		return auditadapter.NewJSONLWriter(os.Stdout)
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		logger.Error("failed to open audit output file", "path", output, "error", err)
		os.Exit(1)
	}
	return auditadapter.NewJSONLWriter(f)
}
