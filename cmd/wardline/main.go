package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetadapter "github.com/kabirnarang39/wardline/internal/features/budget/adapter"
	budgetusecase "github.com/kabirnarang39/wardline/internal/features/budget/usecase"
	dashboardadapter "github.com/kabirnarang39/wardline/internal/features/dashboard/adapter"
	dashboarddomain "github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
	dashboardusecase "github.com/kabirnarang39/wardline/internal/features/dashboard/usecase"
	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	opaadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/opa"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/kabirnarang39/wardline/internal/platform/tracing"
	"github.com/kabirnarang39/wardline/internal/platform/version"
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

	// ringBufferCapacity bounds the dashboard's in-memory live audit view.
	// It's a code constant, not operator-configurable — see
	// docs/superpowers/specs/2026-07-27-web-ui-design.md "Config".
	ringBufferCapacity = 1000
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

	featureFlags := flags.NewStaticProvider(cfg.Features)
	webUIEnabled := featureFlags.Enabled("web_ui")

	writer, auditCloser := buildAuditSink(logger, featureFlags, cfg.Audit)

	var liveSink auditdomain.LiveSink = auditadapter.NoopSink{}
	var ringBuffer *dashboardusecase.RingBuffer
	if webUIEnabled {
		ringBuffer = dashboardusecase.NewRingBuffer(ringBufferCapacity)
		liveSink = ringBuffer
	}

	recorder := auditusecase.NewRecorder(writer, liveSink, func(err error) {
		logger.Error("audit write failed", "error", err)
	})

	decider := proxyusecase.NewDecider(engine)

	limiter := budgetadapter.NewInMemoryLimiter(cfg.Budget.RequestsPerWindow, time.Duration(cfg.Budget.WindowSeconds)*time.Second)
	budgetChecker := budgetusecase.NewChecker(featureFlags, limiter)

	tracingProvider, err := buildTracingProvider(logger, featureFlags, cfg.Tracing)
	if err != nil {
		logger.Error("failed to initialize tracing", "error", err)
		os.Exit(1)
	}

	handler := proxyadapter.NewHandler(decider, recorder, cfg.UpstreamURL, budgetChecker, tracingProvider.Tracer())

	startedAt := time.Now()

	// dashboardHandler is only ever meaningfully used inside the
	// webUIEnabled block below: buildTopHandler returns the bare proxy
	// handler outright when web_ui is off, never touching this variable.
	var dashboardHandler http.Handler
	if webUIEnabled {
		policySource, err := os.ReadFile(cfg.PolicyFile)
		if err != nil {
			logger.Error("failed to read policy file for dashboard", "error", err)
			os.Exit(1)
		}
		policyInfo := dashboarddomain.PolicyInfo{Backend: cfg.PolicyBackend, Source: string(policySource)}

		statusProvider := dashboardusecase.NewStatusProvider(
			version.Version, cfg.Listen, cfg.Upstream, cfg.Features, startedAt, time.Now,
		)

		dashboardHandler = dashboardadapter.NewHandler(ringBuffer, statusProvider, policyInfo, dashboardadapter.Assets())
		logger.Info("dashboard enabled", "path", "/dashboard/")
	}

	topHandler := buildTopHandler(handler, dashboardHandler, webUIEnabled)

	// Log what the operator has toggled on so a flag isn't silently ignored.
	for name := range cfg.Features {
		if featureFlags.Enabled(name) {
			logger.Info("feature enabled", "feature", name)
		}
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           topHandler,
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
			if auditCloser != nil {
				if err := auditCloser.Close(); err != nil {
					logger.Error("audit writer shutdown failed", "error", err)
				}
			}
			os.Exit(1)
		}
	case <-ctx.Done():
		// Release the signal registration immediately so a second
		// SIGINT/SIGTERM during a slow drain takes the OS's default action
		// (immediate termination) instead of being swallowed by the still-live
		// NotifyContext registration until runServe returns. The deferred
		// stop() above still covers the other branch, where ctx.Done() never
		// fires.
		stop()
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
	if auditCloser != nil {
		if err := auditCloser.Close(); err != nil {
			logger.Error("audit writer shutdown failed", "error", err)
		}
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

// buildTopHandler routes /dashboard/ requests to dashboard when web_ui is
// on, and everything else (including /dashboard/ when web_ui is off,
// same as v0.1's proxy-handles-everything behavior) to proxy. The
// dashboard is never reachable unless the operator has explicitly
// enabled it — this is the one place the flag decision is made, not
// scattered through request handling. When web_ui is on, requests pass
// through an http.ServeMux, which applies stdlib path cleaning/redirects
// (e.g. collapsing "//tool" or resolving "..") that do not happen when
// the flag is off and the bare proxy handler receives the raw path.
func buildTopHandler(proxy, dashboard http.Handler, webUIEnabled bool) http.Handler {
	if !webUIEnabled {
		return proxy
	}
	mux := http.NewServeMux()
	mux.Handle("/dashboard/", dashboard)
	mux.Handle("/", proxy)
	return mux
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

// buildAuditSink picks the audit Writer for the current postgres_storage
// flag state and returns an io.Closer for shutdown to drain — nil when the
// writer holds no closeable resource (the JSONL writer's file handle,
// same as before this helper existed, is reclaimed by process exit and
// was never explicitly closed). It also centralizes both directions of
// the audit-config-vs-flag mismatch: audit.output set while
// postgres_storage is on (output is ignored) and audit.postgres_dsn set
// while postgres_storage is off (silently JSONL-backed audit trail,
// possibly not what the operator intended — the flag-on-no-DSN case is
// already caught by config validation before runServe ever calls this).
func buildAuditSink(logger *slog.Logger, featureFlags flags.Provider, cfg config.AuditConfig) (auditdomain.Writer, io.Closer) {
	postgresStorageEnabled := featureFlags.Enabled("postgres_storage")

	if cfg.Output != "" && postgresStorageEnabled {
		logger.Info("audit.output is set but features.postgres_storage is on; audit.output is being ignored",
			"output", cfg.Output)
	}
	if cfg.PostgresDSN != "" && !postgresStorageEnabled {
		logger.Info("audit.postgres_dsn is set but features.postgres_storage is off; audit entries are not being written to postgres",
			"postgres_dsn_configured", true)
	}

	if postgresStorageEnabled {
		pw, err := auditadapter.NewPostgresWriter(cfg.PostgresDSN)
		if err != nil {
			logger.Error("failed to initialize postgres audit writer", "error", err)
			os.Exit(1)
		}
		return pw, pw
	}

	return buildAuditWriter(logger, cfg.Output), nil
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
