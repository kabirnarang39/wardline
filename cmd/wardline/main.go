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

	anomalyadapter "github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetadapter "github.com/kabirnarang39/wardline/internal/features/budget/adapter"
	budgetusecase "github.com/kabirnarang39/wardline/internal/features/budget/usecase"
	credentialadapter "github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	credentialusecase "github.com/kabirnarang39/wardline/internal/features/credential/usecase"
	dashboardadapter "github.com/kabirnarang39/wardline/internal/features/dashboard/adapter"
	dashboarddomain "github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
	dashboardusecase "github.com/kabirnarang39/wardline/internal/features/dashboard/usecase"
	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	cedaradapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/cedar"
	opaadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/opa"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
	rbacadapter "github.com/kabirnarang39/wardline/internal/features/rbac/adapter"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	rbacusecase "github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
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
	anomalyDetectionEnabled := featureFlags.Enabled("anomaly_detection")

	writer, auditCloser := buildAuditSink(logger, featureFlags, cfg.Audit)

	var ringBuffer *dashboardusecase.RingBuffer
	if webUIEnabled {
		ringBuffer = dashboardusecase.NewRingBuffer(ringBufferCapacity)
	}

	var anomalyDetector *anomalyusecase.Detector
	var anomalyBuffer *anomalyusecase.AlertBuffer
	var anomalyGCStop chan struct{}
	if anomalyDetectionEnabled {
		anomalyWriter, err := buildAnomalyWriter(logger, cfg.Anomaly.Output)
		if err != nil {
			logger.Error("failed to open anomaly output file", "path", cfg.Anomaly.Output, "error", err)
			os.Exit(1)
		}
		bufferCapacity := cfg.Anomaly.BufferCapacity
		if bufferCapacity <= 0 {
			bufferCapacity = ringBufferCapacity
		}
		anomalyBuffer = anomalyusecase.NewAlertBuffer(bufferCapacity)
		anomalyDetector = anomalyusecase.NewDetector(anomalyHeuristicConfig(cfg.Anomaly), anomalyWriter, anomalyBuffer, func(err error) {
			logger.Error("anomaly write failed", "error", err)
		}, time.Now)

		gcInterval := time.Duration(cfg.Anomaly.GCIntervalSeconds) * time.Second
		if gcInterval <= 0 {
			gcInterval = 10 * time.Minute
		}
		anomalyGCStop = make(chan struct{})
		go anomalyusecase.StartGC(anomalyDetector, gcInterval, anomalyGCStop)
		logger.Info("anomaly detection enabled", "output", cfg.Anomaly.Output)
	}

	var liveSink auditdomain.LiveSink = auditadapter.NoopSink{}
	switch {
	case webUIEnabled && anomalyDetectionEnabled:
		liveSink = auditadapter.MultiSink{ringBuffer, anomalyDetector}
	case webUIEnabled:
		liveSink = ringBuffer
	case anomalyDetectionEnabled:
		liveSink = anomalyDetector
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

	credentialIssuanceEnabled := featureFlags.Enabled("credential_issuance")
	var identityAuth proxyadapter.IdentityAuthenticator = proxyadapter.HeaderIdentity{}

	rbacEnabled := featureFlags.Enabled("rbac")
	var rbacChecker *rbacusecase.Checker
	if rbacEnabled {
		authorizer, err := rbacadapter.LoadAuthorizer(cfg.RBAC.ConfigFile)
		if err != nil {
			logger.Error("failed to load rbac file", "error", err)
			os.Exit(1)
		}
		rbacChecker = rbacusecase.NewChecker(featureFlags, authorizer)
		logger.Info("rbac enabled", "config_file", cfg.RBAC.ConfigFile)
	}
	// newRevokeAuthorizer is handed a pointer to the identityAuth variable:
	// it's declared above (still HeaderIdentity{} at this point) and only
	// reassigned to bearerIdentity inside the credentialIssuanceEnabled
	// block below, but the returned RevokeAuthorizer is never invoked
	// until a real request arrives, long after that reassignment has
	// already happened -- so dereferencing the pointer at that point
	// always sees identityAuth's final value.
	var revokeAuthorizer credentialadapter.RevokeAuthorizer
	if rbacEnabled {
		revokeAuthorizer = newRevokeAuthorizer(&identityAuth, rbacChecker, logger)
	}

	var credentialHandler *credentialadapter.Handler
	if credentialIssuanceEnabled {
		bootstrapper, err := credentialadapter.LoadBootstrapper(cfg.Credential.IdentitiesFile)
		if err != nil {
			logger.Error("failed to load credentials file", "error", err)
			os.Exit(1)
		}
		issuerVerifier, err := credentialadapter.NewJWTIssuerVerifier()
		if err != nil {
			logger.Error("failed to initialize credential issuer", "error", err)
			os.Exit(1)
		}
		revocationList := credentialadapter.NewRevocationList()
		issuance := credentialusecase.NewIssuanceService(bootstrapper, issuerVerifier)
		verification := credentialusecase.NewVerificationService(issuerVerifier, revocationList)
		revocation := credentialusecase.NewRevocationService(revocationList)
		credentialHandler = credentialadapter.NewHandler(issuance, revocation, logger, revokeAuthorizer)
		identityAuth = proxyadapter.NewBearerIdentity(verification)
		logger.Info("credential issuance enabled", "identities_file", cfg.Credential.IdentitiesFile)
	}

	handler := proxyadapter.NewHandler(decider, recorder, cfg.UpstreamURL, budgetChecker, tracingProvider.Tracer(), identityAuth, logger)

	startedAt := time.Now()

	extraRoutes := map[string]http.Handler{}
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

		var anomalySource dashboardadapter.AnomalySource
		if anomalyDetectionEnabled {
			anomalySource = anomalyBuffer
		}
		var dashboardRoute http.Handler = dashboardadapter.NewHandler(ringBuffer, statusProvider, policyInfo, dashboardadapter.Assets(), anomalySource)
		if rbacEnabled {
			dashboardRoute = rbacadapter.RequirePermission(rbacChecker, identityAuth, "default", rbacdomain.PermissionDashboardView, dashboardRoute, logger)
		}
		extraRoutes["/dashboard/"] = dashboardRoute
		logger.Info("dashboard enabled", "path", "/dashboard/")
	}
	if credentialIssuanceEnabled {
		extraRoutes["/credentials/token"] = http.HandlerFunc(credentialHandler.HandleToken)
		extraRoutes["/credentials/revoke"] = http.HandlerFunc(credentialHandler.HandleRevoke)
	}

	topHandler := buildTopHandler(handler, extraRoutes)

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
			if anomalyGCStop != nil {
				close(anomalyGCStop)
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
	if anomalyGCStop != nil {
		close(anomalyGCStop)
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

// revokeAuthorizerFunc adapts a plain function to credentialadapter.RevokeAuthorizer,
// so the closure built in runServe doesn't need its own named type there.
type revokeAuthorizerFunc func(r *http.Request) bool

func (f revokeAuthorizerFunc) Allowed(r *http.Request) bool { return f(r) }

// newRevokeAuthorizer builds the RevokeAuthorizer wired into
// /credentials/revoke when rbac is on: a non-loopback caller is allowed
// through only if identity resolves and the resolved identity holds
// credential:revoke. identityAuth is a pointer so the returned
// RevokeAuthorizer -- not invoked until a real request arrives, well
// after runServe finishes wiring -- always sees identityAuth's final
// value even though it's built before credential_issuance's later
// reassignment of that variable (see the comment at this function's call
// site in runServe).
func newRevokeAuthorizer(identityAuth *proxyadapter.IdentityAuthenticator, checker *rbacusecase.Checker, logger *slog.Logger) credentialadapter.RevokeAuthorizer {
	return revokeAuthorizerFunc(func(r *http.Request) bool {
		who, err := (*identityAuth).Authenticate(r)
		if err != nil {
			logger.Warn("rbac revoke authorization: identity resolution failed", "remote_addr", r.RemoteAddr)
			return false
		}
		return checker.Check(who, "default", rbacdomain.PermissionCredentialRevoke)
	})
}

// buildTopHandler routes each key of extraRoutes to its handler, and
// everything else to proxy. A route is only ever present in the map when
// its owning feature flag is on — this is the one place that decision is
// made, not scattered through request handling. Called with an empty map,
// it returns the bare proxy handler unchanged (same as v0.1's
// proxy-handles-everything behavior, and identical to today's behavior
// when no optional feature is enabled). Any non-empty map routes through
// an http.ServeMux, which applies stdlib path cleaning/redirects (e.g.
// collapsing "//tool" or resolving "..") that do not happen when the map
// is empty and the bare proxy handler receives the raw path.
func buildTopHandler(proxy http.Handler, extraRoutes map[string]http.Handler) http.Handler {
	if len(extraRoutes) == 0 {
		return proxy
	}
	mux := http.NewServeMux()
	for pattern, h := range extraRoutes {
		mux.Handle(pattern, h)
	}
	mux.Handle("/", proxy)
	return mux
}

func runValidatePolicy(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("validate-policy", flag.ExitOnError)
	path := fs.String("file", "policy.yaml", "path to policy file")
	backend := fs.String("backend", "yaml", `policy backend: "yaml", "opa", or "cedar"`)
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	if _, err := loadPolicyEngine(*backend, *path); err != nil {
		logger.Error("failed to load policy", "error", err)
		os.Exit(1)
	}
	fmt.Println("policy file is valid")
}

// loadPolicyEngine picks the policy.Engine implementation named by
// backend ("yaml", "opa", or "cedar"; "" defaults to "yaml"). runServe
// only ever passes a value config.Load has already validated, but
// runValidatePolicy passes its raw, unvalidated -backend flag straight
// through, so any other value is rejected explicitly here rather than
// silently falling back to the YAML loader.
func loadPolicyEngine(backend, path string) (policydomain.Engine, error) {
	switch backend {
	case "opa":
		return opaadapter.LoadRegoFile(path)
	case "cedar":
		return cedaradapter.LoadCedarFile(path)
	case "yaml", "":
		return policyadapter.LoadFile(path)
	default:
		return nil, fmt.Errorf("unknown policy backend %q (want \"yaml\", \"opa\", or \"cedar\")", backend)
	}
}

func runValidateConfig(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
	path := fs.String("config", "wardline.yaml", "path to config file")
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	cfg, err := config.Load(*path)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	if flags.NewStaticProvider(cfg.Features).Enabled("rbac") {
		if _, err := rbacadapter.LoadAuthorizer(cfg.RBAC.ConfigFile); err != nil {
			logger.Error("failed to load rbac file", "error", err)
			os.Exit(1)
		}
	}
	if flags.NewStaticProvider(cfg.Features).Enabled("anomaly_detection") {
		if _, err := buildAnomalyWriter(logger, cfg.Anomaly.Output); err != nil {
			logger.Error("failed to open anomaly output", "path", cfg.Anomaly.Output, "error", err)
			os.Exit(1)
		}
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

// anomalyHeuristicConfig translates the operator-facing AnomalyConfig
// into anomaly/domain.HeuristicConfig, the shape Detector actually
// consumes -- kept as a pure translation with no I/O so it's trivial to
// eyeball against the config struct it's built from.
func anomalyHeuristicConfig(cfg config.AnomalyConfig) anomalydomain.HeuristicConfig {
	return anomalydomain.HeuristicConfig{
		WindowSeconds:        cfg.WindowSeconds,
		RateSpikeEnabled:     cfg.RateSpike.Enabled,
		RateMultiplier:       cfg.RateSpike.Multiplier,
		RateMinCalls:         cfg.RateSpike.MinCalls,
		NovelToolEnabled:     cfg.NovelTool.Enabled,
		DenyRateSpikeEnabled: cfg.DenyRateSpike.Enabled,
		DenyRateThreshold:    cfg.DenyRateSpike.Threshold,
		DenyRateMinCalls:     cfg.DenyRateSpike.MinCalls,
		GCIntervalSeconds:    cfg.GCIntervalSeconds,
	}
}

// buildAnomalyWriter opens output ("stdout" or a file path) and wraps it
// in anomaly/adapter.JSONLWriter -- same shape as buildAuditWriter, kept
// as a separate function (not a parameter to buildAuditWriter) because
// anomaly output is a distinct stream from the audit trail, opened only
// when anomaly_detection is on, and returns an error instead of calling
// os.Exit itself so the caller can log with its own context before
// exiting.
func buildAnomalyWriter(logger *slog.Logger, output string) (*anomalyadapter.JSONLWriter, error) {
	if output == "stdout" {
		return anomalyadapter.NewJSONLWriter(os.Stdout), nil
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return anomalyadapter.NewJSONLWriter(f), nil
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
