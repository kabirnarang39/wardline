package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	anomalyadapter "github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetadapter "github.com/kabirnarang39/wardline/internal/features/budget/adapter"
	budgetusecase "github.com/kabirnarang39/wardline/internal/features/budget/usecase"
	complianceadapter "github.com/kabirnarang39/wardline/internal/features/compliance/adapter"
	complianceusecase "github.com/kabirnarang39/wardline/internal/features/compliance/usecase"
	credentialadapter "github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	credentialdomain "github.com/kabirnarang39/wardline/internal/features/credential/domain"
	credentialusecase "github.com/kabirnarang39/wardline/internal/features/credential/usecase"
	dashboardadapter "github.com/kabirnarang39/wardline/internal/features/dashboard/adapter"
	dashboarddomain "github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
	dashboardusecase "github.com/kabirnarang39/wardline/internal/features/dashboard/usecase"
	federationadapter "github.com/kabirnarang39/wardline/internal/features/federation/adapter"
	federationdomain "github.com/kabirnarang39/wardline/internal/features/federation/domain"
	federationusecase "github.com/kabirnarang39/wardline/internal/features/federation/usecase"
	healthadapter "github.com/kabirnarang39/wardline/internal/features/health/adapter"
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
		logger.Error("usage: wardline <serve|validate-policy|validate-config|export-evidence|policy-pack> [flags]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(logger, os.Args[2:])
	case "validate-policy":
		runValidatePolicy(logger, os.Args[2:])
	case "validate-config":
		runValidateConfig(logger, os.Args[2:])
	case "export-evidence":
		runExportEvidence(logger, os.Args[2:])
	case "policy-pack":
		runPolicyPack(logger, os.Args[2:])
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
	var blockChecker *anomalyusecase.BlockChecker
	var autoBlockGCStop chan struct{}
	if anomalyDetectionEnabled {
		anomalyWriter, err := buildAnomalyWriter(cfg.Anomaly.Output)
		if err != nil {
			logger.Error("failed to open anomaly output file", "path", cfg.Anomaly.Output, "error", err)
			os.Exit(1)
		}
		bufferCapacity := cfg.Anomaly.BufferCapacity
		if bufferCapacity <= 0 {
			bufferCapacity = ringBufferCapacity
		}
		anomalyBuffer = anomalyusecase.NewAlertBuffer(bufferCapacity)
		heuristicCfg := anomalyHeuristicConfig(cfg.Anomaly)

		// Always positive: config.validate() defaults gc_interval_seconds
		// when anomaly_detection is on. A second fallback here is what let an
		// omitted gc_interval_seconds bypass the auto_block/GC-interval
		// cross-validation, which runs before this line ever does.
		gcInterval := time.Duration(cfg.Anomaly.GCIntervalSeconds) * time.Second

		if cfg.Anomaly.AutoBlock.Enabled {
			blockChecker = anomalyusecase.NewBlockChecker(heuristicCfg.AutoBlock, time.Now)
			// auto_block has no gc_interval_seconds field of its own (see
			// config.AutoBlockConfig) -- it's a sub-feature of anomaly
			// detection, so its GC just reuses the same gcInterval already
			// derived above for the detector's own per-identity state GC
			// rather than inventing a second, independently-tunable knob
			// for what's a tiny in-memory map.
			autoBlockGCStop = make(chan struct{})
			go anomalyusecase.StartBlockGC(blockChecker, gcInterval, autoBlockGCStop)
			logger.Info("auto-block enabled", "block_duration_seconds", cfg.Anomaly.AutoBlock.BlockDurationSeconds)
		}

		onAnomalyWriteErr := func(err error) {
			logger.Error("anomaly write failed", "error", err)
		}
		// blockChecker is passed through two branches, not directly as the
		// possibly-nil *BlockChecker variable, for the same typed-nil
		// reason as the liveSink switch below: a nil *BlockChecker placed
		// into NewDetector's blocker interface parameter would be a
		// non-nil interface wrapping a nil pointer, which Detector's own
		// "d.blocker != nil" guard can't see -- it would call Block on a
		// nil receiver on the first ml_score hit instead of skipping.
		if blockChecker != nil {
			anomalyDetector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, anomalyBuffer, blockChecker, onAnomalyWriteErr, time.Now)
		} else {
			anomalyDetector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, anomalyBuffer, nil, onAnomalyWriteErr, time.Now)
		}

		anomalyGCStop = make(chan struct{})
		go anomalyusecase.StartGC(anomalyDetector, gcInterval, anomalyGCStop)
		logger.Info("anomaly detection enabled", "output", cfg.Anomaly.Output)
	}

	// federation requires anomaly_detection (enforced by config.validate()),
	// so anomalyBuffer above is always non-nil whenever federationEnabled is
	// true here.
	federationEnabled := featureFlags.Enabled("federation")
	var correlator *federationusecase.Correlator
	var correlatedBuffer *federationusecase.CorrelatedAlertBuffer
	var federationSummariesHandler http.Handler
	var federationPublishStop chan struct{}
	var federationGCStop chan struct{}
	if federationEnabled {
		instanceID := deriveInstanceID(logger, cfg.Federation.InstanceID)

		peers, err := federationadapter.LoadPeers(cfg.Federation.PeersFile)
		if err != nil {
			logger.Error("failed to load federation peers file", "error", err)
			os.Exit(1)
		}
		if len(peers) == 0 {
			// Not necessarily a misconfiguration (an operator may be
			// mid-rollout), but silent otherwise -- see peers_loader.go's
			// LoadPeers doc comment for why this warning lives here rather
			// than in that pure, logger-free loader.
			logger.Warn("federation is enabled but peers_file lists no peers; nothing to correlate with yet")
		}
		for _, peer := range peers {
			if peer.ID == instanceID {
				// Now a more likely misconfiguration than before this cycle:
				// instance_id defaults to os.Hostname(), which is identical
				// for co-located processes and was previously undocumented
				// (see README.md "Federation" and FederationConfig.InstanceID's
				// doc comment). Warn loudly but don't block startup -- a
				// self-referential peer entry is harmless (Correlator only
				// counts an instance ID once via its own Ingest call), just
				// almost certainly not what the operator intended.
				logger.Warn("federation peer id matches this instance's own instance_id; likely misconfiguration", "instance_id", instanceID)
			}
		}
		signingKeyPEM, err := os.ReadFile(cfg.Federation.SigningKeyFile)
		if err != nil {
			logger.Error("failed to read federation signing key file", "error", err)
			os.Exit(1)
		}
		signingKey, err := federationadapter.ParsePrivateKeyPEM(signingKeyPEM)
		if err != nil {
			logger.Error("failed to parse federation signing key", "error", err)
			os.Exit(1)
		}
		// The shared secret is opaque HMAC key material, not PEM -- read raw,
		// no parsing, matching how RBAC/credential files that aren't
		// themselves structured configs are handled.
		sharedSecret, err := os.ReadFile(cfg.Federation.SharedSecretFile)
		if err != nil {
			logger.Error("failed to read federation shared secret file", "error", err)
			os.Exit(1)
		}

		correlatedBuffer = federationusecase.NewCorrelatedAlertBuffer(ringBufferCapacity)
		correlator = federationusecase.NewCorrelator(federationdomain.FederationConfig{
			PublishIntervalSeconds:     cfg.Federation.PublishIntervalSeconds,
			MinInstancesForCorrelation: cfg.Federation.MinInstancesForCorrelation,
			CorrelationWindowSeconds:   cfg.Federation.CorrelationWindowSeconds,
			GCIntervalSeconds:          cfg.Federation.GCIntervalSeconds,
		}, func(a federationdomain.CorrelatedAlert) {
			// This is the feature's whole payoff signal -- without a log
			// line here it only ever lives in the in-memory
			// correlatedBuffer (gone on restart) and the dashboard, so an
			// operator with web_ui off, or without a dashboard open at the
			// right moment, would never see it at all.
			logger.Warn("cross-instance correlated anomaly",
				"fingerprint", a.Fingerprint, "kind", a.Kind, "instances", a.InstanceIDs)
			correlatedBuffer.Add(a)
		}, time.Now)

		// One buffer, two readers -- the dashboard's existing anomalies
		// handler and this new Publisher both read from the same
		// anomalyBuffer the anomaly_detection block above already
		// constructed.
		publisher := federationusecase.NewPublisher(
			instanceID, anomalyBuffer, peers, signingKey, sharedSecret,
			federationadapter.NewHTTPSender(&http.Client{Timeout: 10 * time.Second}),
			cfg.Federation.PublishIntervalSeconds,
		)

		federationPublishStop = make(chan struct{})
		// Publisher.PublishOnce also returns the summaries it aggregated for
		// this tick; feeding them straight into the local Correlator here
		// means this instance's own detections count toward correlation
		// using the exact same aggregation window Publisher just computed,
		// rather than a second, potentially-drifting Aggregate call.
		go federationusecase.StartPublisher(publisher, time.Duration(cfg.Federation.PublishIntervalSeconds)*time.Second, federationPublishStop,
			func(summaries []federationdomain.AnomalySummary) {
				for _, s := range summaries {
					correlator.Ingest(instanceID, s)
				}
			},
			func(errs []error) {
				for _, e := range errs {
					logger.Error("federation publish failed", "error", e)
				}
			},
		)

		federationGCStop = make(chan struct{})
		go federationusecase.StartCorrelatorGC(correlator, time.Duration(cfg.Federation.GCIntervalSeconds)*time.Second, federationGCStop)

		federationSummariesHandler = federationadapter.NewHandler(peers, correlator.Ingest, logger)
		logger.Info("federation enabled", "instance_id", instanceID, "peers", len(peers))
	}

	// Exhaustive over both flags rather than MultiSink{ringBuffer,
	// anomalyDetector} with nil members: a nil *RingBuffer or *Detector
	// placed in a LiveSink slot is a typed nil, which MultiSink's nil check
	// cannot see, so it would be dispatched to and panic on the first
	// request. Every sink reaching MultiSink here is already constructed.
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

	postgresStorageEnabled := featureFlags.Enabled("postgres_storage")
	var healthPinger func(ctx context.Context) error
	var healthDB *sql.DB
	if postgresStorageEnabled {
		// One small, long-lived pool dedicated to /readyz pings --
		// independent of the audit writer's own pool (different
		// lifecycle, doesn't need to share its longer queryTimeout),
		// but shared across every poll rather than opening a fresh
		// connection (a full TCP+auth handshake) on every single
		// probe, which a ~10s Kubernetes probe cadence would otherwise
		// pay on every request. sql.Open itself doesn't dial -- the
		// pool connects lazily on first PingContext.
		db, err := sql.Open("pgx", cfg.Audit.PostgresDSN)
		if err != nil {
			logger.Error("failed to open health-check database pool", "error", err)
			os.Exit(1)
		}
		db.SetMaxOpenConns(2)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(5 * time.Minute)
		healthDB = db
		healthPinger = func(ctx context.Context) error {
			return healthDB.PingContext(ctx)
		}
	}
	healthHandler := healthadapter.NewHandler(healthPinger)

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
	var revokerCloser io.Closer
	if credentialIssuanceEnabled {
		bootstrapper, err := credentialadapter.LoadBootstrapper(cfg.Credential.IdentitiesFile)
		if err != nil {
			logger.Error("failed to load credentials file", "error", err)
			os.Exit(1)
		}
		issuerVerifier, err := credentialadapter.NewJWTIssuerVerifier(cfg.Credential.SigningKeyFile)
		if err != nil {
			logger.Error("failed to initialize credential issuer", "error", err)
			os.Exit(1)
		}
		if cfg.Credential.SigningKeyFile == "" {
			logger.Warn("credential issuance signing key is generated fresh in-process; safe for exactly one replica -- set credential.signing_key_file to run more than one")
		}

		var revoker credentialdomain.Revoker
		if postgresStorageEnabled {
			pr, err := credentialadapter.NewPostgresRevoker(cfg.Audit.PostgresDSN, logger)
			if err != nil {
				logger.Error("failed to initialize postgres revoker", "error", err)
				os.Exit(1)
			}
			revoker = pr
			revokerCloser = pr
			logger.Info("credential revocation backed by postgres (shared across replicas)")
		} else {
			revoker = credentialadapter.NewRevocationList()
			logger.Warn("credential revocation is in-process only; safe for exactly one replica -- enable features.postgres_storage to share revocation across replicas")
		}

		issuance := credentialusecase.NewIssuanceService(bootstrapper, issuerVerifier)
		verification := credentialusecase.NewVerificationService(issuerVerifier, revoker)
		revocation := credentialusecase.NewRevocationService(revoker)
		credentialHandler = credentialadapter.NewHandler(issuance, revocation, logger, revokeAuthorizer)
		// verification already satisfies proxyadapter.Authenticator directly
		// -- both return (identity, tenant, err) -- so no adapter shim is
		// needed to bridge the two.
		identityAuth = proxyadapter.NewBearerIdentity(verification)
		logger.Info("credential issuance enabled", "identities_file", cfg.Credential.IdentitiesFile)
	}

	// Declared as the interface type and left at its zero value (a true
	// nil interface) unless blockChecker is a guaranteed-non-nil
	// *BlockChecker -- same typed-nil avoidance as anomalySource/
	// federationSource below, and the liveSink switch above.
	var autoBlockChecker proxyadapter.AutoBlockChecker
	if blockChecker != nil {
		autoBlockChecker = blockChecker
	}
	handler := proxyadapter.NewHandler(decider, recorder, cfg.UpstreamURL, budgetChecker, tracingProvider.Tracer(), identityAuth, logger, autoBlockChecker)

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
		var federationSource dashboardadapter.FederationSource
		if federationEnabled {
			federationSource = correlatedBuffer
		}
		var blockedSource dashboardadapter.BlockedSource
		if blockChecker != nil {
			blockedSource = blockChecker
		}
		var dashboardRoute http.Handler = dashboardadapter.NewHandler(ringBuffer, statusProvider, policyInfo, dashboardadapter.Assets(), anomalySource, federationSource, blockedSource)
		if rbacEnabled {
			dashboardRoute = rbacadapter.RequirePermission(rbacChecker, identityAuth, rbacdomain.PermissionDashboardView, dashboardRoute, logger)
		}
		extraRoutes["/dashboard/"] = dashboardRoute
		logger.Info("dashboard enabled", "path", "/dashboard/")
	}
	if credentialIssuanceEnabled {
		extraRoutes["/credentials/token"] = http.HandlerFunc(credentialHandler.HandleToken)
		extraRoutes["/credentials/revoke"] = http.HandlerFunc(credentialHandler.HandleRevoke)
	}
	if federationEnabled {
		// Unconditional on web_ui, unlike the dashboard route above -- a
		// peer must be able to reach this even when the local dashboard UI
		// is off, matching /credentials/token's unconditional-when-flag-on
		// pattern.
		extraRoutes["/federation/summaries"] = federationSummariesHandler
	}
	// Unconditional, unlike every other extraRoutes entry -- every
	// deployment needs health/readiness checking, it isn't a feature an
	// operator opts into with a flag.
	extraRoutes["/healthz"] = healthHandler
	extraRoutes["/readyz"] = healthHandler

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
			if revokerCloser != nil {
				if err := revokerCloser.Close(); err != nil {
					logger.Error("revoker shutdown failed", "error", err)
				}
			}
			if healthDB != nil {
				if err := healthDB.Close(); err != nil {
					logger.Error("health-check database pool shutdown failed", "error", err)
				}
			}
			if anomalyGCStop != nil {
				close(anomalyGCStop)
			}
			if autoBlockGCStop != nil {
				close(autoBlockGCStop)
			}
			if federationPublishStop != nil {
				close(federationPublishStop)
			}
			if federationGCStop != nil {
				close(federationGCStop)
			}
			os.Exit(1)
		}
	case <-ctx.Done():
		// An in-process substitute for a Kubernetes preStop sleep -- see
		// Config.ShutdownDelaySeconds' doc comment for why this exists
		// instead of a shell-based lifecycle hook. Runs BEFORE
		// SetDraining so the pod keeps serving and reporting ready for
		// this long, exactly like a real preStop hook delaying SIGTERM:
		// the point is to buy Endpoints-propagation time while nothing
		// about this replica's behavior changes yet. This is the only
		// thing allowed to run before SetDraining -- everything else in
		// this branch keeps its original relative order (SetDraining,
		// then stop(), then the log line, then Shutdown) since that
		// ordering also controls how wide the window is for a readiness
		// probe to actually observe a 503 before the listener closes;
		// don't reorder those without re-verifying
		// TestHealthEndToEnd_ReadyzFlipsToUnreadyDuringShutdown stays
		// reliably green (moving stop() earlier once measurably shrank
		// that window and made the test flake far more often).
		if cfg.ShutdownDelaySeconds > 0 {
			logger.Info("delaying shutdown drain", "seconds", cfg.ShutdownDelaySeconds)
			time.Sleep(time.Duration(cfg.ShutdownDelaySeconds) * time.Second)
		}
		// Flip readiness before anything else: a polling Kubernetes
		// readiness probe needs the pod out of Service endpoint
		// rotation as early as possible in the drain window, not after
		// srv.Shutdown has already started refusing new connections.
		healthHandler.SetDraining(true)
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
	if revokerCloser != nil {
		if err := revokerCloser.Close(); err != nil {
			logger.Error("revoker shutdown failed", "error", err)
		}
	}
	if healthDB != nil {
		if err := healthDB.Close(); err != nil {
			logger.Error("health-check database pool shutdown failed", "error", err)
		}
	}
	if anomalyGCStop != nil {
		close(anomalyGCStop)
	}
	if autoBlockGCStop != nil {
		close(autoBlockGCStop)
	}
	if federationPublishStop != nil {
		close(federationPublishStop)
	}
	if federationGCStop != nil {
		close(federationGCStop)
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
		// The resolved tenant isn't used here yet -- a later task in this
		// plan tenant-scopes this check (cross-tenant revoke handling); for
		// now this preserves the existing hardcoded-"default" behavior
		// exactly.
		who, _, err := (*identityAuth).Authenticate(r)
		if err != nil {
			logger.Warn("rbac revoke authorization: identity resolution failed", "remote_addr", r.RemoteAddr)
			return false
		}
		return checker.Check(who, "default", rbacdomain.PermissionCredentialRevoke)
	})
}

// buildTopHandler routes each key of extraRoutes to its handler, and
// everything else to proxy. Every route except /healthz and /readyz is
// only ever present in the map when its owning feature flag is on — this
// is the one place that decision is made, not scattered through request
// handling. The empty-map fast path below (bare proxy handler, byte-for-
// byte v0.1 pass-through with no path cleaning at all) is retained for
// callers/tests that construct a map without the two unconditional health
// routes, but runServe itself always registers /healthz and /readyz, so
// in every real deployment extraRoutes is never empty and the mux branch
// always runs. That means stdlib path cleaning/redirects (e.g. collapsing
// "//tool" or resolving "..") now apply to every deployment, not only
// ones with dashboard/credential/rbac routes on as before this cycle —
// an accepted, necessary trade-off of giving health/readiness checks real
// routes rather than special-casing them inside the proxy handler itself.
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
	logger.Info("policy file is valid")
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
	if flags.NewStaticProvider(cfg.Features).Enabled("credential_issuance") && cfg.Credential.SigningKeyFile != "" {
		if _, err := credentialadapter.NewJWTIssuerVerifier(cfg.Credential.SigningKeyFile); err != nil {
			logger.Error("failed to load credential signing key file", "error", err)
			os.Exit(1)
		}
	}
	// Check that anomaly.output's parent directory exists rather than
	// opening the file: validate-config must have no filesystem side
	// effects, and buildAnomalyWriter's O_CREATE would leave a stray empty
	// 0600 file (and a leaked descriptor) behind on every validation run.
	// This catches the common failure -- a typo'd or not-yet-created
	// directory -- which is the case runServe would otherwise only report
	// at startup.
	if flags.NewStaticProvider(cfg.Features).Enabled("anomaly_detection") && cfg.Anomaly.Output != "stdout" {
		dir := filepath.Dir(cfg.Anomaly.Output)
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			logger.Error("anomaly.output directory is not usable", "path", cfg.Anomaly.Output, "dir", dir, "error", err)
			os.Exit(1)
		}
	}
	if flags.NewStaticProvider(cfg.Features).Enabled("federation") {
		if _, err := federationadapter.LoadPeers(cfg.Federation.PeersFile); err != nil {
			logger.Error("failed to load federation peers file", "error", err)
			os.Exit(1)
		}
		signingKeyPEM, err := os.ReadFile(cfg.Federation.SigningKeyFile)
		if err != nil {
			logger.Error("failed to read federation signing key file", "error", err)
			os.Exit(1)
		}
		if _, err := federationadapter.ParsePrivateKeyPEM(signingKeyPEM); err != nil {
			logger.Error("failed to parse federation signing key file", "error", err)
			os.Exit(1)
		}
		if _, err := os.ReadFile(cfg.Federation.SharedSecretFile); err != nil {
			logger.Error("failed to read federation shared secret file", "error", err)
			os.Exit(1)
		}
	}
	logger.Info("config file is valid")
}

// runExportEvidence assembles a compliance evidence bundle covering
// [-from, -to) from the audit trail, the anomaly log (if enabled), the
// policy source, and rbac.yaml (if enabled), and writes it as a
// checksum-verified .tar.gz. No feature flag gates this command -- like
// validate-policy/validate-config, it's an explicitly-invoked offline
// operation, not passive runtime behavior.
func runExportEvidence(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("export-evidence", flag.ExitOnError)
	configPath := fs.String("config", "wardline.yaml", "path to config file")
	fromStr := fs.String("from", "", "start of the evidence range (RFC3339), required")
	toStr := fs.String("to", "", "end of the evidence range (RFC3339), defaults to now")
	outputPath := fs.String("output", "", "output bundle path, defaults to ./evidence-<from>-<to>.tar.gz")
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	if *fromStr == "" {
		logger.Error("-from is required (RFC3339, e.g. 2026-07-01T00:00:00Z)")
		os.Exit(1)
	}
	from, err := time.Parse(time.RFC3339, *fromStr)
	if err != nil {
		logger.Error("invalid -from", "error", err)
		os.Exit(1)
	}
	to := time.Now()
	if *toStr != "" {
		to, err = time.Parse(time.RFC3339, *toStr)
		if err != nil {
			logger.Error("invalid -to", "error", err)
			os.Exit(1)
		}
	}
	if !from.Before(to) {
		logger.Error("-from must be before -to")
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	featureFlags := flags.NewStaticProvider(cfg.Features)

	var auditReader auditdomain.Reader
	var jsonlReader *auditadapter.JSONLReader
	if featureFlags.Enabled("postgres_storage") {
		// Same precedence buildAuditSink applies for serve: postgres wins,
		// audit.output is ignored. Logged here too because "my bundle is
		// empty" against a config that has both set is otherwise silent --
		// the operator can't tell which of the two stores was read.
		if cfg.Audit.Output != "" {
			logger.Info("audit.output is set but features.postgres_storage is on; exporting from postgres and ignoring audit.output",
				"output", cfg.Audit.Output)
		}
		// NewPostgresWriter runs CREATE TABLE/INDEX IF NOT EXISTS on
		// connect, so this read-only export needs the same DDL-capable DSN
		// serve uses -- a SELECT-only compliance role can't run it. See
		// README.md "Compliance evidence export"; a dedicated read-only
		// connector is deferred (it also needs a separate DSN config field
		// to be useful, which is a design change, not a bug fix).
		pw, err := auditadapter.NewPostgresWriter(cfg.Audit.PostgresDSN)
		if err != nil {
			logger.Error("failed to connect to postgres", "error", err)
			os.Exit(1)
		}
		defer func() { _ = pw.Close() }()
		auditReader = pw
	} else if cfg.Audit.Output == "stdout" {
		logger.Error("audit trail is not queryable when audit.output is stdout -- configure a file path or features.postgres_storage to use export-evidence")
		os.Exit(1)
	} else {
		jsonlReader = auditadapter.NewJSONLReader(cfg.Audit.Output)
		auditReader = jsonlReader
	}

	ctx := context.Background()
	auditEntries, err := auditReader.Query(ctx, from, to)
	if err != nil {
		logger.Error("failed to query audit entries", "error", err)
		os.Exit(1)
	}
	skippedAuditLines := 0
	if jsonlReader != nil {
		skippedAuditLines = jsonlReader.SkippedLines
	}

	var anomalies []anomalydomain.Anomaly
	skippedAnomalyLines := 0
	if featureFlags.Enabled("anomaly_detection") && cfg.Anomaly.Output != "" && cfg.Anomaly.Output != "stdout" {
		anomalyReader := anomalyadapter.NewJSONLReader(cfg.Anomaly.Output)
		anomalies, err = anomalyReader.Query(ctx, from, to)
		switch {
		// anomaly.output only exists once serve has started at least once
		// with anomaly_detection on (buildAnomalyWriter's O_CREATE), so an
		// operator who enables the flag and exports before restarting has
		// no file yet. That's "no anomalies fired", not a failure -- the
		// bundle already omits anomalies.jsonl for a zero-anomaly range.
		// The audit file deliberately does NOT get this treatment: an
		// absent audit trail must never quietly become a 0-entry evidence
		// bundle.
		case errors.Is(err, os.ErrNotExist):
			logger.Warn("anomaly output file does not exist yet; exporting zero anomalies",
				"path", cfg.Anomaly.Output)
		case err != nil:
			logger.Error("failed to query anomaly entries", "error", err)
			os.Exit(1)
		default:
			skippedAnomalyLines = anomalyReader.SkippedLines
		}
	}

	var policySource []byte
	if cfg.PolicyFile != "" {
		policySource, err = os.ReadFile(cfg.PolicyFile)
		if err != nil {
			logger.Error("failed to read policy file", "error", err)
			os.Exit(1)
		}
	}

	var rbacSource []byte
	if featureFlags.Enabled("rbac") && cfg.RBAC.ConfigFile != "" {
		rbacSource, err = os.ReadFile(cfg.RBAC.ConfigFile)
		if err != nil {
			logger.Error("failed to read rbac file", "error", err)
			os.Exit(1)
		}
	}

	manifestFeatures := cfg.Features
	if manifestFeatures == nil {
		// cfg.Features is nil whenever the operator's wardline.yaml omits
		// the features: block entirely (yaml.v3 leaves an absent mapping
		// key as a nil map, not an empty one). BuildManifest passes it
		// straight through, so without this it would serialize the
		// manifest as "features": null instead of the guaranteed-{}
		// shape the two count maps next to it always have.
		manifestFeatures = map[string]bool{}
	}
	manifest := complianceusecase.BuildManifest(version.Version, from, to, time.Now(), manifestFeatures, auditEntries, skippedAuditLines, anomalies, skippedAnomalyLines)

	output := *outputPath
	if output == "" {
		sanitize := func(s string) string { return strings.ReplaceAll(s, ":", "-") }
		output = fmt.Sprintf("./evidence-%s-%s.tar.gz", sanitize(from.Format(time.RFC3339)), sanitize(to.Format(time.RFC3339)))
	}

	tmpPath := output + ".tmp"
	// 0600, not os.Create's 0666&umask: the bundle aggregates the whole
	// audit trail (whose own file wardline opens 0600), the rbac bindings
	// and the policy source into one artifact, so a world-readable default
	// would widen access to evidence on any shared host.
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logger.Error("failed to create output file", "path", tmpPath, "error", err)
		os.Exit(1)
	}
	if err := complianceadapter.WriteBundle(f, manifest, auditEntries, anomalies, policySource, cfg.PolicyBackend, rbacSource); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		logger.Error("failed to write evidence bundle", "error", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		logger.Error("failed to close output file", "error", err)
		os.Exit(1)
	}
	if err := os.Rename(tmpPath, output); err != nil {
		_ = os.Remove(tmpPath)
		logger.Error("failed to finalize output file", "error", err)
		os.Exit(1)
	}

	logger.Info("wrote evidence bundle", "output", output, "audit_entries", len(auditEntries), "anomalies", len(anomalies))
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

// deriveInstanceID returns override if non-empty (an operator-supplied
// federation.instance_id, for topologies where os.Hostname() isn't
// unique per process -- see FederationConfig.InstanceID's doc comment).
// Otherwise it derives an ID from os.Hostname(), falling back to a
// random suffix (logged as a warning, never fatal) if that fails -- an
// instance ID is only used to label this instance's own summaries to
// peers and to the local Correlator, so a missing/unstable hostname
// must never block startup.
func deriveInstanceID(logger *slog.Logger, override string) string {
	return deriveInstanceIDFrom(logger, override, os.Hostname)
}

// deriveInstanceIDFrom is deriveInstanceID's real logic, taking the
// hostname lookup as a func so tests can drive both the "hostname
// resolves" and "hostname lookup fails" paths deterministically --
// os.Hostname() itself essentially never fails in a real environment,
// so there'd be no other way to exercise the random-suffix fallback.
func deriveInstanceIDFrom(logger *slog.Logger, override string, hostname func() (string, error)) string {
	if override != "" {
		return override
	}
	if host, err := hostname(); err == nil && host != "" {
		return host
	}
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read failing indicates a broken system entropy
		// source -- exceptionally rare. Fall back to a fixed suffix rather
		// than making instance ID derivation itself capable of failing.
		buf = []byte{0xde, 0xad, 0xbe, 0xef}
	}
	instanceID := fmt.Sprintf("wardline-%x", buf)
	logger.Warn("failed to determine hostname for federation instance ID; using a random suffix instead", "instance_id", instanceID)
	return instanceID
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
		MLScore: anomalydomain.MLScoreConfig{
			Enabled:        cfg.MLScore.Enabled,
			ScoreThreshold: cfg.MLScore.ScoreThreshold,
			MinCalls:       cfg.MLScore.MinCalls,
		},
		AutoBlock: anomalydomain.AutoBlockConfig{
			Enabled:              cfg.AutoBlock.Enabled,
			ScoreThreshold:       cfg.AutoBlock.ScoreThreshold,
			BlockDurationSeconds: cfg.AutoBlock.BlockDurationSeconds,
		},
	}
}

// buildAnomalyWriter opens output ("stdout" or a file path) and wraps it
// in anomaly/adapter.JSONLWriter -- same shape as buildAuditWriter, kept
// as a separate function (not a parameter to buildAuditWriter) because
// anomaly output is a distinct stream from the audit trail, opened only
// when anomaly_detection is on, and returns an error instead of calling
// os.Exit itself (hence no logger parameter, unlike buildAuditWriter) so
// the caller can log with its own context before exiting.
func buildAnomalyWriter(output string) (*anomalyadapter.JSONLWriter, error) {
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
