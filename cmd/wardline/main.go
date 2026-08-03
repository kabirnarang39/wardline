package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
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
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
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
	scimadapter "github.com/kabirnarang39/wardline/internal/features/scim/adapter"
	scimusecase "github.com/kabirnarang39/wardline/internal/features/scim/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
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
		logger.Error("usage: wardline <serve|validate-policy|validate-config|export-evidence|policy-pack|infer-policy> [flags]")
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
	case "infer-policy":
		runInferPolicy(logger, os.Args[2:])
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
	policyHolder := reload.NewReloadableEngine(&engine)
	policyReload := newPolicyReloadFn(policyHolder, *configPath)

	featureFlags := flags.NewStaticProvider(cfg.Features)
	webUIEnabled := featureFlags.Enabled("web_ui")
	anomalyDetectionEnabled := featureFlags.Enabled("anomaly_detection")
	postgresStorageEnabled := featureFlags.Enabled("postgres_storage")

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
	var anomalyBaselineStoreCloser io.Closer
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

		// Gated on anomaly_detection as well as postgres_storage, mirroring
		// how scim, credential_issuance, and budget_enforcement each gate
		// their own Postgres branch on their own feature flag first. Without
		// the anomaly_detection check, an operator who turned on
		// postgres_storage alone would get the anomaly_baselines table
		// touched and a connection pool opened for a feature they never
		// enabled.
		var baselineStore *anomalyadapter.PostgresBaselineStore
		if postgresStorageEnabled {
			// Reuses deriveInstanceID -- the same hostname-based (random-
			// suffix-on-failure) identity federation already derives for its
			// own instance ID -- rather than inventing a second ID scheme.
			// Deliberately independent of federation's own instance_id
			// config field and derived unconditionally here (no override,
			// and regardless of federationEnabled): the baseline store's
			// instance ID must answer "what stably identifies this replica"
			// even when federation is off, so this feature isn't coupled to
			// that one.
			anomalyInstanceID := deriveInstanceID(logger, "")
			bs, err := anomalyadapter.NewPostgresBaselineStore(cfg.Audit.PostgresDSN, anomalyInstanceID, logger)
			if err != nil {
				logger.Error("failed to initialize postgres anomaly baseline store", "error", err)
				os.Exit(1)
			}
			baselineStore = bs
			anomalyBaselineStoreCloser = bs
			logger.Info("anomaly baseline persistence backed by postgres (survives restarts)")
		} else {
			logger.Warn("anomaly baselines are in-process only; a restart resets every identity's history -- enable features.postgres_storage to persist across restarts")
		}

		// blockChecker and baselineStore are each passed through explicit
		// nil branches, not directly as their possibly-nil pointer
		// variables, for the same typed-nil reason as the liveSink switch
		// below: a nil *BlockChecker/*PostgresBaselineStore placed into
		// NewDetector's blocker/store interface parameters would be a
		// non-nil interface wrapping a nil pointer, which Detector's own
		// "!= nil" guards can't see -- it would call through to a nil
		// receiver on the first hit instead of skipping.
		//
		// ponytail: a 4-arm combinatorial switch doesn't scale past 2
		// nilable dependencies -- deliberately left as-is rather than
		// collapsed, though: usecase.blocker/usecase.baselineStore (the
		// interface types NewDetector's parameters actually have) are both
		// unexported, so this package cannot name them to declare a local
		// "var bc blocker" the way a cleaner version of this switch would
		// need to. A helper inside the usecase package itself could nil-guard
		// *BlockChecker (defined in that package, no cycle), but not
		// *PostgresBaselineStore -- that type lives in the adapter package,
		// which already imports usecase, so usecase importing it back would
		// be a cycle. Exporting blocker/baselineStore purely to let main.go
		// spell their names here would be an API-shape change for a cosmetic
		// nit; not worth it for 2 dependencies.
		switch {
		case blockChecker != nil && baselineStore != nil:
			anomalyDetector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, anomalyBuffer, blockChecker, onAnomalyWriteErr, time.Now, baselineStore)
		case blockChecker != nil:
			anomalyDetector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, anomalyBuffer, blockChecker, onAnomalyWriteErr, time.Now, nil)
		case baselineStore != nil:
			anomalyDetector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, anomalyBuffer, nil, onAnomalyWriteErr, time.Now, baselineStore)
		default:
			anomalyDetector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, anomalyBuffer, nil, onAnomalyWriteErr, time.Now, nil)
		}

		if err := anomalyDetector.LoadBaselines(); err != nil {
			logger.Error("failed to load persisted anomaly baselines", "error", err)
			os.Exit(1)
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

	decider := proxyusecase.NewDeciderWithHolder(policyHolder)

	budgetEnforcementEnabled := featureFlags.Enabled("budget_enforcement")

	// Gated on budget_enforcement as well as postgres_storage, mirroring
	// how scim and credential_issuance each gate their own Postgres branch
	// on their own feature flag first. Without the budget_enforcement
	// check, an operator who turned on postgres_storage alone would get
	// the budget_buckets table created, a 10-connection pool opened, and a
	// possible os.Exit(1) on init failure -- all for a feature they never
	// enabled. The Checker no-ops on the flag regardless of which Limiter
	// backs it, so InMemoryLimiter is the harmless choice when off.
	var limiter budgetdomain.Limiter
	var budgetLimiterCloser io.Closer
	if postgresStorageEnabled && budgetEnforcementEnabled {
		pl, err := budgetadapter.NewPostgresLimiter(cfg.Audit.PostgresDSN, cfg.Budget.RequestsPerWindow, time.Duration(cfg.Budget.WindowSeconds)*time.Second, logger)
		if err != nil {
			logger.Error("failed to initialize postgres budget limiter", "error", err)
			os.Exit(1)
		}
		for tenantName, tenantCfg := range cfg.Budget.Tenants {
			pl.SetTenantLimit(tenantName, tenantCfg.RequestsPerWindow, time.Duration(tenantCfg.WindowSeconds)*time.Second)
		}
		for toolName, toolCfg := range cfg.Budget.Tools {
			pl.SetToolLimit(toolName, toolCfg.RequestsPerWindow, time.Duration(toolCfg.WindowSeconds)*time.Second)
		}
		limiter = pl
		budgetLimiterCloser = pl
		logger.Info("budget enforcement backed by postgres (shared across replicas)")
	} else {
		il := budgetadapter.NewInMemoryLimiter(cfg.Budget.RequestsPerWindow, time.Duration(cfg.Budget.WindowSeconds)*time.Second)
		for tenantName, tenantCfg := range cfg.Budget.Tenants {
			il.SetTenantLimit(tenantName, tenantCfg.RequestsPerWindow, time.Duration(tenantCfg.WindowSeconds)*time.Second)
		}
		for toolName, toolCfg := range cfg.Budget.Tools {
			il.SetToolLimit(toolName, toolCfg.RequestsPerWindow, time.Duration(toolCfg.WindowSeconds)*time.Second)
		}
		limiter = il
		// Only warn when the feature is actually on -- a disabled feature
		// is silent in this codebase, and the "budget is not being
		// enforced" Info log above already covers the off case.
		if budgetEnforcementEnabled {
			logger.Warn("budget enforcement is in-process only; safe for exactly one replica -- enable features.postgres_storage to share across replicas")
		}
	}
	budgetChecker := budgetusecase.NewChecker(featureFlags, limiter)
	budgetReload := newBudgetReloadFn(limiter, *configPath, cfg.Budget.Tenants, cfg.Budget.Tools)

	tracingProvider, err := buildTracingProvider(logger, featureFlags, cfg.Tracing)
	if err != nil {
		logger.Error("failed to initialize tracing", "error", err)
		os.Exit(1)
	}

	credentialIssuanceEnabled := featureFlags.Enabled("credential_issuance")
	var identityAuth proxyadapter.IdentityAuthenticator = proxyadapter.HeaderIdentity{}

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
	scimEnabled := featureFlags.Enabled("scim")
	var rbacChecker *rbacusecase.Checker
	// rbacAuthorizer is kept as a named reference to the file-loaded
	// *StaticAuthorizer (rather than only assigning straight into
	// rbacChecker) so the scim block below can rewrap it in a
	// CompositeAuthorizer without reloading rbac.config_file.
	var rbacAuthorizer *rbacadapter.StaticAuthorizer
	// rbacHolder holds whichever domain.Authorizer rbacChecker currently
	// delegates to (the bare StaticAuthorizer, or -- once the scim block
	// below runs -- a CompositeAuthorizer wrapping it). A hot reload
	// swaps this holder rather than rebuilding rbacChecker, so the SAME
	// Checker instance observes the new authorizer on its very next call.
	var rbacHolder *reload.ReloadableEngine[rbacdomain.Authorizer]
	if rbacEnabled {
		authorizer, err := rbacadapter.LoadAuthorizer(cfg.RBAC.ConfigFile)
		if err != nil {
			logger.Error("failed to load rbac file", "error", err)
			os.Exit(1)
		}
		rbacAuthorizer = authorizer
		var initialAuthorizer rbacdomain.Authorizer = authorizer
		rbacHolder = reload.NewReloadableEngine(&initialAuthorizer)
		rbacChecker = rbacusecase.NewCheckerWithHolder(featureFlags, rbacHolder)
		logger.Info("rbac enabled", "config_file", cfg.RBAC.ConfigFile)
	}

	// scimBindingStore holds either an in-memory *scimusecase.BindingStore
	// or a *scimadapter.PostgresBindingStore, spelled out here as the
	// narrow method set both scimusecase.ProvisioningService.SetBindingStore
	// and rbacusecase.NewCompositeAuthorizer's dynamic source expect --
	// their own bindingSink/dynamicBindingSource types are unexported, so
	// this package can't reference them by name. Named (rather than an
	// inline interface literal) so newRBACReloadFn's signature below can
	// reference the exact same shape.
	var scimBindingStore scimDynamicBindingSource
	var scimHandler http.Handler
	var bindingStoreCloser io.Closer
	if scimEnabled {
		if cfg.Scim.PersistPostgres {
			pbs, err := scimadapter.NewPostgresBindingStore(cfg.Audit.PostgresDSN, logger)
			if err != nil {
				logger.Error("failed to initialize scim postgres binding store", "error", err)
				os.Exit(1)
			}
			scimBindingStore = pbs
			// Registered as a closer so its connection pool is released on
			// exit -- mirrors oidcCloser below (M2).
			bindingStoreCloser = pbs
			logger.Info("scim-provisioned bindings backed by postgres (shared across replicas)")
		} else {
			scimBindingStore = scimusecase.NewBindingStore()
			logger.Warn("scim-provisioned bindings are in-process only; safe for exactly one replica -- enable scim.persist_postgres to share across replicas")
		}
		if rbacEnabled {
			var composite rbacdomain.Authorizer = rbacusecase.NewCompositeAuthorizer(
				rbacAuthorizer,
				scimBindingStore,
				rbacAuthorizer.RoleHasPermission,
			)
			rbacHolder.Swap(&composite)
		}

		// config.Config.validate() only requires scim.bearer_token_env to
		// name a non-empty env var, not that the env var actually resolves
		// to a value at runtime -- scimadapter.NewHandler panics on an
		// empty bearerToken, so that mistake is caught here with a clean
		// log+exit instead of a raw panic.
		scimToken := os.Getenv(cfg.Scim.BearerTokenEnv)
		if scimToken == "" {
			logger.Error("scim bearer token env var is not set or empty", "env", cfg.Scim.BearerTokenEnv)
			os.Exit(1)
		}
		provisioning := scimusecase.NewProvisioningService()
		provisioning.SetBindingStore(scimBindingStore)
		scimHandler = scimadapter.NewHandler(provisioning, provisioning, scimToken, logger)
		logger.Info("scim enabled", "path", "/scim/v2/")
	}

	rbacReload := newRBACReloadFn(rbacHolder, *configPath, rbacEnabled, scimEnabled, scimBindingStore)
	// identityTenantLookup resolves a *target* revoke identity's own
	// tenant. It's a settable closure for the same reason identityAuth is
	// handed to newRevokeAuthorizer by pointer below: the bootstrapper
	// that can actually answer this lookup isn't loaded until the
	// credentialIssuanceEnabled block further down, but newRevokeAuthorizer
	// (and the request it services) run later still, after the
	// reassignment. Defaults to "unknown" so a build with rbac on but
	// credential_issuance off fails the cross-tenant check closed instead
	// of panicking on a nil func.
	identityTenantLookup := func(string) (string, bool) { return "", false }
	// newRevokeAuthorizer is handed a pointer to the identityAuth variable:
	// it's declared above (still HeaderIdentity{} at this point) and only
	// reassigned to bearerIdentity inside the credentialIssuanceEnabled
	// block below, but the returned RevokeAuthorizer is never invoked
	// until a real request arrives, long after that reassignment has
	// already happened -- so dereferencing the pointer at that point
	// always sees identityAuth's final value.
	var revokeAuthorizer credentialadapter.RevokeAuthorizer
	if rbacEnabled {
		revokeAuthorizer = newRevokeAuthorizer(&identityAuth, rbacChecker, func(identity string) (string, bool) { return identityTenantLookup(identity) }, logger)
	}

	var credentialHandler *credentialadapter.Handler
	var revokerCloser io.Closer
	var refreshStoreCloser io.Closer
	var oidcCloser io.Closer
	var mtlsHeader string
	if credentialIssuanceEnabled {
		var bootstrapper credentialdomain.Bootstrapper
		switch cfg.Credential.BootstrapSource {
		case "oidc":
			oidcBootstrapper, err := credentialadapter.NewOIDCBootstrapper(cfg.Credential.OIDC.Issuer, cfg.Credential.OIDC.JWKSURI, cfg.Credential.OIDC.Audience, cfg.Credential.OIDC.IdentityClaim, cfg.Credential.OIDC.TenantClaim)
			if err != nil {
				logger.Error("failed to initialize oidc bootstrapper", "error", err)
				os.Exit(1)
			}
			bootstrapper = oidcBootstrapper
			// Registered as a closer so its JWKS cache's background refresh
			// goroutines are shut down on exit -- see OIDCBootstrapper.Close's
			// doc comment.
			oidcCloser = oidcBootstrapper
			// OIDC has no static identity registry to look up an arbitrary
			// identity's tenant from after the fact -- it only ever learns an
			// identity's tenant at the moment that identity itself
			// authenticates. Fail closed: every revoke of any identity now
			// requires a global ClusterRoleBinding grant. Known limitation,
			// documented in Task 25's docs update rather than solved
			// differently here.
			identityTenantLookup = func(string) (string, bool) { return "", false }
			logger.Info("credential issuance enabled (oidc bootstrap)", "issuer", cfg.Credential.OIDC.Issuer)
		case "mtls":
			mtlsBootstrapper, err := credentialadapter.LoadMTLSBootstrapper(cfg.Credential.IdentitiesFile)
			if err != nil {
				logger.Error("failed to load credentials file", "error", err)
				os.Exit(1)
			}
			bootstrapper = mtlsBootstrapper
			identityTenantLookup = mtlsBootstrapper.TenantOf
			mtlsHeader = cfg.Credential.MTLS.Header
			logger.Info("credential issuance enabled (mtls bootstrap)", "identities_file", cfg.Credential.IdentitiesFile, "header", mtlsHeader)
		default:
			psBootstrapper, err := credentialadapter.LoadBootstrapper(cfg.Credential.IdentitiesFile)
			if err != nil {
				logger.Error("failed to load credentials file", "error", err)
				os.Exit(1)
			}
			bootstrapper = psBootstrapper
			identityTenantLookup = psBootstrapper.TenantOf
			logger.Info("credential issuance enabled", "identities_file", cfg.Credential.IdentitiesFile)
		}
		accessTokenTTL := time.Duration(cfg.Credential.AccessTokenTTLSeconds) * time.Second
		refreshTokenTTL := time.Duration(cfg.Credential.RefreshTokenTTLSeconds) * time.Second
		issuerVerifier, err := credentialadapter.NewJWTIssuerVerifier(cfg.Credential.SigningKeyFile, accessTokenTTL)
		if err != nil {
			logger.Error("failed to initialize credential issuer", "error", err)
			os.Exit(1)
		}
		if cfg.Credential.SigningKeyFile == "" {
			logger.Warn("credential issuance signing key is generated fresh in-process; safe for exactly one replica -- set credential.signing_key_file to run more than one")
		}

		var revoker credentialdomain.Revoker
		var refreshStore credentialdomain.RefreshStore
		if postgresStorageEnabled {
			pr, err := credentialadapter.NewPostgresRevoker(cfg.Audit.PostgresDSN, logger)
			if err != nil {
				logger.Error("failed to initialize postgres revoker", "error", err)
				os.Exit(1)
			}
			revoker = pr
			revokerCloser = pr
			prs, err := credentialadapter.NewPostgresRefreshStore(cfg.Audit.PostgresDSN)
			if err != nil {
				logger.Error("failed to initialize postgres refresh store", "error", err)
				os.Exit(1)
			}
			refreshStore = prs
			refreshStoreCloser = prs
			logger.Info("credential revocation and refresh tokens backed by postgres (shared across replicas)")
		} else {
			revoker = credentialadapter.NewRevocationList()
			refreshStore = credentialadapter.NewInMemoryRefreshStore()
			logger.Warn("credential revocation and refresh tokens are in-process only; safe for exactly one replica -- enable features.postgres_storage to share across replicas")
		}

		issuance := credentialusecase.NewIssuanceService(bootstrapper, issuerVerifier, refreshStore, refreshTokenTTL)
		verification := credentialusecase.NewVerificationService(issuerVerifier, revoker)
		revocation := credentialusecase.NewRevocationService(revoker, refreshStore)
		refresh := credentialusecase.NewRefreshService(refreshStore, revoker, issuerVerifier, refreshTokenTTL, time.Now)
		credentialHandler = credentialadapter.NewHandler(issuance, revocation, refresh, logger, revokeAuthorizer, func(identity string) (string, bool) { return identityTenantLookup(identity) }, mtlsHeader, accessTokenTTL)
		// verification already satisfies proxyadapter.Authenticator directly
		// -- both return (identity, tenant, err) -- so no adapter shim is
		// needed to bridge the two.
		identityAuth = proxyadapter.NewBearerIdentity(verification)
	}

	// Declared as the interface type and left at its zero value (a true
	// nil interface) unless blockChecker is a guaranteed-non-nil
	// *BlockChecker -- same typed-nil avoidance as anomalySource/
	// federationSource below, and the liveSink switch above.
	var autoBlockChecker proxyadapter.AutoBlockChecker
	if blockChecker != nil {
		autoBlockChecker = blockChecker
	}
	// mtlsHeader is "" unless bootstrap_source is mtls; when set, the proxy
	// strips it before forwarding so the untrusted upstream never learns
	// the string that mints Wardline bearer tokens.
	handler := proxyadapter.NewHandler(decider, recorder, cfg.UpstreamURL, budgetChecker, tracingProvider.Tracer(), identityAuth, logger, autoBlockChecker, mtlsHeader)

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

		// scopeResolver derives each dashboard request's tenant filter from
		// the RBAC-resolved caller identity only -- never from anything the
		// request itself carries. nil (rbac off) keeps every view unfiltered,
		// identical to pre-Task-23 behavior. identityAuth is captured by
		// value here (not by pointer, unlike newRevokeAuthorizer's use of it)
		// because this closure and RequirePermission's own use of identityAuth
		// just below are both built after every reassignment of that variable
		// earlier in runServe (see bearer-identity wiring above) has already
		// happened -- there is no later reassignment for it to miss.
		var scopeResolver dashboardadapter.TenantScopeResolver
		if rbacEnabled {
			scopeResolver = newScopeResolver(identityAuth, rbacChecker)
		}

		// unblockAuthorizer gates DELETE /dashboard/api/anomalies/blocked/{identity}
		// separately from the read-only dashboard:view permission the rest
		// of the dashboard route relies on: an unblock is a mutation that
		// undoes an automated enforcement decision, so it requires
		// credential:revoke -- the closest existing permission tier for
		// "an admin may override a security decision" -- rather than
		// dashboard:view. Extracted to newUnblockAuthorizer (mirroring
		// newScopeResolver just above, and newRevokeAuthorizer below) so the
		// permission wiring is directly unit-testable rather than only
		// reachable through runServe's full wiring.
		var unblockAuthorizer dashboardadapter.UnblockAuthorizer
		if rbacEnabled {
			unblockAuthorizer = newUnblockAuthorizer(identityAuth, rbacChecker)
		}

		// reloadCoordinator dispatches POST /dashboard/api/reload/{domain} to
		// the Task 2/3/4 hot-reload closures built earlier in runServe
		// (policyReload, rbacReload, budgetReload -- see their own
		// declarations above). OnAudit is a stub for now: Task 6 fills it in
		// (log + buffer, not the audit/domain.Entry stream).
		reloadCoordinator := &reload.ReloadCoordinator{
			Reloaders: map[string]func() error{
				"policy": policyReload,
				"rbac":   rbacReload,
				"budget": budgetReload,
			},
			OnAudit: func(reload.ReloadResult) {},
		}

		// reloadAuth gates POST /dashboard/api/reload/{domain} the same way
		// unblockAuthorizer just above gates DELETE
		// /dashboard/api/anomalies/blocked/{identity} -- via an injected
		// Authorizer requiring a specific permission (config:edit here,
		// credential:revoke there), never via a second top-level
		// rbacadapter.RequirePermission wrap around the whole /dashboard/
		// tree (that would only ever let dashboard:view gate it). nil when
		// rbac is off, matching unblockAuthorizer's own nil posture: this
		// mutation is unavailable entirely without rbac, not merely ungated.
		var reloadAuth dashboardadapter.ReloadAuthorizer
		if rbacEnabled {
			reloadAuth = newReloadAuthorizer(identityAuth, rbacChecker)
		}

		var dashboardRoute http.Handler = dashboardadapter.NewHandler(ringBuffer, statusProvider, policyInfo, dashboardadapter.Assets(), anomalySource, federationSource, blockedSource, scopeResolver, unblockAuthorizer, reloadCoordinator, reloadAuth)
		if rbacEnabled {
			dashboardRoute = rbacadapter.RequirePermission(rbacChecker, identityAuth, rbacdomain.PermissionDashboardView, dashboardRoute, logger)
		}
		extraRoutes["/dashboard/"] = dashboardRoute
		logger.Info("dashboard enabled", "path", "/dashboard/")
	}
	// Registered unconditionally, unlike /dashboard/ above -- mirrors
	// handleAnomalies/handleFederationCorrelated/handleBlocked's nil-source
	// pattern in dashboard/adapter/handler.go: the route always exists, but
	// returns a clean 404 when credential_issuance is off, instead of an
	// unregistered path falling through to the "/" catch-all proxy handler
	// (same bug class /favicon.ico had -- see below). credentialHandler is
	// nil here when the flag is off; taking its methods as values is safe
	// since credentialsRouteOrNotFound never invokes them in that case.
	//
	// Trade-off worth naming: this also means a disabled /credentials/*
	// permanently shadows those exact paths from ever reaching the proxy,
	// even for an upstream that happens to expose a path with that literal
	// name -- a spurious audit-log entry from silently swallowing the
	// request would be worse than a 404 for that vanishingly rare case, so
	// this is the correct trade-off, just written down explicitly (M9).
	extraRoutes["/credentials/token"] = credentialsRouteOrNotFound(credentialIssuanceEnabled, credentialHandler.HandleToken)
	extraRoutes["/credentials/revoke"] = credentialsRouteOrNotFound(credentialIssuanceEnabled, credentialHandler.HandleRevoke)
	extraRoutes["/credentials/refresh"] = credentialsRouteOrNotFound(credentialIssuanceEnabled, credentialHandler.HandleRefresh)
	// Unconditional on web_ui, unlike the dashboard route above -- a peer
	// must be able to reach this even when the local dashboard UI is off,
	// matching /credentials/token's unconditional-when-flag-on pattern.
	// Registered even when federation is off (routeOrNotFound never invokes
	// the nil federationSummariesHandler in that case) so a partially-rolled-
	// out federation cluster's peers stop generating a spurious audit-log
	// "error" entry per POST instead of a clean 404 -- same bug class as
	// /favicon.ico and /credentials/*, and the same shadowing trade-off as
	// /credentials/* above (M9): an upstream that happens to expose its own
	// /federation/summaries path is now permanently shadowed too.
	extraRoutes["/federation/summaries"] = routeOrNotFound(federationEnabled, federationSummariesHandler)
	// No rbacadapter.RequirePermission wrapping here, unlike /dashboard/ --
	// SCIM authenticates its own bearer token inside Handler.ServeHTTP, an
	// independent trust boundary matching /federation/summaries' own
	// message-level auth rather than RBAC. Registered unconditionally for
	// the same reason /federation/summaries is above: an IdP already
	// provisioned against /scim/v2/* on a poll cadence would otherwise write
	// a spurious audit-log "error" entry forever whenever scim is off; same
	// M9 shadowing trade-off applies.
	extraRoutes["/scim/v2/"] = routeOrNotFound(scimEnabled, scimHandler)
	// Unconditional, unlike every other extraRoutes entry -- every
	// deployment needs health/readiness checking, it isn't a feature an
	// operator opts into with a flag.
	extraRoutes["/healthz"] = healthHandler
	extraRoutes["/readyz"] = healthHandler
	// Also unconditional, and deliberately independent of webUIEnabled:
	// browsers request GET /favicon.ico from the origin root automatically
	// on every page load, dashboard or not. Without a route registered
	// here it falls through to the "/" catch-all proxy handler, which has
	// no method/body guard and audits the unparseable request as an
	// "error" decision -- a stray entry that shows up in a fresh
	// dashboard's audit log/KPI tiles before any real MCP traffic exists.
	// Serving it from a more specific mux pattern than "/" (see
	// buildTopHandler) satisfies the browser before it ever reaches the
	// proxy, for every deployment, dashboard enabled or not.
	extraRoutes["/favicon.ico"] = faviconHandler(logger)
	// Same bug class and same unconditional-registration fix as
	// /favicon.ico just above, for the rest of the top-level paths a
	// browser or crawler routinely requests unprompted: none of these are
	// ever a legitimate MCP JSON-RPC call under any feature-flag
	// combination, so each gets a bare 404 rather than falling through to
	// the proxy catch-all and polluting the audit log. Unlike favicon,
	// there's no real content to serve for any of these -- the fix is
	// keeping them off the proxy/audit-log, not adding new product
	// surface, so noiseRouteHandler is a shared no-op 404.
	for _, path := range []string{
		"/robots.txt",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
		"/.well-known/appspecific/com.chrome.devtools.json",
		"/sitemap.xml",
	} {
		extraRoutes[path] = http.HandlerFunc(noiseRouteHandler)
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
			if revokerCloser != nil {
				if err := revokerCloser.Close(); err != nil {
					logger.Error("revoker shutdown failed", "error", err)
				}
			}
			if refreshStoreCloser != nil {
				if err := refreshStoreCloser.Close(); err != nil {
					logger.Error("refresh store shutdown failed", "error", err)
				}
			}
			if budgetLimiterCloser != nil {
				if err := budgetLimiterCloser.Close(); err != nil {
					logger.Error("budget limiter shutdown failed", "error", err)
				}
			}
			if anomalyBaselineStoreCloser != nil {
				if err := anomalyBaselineStoreCloser.Close(); err != nil {
					logger.Error("anomaly baseline store shutdown failed", "error", err)
				}
			}
			if oidcCloser != nil {
				if err := oidcCloser.Close(); err != nil {
					logger.Error("oidc bootstrapper shutdown failed", "error", err)
				}
			}
			if bindingStoreCloser != nil {
				if err := bindingStoreCloser.Close(); err != nil {
					logger.Error("scim binding store shutdown failed", "error", err)
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
	if refreshStoreCloser != nil {
		if err := refreshStoreCloser.Close(); err != nil {
			logger.Error("refresh store shutdown failed", "error", err)
		}
	}
	if budgetLimiterCloser != nil {
		if err := budgetLimiterCloser.Close(); err != nil {
			logger.Error("budget limiter shutdown failed", "error", err)
		}
	}
	if anomalyBaselineStoreCloser != nil {
		if err := anomalyBaselineStoreCloser.Close(); err != nil {
			logger.Error("anomaly baseline store shutdown failed", "error", err)
		}
	}
	if oidcCloser != nil {
		if err := oidcCloser.Close(); err != nil {
			logger.Error("oidc bootstrapper shutdown failed", "error", err)
		}
	}
	if bindingStoreCloser != nil {
		if err := bindingStoreCloser.Close(); err != nil {
			logger.Error("scim binding store shutdown failed", "error", err)
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

// unblockAuthorizerFunc adapts a plain function to
// dashboardadapter.UnblockAuthorizer, mirroring revokeAuthorizerFunc's
// exact pattern immediately above -- the closure built in runServe
// doesn't need its own named type there either.
type unblockAuthorizerFunc func(r *http.Request, targetTenant string) bool

func (f unblockAuthorizerFunc) AllowedFor(r *http.Request, targetTenant string) bool {
	return f(r, targetTenant)
}

// reloadAuthorizerFunc adapts a plain function to
// dashboardadapter.ReloadAuthorizer, mirroring unblockAuthorizerFunc's
// exact pattern immediately above.
type reloadAuthorizerFunc func(r *http.Request) (identity string, ok bool)

func (f reloadAuthorizerFunc) Authorize(r *http.Request) (string, bool) { return f(r) }

// tenantScopeResolverFunc adapts a plain function to
// dashboardadapter.TenantScopeResolver, matching revokeAuthorizerFunc's
// pattern immediately above -- the scopeResolver closure built in
// runServe doesn't need its own named type there either.
type tenantScopeResolverFunc func(r *http.Request) string

func (f tenantScopeResolverFunc) TenantFilter(r *http.Request) string { return f(r) }

// dashboardFailClosedTenantFilter is returned when the dashboard's
// tenant-scope resolver hits an authentication error -- verified
// unreachable in production (RequirePermission already rejects an
// auth failure before this closure runs), but a security filter's
// error path must fail closed, not silently fall back to "" (which
// means unfiltered/see-everything). Contains \x00, which cannot appear
// in a tenant name sourced from a JWT claim, SCIM UserName, or config
// value -- so it can never accidentally match a real tenant's data,
// meaning every tenant-filtered view returns zero entries instead.
const dashboardFailClosedTenantFilter = "\x00unresolved"

// newScopeResolver builds the dashboardadapter.TenantScopeResolver wired
// into the dashboard route when rbac is on -- extracted out of runServe's
// inline closure (mirroring newRevokeAuthorizer just below) so the
// fail-closed-on-auth-error behavior can be unit-tested in isolation.
func newScopeResolver(identityAuth proxyadapter.IdentityAuthenticator, checker *rbacusecase.Checker) dashboardadapter.TenantScopeResolver {
	return tenantScopeResolverFunc(func(r *http.Request) string {
		who, callerTenant, err := identityAuth.Authenticate(r)
		if err != nil {
			return dashboardFailClosedTenantFilter // fail closed, not unfiltered -- see const's doc comment
		}
		if checker.IsGlobal(who, rbacdomain.PermissionDashboardView) {
			return ""
		}
		return callerTenant
	})
}

// newUnblockAuthorizer builds the dashboardadapter.UnblockAuthorizer wired
// into DELETE /dashboard/api/anomalies/blocked/{identity} when rbac is on:
// a caller is allowed through only if identity resolves and the resolved
// identity holds credential:revoke -- the closest existing permission
// tier for "an admin may override a security decision" (an unblock undoes
// an automated enforcement decision, so it is gated separately from the
// read-only dashboard:view permission the rest of the dashboard route
// relies on). Mirrors newRevokeAuthorizer's cross-tenant reasoning
// exactly, including the escape hatch: cross-tenant authority for THIS
// mutation must come from credential:revoke's own IsGlobal, never from
// dashboard:view's (the final-review C1 bug -- an earlier version of this
// function delegated the cross-tenant decision to h.tenantFilter, which
// is derived from a global grant of the READ-ONLY dashboard:view
// permission; a caller with global dashboard:view plus only
// tenant-scoped credential:revoke could then name and clear an arbitrary
// other tenant's block despite having zero revoke authority there).
// identityAuth is captured by value (not by pointer), matching
// newScopeResolver just above rather than newRevokeAuthorizer just below,
// since this closure is likewise built after every reassignment of
// identityAuth earlier in runServe has already happened.
func newUnblockAuthorizer(identityAuth proxyadapter.IdentityAuthenticator, checker *rbacusecase.Checker) dashboardadapter.UnblockAuthorizer {
	return unblockAuthorizerFunc(func(r *http.Request, targetTenant string) bool {
		who, callerTenant, err := identityAuth.Authenticate(r)
		if err != nil {
			return false
		}
		if !checker.Check(who, callerTenant, rbacdomain.PermissionCredentialRevoke) {
			return false
		}
		// Cross-tenant authority must come from THIS permission (the one
		// this mutation actually exercises), never from dashboard:view.
		return targetTenant == "" || targetTenant == callerTenant || checker.IsGlobal(who, rbacdomain.PermissionCredentialRevoke)
	})
}

// newReloadAuthorizer builds the dashboardadapter.ReloadAuthorizer wired
// into POST /dashboard/api/reload/{domain} when rbac is on: a caller is
// allowed through only if identity resolves and the resolved identity
// holds config:edit -- the new, stricter permission tier for hot-reload
// mutations (see rbacdomain.PermissionConfigEdit's doc comment), gated
// separately from the read-only dashboard:view permission the rest of
// the dashboard route relies on. Reload is not tenant-scoped (policy/
// rbac/budget config applies cluster-wide, there is no per-tenant reload
// target to check cross-tenant authority against), so this mirrors
// newUnblockAuthorizer's identity-resolution/permission-check shape but
// has no cross-tenant escape-hatch check to make. Returns the resolved
// identity on success so ReloadResult.AppliedBy can carry it into the
// audit trail.
func newReloadAuthorizer(identityAuth proxyadapter.IdentityAuthenticator, checker *rbacusecase.Checker) dashboardadapter.ReloadAuthorizer {
	return reloadAuthorizerFunc(func(r *http.Request) (string, bool) {
		who, callerTenant, err := identityAuth.Authenticate(r)
		if err != nil {
			return "", false
		}
		if !checker.Check(who, callerTenant, rbacdomain.PermissionConfigEdit) {
			return "", false
		}
		return who, true
	})
}

// newRevokeAuthorizer builds the RevokeAuthorizer wired into
// /credentials/revoke when rbac is on: a non-loopback caller is allowed
// through only if identity resolves, the resolved identity holds
// credential:revoke, and -- unless that grant is global
// (rbacdomain.Authorizer.IsGlobal, a ClusterRoleBinding) -- the caller's
// own tenant matches the tenant of the identity being revoked. identityAuth
// is a pointer so the returned RevokeAuthorizer -- not invoked until a real
// request arrives, well after runServe finishes wiring -- always sees
// identityAuth's final value even though it's built before
// credential_issuance's later reassignment of that variable (see the
// comment at this function's call site in runServe). identityTenant looks
// up the *target* identity's tenant (from the loaded credential
// Bootstrapper's registered identities, once it's loaded -- same
// call-site-ordering reasoning as identityAuth above); ok is false for an
// identity identityTenant doesn't recognize, which fails the check closed.
func newRevokeAuthorizer(identityAuth *proxyadapter.IdentityAuthenticator, checker *rbacusecase.Checker, identityTenant func(identity string) (tenant string, ok bool), logger *slog.Logger) credentialadapter.RevokeAuthorizer {
	return revokeAuthorizerFunc(func(r *http.Request) bool {
		who, callerTenant, err := (*identityAuth).Authenticate(r)
		if err != nil {
			logger.Warn("rbac revoke authorization: identity resolution failed", "remote_addr", r.RemoteAddr)
			return false
		}
		if !checker.Check(who, callerTenant, rbacdomain.PermissionCredentialRevoke) {
			return false
		}
		if checker.IsGlobal(who, rbacdomain.PermissionCredentialRevoke) {
			return true
		}
		targetIdentity, err := targetIdentityFromRequest(r)
		if err != nil {
			logger.Warn("rbac revoke authorization: could not determine target identity for tenant check", "remote_addr", r.RemoteAddr)
			return false
		}
		targetTenant, ok := identityTenant(targetIdentity)
		return ok && targetTenant == callerTenant
	})
}

// maxRevokeAuthorizerPeekBytes bounds targetIdentityFromRequest's read of
// the not-yet-decoded revoke request body -- same 64 KiB headroom as
// credentialadapter's own maxTokenRequestBodyBytes for a
// {"identity":"..."} body, kept as a separate constant since that one is
// unexported from this package.
const maxRevokeAuthorizerPeekBytes = 64 << 10

// targetIdentityFromRequest reads r.Body far enough to learn the
// "identity" field of a revoke request, then replaces r.Body with a fresh
// reader over the same bytes -- http.Request.Body is a single-read
// stream, and HandleRevoke (internal/features/credential/adapter/http_handler.go)
// still needs to decode this same body itself after Allowed returns, so
// this must never leave it drained. Same reset pattern already used in
// proxy/adapter/handler.go's ServeHTTP for the identical problem.
func targetIdentityFromRequest(r *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRevokeAuthorizerPeekBytes))
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var req struct {
		Identity string `json:"identity"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Identity == "" {
		return "", fmt.Errorf("no identity in request body")
	}
	return req.Identity, nil
}

// faviconHandler serves favicon.ico out of the dashboard's own embedded
// asset tree (dashboardadapter.Assets(), the same //go:embed web/dist
// already used for style.css/app.js/fonts) regardless of whether web_ui
// is on -- the dashboard package and its embed are always compiled in,
// the flag only gates whether /dashboard/ itself is routed. Read once at
// startup and served from memory rather than through http.FileServer:
// the content type is set explicitly instead of relying on the host's
// mime.types having an .ico entry (Go's stdlib mime table doesn't
// register one by default), which a minimal container image may lack.
func faviconHandler(logger *slog.Logger) http.Handler {
	data, err := fs.ReadFile(dashboardadapter.Assets(), "favicon.ico")
	if err != nil {
		// Embedded at compile time (internal/features/dashboard/adapter/web/dist/favicon.ico)
		// -- a missing file here is a build-time problem, not a runtime one.
		logger.Error("failed to read embedded favicon", "error", err)
		os.Exit(1)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
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

// routeOrNotFound returns h unchanged when enabled, otherwise a handler that
// responds with a clean 404 -- so a route stays registered on the mux
// (never reaching the "/" proxy catch-all, and never writing an audit-log
// entry) whether or not its owning feature flag is on, matching
// dashboard's handleAnomalies-style nil-source-returns-404 convention
// instead of that package's real MCP JSON-RPC error shape leaking out on
// an unregistered path. Shared by /credentials/* (via
// credentialsRouteOrNotFound below), /federation/summaries, and
// /scim/v2/ -- three different feature flags hitting the identical bug
// class and fix (I1). enabled is checked before h is touched at all, so a
// nil h (the disabled-flag zero value every caller here passes) is never
// dereferenced.
func routeOrNotFound(enabled bool, h http.Handler) http.Handler {
	if enabled {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
}

// credentialsRouteOrNotFound is routeOrNotFound specialized to
// http.HandlerFunc for /credentials/*'s call sites, which each pass a
// Handler *method value* (e.g. credentialHandler.HandleToken) rather than
// an http.Handler.
func credentialsRouteOrNotFound(enabled bool, fn http.HandlerFunc) http.HandlerFunc {
	return routeOrNotFound(enabled, fn).ServeHTTP
}

// noiseRouteHandler answers well-known browser/crawler request paths
// (robots.txt, apple-touch-icon*, the Chrome DevTools well-known probe,
// sitemap.xml) that will never be a legitimate MCP JSON-RPC call under any
// feature-flag combination. There's no real content to serve for any of
// them -- unlike faviconHandler above, this is a bare 404, not an embedded
// asset (I1).
func noiseRouteHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

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

// newPolicyReloadFn builds the policy hot-reload closure: it re-reads the
// config file at configPath and re-runs loadPolicyEngine -- the exact same
// construction path runServe used at startup -- against whatever
// policy_file/policy_backend that config currently names. It only calls
// policyHolder.Swap when construction fully succeeds: a config-load,
// parse, or validation error is returned to the caller and Swap is never
// reached, so the previously-loaded engine keeps enforcing every request
// completely untouched. This closure is what a later task registers with
// the ReloadCoordinator under reloaders["policy"].
func newPolicyReloadFn(policyHolder *reload.ReloadableEngine[policydomain.Engine], configPath string) func() error {
	return func() error {
		newCfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("reload policy: %w", err)
		}
		newEngine, err := loadPolicyEngine(newCfg.PolicyBackend, newCfg.PolicyFile)
		if err != nil {
			return fmt.Errorf("reload policy: %w", err)
		}
		policyHolder.Swap(&newEngine)
		return nil
	}
}

// scimDynamicBindingSource is the narrow method set both
// scimusecase.ProvisioningService.SetBindingStore and
// rbacusecase.NewCompositeAuthorizer's dynamic source expect -- named so
// runServe's scimBindingStore variable and newRBACReloadFn's parameter
// below share the exact same type instead of two separately-spelled
// interface literals.
type scimDynamicBindingSource interface {
	SetGroupMembers(groupName string, memberUserNames []string)
	RemoveGroup(groupName string)
	Bindings(identity string) ([]rbacdomain.ClusterRoleBinding, []rbacdomain.RoleBinding)
}

// newRBACReloadFn builds the RBAC hot-reload closure: it re-reads the
// config file at configPath and re-runs rbacadapter.LoadAuthorizer --
// the exact same construction path runServe used at startup -- against
// whatever rbac.config_file that config currently names.
//
// Critical: this reloads ONLY the static, YAML-sourced half of the
// authorizer. When scim was enabled at startup, the freshly loaded
// StaticAuthorizer is re-wrapped in a NEW CompositeAuthorizer around the
// SAME scimBindingStore instance already running -- scimBindingStore
// holds live role-binding state mutated by real SCIM provisioning calls
// and is never itself reconstructed or reset here. Reloading RBAC must
// never discard a live SCIM-provisioned binding.
//
// It only calls rbacHolder.Swap when construction fully succeeds: a
// config-load, parse, or validation error is returned to the caller and
// Swap is never reached, so the previously-loaded authorizer (and its
// SCIM composition, if any) keeps enforcing every request completely
// untouched. This closure is what a later task registers with the
// ReloadCoordinator under reloaders["rbac"].
//
// When rbac itself is disabled (rbacEnabled false), rbacHolder is nil
// and there is nothing to reload -- the returned closure is a no-op that
// always succeeds.
func newRBACReloadFn(rbacHolder *reload.ReloadableEngine[rbacdomain.Authorizer], configPath string, rbacEnabled, scimEnabled bool, scimBindingStore scimDynamicBindingSource) func() error {
	if !rbacEnabled {
		return func() error { return nil }
	}
	return func() error {
		newCfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("reload rbac: %w", err)
		}
		newStaticAuthorizer, err := rbacadapter.LoadAuthorizer(newCfg.RBAC.ConfigFile)
		if err != nil {
			return fmt.Errorf("reload rbac: %w", err)
		}
		var newAuthorizer rbacdomain.Authorizer = newStaticAuthorizer
		if scimEnabled {
			// CRITICAL: reuse the SAME scimBindingStore already running --
			// do NOT reconstruct it, that would discard every live
			// SCIM-provisioned binding.
			newAuthorizer = rbacusecase.NewCompositeAuthorizer(
				newStaticAuthorizer,
				scimBindingStore,
				newStaticAuthorizer.RoleHasPermission,
			)
		}
		rbacHolder.Swap(&newAuthorizer)
		return nil
	}
}

// newBudgetReloadFn builds the budget hot-reload closure. Unlike
// newPolicyReloadFn/newRBACReloadFn, it never constructs a new Limiter or
// calls any ReloadableEngine.Swap -- InMemoryLimiter and PostgresLimiter
// both hold live, in-flight per-identity/tenant/tool request counters, and
// swapping the whole instance would silently reset every currently-tracked
// counter to zero, letting a caller briefly burst past their real limit at
// the exact moment a reload happens. Instead this re-reads the config file
// at configPath and updates the SAME running limiter's thresholds in
// place via SetDefaultLimit/SetTenantLimit/SetToolLimit.
//
// initialTenants/initialTools seed the closure's own before/after diff
// (config.BudgetConfig is Budget.Tenants/Budget.Tools's real map value
// type) with the config the process actually started with, so the very
// first reload can already tell whether an override was removed.
// SetTenantLimit/SetToolLimit alone can only add or update an override,
// never remove one -- a tenant/tool present in the PREVIOUS config but
// absent from the new one is explicitly cleared via
// ClearTenantLimit/ClearToolLimit so a removed override doesn't survive as
// a stale leftover forever. config.Load's own validate() already rejects
// a negative/zero RequestsPerWindow/WindowSeconds before this closure ever
// runs, so no extra defense-in-depth check is needed here.
func newBudgetReloadFn(limiter budgetdomain.Limiter, configPath string, initialTenants, initialTools map[string]config.BudgetConfig) func() error {
	previousBudgetTenants := initialTenants
	previousBudgetTools := initialTools
	return func() error {
		newCfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("reload budget: %w", err)
		}
		limiter.SetDefaultLimit(newCfg.Budget.RequestsPerWindow, time.Duration(newCfg.Budget.WindowSeconds)*time.Second)

		// Clear overrides present in the OLD config but absent from the
		// new one, so a removed override doesn't survive as a stale
		// leftover.
		for tenantName := range previousBudgetTenants {
			if _, stillPresent := newCfg.Budget.Tenants[tenantName]; !stillPresent {
				limiter.ClearTenantLimit(tenantName)
			}
		}
		for tenantName, tenantCfg := range newCfg.Budget.Tenants {
			limiter.SetTenantLimit(tenantName, tenantCfg.RequestsPerWindow, time.Duration(tenantCfg.WindowSeconds)*time.Second)
		}
		for toolName := range previousBudgetTools {
			if _, stillPresent := newCfg.Budget.Tools[toolName]; !stillPresent {
				limiter.ClearToolLimit(toolName)
			}
		}
		for toolName, toolCfg := range newCfg.Budget.Tools {
			limiter.SetToolLimit(toolName, toolCfg.RequestsPerWindow, time.Duration(toolCfg.WindowSeconds)*time.Second)
		}

		previousBudgetTenants = newCfg.Budget.Tenants // update tracking for the NEXT reload's diff
		previousBudgetTools = newCfg.Budget.Tools
		return nil
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
	if flags.NewStaticProvider(cfg.Features).Enabled("scim") {
		// Attempts the same handler construction runServe does, minus
		// scim.persist_postgres -- validate-config must have no network
		// side effects, matching postgres_storage not being probed here
		// either. This still catches the real, common misconfiguration:
		// scim.bearer_token_env naming an env var that isn't actually set.
		scimToken := os.Getenv(cfg.Scim.BearerTokenEnv)
		if scimToken == "" {
			logger.Error("scim bearer token env var is not set or empty", "env", cfg.Scim.BearerTokenEnv)
			os.Exit(1)
		}
		provisioning := scimusecase.NewProvisioningService()
		provisioning.SetBindingStore(scimusecase.NewBindingStore())
		_ = scimadapter.NewHandler(provisioning, provisioning, scimToken, logger)
	}
	if flags.NewStaticProvider(cfg.Features).Enabled("credential_issuance") && cfg.Credential.SigningKeyFile != "" {
		if _, err := credentialadapter.NewJWTIssuerVerifier(cfg.Credential.SigningKeyFile, time.Duration(cfg.Credential.AccessTokenTTLSeconds)*time.Second); err != nil {
			logger.Error("failed to load credential signing key file", "error", err)
			os.Exit(1)
		}
	}
	if flags.NewStaticProvider(cfg.Features).Enabled("credential_issuance") && cfg.Credential.BootstrapSource == "oidc" {
		// Soft warning, not os.Exit(1): the IdP's JWKS endpoint may be
		// transiently unreachable from wherever validate-config runs (e.g. a
		// CI pipeline outside the IdP's network) without the rest of the
		// oidc config block being wrong -- see design doc "CLI".
		oidcBootstrapper, err := credentialadapter.NewOIDCBootstrapper(cfg.Credential.OIDC.Issuer, cfg.Credential.OIDC.JWKSURI, cfg.Credential.OIDC.Audience, cfg.Credential.OIDC.IdentityClaim, cfg.Credential.OIDC.TenantClaim)
		if err != nil {
			logger.Warn("failed to initialize oidc bootstrapper (jwks endpoint may be unreachable); not treated as a hard failure", "error", err)
		} else if err := oidcBootstrapper.Close(); err != nil {
			logger.Warn("failed to shut down oidc bootstrapper after validation", "error", err)
		}
	}
	if flags.NewStaticProvider(cfg.Features).Enabled("credential_issuance") && cfg.Credential.BootstrapSource == "mtls" {
		// Unlike the oidc block above, this is a local file read with no
		// network call to fail softly on -- either the credentials file
		// parses or it's a real config error, so this is a hard exit like
		// the credential.identities_file emptiness check already is.
		if _, err := credentialadapter.LoadMTLSBootstrapper(cfg.Credential.IdentitiesFile); err != nil {
			logger.Error("failed to load credentials file", "error", err)
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

	auditReader, jsonlReader, err := newAuditReader(logger, featureFlags, cfg.Audit, "export-evidence")
	if err != nil {
		logger.Error("failed to set up audit reader", "error", err)
		os.Exit(1)
	}
	if closer, ok := auditReader.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
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
// random suffix (logged as a warning, never fatal) if that fails.
// Shared by two independent callers -- federation (labeling this
// instance's summaries to peers and the local Correlator) and the
// anomaly baseline store (scoping Postgres rows to this replica, see
// I1 in the anomaly-baseline-dashboard final review) -- so a
// missing/unstable hostname must never block startup, and the random
// suffix has a caller-specific consequence: for the baseline store, a
// fresh random ID on every restart means every restart's baselines
// start from empty and the previous run's rows become permanently
// orphaned in anomaly_baselines (never re-adopted, never deleted).
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
	// Deliberately caller-agnostic -- this helper backs both federation
	// and anomaly-baseline persistence, so naming either one here would
	// misdirect debugging for the other (the exact wrong-subsystem
	// problem M1 fixed for checkpoint-save errors elsewhere in this
	// cycle).
	logger.Warn("failed to determine hostname for instance ID derivation; using a random suffix instead", "instance_id", instanceID)
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
