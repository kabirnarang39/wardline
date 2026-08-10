package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"

	anomalyadapter "github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	approvaladapter "github.com/kabirnarang39/wardline/internal/features/approval/adapter"
	approvaldomain "github.com/kabirnarang39/wardline/internal/features/approval/domain"
	approvalusecase "github.com/kabirnarang39/wardline/internal/features/approval/usecase"
	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetadapter "github.com/kabirnarang39/wardline/internal/features/budget/adapter"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	budgetusecase "github.com/kabirnarang39/wardline/internal/features/budget/usecase"
	complianceadapter "github.com/kabirnarang39/wardline/internal/features/compliance/adapter"
	compliancedomain "github.com/kabirnarang39/wardline/internal/features/compliance/domain"
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
	grpcadapter "github.com/kabirnarang39/wardline/internal/features/grpcproxy/adapter"
	healthadapter "github.com/kabirnarang39/wardline/internal/features/health/adapter"
	jobbudgetadapter "github.com/kabirnarang39/wardline/internal/features/jobbudget/adapter"
	jobbudgetdomain "github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	jobbudgetusecase "github.com/kabirnarang39/wardline/internal/features/jobbudget/usecase"
	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	cedaradapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/cedar"
	opaadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/opa"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxydomain "github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
	rbacadapter "github.com/kabirnarang39/wardline/internal/features/rbac/adapter"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	rbacusecase "github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
	scimadapter "github.com/kabirnarang39/wardline/internal/features/scim/adapter"
	scimusecase "github.com/kabirnarang39/wardline/internal/features/scim/usecase"
	taintadapter "github.com/kabirnarang39/wardline/internal/features/taint/adapter"
	taintdomain "github.com/kabirnarang39/wardline/internal/features/taint/domain"
	taintusecase "github.com/kabirnarang39/wardline/internal/features/taint/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
	platformsession "github.com/kabirnarang39/wardline/internal/platform/session"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
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

	// readinessDrainWindow holds the listener open briefly after /readyz
	// flips to 503 (SetDraining) and before srv.Shutdown starts refusing
	// new connections. Without it the not-ready window is only a few
	// scheduler ticks wide -- unobservable to a polling readiness probe
	// (which is the whole point of the drain: let the orchestrator pull
	// this replica out of rotation before connections start being
	// refused), and the reason the e2e drain test flaked under -race/CI
	// load. Deliberately small: it adds at most this much to shutdown,
	// negligible against the 10s HTTP drain and any orchestrator grace
	// period, but wide enough for a fast poller to reliably catch the 503.
	readinessDrainWindow = 150 * time.Millisecond

	// ringBufferCapacity bounds the dashboard's in-memory live audit view.
	// It's a code constant, not operator-configurable — see
	// docs/superpowers/specs/2026-07-27-web-ui-design.md "Config".
	ringBufferCapacity = 1000
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if len(os.Args) < 2 {
		logger.Error("usage: wardline <serve|validate-policy|validate-config|export-evidence|verify-evidence|generate-signing-key|policy-pack|infer-policy> [flags]")
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
	case "verify-evidence":
		runVerifyEvidence(logger, os.Args[2:])
	case "generate-signing-key":
		runGenerateSigningKey(logger, os.Args[2:])
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
	taintTrackingEnabled := featureFlags.Enabled("taint_tracking")
	approvalWorkflowEnabled := featureFlags.Enabled("approval_workflow")
	jobBudgetEnabled := featureFlags.Enabled("job_budget")

	writer, auditCloser := buildAuditSink(logger, featureFlags, cfg.Audit)

	// retentionStop/scheduledExportStop are independent of
	// anomalyDetectionEnabled -- retention purges the audit log even when
	// anomaly detection is off, and scheduled export needs only the
	// audit trail to be queryable, not anomaly detection.
	retentionStop := maybeStartRetention(logger, featureFlags, cfg, writer)
	scheduledExportStop := maybeStartScheduledExport(logger, featureFlags, cfg)

	var ringBuffer *dashboardusecase.RingBuffer
	if webUIEnabled {
		ringBuffer = dashboardusecase.NewRingBuffer(ringBufferCapacity)
	}

	var anomalyDetector *anomalyusecase.Detector
	var anomalyBuffer *anomalyusecase.AlertBuffer
	var anomalyGCStop chan struct{}
	// blocker is the auto-block surface passed to the detector, proxy, and
	// dashboard -- either the in-memory *BlockChecker (with its own GC
	// ticker) or the Postgres-backed *PostgresBlockStore (shared across HA
	// replicas, self-reaping in SQL). blockStoreCloser drains the Postgres
	// pool on shutdown, nil for the in-memory case.
	var blocker anomalydomain.Blocker
	var blockStoreCloser io.Closer
	var autoBlockGCStop chan struct{}
	var anomalyBaselineStoreCloser io.Closer
	if anomalyDetectionEnabled {
		as := buildAnomalyStack(logger, cfg, postgresStorageEnabled)
		anomalyDetector = as.detector
		anomalyBuffer = as.buffer
		blocker = as.blocker
		anomalyGCStop = as.gcStop
		autoBlockGCStop = as.autoBlockGCStop
		blockStoreCloser = as.blockStoreCloser
		anomalyBaselineStoreCloser = as.baselineCloser
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

	// Build the taint engine before the live-sink assembly: it is both a
	// LiveSink (sets/clears taint from the audit stream) and the source of
	// the decision-time taint lookup. Constructed only when taint_tracking is
	// on, so the whole slice stays out of the wiring otherwise.
	var taintEngine *taintusecase.Engine
	var taintLookup proxyusecase.TaintLookup
	if taintTrackingEnabled {
		taintCfg := taintdomain.TaintConfig{
			UntrustedSources:     cfg.Taint.UntrustedSources,
			DeclassifySources:    cfg.Taint.DeclassifySources,
			TTLSeconds:           cfg.Taint.TTLSeconds,
			SessionWindowSeconds: cfg.Taint.SessionWindowSeconds,
			SessionHeader:        cfg.Taint.SessionHeader,
		}
		taintEngine = taintusecase.NewEngine(taintCfg, taintadapter.NewInMemoryStore(), time.Now)
		window := taintCfg.Window()
		taintLookup = func(call proxydomain.ToolCall) bool {
			// An explicit X-Wardline-Session header wins (matching Publish's
			// set-side preference); absent one, the TTL-window bucket derived
			// from wall-clock time is the fallback session boundary.
			session := platformsession.SessionID(call.SessionID, call.Tenant, call.Identity, call.Timestamp, window)
			return taintEngine.Current(call.Tenant, call.Identity, session, call.Timestamp).Tainted
		}
		logger.Info("taint tracking enabled", "untrusted_sources", cfg.Taint.UntrustedSources, "ttl_seconds", taintCfg.TTL())
	}

	// Gated on postgres_storage the same way budget/taint select their
	// backend: a shared Postgres meter when replicas need to agree on one
	// job's count, an in-process map otherwise.
	var jobBudgetChecker *jobbudgetusecase.Checker
	// jobBudgetMeter is hoisted out of the if-block below (rather than
	// declared local to it, like jobBudgetCfg) so the dashboard wiring
	// further down can type-assert it onto jobbudgetdomain.Lister -- the
	// Checker itself keeps its meter private, so this is the only handle
	// to the concrete adapter the dashboard can reach.
	var jobBudgetMeter jobbudgetdomain.Meter
	if jobBudgetEnabled {
		jobBudgetCfg := jobbudgetdomain.Config{RequestsPerJob: cfg.JobBudget.RequestsPerJob}
		if postgresStorageEnabled {
			pm, err := jobbudgetadapter.NewPostgresMeter(cfg.Audit.PostgresDSN, logger)
			if err != nil {
				logger.Error("failed to initialize postgres job-budget meter", "error", err)
				os.Exit(1)
			}
			jobBudgetMeter = pm
			logger.Info("job budget backed by postgres (shared across replicas)")
		} else {
			jobBudgetMeter = jobbudgetadapter.NewInMemoryMeter()
		}
		jobBudgetChecker = jobbudgetusecase.NewChecker(featureFlags, jobBudgetMeter, jobBudgetCfg)
		logger.Info("job budget enabled", "requests_per_job", jobBudgetCfg.Limit())
	}

	// jobBudgetLookup is the non-incrementing peek (IsOverBudget) that feeds
	// policy's input.job_over_budget -- never Check, which increments and is
	// reserved for the handler's hard gate (Task 8) as the only caller.
	var jobBudgetLookup proxyusecase.JobBudgetLookup
	if jobBudgetChecker != nil {
		jobBudgetLookup = func(call proxydomain.ToolCall) bool {
			return jobBudgetChecker.IsOverBudget(call.Tenant, call.Identity, call.SessionID, call.Timestamp)
		}
	}

	// Append only constructed sinks: each is built inside its own flag block,
	// so a disabled feature contributes nothing and no typed-nil ever reaches
	// MultiSink (a nil *RingBuffer/*Detector/*Engine in a LiveSink slot is a
	// typed nil MultiSink's nil check cannot see, and would panic on the first
	// request). An empty MultiSink is a valid no-op sink.
	sinks := auditadapter.MultiSink{}
	if webUIEnabled {
		sinks = append(sinks, ringBuffer)
	}
	if anomalyDetectionEnabled {
		sinks = append(sinks, anomalyDetector)
	}
	if taintEngine != nil {
		sinks = append(sinks, taintEngine)
	}
	var liveSink auditdomain.LiveSink = sinks

	recorder := auditusecase.NewRecorder(writer, liveSink, func(err error) {
		logger.Error("audit write failed", "error", err)
	})

	decider := proxyusecase.NewDeciderWithHolderTaintAndJobBudget(policyHolder, taintLookup, jobBudgetLookup)

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
	// The gRPC transport resolves identity from request metadata rather than
	// HTTP headers, so it needs its own resolver -- but backed by the same
	// credential verification service, so both transports authenticate a
	// bearer token identically. Defaults to unauthenticated metadata, mirroring
	// identityAuth's HeaderIdentity default.
	var grpcIdentity grpcadapter.IdentityResolver = grpcadapter.MetadataIdentity{}

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
	var jwksHandler *credentialadapter.JWKSHandler
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
		issuerVerifier, err := credentialadapter.NewJWTIssuerVerifier(cfg.Credential.SigningKeyFile, cfg.Credential.PreviousSigningKeyFiles, accessTokenTTL)
		if err != nil {
			logger.Error("failed to initialize credential issuer", "error", err)
			os.Exit(1)
		}
		if cfg.Credential.SigningKeyFile == "" {
			logger.Warn("credential issuance signing key is generated fresh in-process; safe for exactly one replica -- set credential.signing_key_file to run more than one")
		}
		if len(cfg.Credential.PreviousSigningKeyFiles) > 0 {
			logger.Info("credential signing-key rotation window active", "previous_keys", len(cfg.Credential.PreviousSigningKeyFiles))
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
		jwksHandler = credentialadapter.NewJWKSHandler(issuerVerifier, logger)
		// verification already satisfies proxyadapter.Authenticator directly
		// -- both return (identity, tenant, err) -- so no adapter shim is
		// needed to bridge the two.
		identityAuth = proxyadapter.NewBearerIdentity(verification)
		// verification also satisfies grpcadapter.TokenAuthenticator (same
		// token -> identity/tenant contract), so the gRPC transport shares the
		// exact same bearer verification path.
		grpcIdentity = grpcadapter.NewBearerIdentity(verification)
	}

	// Declared as the interface type and left at its zero value (a true
	// nil interface) unless blocker is non-nil -- same typed-nil avoidance
	// as anomalySource/federationSource below. blocker already IS an
	// interface (in-memory or Postgres-backed), so this is a plain nil
	// check, not the wrap-a-concrete-pointer dance the old code needed.
	var autoBlockChecker proxyadapter.AutoBlockChecker
	if blocker != nil {
		autoBlockChecker = blocker
	}
	// The approval manager is built only when approval_workflow is on; a nil
	// port makes the proxy fail closed on any needs_approval outcome.
	var approvalManager *approvalusecase.Manager
	if approvalWorkflowEnabled {
		grantTTL := time.Duration(approvaldomain.Config{GrantTTLSeconds: cfg.Approval.GrantTTLSeconds}.GrantTTL()) * time.Second
		approvalManager = approvalusecase.NewManager(approvaladapter.NewInMemoryStore(), time.Now, grantTTL, newApprovalID)
		logger.Info("approval workflow enabled", "grant_ttl", grantTTL)
	}

	// The session header is plumbed onto the ToolCall/audit Entry whenever
	// taint, approval, or job_budget is on — all three scope by (tenant,
	// identity, session).
	sessionHeader := ""
	if taintTrackingEnabled || approvalWorkflowEnabled || jobBudgetEnabled {
		sessionHeader = taintdomain.TaintConfig{SessionHeader: cfg.Taint.SessionHeader}.Header()
	}

	// approvalPort is a typed nil unless approval_workflow is on; passing a
	// typed *Manager nil through the ApprovalPort interface would defeat the
	// handler's nil check, so keep it an untyped nil when disabled.
	var approvalPort proxyadapter.ApprovalPort
	if approvalManager != nil {
		approvalPort = approvalManager
	}

	// mtlsHeader is "" unless bootstrap_source is mtls; when set, the proxy
	// strips it before forwarding so the untrusted upstream never learns
	// the string that mints Wardline bearer tokens.
	//
	// jobBudgetPort is a typed nil unless job_budget is on -- passing the
	// concrete *jobbudgetusecase.Checker nil pointer straight through the
	// JobBudgetChecker interface would defeat the handler's nil check (same
	// trap approvalPort/autoBlockChecker above avoid), so keep it an untyped
	// nil when disabled.
	var jobBudgetPort proxyadapter.JobBudgetChecker
	if jobBudgetChecker != nil {
		jobBudgetPort = jobBudgetChecker
	}
	handler := proxyadapter.NewHandlerWithApproval(decider, recorder, cfg.UpstreamURL, budgetChecker, tracingProvider.Tracer(), identityAuth, logger, autoBlockChecker, mtlsHeader, approvalPort, sessionHeader, jobBudgetPort)

	startedAt := time.Now()

	extraRoutes := map[string]http.Handler{}
	if webUIEnabled {
		policyInfo, err := buildPolicyInfo(cfg.PolicyBackend, cfg.PolicyFile)
		if err != nil {
			logger.Error("failed to read policy file for dashboard", "error", err)
			os.Exit(1)
		}
		// policyInfoHolder makes GET /dashboard/api/policy live instead of
		// a snapshot frozen at startup -- the "policy" Reloader registered
		// on reloadCoordinator below (and the Rule editor's own
		// WriteAndReload) both Swap it after a successful reload, so a
		// hot-reloaded or dashboard-edited policy is reflected on the very
		// next GET, not after a process restart.
		policyInfoHolder := reload.NewReloadableEngine(&policyInfo)
		policySource := policySourceFunc(func() dashboarddomain.PolicyInfo { return *policyInfoHolder.Current() })

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
		if blocker != nil {
			blockedSource = blocker
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

		// rbacSource backs GET /dashboard/api/rbac with the same real,
		// already-loaded rbacAuthorizer every other rbac-gated route in
		// this file reads from -- nil (rbac off) makes that route answer
		// 404, the same "not wired" posture as every other optional
		// Source above.
		var rbacSource dashboardadapter.RBACSource
		if rbacEnabled {
			rbacSource = rbacAuthorizer
		}

		// budgetSource backs GET /dashboard/api/budget with the same real,
		// already-constructed limiter budgetChecker reads from -- nil
		// (budget_enforcement off) makes that route answer 404, the same
		// "not wired" posture as every other optional Source above. limiter
		// itself is never nil (an InMemoryLimiter backs it even when the
		// feature is off, harmlessly unused by budgetChecker), so the nil
		// check has to happen here, not by testing limiter directly.
		var budgetSource dashboardadapter.BudgetSource
		if budgetEnforcementEnabled {
			budgetSource = limiter
		}

		// reloadBuffer gives operators visibility into every reload attempt
		// (success or rejection), independent of the audit/domain.Entry
		// stream -- see reload.ReloadEventBuffer's doc comment for why a
		// reload event gets its own purpose-built buffer rather than
		// reusing the general audit log. Capacity: reload events are rare
		// (operator-triggered), 100 is generous headroom, not a tuned
		// figure.
		reloadBuffer := reload.NewReloadEventBuffer(100)

		// reloadCoordinator dispatches POST /dashboard/api/reload/{domain} to
		// the Task 2/3/4 hot-reload closures built earlier in runServe
		// (policyReload, rbacReload, budgetReload -- see their own
		// declarations above). OnAudit logs the outcome (Info on success,
		// Warn on rejection -- a rejected reload is exactly as important to
		// surface as an accepted one) and records it into reloadBuffer for
		// GET /dashboard/api/reload/history.
		reloadCoordinator := &reload.ReloadCoordinator{
			Reloaders: map[string]func() error{
				// Wraps policyReload with a refresh of policyInfoHolder --
				// GET /dashboard/api/policy and the Rule editor must see
				// the new content immediately after ANY successful policy
				// reload, not just ones triggered through WriteAndReload
				// below (an operator editing the file directly on disk and
				// hitting reload some other way must be reflected too).
				"policy": func() error {
					if err := policyReload(); err != nil {
						return err
					}
					info, err := buildPolicyInfo(cfg.PolicyBackend, cfg.PolicyFile)
					if err != nil {
						return fmt.Errorf("refresh policy info after reload: %w", err)
					}
					policyInfoHolder.Swap(&info)
					return nil
				},
				"rbac":   rbacReload,
				"budget": budgetReload,
			},
			OnAudit: func(result reload.ReloadResult) {
				if result.OK {
					logger.Info("config reload applied", "domain", result.Domain, "applied_by", result.AppliedBy)
				} else {
					logger.Warn("config reload rejected", "domain", result.Domain, "applied_by", result.AppliedBy, "error", result.Error)
				}
				reloadBuffer.Add(result)
			},
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

		// callerInfoResolver backs the topbar's identity display (GET
		// /dashboard/api/status's CallerIdentity/CallerCanConfigEdit) --
		// purely a display concern, wired the same "nil when rbac is off"
		// way as every other resolver above; it grants no access itself
		// (reloadAuth/unblockAuthorizer/scopeResolver already own every
		// access decision, independently).
		var callerInfoResolver dashboardadapter.CallerInfoResolver
		if rbacEnabled {
			callerInfoResolver = newCallerInfoResolver(identityAuth, rbacChecker)
		}

		// policyWriter backs the Policy view's structured Rule editor --
		// only meaningful for the yaml backend (opa/cedar have no such
		// structured rule representation to write back); nil for either
		// other backend, matching every other "not wired" nil-source
		// posture in this file. Writing then reuses the exact same
		// "policy" Reloader just registered above (reloadCoordinator.Reload),
		// so a rule-editor save produces the identical Reload log entry a
		// POST /dashboard/api/reload/policy would.
		var policyWriter dashboardadapter.PolicyWriter
		if cfg.PolicyBackend == "yaml" {
			policyWriter = policyWriterFunc(func(rules []policydomain.Rule, def policydomain.Effect, appliedBy string) error {
				if err := policyadapter.WriteFile(cfg.PolicyFile, rules, def); err != nil {
					return err
				}
				result := reloadCoordinator.Reload("policy", appliedBy)
				if !result.OK {
					return fmt.Errorf("%s", result.Error)
				}
				return nil
			})
		}

		// budgetWriter backs the Budget view's editor (PUT
		// /dashboard/api/budget) -- writes the config file's budget:
		// section (see config.WriteBudgetSection, a surgical node-level
		// edit that preserves every other key) then reuses the exact same
		// "budget" Reloader reloadCoordinator already owns, mirroring
		// policyWriter's own write-then-Reload shape exactly. nil when
		// budget_enforcement is off (budgetSource itself is nil then too).
		var budgetWriter dashboardadapter.BudgetWriter
		if budgetEnforcementEnabled {
			budgetWriter = budgetWriterFunc(func(def budgetdomain.LimitInfo, tenantOverrides, toolOverrides []budgetdomain.OverrideInfo, appliedBy string) error {
				tenants := make(map[string]config.BudgetConfig, len(tenantOverrides))
				for _, o := range tenantOverrides {
					tenants[o.Name] = config.BudgetConfig{RequestsPerWindow: o.RequestsPerWindow, WindowSeconds: int(o.Window.Seconds())}
				}
				tools := make(map[string]config.BudgetConfig, len(toolOverrides))
				for _, o := range toolOverrides {
					tools[o.Name] = config.BudgetConfig{RequestsPerWindow: o.RequestsPerWindow, WindowSeconds: int(o.Window.Seconds())}
				}
				budgetCfg := config.BudgetConfig{RequestsPerWindow: def.RequestsPerWindow, WindowSeconds: int(def.Window.Seconds()), Tenants: tenants, Tools: tools}
				if err := config.WriteBudgetSection(*configPath, budgetCfg); err != nil {
					return err
				}
				result := reloadCoordinator.Reload("budget", appliedBy)
				if !result.OK {
					return fmt.Errorf("%s", result.Error)
				}
				return nil
			})
		}

		// complianceSource backs GET /dashboard/api/compliance -- nil
		// (audit trail not queryable, matching export-evidence's own
		// "stdout isn't queryable" gate) leaves the route 404, the same
		// "not wired" posture as every other nil-source route.
		var complianceSource dashboardadapter.ComplianceSource
		if postgresStorageEnabled || (cfg.Audit.Output != "" && cfg.Audit.Output != "stdout") {
			complianceSource = complianceSourceFunc(func(ctx context.Context, from, to time.Time) (compliancedomain.Manifest, error) {
				manifest, _, _, err := queryComplianceManifest(logger, cfg, featureFlags, from, to)
				return manifest, err
			})
		}

		// approvalSource backs the dashboard Approvals view -- only wired
		// when approval_workflow is on (approvalManager non-nil). Kept an
		// interface var so a typed *Manager nil never defeats the handler's
		// nil check, mirroring approvalPort above.
		var approvalSource dashboardadapter.ApprovalSource
		if approvalManager != nil {
			approvalSource = approvalManager
		}

		// jobBudgetSource backs the dashboard job-budget view -- only
		// wired when job_budget is on (jobBudgetMeter non-nil) AND the
		// concrete meter happens to implement the optional
		// jobbudgetdomain.Lister capability (both InMemoryMeter and
		// PostgresMeter do; a future token/cost Meter need not). Kept an
		// interface var so a failed type assertion or a nil meter never
		// defeats the handler's own nil check, mirroring approvalSource
		// above.
		var jobBudgetSource dashboardadapter.JobBudgetSource
		if jobBudgetMeter != nil {
			if lister, ok := jobBudgetMeter.(jobbudgetdomain.Lister); ok {
				jobBudgetSource = lister
			}
		}

		var dashboardRoute http.Handler = dashboardadapter.NewHandler(ringBuffer, statusProvider, policySource, dashboardadapter.Assets(), anomalySource, federationSource, blockedSource, scopeResolver, unblockAuthorizer, rbacSource, budgetSource, reloadCoordinator, reloadAuth, reloadBuffer, callerInfoResolver, policyWriter, budgetWriter, complianceSource, approvalSource, jobBudgetSource)
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
	// jwksHandler is nil when credential_issuance is off; credentialsRouteOrNotFound
	// never invokes it in that case (returns 404), same guard as the routes above.
	extraRoutes["/credentials/jwks"] = credentialsRouteOrNotFound(credentialIssuanceEnabled, jwksHandlerFunc(jwksHandler))
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
	// Operator approval surface (GET /approvals/pending, POST
	// /approvals/{id}/approve|deny), loopback-only (nil authorizer). Only
	// registered when the manager was built, so an unwired approval feature
	// doesn't shadow an upstream that happens to expose /approvals/*.
	if approvalManager != nil {
		extraRoutes["/approvals/"] = approvaladapter.NewHTTPHandler(approvalManager, nil, logger)
	}
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
	favicon := faviconHandler(logger)
	extraRoutes["/favicon.ico"] = favicon
	extraRoutes["/favicon.svg"] = favicon
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

	// Startup security posture: the proxy fails closed on policy, but by
	// default identity is trusted from the X-Wardline-Identity header
	// (spoofable) and the dashboard's read views are unauthenticated. Warn
	// loudly so an operator never mistakes "off by default" for "secure by
	// default" -- see README Hardening. credential_issuance verifies a
	// bearer token instead of trusting the header; rbac gates the dashboard.
	for _, w := range insecureDefaultWarnings(credentialIssuanceEnabled, webUIEnabled, rbacEnabled) {
		logger.Warn(w)
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

	// gRPC transport: a second listener running the same enforcement pipeline
	// (policy/budget/auto-block/audit) as the HTTP proxy, reusing the very same
	// decider/budgetChecker/autoBlockChecker/recorder instances so both
	// transports share one policy engine, one budget, and one audit trail. A
	// fatal Serve error shares the HTTP path's serveErr channel; graceful
	// shutdown GracefulStops it alongside srv.Shutdown below.
	var grpcServer *grpc.Server
	var grpcUpstreamConn *grpc.ClientConn
	if featureFlags.Enabled("grpc_transport") {
		conn, err := grpcadapter.DialUpstream(cfg.GRPCUpstream, cfg.GRPCUpstreamTLS)
		if err != nil {
			logger.Error("gRPC upstream dial failed", "error", err, "upstream", cfg.GRPCUpstream)
			os.Exit(1)
		}
		grpcUpstreamConn = conn
		grpcProxy := grpcadapter.NewProxy(decider, budgetChecker, autoBlockChecker, recorder, grpcIdentity, conn, logger)
		grpcServer = grpc.NewServer(grpcProxy.ServerOptions()...)
		lis, err := net.Listen("tcp", cfg.GRPCListen)
		if err != nil {
			logger.Error("gRPC listen failed", "error", err, "addr", cfg.GRPCListen)
			os.Exit(1)
		}
		go func() {
			logger.Info("wardline gRPC listening", "addr", cfg.GRPCListen, "upstream", cfg.GRPCUpstream)
			if err := grpcServer.Serve(lis); err != nil {
				serveErr <- err
			}
		}()
	}

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
			if blockStoreCloser != nil {
				if err := blockStoreCloser.Close(); err != nil {
					logger.Error("anomaly block store shutdown failed", "error", err)
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
			if retentionStop != nil {
				close(retentionStop)
			}
			if scheduledExportStop != nil {
				close(scheduledExportStop)
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
		// Bounded observable-drain window: /readyz has been 503 since
		// SetDraining above; hold here so a readiness probe reliably sees it
		// before srv.Shutdown closes the listener. See readinessDrainWindow.
		time.Sleep(readinessDrainWindow)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
		if grpcServer != nil {
			grpcServer.GracefulStop()
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
	if retentionStop != nil {
		close(retentionStop)
	}
	if scheduledExportStop != nil {
		close(scheduledExportStop)
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
	if grpcUpstreamConn != nil {
		if err := grpcUpstreamConn.Close(); err != nil {
			logger.Error("gRPC upstream connection shutdown failed", "error", err)
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

// callerInfoResolverFunc adapts a plain function to
// dashboardadapter.CallerInfoResolver, matching tenantScopeResolverFunc's
// pattern immediately above.
type callerInfoResolverFunc func(r *http.Request) (identity string, canConfigEdit bool)

func (f callerInfoResolverFunc) CallerInfo(r *http.Request) (string, bool) { return f(r) }

// policySourceFunc adapts a plain function to dashboardadapter.PolicySource,
// matching callerInfoResolverFunc's pattern immediately above.
type policySourceFunc func() dashboarddomain.PolicyInfo

func (f policySourceFunc) Current() dashboarddomain.PolicyInfo { return f() }

// complianceSourceFunc adapts a plain function to
// dashboardadapter.ComplianceSource, same shape as policySourceFunc.
type complianceSourceFunc func(ctx context.Context, from, to time.Time) (compliancedomain.Manifest, error)

func (f complianceSourceFunc) Query(ctx context.Context, from, to time.Time) (compliancedomain.Manifest, error) {
	return f(ctx, from, to)
}

// policyWriterFunc adapts a plain function to dashboardadapter.PolicyWriter,
// matching policySourceFunc's pattern immediately above.
type policyWriterFunc func(rules []policydomain.Rule, def policydomain.Effect, appliedBy string) error

func (f policyWriterFunc) WriteAndReload(rules []policydomain.Rule, def policydomain.Effect, appliedBy string) error {
	return f(rules, def, appliedBy)
}

// budgetWriterFunc adapts a plain function to dashboardadapter.BudgetWriter,
// matching policyWriterFunc's pattern immediately above.
type budgetWriterFunc func(def budgetdomain.LimitInfo, tenantOverrides, toolOverrides []budgetdomain.OverrideInfo, appliedBy string) error

func (f budgetWriterFunc) WriteAndReload(def budgetdomain.LimitInfo, tenantOverrides, toolOverrides []budgetdomain.OverrideInfo, appliedBy string) error {
	return f(def, tenantOverrides, toolOverrides, appliedBy)
}

// newCallerInfoResolver builds the dashboardadapter.CallerInfoResolver
// wired into the dashboard route's topbar identity display when rbac is
// on -- purely a display concern (see CallerInfoResolver's own doc
// comment): it grants no access itself, only resolves who the topbar
// should name and whether to show the config:edit pill, mirroring
// newReloadAuthorizer's own config:edit check exactly but never denying
// the request over it.
func newCallerInfoResolver(identityAuth proxyadapter.IdentityAuthenticator, checker *rbacusecase.Checker) dashboardadapter.CallerInfoResolver {
	return callerInfoResolverFunc(func(r *http.Request) (string, bool) {
		who, callerTenant, err := identityAuth.Authenticate(r)
		if err != nil || who == "" {
			return "", false
		}
		return who, checker.Check(who, callerTenant, rbacdomain.PermissionConfigEdit)
	})
}

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

// faviconHandler serves the dashboard's SVG favicon out of its own
// embedded asset tree (dashboardadapter.Assets(), the same //go:embed
// web/dist already used for style.css/app.js/fonts) regardless of whether
// web_ui is on -- the dashboard package and its embed are always compiled
// in, the flag only gates whether /dashboard/ itself is routed. The mark
// is the same one the docs site and landing page use. Read once at startup
// and served from memory with an explicit content type. It answers both
// /favicon.svg and the /favicon.ico browsers auto-request from the origin
// root: a modern browser honors the returned image/svg+xml content type
// regardless of the .ico URL, and either way the request is absorbed here
// rather than falling through to the proxy catch-all and polluting the
// audit log.
func faviconHandler(logger *slog.Logger) http.Handler {
	data, err := fs.ReadFile(dashboardadapter.Assets(), "favicon.svg")
	if err != nil {
		// Embedded at compile time (internal/features/dashboard/adapter/web/dist/favicon.svg)
		// -- a missing file here is a build-time problem, not a runtime one.
		logger.Error("failed to read embedded favicon", "error", err)
		os.Exit(1)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
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

// jwksHandlerFunc adapts a possibly-nil *JWKSHandler to an http.HandlerFunc
// -- nil when credential_issuance is off, in which case
// credentialsRouteOrNotFound's enabled=false guard means this func is
// never actually invoked (so the nil deref inside is unreachable), same
// pattern as the credentialHandler method values above.
func jwksHandlerFunc(h *credentialadapter.JWKSHandler) http.HandlerFunc {
	if h == nil {
		return func(w http.ResponseWriter, r *http.Request) { http.Error(w, "not found", http.StatusNotFound) }
	}
	return h.ServeHTTP
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

// insecureDefaultWarnings returns the startup security warnings implied by
// the current flag posture: a spoofable trusted-header identity when
// credential_issuance is off, and an unauthenticated dashboard when the web
// UI is on without rbac. Pure and flag-only so the branch is testable
// without standing up a server.
func insecureDefaultWarnings(credentialIssuance, webUI, rbac bool) []string {
	var warnings []string
	if !credentialIssuance {
		warnings = append(warnings, "insecure default: identity is trusted from the X-Wardline-Identity header and is spoofable; enable credential_issuance to verify a bearer token")
	}
	if webUI && !rbac {
		warnings = append(warnings, "insecure default: dashboard read views are unauthenticated; enable rbac to gate dashboard access")
	}
	return warnings
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

// newApprovalID returns an unguessable approval-request id: 16 crypto/rand
// bytes hex-encoded. The id is the only handle an operator has to approve a
// specific pending request, so it must not be predictable. A crypto/rand read
// failing means broken system entropy — panic rather than mint a weak id.
func newApprovalID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand read failed generating approval id: %v", err))
	}
	return hex.EncodeToString(buf)
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
// buildPolicyInfo reads path and returns the dashboard's live PolicyInfo
// snapshot for it -- Rules/Default populated only for the yaml backend
// (via policyadapter.ParseRules, the real parser, never a hand-rolled
// duplicate), left zero-valued for opa/cedar where no such structured
// representation exists. A yaml parse failure here is NOT fatal the way
// engine construction failure is: this is a display-only convenience
// for the Rule editor, and a yaml file that fails ParseRules (should be
// unreachable in practice, since WriteFile validates before ever
// persisting, and loadPolicyEngine already validated whatever's on disk
// at startup/reload) degrades to "Source only, no structured Rules"
// rather than blocking the dashboard route from mounting at all.
func buildPolicyInfo(backend, path string) (dashboarddomain.PolicyInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return dashboarddomain.PolicyInfo{}, err
	}
	info := dashboarddomain.PolicyInfo{Backend: backend, Source: string(data)}
	if backend == "yaml" {
		if rules, def, parseErr := policyadapter.ParseRules(data); parseErr == nil {
			info.Rules = make([]dashboarddomain.PolicyRuleEntry, len(rules))
			for i, r := range rules {
				info.Rules[i] = dashboarddomain.PolicyRuleEntry{Identity: r.Identity, Tool: r.Tool, Tenant: r.Tenant, Effect: string(r.Effect), Method: r.Method}
			}
			info.Default = string(def)
		}
	}
	return info, nil
}

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
	if flags.NewStaticProvider(cfg.Features).Enabled("credential_issuance") && (cfg.Credential.SigningKeyFile != "" || len(cfg.Credential.PreviousSigningKeyFiles) > 0) {
		// NewJWTIssuerVerifier loads and parses both the primary signing
		// key and every previous (verification-only) rotation key, so this
		// one construction validates the whole set -- fail loud before
		// serve, matching every other optional file-based config check.
		if _, err := credentialadapter.NewJWTIssuerVerifier(cfg.Credential.SigningKeyFile, cfg.Credential.PreviousSigningKeyFiles, time.Duration(cfg.Credential.AccessTokenTTLSeconds)*time.Second); err != nil {
			logger.Error("failed to load credential signing key file(s)", "error", err)
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
	signKeyPath := fs.String("sign-key", "", "path to a PEM-encoded RSA private key (PKCS1 or PKCS8) to sign the bundle with, optional")
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

	var signingKey *rsa.PrivateKey
	if *signKeyPath != "" {
		signingKey, err = loadSigningKey(*signKeyPath)
		if err != nil {
			logger.Error("failed to load signing key", "error", err)
			os.Exit(1)
		}
	}

	output := *outputPath
	if output == "" {
		sanitize := func(s string) string { return strings.ReplaceAll(s, ":", "-") }
		output = fmt.Sprintf("./evidence-%s-%s.tar.gz", sanitize(from.Format(time.RFC3339)), sanitize(to.Format(time.RFC3339)))
	}

	auditCount, anomalyCount, err := buildAndWriteEvidenceBundle(logger, cfg, featureFlags, from, to, output, signingKey)
	if err != nil {
		logger.Error("failed to write evidence bundle", "error", err)
		os.Exit(1)
	}

	logger.Info("wrote evidence bundle", "output", output, "audit_entries", auditCount, "anomalies", anomalyCount, "signed", signingKey != nil)
}

// loadSigningKey reads and parses a PEM-encoded RSA private key from
// path -- shared by export-evidence's -sign-key flag and the scheduled
// export job (both need the exact same "read file, parse PEM" step).
func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}
	key, err := complianceadapter.ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse signing key %s: %w", path, err)
	}
	return key, nil
}

// redactedIdentitiesYAML is the minimal subset of credentials.yaml's
// shape this reads -- deliberately omitting "secret"/"spiffe_id" so
// those values are never even unmarshaled into memory on this codepath,
// not just omitted from the bundle afterward.
type redactedIdentitiesYAML struct {
	Identities []struct {
		Name   string `yaml:"name"`
		Tenant string `yaml:"tenant"`
	} `yaml:"identities"`
}

// readRedactedIdentities reads path (the same file
// credential.identities_file points at) and returns each entry's Name
// and Tenant only -- see compliancedomain.RedactedIdentity's doc comment
// for why Secret/SpiffeID must never reach a compliance bundle.
func readRedactedIdentities(path string) ([]compliancedomain.RedactedIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identities file %s: %w", path, err)
	}
	var raw redactedIdentitiesYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse identities file %s: %w", path, err)
	}
	out := make([]compliancedomain.RedactedIdentity, len(raw.Identities))
	for i, e := range raw.Identities {
		t := e.Tenant
		if t == "" {
			t = tenant.Default
		}
		out[i] = compliancedomain.RedactedIdentity{Name: e.Name, Tenant: t}
	}
	return out, nil
}

// buildAndWriteEvidenceBundle assembles and atomically writes a
// compliance evidence bundle covering [from, to) to outputPath --
// shared by runExportEvidence (the CLI path) and the scheduled export
// background job, one implementation for both callers. signingKey is
// optional (nil skips signing, matching WriteBundle's own nil
// convention).
// queryComplianceManifest runs the exact query+aggregate logic
// export-evidence's CLI path and the scheduled export job both need --
// factored out so GET /dashboard/api/compliance's live query can reuse
// it too (three callers, one implementation), returning the raw
// audit/anomaly entries alongside the built Manifest since
// buildAndWriteEvidenceBundle's caller still needs those for
// WriteBundle, while the dashboard querier only needs the Manifest.
func queryComplianceManifest(logger *slog.Logger, cfg *config.Config, featureFlags flags.Provider, from, to time.Time) (compliancedomain.Manifest, []auditdomain.Entry, []anomalydomain.Anomaly, error) {
	auditReader, jsonlReader, err := newAuditReader(logger, featureFlags, cfg.Audit, "export-evidence")
	if err != nil {
		return compliancedomain.Manifest{}, nil, nil, fmt.Errorf("set up audit reader: %w", err)
	}
	if closer, ok := auditReader.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}

	ctx := context.Background()
	auditEntries, err := auditReader.Query(ctx, from, to)
	if err != nil {
		return compliancedomain.Manifest{}, nil, nil, fmt.Errorf("query audit entries: %w", err)
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
			return compliancedomain.Manifest{}, nil, nil, fmt.Errorf("query anomaly entries: %w", err)
		default:
			skippedAnomalyLines = anomalyReader.SkippedLines
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
	return manifest, auditEntries, anomalies, nil
}

func buildAndWriteEvidenceBundle(logger *slog.Logger, cfg *config.Config, featureFlags flags.Provider, from, to time.Time, outputPath string, signingKey *rsa.PrivateKey) (auditCount, anomalyCount int, err error) {
	manifest, auditEntries, anomalies, err := queryComplianceManifest(logger, cfg, featureFlags, from, to)
	if err != nil {
		return 0, 0, err
	}

	var policySource []byte
	if cfg.PolicyFile != "" {
		policySource, err = os.ReadFile(cfg.PolicyFile)
		if err != nil {
			return 0, 0, fmt.Errorf("read policy file: %w", err)
		}
	}

	var rbacSource []byte
	if featureFlags.Enabled("rbac") && cfg.RBAC.ConfigFile != "" {
		rbacSource, err = os.ReadFile(cfg.RBAC.ConfigFile)
		if err != nil {
			return 0, 0, fmt.Errorf("read rbac file: %w", err)
		}
	}

	var identities []compliancedomain.RedactedIdentity
	if featureFlags.Enabled("credential_issuance") && cfg.Credential.IdentitiesFile != "" {
		identities, err = readRedactedIdentities(cfg.Credential.IdentitiesFile)
		if err != nil {
			return 0, 0, fmt.Errorf("read identities: %w", err)
		}
	}

	dir := filepath.Dir(outputPath)
	tmp, err := os.CreateTemp(dir, ".evidence-*.tar.gz.tmp")
	if err != nil {
		return 0, 0, fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	// 0600, not the temp file's default: the bundle aggregates the whole
	// audit trail (whose own file wardline opens 0600), the rbac
	// bindings, and the policy source into one artifact, so a
	// world-readable default would widen access to evidence on any
	// shared host.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return 0, 0, fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := complianceadapter.WriteBundle(tmp, manifest, auditEntries, anomalies, policySource, cfg.PolicyBackend, rbacSource, identities, signingKey); err != nil {
		_ = tmp.Close()
		return 0, 0, fmt.Errorf("write evidence bundle: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, 0, fmt.Errorf("close output file: %w", err)
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return 0, 0, fmt.Errorf("finalize output file: %w", err)
	}
	cleanup = false
	return len(auditEntries), len(anomalies), nil
}

// runGenerateSigningKey writes a fresh 2048-bit RSA keypair (PKCS8
// private / PKIX public, PEM-encoded) to -private-key/-public-key --
// the shape export-evidence -sign-key and verify-evidence -public-key
// both expect. An operator who already has a compliant key (e.g. from
// their org's PKI) never needs this command; it exists purely so a
// first-time user isn't required to reach for openssl.
func runGenerateSigningKey(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("generate-signing-key", flag.ExitOnError)
	privateKeyPath := fs.String("private-key", "signing-key.pem", "output path for the PEM-encoded RSA private key")
	publicKeyPath := fs.String("public-key", "signing-key.pub.pem", "output path for the PEM-encoded RSA public key")
	_ = fs.Parse(args)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Error("failed to generate key", "error", err)
		os.Exit(1)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		logger.Error("failed to marshal private key", "error", err)
		os.Exit(1)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	// 0600: a signing private key is the whole trust basis for evidence
	// bundle authenticity -- a world-readable default would defeat the
	// point before the file is even used once.
	if err := os.WriteFile(*privateKeyPath, privPEM, 0o600); err != nil {
		logger.Error("failed to write private key", "path", *privateKeyPath, "error", err)
		os.Exit(1)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		logger.Error("failed to marshal public key", "error", err)
		os.Exit(1)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(*publicKeyPath, pubPEM, 0o644); err != nil {
		logger.Error("failed to write public key", "path", *publicKeyPath, "error", err)
		os.Exit(1)
	}

	logger.Info("generated signing key", "private_key", *privateKeyPath, "public_key", *publicKeyPath)
}

// runVerifyEvidence re-verifies an evidence bundle's checksums.txt
// against every other file it lists (the integrity guarantee every
// bundle already carries, signed or not) and, when -public-key is
// given, additionally verifies checksums.txt.sig against that key (the
// authenticity guarantee only a signed bundle carries). Exits 1 on any
// failure -- unlike sha256sum -c, this also has an opinion about
// authenticity, not just integrity.
func runVerifyEvidence(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("verify-evidence", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "path to the evidence bundle (.tar.gz), required")
	publicKeyPath := fs.String("public-key", "", "path to a PEM-encoded RSA public key to verify the signature against, optional")
	_ = fs.Parse(args)

	if *bundlePath == "" {
		logger.Error("-bundle is required")
		os.Exit(1)
	}

	files, err := complianceadapter.ReadBundle(*bundlePath)
	if err != nil {
		logger.Error("failed to read bundle", "error", err)
		os.Exit(1)
	}

	checksums, ok := files["checksums.txt"]
	if !ok {
		logger.Error("bundle has no checksums.txt -- not a valid evidence bundle")
		os.Exit(1)
	}
	mismatches, err := complianceadapter.VerifyChecksums(checksums, files)
	if err != nil {
		logger.Error("failed to parse checksums.txt", "error", err)
		os.Exit(1)
	}
	if len(mismatches) > 0 {
		for _, m := range mismatches {
			logger.Error("checksum mismatch", "file", m)
		}
		os.Exit(1)
	}
	unexpected, err := complianceadapter.UnexpectedFiles(checksums, files)
	if err != nil {
		logger.Error("failed to parse checksums.txt", "error", err)
		os.Exit(1)
	}
	if len(unexpected) > 0 {
		for _, name := range unexpected {
			logger.Error("unexpected file in bundle -- not covered by checksums.txt", "file", name)
		}
		os.Exit(1)
	}
	logger.Info("checksums verified", "files", len(files)-1)

	if *publicKeyPath == "" {
		logger.Info("no -public-key given; skipping signature verification (integrity-only check passed)")
		return
	}

	sig, ok := files["checksums.txt.sig"]
	if !ok {
		logger.Error("-public-key given but bundle is not signed (no checksums.txt.sig) -- nothing to verify")
		os.Exit(1)
	}
	pubPEM, err := os.ReadFile(*publicKeyPath)
	if err != nil {
		logger.Error("failed to read public key", "error", err)
		os.Exit(1)
	}
	pubKey, err := complianceadapter.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		logger.Error("failed to parse public key", "error", err)
		os.Exit(1)
	}
	if !complianceadapter.Verify(checksums, sig, pubKey) {
		logger.Error("signature verification FAILED -- bundle was not signed by the holder of this public key, or has been tampered with since signing")
		os.Exit(1)
	}
	logger.Info("signature verified: bundle authenticity confirmed")
}

// maybeStartRetention starts the background log-retention purge job when
// the log_retention flag is on and there is at least one purgeable sink,
// returning its stop channel (nil when retention is off or there's nothing
// to purge, so the caller's shutdown nil-checks it like before).
func maybeStartRetention(logger *slog.Logger, featureFlags flags.Provider, cfg *config.Config, writer auditdomain.Writer) chan struct{} {
	if !featureFlags.Enabled("log_retention") {
		return nil
	}
	var purgers []complianceusecase.NamedPurger
	if p := buildAuditPurger(featureFlags, cfg.Audit, writer); p != nil {
		purgers = append(purgers, complianceusecase.NamedPurger{Name: "audit", RetentionDays: cfg.Audit.RetentionDays, Purge: p.Purge})
	}
	if p := buildAnomalyPurger(cfg.Anomaly); p != nil {
		purgers = append(purgers, complianceusecase.NamedPurger{Name: "anomaly", RetentionDays: cfg.Anomaly.RetentionDays, Purge: p.Purge})
	}
	if len(purgers) == 0 {
		return nil
	}
	interval := time.Duration(cfg.Retention.CheckIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	stop := make(chan struct{})
	go startRetentionJob(logger, purgers, interval, stop)
	logger.Info("log retention enabled", "check_interval", interval, "purgers", len(purgers))
	return stop
}

// maybeStartScheduledExport starts the periodic compliance-evidence export
// job when the compliance_scheduled_export flag is on, returning its stop
// channel (nil when the flag is off). Fatal on signing-key load or output
// directory creation failure — the same fail-fast behavior the inline
// composition-root code had.
func maybeStartScheduledExport(logger *slog.Logger, featureFlags flags.Provider, cfg *config.Config) chan struct{} {
	if !featureFlags.Enabled("compliance_scheduled_export") {
		return nil
	}
	var signingKey *rsa.PrivateKey
	if cfg.Compliance.SigningKeyFile != "" {
		var err error
		signingKey, err = loadSigningKey(cfg.Compliance.SigningKeyFile)
		if err != nil {
			logger.Error("failed to load compliance scheduled-export signing key", "error", err)
			os.Exit(1)
		}
	}
	// 0700: the output directory holds evidence bundles (already
	// individually 0600), so the directory itself must not be
	// world-traversable either.
	if err := os.MkdirAll(cfg.Compliance.ScheduledExportOutputDir, 0o700); err != nil {
		logger.Error("failed to create scheduled export output directory", "path", cfg.Compliance.ScheduledExportOutputDir, "error", err)
		os.Exit(1)
	}
	interval := time.Duration(cfg.Compliance.ScheduledExportIntervalSeconds) * time.Second
	stop := make(chan struct{})
	go startScheduledExportJob(logger, cfg, featureFlags, interval, signingKey, stop)
	logger.Info("compliance scheduled export enabled", "interval", interval, "output_dir", cfg.Compliance.ScheduledExportOutputDir, "signed", signingKey != nil)
	return stop
}

// anomalyStack is the set of anomaly-detection components buildAnomalyStack
// wires up, handed back to the composition root as one value. Fields are
// nil when their sub-feature is off (no auto-block, no postgres), which the
// caller's later wiring and shutdown already nil-check exactly as before.
type anomalyStack struct {
	detector         *anomalyusecase.Detector
	buffer           *anomalyusecase.AlertBuffer
	blocker          anomalydomain.Blocker
	gcStop           chan struct{}
	autoBlockGCStop  chan struct{}
	blockStoreCloser io.Closer
	baselineCloser   io.Closer
}

// buildAnomalyStack constructs the detector, alert buffer, auto-block
// surface, baseline store, and their GC tickers/closers from config. Fatal
// (os.Exit) on any store-open failure — the same fail-fast the inline
// composition-root code had. Call only when the anomaly_detection flag is on.
func buildAnomalyStack(logger *slog.Logger, cfg *config.Config, postgresStorageEnabled bool) anomalyStack {
	var s anomalyStack

	anomalyWriter, err := buildAnomalyWriter(cfg.Anomaly.Output)
	if err != nil {
		logger.Error("failed to open anomaly output file", "path", cfg.Anomaly.Output, "error", err)
		os.Exit(1)
	}
	bufferCapacity := cfg.Anomaly.BufferCapacity
	if bufferCapacity <= 0 {
		bufferCapacity = ringBufferCapacity
	}
	s.buffer = anomalyusecase.NewAlertBuffer(bufferCapacity)
	heuristicCfg := anomalyHeuristicConfig(cfg.Anomaly)

	// Always positive: config.validate() defaults gc_interval_seconds
	// when anomaly_detection is on. A second fallback here is what let an
	// omitted gc_interval_seconds bypass the auto_block/GC-interval
	// cross-validation, which runs before this line ever does.
	gcInterval := time.Duration(cfg.Anomaly.GCIntervalSeconds) * time.Second

	if cfg.Anomaly.AutoBlock.Enabled {
		blockDuration := time.Duration(cfg.Anomaly.AutoBlock.BlockDurationSeconds) * time.Second
		if postgresStorageEnabled {
			// Shared across HA replicas: a block written by one replica
			// is visible to every replica on its next Check. Self-reaps
			// expired rows in SQL, so no separate GC ticker is started
			// (the in-memory StartBlockGC below is only for the map).
			pbs, err := anomalyadapter.NewPostgresBlockStore(cfg.Audit.PostgresDSN, blockDuration, logger)
			if err != nil {
				logger.Error("failed to initialize postgres block store", "error", err)
				os.Exit(1)
			}
			s.blocker = pbs
			s.blockStoreCloser = pbs
			logger.Info("auto-block enabled (shared via postgres)", "block_duration_seconds", cfg.Anomaly.AutoBlock.BlockDurationSeconds)
		} else {
			bc := anomalyusecase.NewBlockChecker(heuristicCfg.AutoBlock, time.Now)
			s.blocker = bc
			// auto_block has no gc_interval_seconds field of its own (see
			// config.AutoBlockConfig) -- it's a sub-feature of anomaly
			// detection, so its GC just reuses the same gcInterval already
			// derived above for the detector's own per-identity state GC
			// rather than inventing a second, independently-tunable knob
			// for what's a tiny in-memory map.
			s.autoBlockGCStop = make(chan struct{})
			go anomalyusecase.StartBlockGC(bc, gcInterval, s.autoBlockGCStop)
			logger.Info("auto-block enabled (per-replica, in-memory -- enable postgres_storage to share across replicas)", "block_duration_seconds", cfg.Anomaly.AutoBlock.BlockDurationSeconds)
		}
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
		s.baselineCloser = bs
		logger.Info("anomaly baseline persistence backed by postgres (survives restarts)")
	} else {
		logger.Warn("anomaly baselines are in-process only; a restart resets every identity's history -- enable features.postgres_storage to persist across restarts")
	}

	// blocker is an interface-typed field (anomalydomain.Blocker),
	// nil-when-unset rather than a possibly-nil concrete pointer, so it
	// can be passed straight into NewDetector's blocker parameter
	// without the typed-nil hazard the old 4-arm switch existed to
	// dodge: assigning a nil *BlockChecker into an interface produces a
	// non-nil interface wrapping a nil pointer, but an unassigned
	// anomalydomain.Blocker is a genuine nil interface Detector's own
	// guard sees correctly. baselineStore is still a concrete pointer
	// (its adapter type isn't behind a shared interface), so it keeps its
	// explicit nil branch.
	if baselineStore != nil {
		s.detector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, s.buffer, s.blocker, onAnomalyWriteErr, time.Now, baselineStore)
	} else {
		s.detector = anomalyusecase.NewDetector(heuristicCfg, anomalyWriter, s.buffer, s.blocker, onAnomalyWriteErr, time.Now, nil)
	}

	if err := s.detector.LoadBaselines(); err != nil {
		logger.Error("failed to load persisted anomaly baselines", "error", err)
		os.Exit(1)
	}

	s.gcStop = make(chan struct{})
	go anomalyusecase.StartGC(s.detector, gcInterval, s.gcStop)
	logger.Info("anomaly detection enabled", "output", cfg.Anomaly.Output)
	return s
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
// buildAuditPurger returns the audit/domain.Purger matching whichever
// backend buildAuditSink actually built -- postgres_storage reuses the
// already-open *PostgresWriter (writer, cast back) rather than opening a
// second connection pool; the JSONL case builds a fresh, stateless
// JSONLPurger from the same Output path. Returns nil when there's
// nothing to purge (stdout, or Output unset) -- callers must nil-check
// before adding it to the retention job's purger list.
func buildAuditPurger(featureFlags flags.Provider, cfg config.AuditConfig, writer auditdomain.Writer) auditdomain.Purger {
	if featureFlags.Enabled("postgres_storage") {
		if pw, ok := writer.(*auditadapter.PostgresWriter); ok {
			return pw
		}
		return nil
	}
	if cfg.Output == "" || cfg.Output == "stdout" {
		return nil
	}
	return auditadapter.NewJSONLPurger(cfg.Output)
}

// buildAnomalyPurger is buildAuditPurger's anomaly-log counterpart.
// Unlike audit, there is no Postgres-backed anomaly LOG (only
// PostgresBaselineStore, which persists behavioral baselines -- a
// distinct concept with its own existing GC, not this retention job's
// concern) -- so this only ever builds a JSONLPurger, or nil.
func buildAnomalyPurger(cfg config.AnomalyConfig) anomalydomain.Purger {
	if cfg.Output == "" || cfg.Output == "stdout" {
		return nil
	}
	return anomalyadapter.NewJSONLPurger(cfg.Output)
}

// startRetentionJob runs RunRetention on a ticker until stop is closed --
// mirrors anomalyusecase.StartGC's exact ticker-until-stop-channel shape.
// A failing purger is logged and does not stop the job; the next tick
// tries again.
func startRetentionJob(logger *slog.Logger, purgers []complianceusecase.NamedPurger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			for _, r := range complianceusecase.RunRetention(context.Background(), purgers, now) {
				if r.Err != nil {
					logger.Error("log retention purge failed", "store", r.Name, "cutoff", r.Cutoff, "error", r.Err)
					continue
				}
				logger.Info("log retention purge completed", "store", r.Name, "cutoff", r.Cutoff, "deleted", r.Deleted)
			}
		}
	}
}

// startScheduledExportJob runs a compliance evidence export on a ticker
// until stop is closed, reusing buildAndWriteEvidenceBundle -- the exact
// same code path export-evidence's CLI handler calls, so scheduled and
// manual exports can never drift apart. lastTick's range is retried (not
// advanced) on a failed export, so a transient failure never creates a
// permanent gap in scheduled coverage -- see
// docs/superpowers/specs/2026-08-08-compliance-evidence-export-hardening-design.md
// "Data flow".
func startScheduledExportJob(logger *slog.Logger, cfg *config.Config, featureFlags flags.Provider, interval time.Duration, signingKey *rsa.PrivateKey, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastTick := time.Now()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			from, to := lastTick, now
			sanitize := func(s string) string { return strings.ReplaceAll(s, ":", "-") }
			output := filepath.Join(cfg.Compliance.ScheduledExportOutputDir,
				fmt.Sprintf("evidence-%s-%s.tar.gz", sanitize(from.UTC().Format(time.RFC3339)), sanitize(to.UTC().Format(time.RFC3339))))
			auditCount, anomalyCount, err := buildAndWriteEvidenceBundle(logger, cfg, featureFlags, from, to, output, signingKey)
			if err != nil {
				logger.Error("scheduled compliance export failed", "error", err, "from", from, "to", to)
				continue
			}
			lastTick = now
			logger.Info("scheduled compliance export completed", "output", output, "audit_entries", auditCount, "anomalies", anomalyCount)
		}
	}
}

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
