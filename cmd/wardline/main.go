package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
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

	handler := proxyadapter.NewHandler(decider, recorder, cfg.UpstreamURL, budgetChecker)

	// Log what the operator has toggled on so a flag isn't silently ignored.
	for name := range cfg.Features {
		if featureFlags.Enabled(name) {
			logger.Info("feature enabled", "feature", name)
		}
	}

	logger.Info("wardline listening", "addr", cfg.Listen, "upstream", cfg.Upstream)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
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
