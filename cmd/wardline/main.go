package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wardline <serve|validate-policy> [flags]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "validate-policy":
		runValidatePolicy(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "wardline.yaml", "path to config file")
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	matcher, err := policyadapter.LoadFile(cfg.PolicyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	writer := buildAuditWriter(cfg.Audit.Output)
	recorder := auditusecase.NewRecorder(writer, func(err error) {
		fmt.Fprintf(os.Stderr, "audit write failed: %v\n", err)
	})

	decider := proxyusecase.NewDecider(matcher)

	handler := proxyadapter.NewHandler(decider, recorder, cfg.UpstreamURL)

	// No v0.1 feature reads flags yet; log what the operator has toggled on
	// so the provider isn't wired in and then silently ignored.
	featureFlags := flags.NewStaticProvider(cfg.Features)
	for name := range cfg.Features {
		if featureFlags.Enabled(name) {
			fmt.Fprintf(os.Stderr, "wardline: feature %q enabled\n", name)
		}
	}

	fmt.Fprintf(os.Stderr, "wardline listening on %s, proxying to %s\n", cfg.Listen, cfg.Upstream)
	if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runValidatePolicy(args []string) {
	fs := flag.NewFlagSet("validate-policy", flag.ExitOnError)
	path := fs.String("file", "policy.yaml", "path to policy file")
	_ = fs.Parse(args) // flag.ExitOnError exits the process on parse failure

	if _, err := policyadapter.LoadFile(*path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("policy file is valid")
}

func buildAuditWriter(output string) *auditadapter.JSONLWriter {
	if output == "stdout" {
		return auditadapter.NewJSONLWriter(os.Stdout)
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return auditadapter.NewJSONLWriter(f)
}
