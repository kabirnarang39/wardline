package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"

	policygenadapter "github.com/kabirnarang39/wardline/internal/features/policygen/adapter"
	policygendomain "github.com/kabirnarang39/wardline/internal/features/policygen/domain"
)

// runInferPolicy implements `wardline infer-policy`: reads the audit
// trail over [-from, -to), infers one allow rule per distinct
// (tenant, identity, tool) combination seen in allow-decision traffic, and
// writes it as a starter policy.yaml-shaped file at -output. No feature
// flag -- an explicitly-invoked offline command, like validate-policy/
// validate-config/export-evidence/policy-pack.
func runInferPolicy(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("infer-policy", flag.ExitOnError)
	configPath := fs.String("config", "wardline.yaml", "path to config file")
	fromStr := fs.String("from", "", "start of the traffic range to learn from (RFC3339), required")
	toStr := fs.String("to", "", "end of the traffic range to learn from (RFC3339), defaults to now")
	outputPath := fs.String("output", "./policy.generated.yaml", "output policy file path")
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
	now := time.Now()
	to := now
	if *toStr != "" {
		to, err = time.Parse(time.RFC3339, *toStr)
		if err != nil {
			logger.Error("invalid -to", "error", err)
			os.Exit(1)
		}
		// Clamp a future -to to now: the audit trail cannot contain
		// entries past this instant, so advertising a wider range in the
		// generated header would overstate what was actually examined.
		if to.After(now) {
			logger.Warn("-to is in the future; clamping to now", "requested", to, "clamped", now)
			to = now
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

	auditReader, jsonlReader, closer, err := newAuditReader(logger, featureFlags, cfg.Audit, "infer-policy")
	if err != nil {
		logger.Error("failed to set up audit reader", "error", err)
		os.Exit(1)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}

	entries, err := auditReader.Query(context.Background(), from, to)
	if err != nil {
		logger.Error("failed to query audit entries", "error", err)
		os.Exit(1)
	}
	skippedLines := 0
	if jsonlReader != nil {
		skippedLines = jsonlReader.SkippedLines
	}

	matched := 0
	for _, e := range entries {
		if e.Decision == "allow" {
			matched++
		}
	}
	if matched == 0 {
		logger.Warn("no allow-decision audit entries found in range; writing an all-deny starter policy", "from", from, "to", to)
	}

	rules := policygendomain.Infer(entries)
	meta := policygenadapter.Meta{From: from, To: to, EntryCount: matched, SkippedLines: skippedLines}
	if err := policygenadapter.WriteFile(*outputPath, rules, meta); err != nil {
		logger.Error("failed to write generated policy file", "error", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %d rule(s) inferred from %d allow-decision entries (of %d total) to %s\n",
		len(rules), matched, len(entries), *outputPath)
}
