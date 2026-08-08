package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	policypackadapter "github.com/kabirnarang39/wardline/internal/features/policypack/adapter"
	policypackusecase "github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

// placeholderIdentityPrefix is what every shipped pack that names an
// identity uses instead of a real one (REPLACE_WITH_YOUR_IDENTITY,
// REPLACE_WITH_ADMIN_IDENTITY, ...). install greps the policy source for
// it to decide whether to warn that the installed file still needs
// editing before it will allow anything.
const placeholderIdentityPrefix = "REPLACE_WITH_"

// buildPackCatalog returns the embedded catalog alone, or -- when
// packsDir is non-empty -- a MultiCatalog merging the embedded catalog
// with an operator-owned directory of packs at packsDir (same
// <name>/pack.yaml + policy file shape as the embedded catalog). A name
// present in both resolves to the packsDir version -- an operator's own
// pack can deliberately shadow a built-in one by reusing its name. See
// docs/superpowers/specs/2026-08-08-policy-pack-marketplace-expansion-design.md
// for why this -- not a network-fetched registry -- is this cycle's
// "marketplace expansion."
func buildPackCatalog(logger *slog.Logger, packsDir string) policypackusecase.PackSource {
	embedded := policypackusecase.NewCatalog(policypackadapter.Packs())
	if packsDir == "" {
		return embedded
	}
	external := policypackusecase.NewCatalog(os.DirFS(packsDir))
	return policypackusecase.NewMultiCatalog(logger, embedded, external)
}

// runPolicyPack dispatches wardline's "policy-pack" subcommand to its own
// list/show/install/compose sub-subcommands. No feature flag -- an
// explicitly-invoked offline command, like validate-policy/
// validate-config/export-evidence.
func runPolicyPack(logger *slog.Logger, args []string) {
	if len(args) < 1 {
		logger.Error("usage: wardline policy-pack <list|show|install|compose> [flags]")
		os.Exit(1)
	}
	packsDirFlags := map[string]bool{"packs-dir": true}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("policy-pack list", flag.ExitOnError)
		packsDir := fs.String("packs-dir", "", "path to an additional directory of operator-owned packs, merged with the embedded catalog")
		_ = fs.Parse(args[1:])
		if !runPolicyPackListTo(os.Stdout, logger, buildPackCatalog(logger, *packsDir)) {
			os.Exit(1)
		}
	case "show":
		fs := flag.NewFlagSet("policy-pack show", flag.ExitOnError)
		packsDir := fs.String("packs-dir", "", "path to an additional directory of operator-owned packs, merged with the embedded catalog")
		_ = fs.Parse(reorderFlagsFirst(args[1:], packsDirFlags))
		if fs.NArg() < 1 {
			logger.Error("usage: wardline policy-pack show <name> [-packs-dir <path>]")
			os.Exit(1)
		}
		if !runPolicyPackShowTo(os.Stdout, logger, buildPackCatalog(logger, *packsDir), fs.Arg(0)) {
			os.Exit(1)
		}
	case "install":
		fs := flag.NewFlagSet("policy-pack install", flag.ExitOnError)
		output := fs.String("output", "./policy.yaml", "path to write the installed policy file")
		packsDir := fs.String("packs-dir", "", "path to an additional directory of operator-owned packs, merged with the embedded catalog")
		// flag.FlagSet.Parse stops at the first non-flag token, but this
		// command's own usage ("install <name> [-output <path>]") puts the
		// positional name first -- reorder so -output/-packs-dir still get
		// parsed when they follow the name, as they do in
		// `install foo -output x`.
		_ = fs.Parse(reorderFlagsFirst(args[1:], map[string]bool{"output": true, "packs-dir": true}))
		if fs.NArg() < 1 {
			logger.Error("usage: wardline policy-pack install <name> [-output <path>] [-packs-dir <path>]")
			os.Exit(1)
		}
		if !runPolicyPackInstallTo(os.Stdout, logger, buildPackCatalog(logger, *packsDir), fs.Arg(0), *output) {
			os.Exit(1)
		}
	case "compose":
		fs := flag.NewFlagSet("policy-pack compose", flag.ExitOnError)
		output := fs.String("output", "./policy.yaml", "path to write the composed policy file")
		packsDir := fs.String("packs-dir", "", "path to an additional directory of operator-owned packs, merged with the embedded catalog")
		_ = fs.Parse(reorderFlagsFirst(args[1:], map[string]bool{"output": true, "packs-dir": true}))
		if fs.NArg() < 2 {
			logger.Error("usage: wardline policy-pack compose <name1> <name2> [...] [-output <path>] [-packs-dir <path>] -- at least 2 packs (a single pack is just `install`)")
			os.Exit(1)
		}
		if !runPolicyPackComposeTo(os.Stdout, logger, buildPackCatalog(logger, *packsDir), fs.Args(), *output) {
			os.Exit(1)
		}
	default:
		logger.Error("unknown policy-pack subcommand", "subcommand", args[0])
		os.Exit(1)
	}
}

// reorderFlagsFirst moves every flag token -- and, per valueFlags, the
// value token it consumes -- to the front of args, followed by the
// remaining (positional) tokens in their original order. Needed because
// flag.FlagSet.Parse stops parsing at the first non-flag argument, which
// would otherwise leave a trailing "-output <path>" unparsed and silently
// defaulted.
//
// valueFlags is a hand-maintained list of flag names (without leading
// dashes) that consume a following token as their value -- kept in sync
// with the FlagSet's own fs.String/fs.Bool calls at each call site.
func reorderFlagsFirst(args []string, valueFlags map[string]bool) []string {
	var flagTokens, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// POSIX "end of flags" terminator: everything after it,
			// including "--" itself, is positional.
			positional = append(positional, args[i:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flagTokens = append(flagTokens, a)
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq == -1 && valueFlags[name] && i+1 < len(args) {
			i++
			flagTokens = append(flagTokens, args[i])
		}
	}
	return append(flagTokens, positional...)
}

// runPolicyPackListTo returns false (and logs a clear error) when the
// catalog fails to list -- the caller decides whether that means
// os.Exit(1) (the real CLI) or a test assertion, same as its show/install
// siblings.
func runPolicyPackListTo(w io.Writer, logger *slog.Logger, catalog policypackusecase.PackSource) bool {
	packs, err := catalog.List()
	if err != nil {
		logger.Error("failed to list policy packs", "error", err)
		return false
	}
	for _, p := range packs {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Backend, p.Version, p.Description)
	}
	return true
}

// runPolicyPackShowTo returns false (and logs a clear error) when name is
// unknown -- the caller decides whether that means os.Exit(1) (the real
// CLI) or a test assertion.
func runPolicyPackShowTo(w io.Writer, logger *slog.Logger, catalog policypackusecase.PackSource, name string) bool {
	pack, policySource, err := catalog.Get(name)
	if err != nil {
		failUnknownPack(logger, catalog, name)
		return false
	}
	_, _ = fmt.Fprintf(w, "name: %s\nbackend: %s\nversion: %s\ndescription: %s\n\n%s", pack.Name, pack.Backend, pack.Version, pack.Description, policySource)
	return true
}

// runPolicyPackInstallTo returns false (and logs a clear error, writing
// nothing) for an unknown pack name or an existing file at output.
func runPolicyPackInstallTo(w io.Writer, logger *slog.Logger, catalog policypackusecase.PackSource, name, output string) bool {
	pack, policySource, err := catalog.Get(name)
	if err != nil {
		failUnknownPack(logger, catalog, name)
		return false
	}
	// O_CREATE|O_EXCL rather than os.Stat-then-os.WriteFile: open(2) with
	// O_EXCL does not follow a final symlink, so it refuses a path that is
	// a dangling symlink -- which os.Stat reports as "does not exist" and
	// os.WriteFile would then follow, writing the policy file somewhere
	// other than the -output path the operator asked for. It closes the
	// stat/write race for free too.
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			logger.Error("refusing to overwrite existing file", "path", output)
		} else {
			logger.Error("failed to create policy file", "path", output, "error", err)
		}
		return false
	}
	_, writeErr := f.Write(policySource)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		// Don't leave a truncated policy file behind for an operator to
		// point wardline at.
		_ = os.Remove(output)
		logger.Error("failed to write policy file", "path", output, "error", writeErr)
		return false
	}

	_, _ = fmt.Fprintf(w, "installed %q to %s\n", pack.Name, output)
	if bytes.Contains(policySource, []byte(placeholderIdentityPrefix)) {
		_, _ = fmt.Fprintf(w, "\nThis pack is a template, not a ready-to-serve policy: edit %s and replace\nevery %s* placeholder with a real identity first. Wardline's YAML\nengine matches identities exactly (no identity wildcard), so an unreplaced\nplaceholder matches nothing and every call falls through to the policy's\ndefault: deny.\n", output, placeholderIdentityPrefix)
	}
	// policy_backend is printed even though %q here is always the default
	// ("yaml") today: an operator whose wardline.yaml already selects opa
	// or cedar for other reasons needs to see that this pack won't load
	// under that backend. Both keys are top-level in wardline.yaml, so
	// they're printed unindented -- they're meant to be pasted as-is.
	_, _ = fmt.Fprintf(w, "\nAdd these top-level keys to your wardline.yaml:\n\npolicy_file: %q\npolicy_backend: %q  # already the default, but this pack only loads under it\n", output, pack.Backend)
	return true
}

// runPolicyPackComposeTo merges the named packs' YAML rules (concatenated
// in the order given -- first-match-wins semantics make that order a
// real, meaningful choice) into one policy file, refusing (writing
// nothing) if any named pack isn't backend: yaml or if the output path
// already exists. A duplicate (identity, tool, tenant) key across the
// composed packs is warned about (stderr, via logger.Warn), not an
// error -- first-match-wins already makes the earlier pack's rule the
// one that takes effect; the warning exists purely so the operator
// notices two packs disagreed, rather than only discovering it by
// reading the composed file closely.
func runPolicyPackComposeTo(w io.Writer, logger *slog.Logger, catalog policypackusecase.PackSource, names []string, output string) bool {
	var allRules []policydomain.Rule
	var lastDefault policydomain.Effect
	seenBy := map[string]string{}
	for _, name := range names {
		pack, policySource, err := catalog.Get(name)
		if err != nil {
			failUnknownPack(logger, catalog, name)
			return false
		}
		if pack.Backend != "yaml" {
			logger.Error("compose only supports backend: yaml packs -- OPA/Cedar composition needs a real parser pass, not string concatenation (deliberately out of scope, see the design doc)", "name", name, "backend", pack.Backend)
			return false
		}
		rules, def, err := policyadapter.ParseRules(policySource)
		if err != nil {
			logger.Error("failed to parse pack policy", "name", name, "error", err)
			return false
		}
		for _, r := range rules {
			key := r.Identity + "\x00" + r.Tool + "\x00" + r.Tenant
			if firstPack, dup := seenBy[key]; dup {
				logger.Warn("composed packs both grant the same (identity, tool, tenant) -- first-match-wins keeps the earlier pack's rule",
					"identity", r.Identity, "tool", r.Tool, "tenant", r.Tenant, "kept_from", firstPack, "also_in", name)
			} else {
				seenBy[key] = name
			}
			allRules = append(allRules, r)
		}
		lastDefault = def
	}

	data, err := policyadapter.MarshalYAML(allRules, lastDefault)
	if err != nil {
		logger.Error("failed to marshal composed policy", "error", err)
		return false
	}

	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			logger.Error("refusing to overwrite existing file", "path", output)
		} else {
			logger.Error("failed to create policy file", "path", output, "error", err)
		}
		return false
	}
	_, writeErr := f.Write(data)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(output)
		logger.Error("failed to write policy file", "path", output, "error", writeErr)
		return false
	}

	_, _ = fmt.Fprintf(w, "composed %d packs (%s) into %s\n", len(names), strings.Join(names, ", "), output)
	if bytes.Contains(data, []byte(placeholderIdentityPrefix)) {
		_, _ = fmt.Fprintf(w, "\nThis file still contains one or more %s* placeholders from the composed\npacks -- replace them with real identities before using it.\n", placeholderIdentityPrefix)
	}
	_, _ = fmt.Fprintf(w, "\nAdd these top-level keys to your wardline.yaml:\n\npolicy_file: %q\npolicy_backend: \"yaml\"\n", output)
	return true
}

func failUnknownPack(logger *slog.Logger, catalog policypackusecase.PackSource, name string) {
	packs, listErr := catalog.List()
	var names []string
	if listErr == nil {
		for _, p := range packs {
			names = append(names, p.Name)
		}
	}
	logger.Error("unknown policy pack", "name", name, "available", strings.Join(names, ", "))
}
