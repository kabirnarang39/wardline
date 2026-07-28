package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	policypackadapter "github.com/kabirnarang39/wardline/internal/features/policypack/adapter"
	policypackusecase "github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

// runPolicyPack dispatches wardline's "policy-pack" subcommand to its own
// list/show/install sub-subcommands. No feature flag -- an explicitly-
// invoked offline command, like validate-policy/validate-config/
// export-evidence.
func runPolicyPack(logger *slog.Logger, args []string) {
	if len(args) < 1 {
		logger.Error("usage: wardline policy-pack <list|show|install> [flags]")
		os.Exit(1)
	}
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	switch args[0] {
	case "list":
		runPolicyPackListTo(os.Stdout, logger, catalog)
	case "show":
		fs := flag.NewFlagSet("policy-pack show", flag.ExitOnError)
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			logger.Error("usage: wardline policy-pack show <name>")
			os.Exit(1)
		}
		if !runPolicyPackShowTo(os.Stdout, logger, catalog, fs.Arg(0)) {
			os.Exit(1)
		}
	case "install":
		fs := flag.NewFlagSet("policy-pack install", flag.ExitOnError)
		output := fs.String("output", "./policy.yaml", "path to write the installed policy file")
		// flag.FlagSet.Parse stops at the first non-flag token, but this
		// command's own usage ("install <name> [-output <path>]") puts the
		// positional name first -- reorder so -output still gets parsed
		// when it follows the name, as it does in `install foo -output x`.
		_ = fs.Parse(reorderFlagsFirst(args[1:], map[string]bool{"output": true}))
		if fs.NArg() < 1 {
			logger.Error("usage: wardline policy-pack install <name> [-output <path>]")
			os.Exit(1)
		}
		if !runPolicyPackInstallTo(os.Stdout, logger, catalog, fs.Arg(0), *output) {
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
func reorderFlagsFirst(args []string, valueFlags map[string]bool) []string {
	var flagTokens, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
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

func runPolicyPackListTo(w io.Writer, logger *slog.Logger, catalog *policypackusecase.Catalog) {
	packs, err := catalog.List()
	if err != nil {
		logger.Error("failed to list policy packs", "error", err)
		os.Exit(1)
	}
	for _, p := range packs {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Backend, p.Description)
	}
}

// runPolicyPackShowTo returns false (and logs a clear error) when name is
// unknown -- the caller decides whether that means os.Exit(1) (the real
// CLI) or a test assertion.
func runPolicyPackShowTo(w io.Writer, logger *slog.Logger, catalog *policypackusecase.Catalog, name string) bool {
	pack, policySource, err := catalog.Get(name)
	if err != nil {
		failUnknownPack(logger, catalog, name)
		return false
	}
	_, _ = fmt.Fprintf(w, "name: %s\nbackend: %s\ndescription: %s\n\n%s", pack.Name, pack.Backend, pack.Description, policySource)
	return true
}

// runPolicyPackInstallTo returns false (and logs a clear error, writing
// nothing) for an unknown pack name or an existing file at output.
func runPolicyPackInstallTo(w io.Writer, logger *slog.Logger, catalog *policypackusecase.Catalog, name, output string) bool {
	pack, policySource, err := catalog.Get(name)
	if err != nil {
		failUnknownPack(logger, catalog, name)
		return false
	}
	if _, err := os.Stat(output); err == nil {
		logger.Error("refusing to overwrite existing file", "path", output)
		return false
	} else if !os.IsNotExist(err) {
		logger.Error("failed to check output path", "path", output, "error", err)
		return false
	}
	if err := os.WriteFile(output, policySource, 0600); err != nil {
		logger.Error("failed to write policy file", "path", output, "error", err)
		return false
	}
	_, _ = fmt.Fprintf(w, "installed %q to %s\n\nAdd to your wardline.yaml:\n  policy_file: %s\n  policy_backend: %s\n", pack.Name, output, output, pack.Backend)
	return true
}

func failUnknownPack(logger *slog.Logger, catalog *policypackusecase.Catalog, name string) {
	packs, listErr := catalog.List()
	var names []string
	if listErr == nil {
		for _, p := range packs {
			names = append(names, p.Name)
		}
	}
	logger.Error("unknown policy pack", "name", name, "available", strings.Join(names, ", "))
}
