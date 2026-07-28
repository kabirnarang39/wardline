package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	policypackadapter "github.com/kabirnarang39/wardline/internal/features/policypack/adapter"
	policypackusecase "github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}

// errorFS is an fs.FS that fails every Open call, so catalog.List's
// underlying fs.ReadDir(fsys, ".") always errors -- used to exercise
// runPolicyPackListTo's error branch, which real embedded packs can't
// reach.
type errorFS struct{}

func (errorFS) Open(name string) (fs.File, error) {
	return nil, fmt.Errorf("errorFS: forced failure opening %q", name)
}

func TestRunPolicyPackList_PrintsAllFourPacks(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	var out bytes.Buffer
	ok := runPolicyPackListTo(&out, discardLogger(), catalog)

	if !ok {
		t.Fatal("expected list to succeed against the real embedded packs")
	}
	for _, name := range []string{"deny-all-baseline", "single-identity-full-access", "read-only-single-identity", "admin-viewer-split"} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("expected list output to contain %q, got:\n%s", name, out.String())
		}
	}
}

func TestRunPolicyPackList_CatalogErrors_ReturnsFalseWithoutExiting(t *testing.T) {
	catalog := policypackusecase.NewCatalog(errorFS{})
	var out bytes.Buffer
	ok := runPolicyPackListTo(&out, discardLogger(), catalog)

	if ok {
		t.Fatal("expected list to fail when the catalog's filesystem errors")
	}
	if out.Len() != 0 {
		t.Errorf("expected no output on error, got:\n%s", out.String())
	}
}

func TestReorderFlagsFirst(t *testing.T) {
	valueFlags := map[string]bool{"output": true}

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "flag after positional (the bug case)",
			args: []string{"deny-all-baseline", "-output", "/tmp/x.yaml"},
			want: []string{"-output", "/tmp/x.yaml", "deny-all-baseline"},
		},
		{
			name: "-output=value form, already flag-first",
			args: []string{"-output=/tmp/x.yaml", "deny-all-baseline"},
			want: []string{"-output=/tmp/x.yaml", "deny-all-baseline"},
		},
		{
			name: "-output=value form, after positional",
			args: []string{"deny-all-baseline", "-output=/tmp/x.yaml"},
			want: []string{"-output=/tmp/x.yaml", "deny-all-baseline"},
		},
		{
			name: "bare - token is positional, not a flag",
			args: []string{"-", "-output", "/tmp/x.yaml"},
			want: []string{"-output", "/tmp/x.yaml", "-"},
		},
		{
			name: "unrecognized flag name does not consume the next token",
			args: []string{"deny-all-baseline", "-bogus"},
			want: []string{"-bogus", "deny-all-baseline"},
		},
		{
			name: "double-dash --output after positional (the form e2e uses)",
			args: []string{"deny-all-baseline", "--output", "/tmp/x.yaml"},
			want: []string{"--output", "/tmp/x.yaml", "deny-all-baseline"},
		},
		{
			name: "-- terminator makes everything after it positional",
			args: []string{"--", "-output", "deny-all-baseline"},
			want: []string{"--", "-output", "deny-all-baseline"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reorderFlagsFirst(tt.args, valueFlags)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reorderFlagsFirst(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestRunPolicyPackShow_KnownName_PrintsManifestAndSource(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	var out bytes.Buffer
	ok := runPolicyPackShowTo(&out, discardLogger(), catalog, "deny-all-baseline")

	if !ok {
		t.Fatal("expected show to succeed for a known pack name")
	}
	if !strings.Contains(out.String(), "default: deny") {
		t.Errorf("expected show output to contain the policy source, got:\n%s", out.String())
	}
}

func TestRunPolicyPackShow_UnknownName_Fails(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	var out bytes.Buffer
	ok := runPolicyPackShowTo(&out, discardLogger(), catalog, "does-not-exist")

	if ok {
		t.Fatal("expected show to fail for an unknown pack name")
	}
}

func TestRunPolicyPackInstall_WritesFile(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	outputPath := filepath.Join(t.TempDir(), "policy.yaml")
	var out bytes.Buffer

	ok := runPolicyPackInstallTo(&out, discardLogger(), catalog, "deny-all-baseline", outputPath)
	if !ok {
		t.Fatal("expected install to succeed")
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected the policy file to be written: %v", err)
	}
	if string(data) != "rules: []\ndefault: deny\n" {
		t.Errorf("unexpected written content: %q", data)
	}
}

func TestRunPolicyPackInstall_TemplatePack_WarnsAboutPlaceholderIdentities(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	var out bytes.Buffer

	if !runPolicyPackInstallTo(&out, discardLogger(), catalog, "single-identity-full-access", filepath.Join(t.TempDir(), "policy.yaml")) {
		t.Fatal("expected install to succeed")
	}
	if !strings.Contains(out.String(), placeholderIdentityPrefix) {
		t.Errorf("expected a placeholder-identity warning for a template pack, got:\n%s", out.String())
	}

	// deny-all-baseline names no identity, so it needs no such warning.
	out.Reset()
	if !runPolicyPackInstallTo(&out, discardLogger(), catalog, "deny-all-baseline", filepath.Join(t.TempDir(), "policy.yaml")) {
		t.Fatal("expected install to succeed")
	}
	if strings.Contains(out.String(), placeholderIdentityPrefix) {
		t.Errorf("deny-all-baseline has no placeholders and should not be warned about, got:\n%s", out.String())
	}
}

// TestRunPolicyPackInstall_PrintedSnippetIsValidTopLevelWardlineYAML pastes
// install's printed snippet into a real config and loads it, so the
// guidance can't drift into something an operator can't actually use.
func TestRunPolicyPackInstall_PrintedSnippetIsValidTopLevelWardlineYAML(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	var out bytes.Buffer
	if !runPolicyPackInstallTo(&out, discardLogger(), policypackusecase.NewCatalog(policypackadapter.Packs()), "deny-all-baseline", policyPath) {
		t.Fatal("expected install to succeed")
	}

	var snippet []string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "policy_file:") || strings.HasPrefix(line, "policy_backend:") {
			snippet = append(snippet, line)
		}
	}
	if len(snippet) != 2 {
		t.Fatalf("expected two unindented top-level config lines, got %v in:\n%s", snippet, out.String())
	}

	configPath := filepath.Join(dir, "wardline.yaml")
	body := "listen: \"127.0.0.1:0\"\nupstream: \"http://127.0.0.1:1\"\naudit:\n  output: stdout\n" + strings.Join(snippet, "\n") + "\n"
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("install's printed snippet does not load as wardline.yaml: %v\n%s", err, body)
	}
	if cfg.PolicyFile != policyPath {
		t.Errorf("expected policy_file %q, got %q", policyPath, cfg.PolicyFile)
	}
	if cfg.PolicyBackend != "yaml" {
		t.Errorf("expected policy_backend %q, got %q", "yaml", cfg.PolicyBackend)
	}
}

// TestRunPolicyPackInstall_RefusesToFollowADanglingSymlink guards the
// reason install uses O_EXCL instead of os.Stat-then-os.WriteFile:
// os.Stat reports a dangling symlink as "does not exist", and
// os.WriteFile would then follow it and write the policy file outside
// the requested -output path.
func TestRunPolicyPackInstall_RefusesToFollowADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.yaml")
	outputPath := filepath.Join(dir, "policy.yaml")
	if err := os.Symlink(target, outputPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var out bytes.Buffer

	if runPolicyPackInstallTo(&out, discardLogger(), policypackusecase.NewCatalog(policypackadapter.Packs()), "deny-all-baseline", outputPath) {
		t.Fatal("expected install to refuse a path that is a dangling symlink")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("install wrote through the symlink to %s, outside the requested -output path", target)
	}
}

func TestRunPolicyPackInstall_RefusesToOverwriteExistingFile(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	outputPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(outputPath, []byte("pre-existing content"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer

	ok := runPolicyPackInstallTo(&out, discardLogger(), catalog, "deny-all-baseline", outputPath)
	if ok {
		t.Fatal("expected install to refuse to overwrite an existing file")
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "pre-existing content" {
		t.Error("expected the existing file's content to be untouched")
	}
}

func TestRunPolicyPackInstall_UnknownName_Fails(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	outputPath := filepath.Join(t.TempDir(), "policy.yaml")
	var out bytes.Buffer

	ok := runPolicyPackInstallTo(&out, discardLogger(), catalog, "does-not-exist", outputPath)
	if ok {
		t.Fatal("expected install to fail for an unknown pack name")
	}
	if _, err := os.Stat(outputPath); err == nil {
		t.Error("expected no file to be written for an unknown pack name")
	}
}
