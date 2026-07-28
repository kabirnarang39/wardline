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
