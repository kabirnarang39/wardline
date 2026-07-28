package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	policypackadapter "github.com/kabirnarang39/wardline/internal/features/policypack/adapter"
	policypackusecase "github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}

func TestRunPolicyPackList_PrintsAllFourPacks(t *testing.T) {
	catalog := policypackusecase.NewCatalog(policypackadapter.Packs())
	var out bytes.Buffer
	runPolicyPackListTo(&out, discardLogger(), catalog)

	for _, name := range []string{"deny-all-baseline", "single-identity-full-access", "read-only-single-identity", "admin-viewer-split"} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("expected list output to contain %q, got:\n%s", name, out.String())
		}
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
