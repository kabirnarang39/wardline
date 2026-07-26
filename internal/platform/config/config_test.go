package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/config"
)

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wardline.yaml")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "http://localhost:9000"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.Upstream != "http://localhost:9000" || cfg.PolicyFile != "./policy.yaml" || cfg.Audit.Output != "stdout" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	path := writeTemp(t, `listen: ""`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
}

func TestLoad_InvalidUpstreamURL(t *testing.T) {
	path := writeTemp(t, `
listen: ":8080"
upstream: "://not-a-url"
policy_file: "./policy.yaml"
audit:
  output: stdout
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/wardline.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
