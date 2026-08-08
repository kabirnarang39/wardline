package adapter_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/compliance/adapter"
	"github.com/kabirnarang39/wardline/internal/features/compliance/domain"
)

func writeTestBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.tar.gz")
	var buf bytes.Buffer
	manifest := domain.Manifest{WardlineVersion: "0.6.0"}
	if err := adapter.WriteBundle(&buf, manifest, nil, nil, []byte("default: allow"), "yaml", nil, nil, nil); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadBundle_ReturnsAllFiles(t *testing.T) {
	path := writeTestBundle(t)
	files, err := adapter.ReadBundle(path)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	for _, want := range []string{"manifest.json", "audit.jsonl", "policy_snapshot", "checksums.txt"} {
		if _, ok := files[want]; !ok {
			t.Errorf("expected ReadBundle to return %q", want)
		}
	}
}

func TestReadBundle_MissingFile(t *testing.T) {
	_, err := adapter.ReadBundle("/nonexistent/evidence.tar.gz")
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestVerifyChecksums_NoMismatchesForAnUntamperedBundle(t *testing.T) {
	path := writeTestBundle(t)
	files, err := adapter.ReadBundle(path)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	mismatches, err := adapter.VerifyChecksums(files["checksums.txt"], files)
	if err != nil {
		t.Fatalf("VerifyChecksums: %v", err)
	}
	if len(mismatches) != 0 {
		t.Errorf("expected no mismatches for an untampered bundle, got %v", mismatches)
	}
}

func TestVerifyChecksums_DetectsTamperedFile(t *testing.T) {
	path := writeTestBundle(t)
	files, err := adapter.ReadBundle(path)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	files["policy_snapshot"] = []byte("default: deny -- tampered")

	mismatches, err := adapter.VerifyChecksums(files["checksums.txt"], files)
	if err != nil {
		t.Fatalf("VerifyChecksums: %v", err)
	}
	if len(mismatches) != 1 || mismatches[0] != "policy_snapshot (checksum mismatch)" {
		t.Errorf("expected exactly one mismatch for policy_snapshot, got %v", mismatches)
	}
}

func TestVerifyChecksums_DetectsMissingFile(t *testing.T) {
	path := writeTestBundle(t)
	files, err := adapter.ReadBundle(path)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	delete(files, "policy_snapshot")

	mismatches, err := adapter.VerifyChecksums(files["checksums.txt"], files)
	if err != nil {
		t.Fatalf("VerifyChecksums: %v", err)
	}
	if len(mismatches) != 1 || mismatches[0] != "policy_snapshot (missing from bundle)" {
		t.Errorf("expected exactly one missing-file mismatch, got %v", mismatches)
	}
}

func TestVerifyChecksums_MalformedLine(t *testing.T) {
	_, err := adapter.VerifyChecksums([]byte("not a valid checksums line"), nil)
	if err == nil {
		t.Fatal("expected an error for a malformed checksums.txt line")
	}
}
