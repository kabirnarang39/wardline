package adapter_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/compliance/adapter"
	"github.com/kabirnarang39/wardline/internal/features/compliance/domain"
)

// readBundle un-gzips and un-tars data, returning a map of file name to
// contents -- the shared assertion helper every test below uses.
func readBundle(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %s: %v", hdr.Name, err)
		}
		files[hdr.Name] = content
	}
	return files
}

func TestWriteBundle_ContainsExpectedFiles(t *testing.T) {
	manifest := domain.Manifest{WardlineVersion: "0.6.0", AuditEntryCount: 1}
	auditEntries := []auditdomain.Entry{
		{Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Identity: "alice", Tool: "read_file", Decision: "allow"},
	}
	anomalies := []anomalydomain.Anomaly{
		{Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Identity: "alice", Kind: anomalydomain.KindNovelTool, Detail: "first call"},
	}

	var buf bytes.Buffer
	if err := adapter.WriteBundle(&buf, manifest, auditEntries, anomalies, []byte("default: allow"), "yaml", []byte("bindings: []"), nil, nil); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}

	files := readBundle(t, buf.Bytes())
	for _, want := range []string{"manifest.json", "audit.jsonl", "anomalies.jsonl", "policy_snapshot", "policy_backend.txt", "rbac_snapshot", "checksums.txt"} {
		if _, ok := files[want]; !ok {
			t.Errorf("expected bundle to contain %q, got files: %v", want, keysOf(files))
		}
	}

	var gotManifest domain.Manifest
	if err := json.Unmarshal(files["manifest.json"], &gotManifest); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v", err)
	}
	if gotManifest.WardlineVersion != "0.6.0" {
		t.Errorf("unexpected manifest content: %+v", gotManifest)
	}

	if !strings.Contains(string(files["audit.jsonl"]), `"identity":"alice"`) {
		t.Errorf("expected audit.jsonl to contain the audit entry, got %s", files["audit.jsonl"])
	}
	if !strings.Contains(string(files["anomalies.jsonl"]), `"kind":"novel_tool"`) {
		t.Errorf("expected anomalies.jsonl to contain the anomaly, got %s", files["anomalies.jsonl"])
	}
	if string(files["policy_snapshot"]) != "default: allow" {
		t.Errorf("unexpected policy_snapshot: %s", files["policy_snapshot"])
	}
	if string(files["policy_backend.txt"]) != "yaml\n" {
		t.Errorf("unexpected policy_backend.txt: %q", files["policy_backend.txt"])
	}
	if string(files["rbac_snapshot"]) != "bindings: []" {
		t.Errorf("unexpected rbac_snapshot: %s", files["rbac_snapshot"])
	}
}

func keysOf(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestWriteBundle_ChecksumsMatchRealSHA256(t *testing.T) {
	manifest := domain.Manifest{WardlineVersion: "0.6.0"}
	var buf bytes.Buffer
	if err := adapter.WriteBundle(&buf, manifest, nil, nil, nil, "", nil, nil, nil); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}

	files := readBundle(t, buf.Bytes())
	checksums := string(files["checksums.txt"])
	for name, content := range files {
		if name == "checksums.txt" {
			continue
		}
		sum := sha256.Sum256(content)
		want := hex.EncodeToString(sum[:]) + "  " + name
		if !strings.Contains(checksums, want) {
			t.Errorf("expected checksums.txt to contain %q, got:\n%s", want, checksums)
		}
	}
}

func TestWriteBundle_OmitsAnomaliesAndRBACWhenNotProvided(t *testing.T) {
	manifest := domain.Manifest{WardlineVersion: "0.6.0"}
	var buf bytes.Buffer
	if err := adapter.WriteBundle(&buf, manifest, nil, nil, []byte("default: allow"), "yaml", nil, nil, nil); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}

	files := readBundle(t, buf.Bytes())
	if _, ok := files["anomalies.jsonl"]; ok {
		t.Error("expected anomalies.jsonl to be omitted when no anomalies are passed")
	}
	if _, ok := files["rbac_snapshot"]; ok {
		t.Error("expected rbac_snapshot to be omitted when no rbac source is passed")
	}
	if _, ok := files["identities.json"]; ok {
		t.Error("expected identities.json to be omitted when no identities are passed")
	}
	if _, ok := files["checksums.txt.sig"]; ok {
		t.Error("expected checksums.txt.sig to be omitted when no signing key is passed")
	}
	if _, ok := files["public_key.pem"]; ok {
		t.Error("expected public_key.pem to be omitted when no signing key is passed")
	}
	if _, ok := files["manifest.json"]; !ok {
		t.Error("expected manifest.json to always be present")
	}
	if _, ok := files["audit.jsonl"]; !ok {
		t.Error("expected audit.jsonl to always be present, even if empty")
	}
}

func TestWriteBundle_SignedBundle_SignatureVerifiesAgainstEmbeddedPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	manifest := domain.Manifest{WardlineVersion: "0.6.0"}
	var buf bytes.Buffer
	if err := adapter.WriteBundle(&buf, manifest, nil, nil, nil, "", nil, nil, key); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}

	files := readBundle(t, buf.Bytes())
	sig, ok := files["checksums.txt.sig"]
	if !ok {
		t.Fatal("expected checksums.txt.sig to be present when a signing key is passed")
	}
	pubPEM, ok := files["public_key.pem"]
	if !ok {
		t.Fatal("expected public_key.pem to be present when a signing key is passed")
	}
	pubKey, err := adapter.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse embedded public key: %v", err)
	}
	if !adapter.Verify(files["checksums.txt"], sig, pubKey) {
		t.Error("expected the signature to verify against the embedded public key")
	}

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	if adapter.Verify(files["checksums.txt"], sig, &wrongKey.PublicKey) {
		t.Error("expected the signature to NOT verify against an unrelated key")
	}
}

func TestWriteBundle_IdentitiesRoundTrip(t *testing.T) {
	manifest := domain.Manifest{WardlineVersion: "0.6.0"}
	identities := []domain.RedactedIdentity{
		{Name: "agent-abc123", Tenant: "acme"},
		{Name: "agent-def456", Tenant: "widgets-inc"},
	}
	var buf bytes.Buffer
	if err := adapter.WriteBundle(&buf, manifest, nil, nil, nil, "", nil, identities, nil); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}

	files := readBundle(t, buf.Bytes())
	raw, ok := files["identities.json"]
	if !ok {
		t.Fatal("expected identities.json to be present when identities are passed")
	}
	var got []domain.RedactedIdentity
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("identities.json is not valid JSON: %v", err)
	}
	if len(got) != 2 || got[0] != identities[0] || got[1] != identities[1] {
		t.Errorf("expected identities to round-trip unchanged, got %+v", got)
	}
}
