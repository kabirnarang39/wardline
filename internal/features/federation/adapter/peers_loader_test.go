package adapter_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/federation/adapter"
)

func writeTestPublicKey(t *testing.T, dir, filename string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pubPEM, 0o600); err != nil {
		t.Fatalf("write public key file: %v", err)
	}
	return path
}

func TestLoadPeers_ValidFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestPublicKey(t, dir, "eu-cluster.pub.pem")

	peersYAML := "peers:\n" +
		"  - id: eu-cluster\n" +
		"    endpoint: https://wardline.eu.example.com/federation/summaries\n" +
		"    public_key_file: " + keyPath + "\n"
	peersPath := filepath.Join(dir, "peers.yaml")
	if err := os.WriteFile(peersPath, []byte(peersYAML), 0o600); err != nil {
		t.Fatalf("write peers file: %v", err)
	}

	peers, err := adapter.LoadPeers(peersPath)
	if err != nil {
		t.Fatalf("LoadPeers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].ID != "eu-cluster" {
		t.Errorf("expected id eu-cluster, got %q", peers[0].ID)
	}
	if peers[0].Endpoint != "https://wardline.eu.example.com/federation/summaries" {
		t.Errorf("expected the configured endpoint, got %q", peers[0].Endpoint)
	}
	if peers[0].PublicKey == nil {
		t.Error("expected a parsed public key")
	}
}

func TestLoadPeers_UnknownField_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestPublicKey(t, dir, "eu-cluster.pub.pem")

	// "endpiont" is a typo of "endpoint" -- a strict decoder must reject
	// this rather than silently treating the peer as having no endpoint,
	// the same fail-closed lesson RBAC's own design doc learned about a
	// typo'd key silently promoting scope.
	peersYAML := "peers:\n" +
		"  - id: eu-cluster\n" +
		"    endpiont: https://wardline.eu.example.com/federation/summaries\n" +
		"    public_key_file: " + keyPath + "\n"
	peersPath := filepath.Join(dir, "peers.yaml")
	if err := os.WriteFile(peersPath, []byte(peersYAML), 0o600); err != nil {
		t.Fatalf("write peers file: %v", err)
	}

	_, err := adapter.LoadPeers(peersPath)
	if err == nil {
		t.Fatal("expected an error for an unknown field, got nil")
	}
}

func TestLoadPeers_MissingFile_ReturnsError(t *testing.T) {
	_, err := adapter.LoadPeers("/nonexistent/peers.yaml")
	if err == nil {
		t.Fatal("expected an error for a missing peers file")
	}
}

func TestLoadPeers_UnparsablePublicKey_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	badKeyPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badKeyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write bad key file: %v", err)
	}

	peersYAML := "peers:\n" +
		"  - id: eu-cluster\n" +
		"    endpoint: https://wardline.eu.example.com/federation/summaries\n" +
		"    public_key_file: " + badKeyPath + "\n"
	peersPath := filepath.Join(dir, "peers.yaml")
	if err := os.WriteFile(peersPath, []byte(peersYAML), 0o600); err != nil {
		t.Fatalf("write peers file: %v", err)
	}

	_, err := adapter.LoadPeers(peersPath)
	if err == nil {
		t.Fatal("expected an error for an unparsable public key file")
	}
}
