package adapter_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/compliance/adapter"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestSignVerify_RoundTrips(t *testing.T) {
	key := generateTestKey(t)
	payload := []byte("evidence bundle checksums")

	sig, err := adapter.Sign(payload, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !adapter.Verify(payload, sig, &key.PublicKey) {
		t.Error("expected a freshly-signed payload to verify")
	}
}

func TestVerify_TamperedPayloadFails(t *testing.T) {
	key := generateTestKey(t)
	sig, err := adapter.Sign([]byte("original"), key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if adapter.Verify([]byte("tampered"), sig, &key.PublicKey) {
		t.Error("expected verification to fail for a tampered payload")
	}
}

func TestVerify_WrongKeyFails(t *testing.T) {
	key := generateTestKey(t)
	wrongKey := generateTestKey(t)
	payload := []byte("evidence bundle checksums")
	sig, err := adapter.Sign(payload, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if adapter.Verify(payload, sig, &wrongKey.PublicKey) {
		t.Error("expected verification to fail against the wrong public key")
	}
}

func TestParsePrivateKeyPEM_PKCS8(t *testing.T) {
	key := generateTestKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := adapter.ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Error("expected the parsed key to match the original")
	}
}

func TestParsePrivateKeyPEM_PKCS1(t *testing.T) {
	key := generateTestKey(t)
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	got, err := adapter.ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Error("expected the parsed key to match the original")
	}
}

func TestParsePrivateKeyPEM_NoPEMBlock(t *testing.T) {
	_, err := adapter.ParsePrivateKeyPEM([]byte("not a pem file"))
	if err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
}

func TestParsePublicKeyPEM_RoundTrips(t *testing.T) {
	key := generateTestKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	got, err := adapter.ParsePublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Error("expected the parsed key to match the original")
	}
}

func TestParsePublicKeyPEM_NoPEMBlock(t *testing.T) {
	_, err := adapter.ParsePublicKeyPEM([]byte("not a pem file"))
	if err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
}
