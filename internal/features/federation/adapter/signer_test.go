package adapter_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/federation/adapter"
)

func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, []byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return priv, privPEM, pubPEM
}

func TestParsePrivateKeyPEM_PKCS8(t *testing.T) {
	_, privPEM, _ := generateTestKeyPair(t)

	key, err := adapter.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParsePrivateKeyPEM_PKCS1(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	key, err := adapter.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM (PKCS1): %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParsePrivateKeyPEM_InvalidPEM_ReturnsError(t *testing.T) {
	_, err := adapter.ParsePrivateKeyPEM([]byte("not a pem block"))
	if err == nil {
		t.Fatal("expected an error for invalid PEM input")
	}
}

func TestParsePublicKeyPEM_Valid(t *testing.T) {
	_, _, pubPEM := generateTestKeyPair(t)

	key, err := adapter.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestSignThenVerify_RoundTrips(t *testing.T) {
	priv, privPEM, pubPEM := generateTestKeyPair(t)
	_ = priv
	privKey, _ := adapter.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := adapter.ParsePublicKeyPEM(pubPEM)

	payload := []byte(`{"instance_id":"eu-cluster","summaries":[]}`)

	sig, err := adapter.Sign(payload, privKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !adapter.Verify(payload, sig, pubKey) {
		t.Fatal("expected signature to verify against the matching public key")
	}
}

func TestVerify_FailsAgainstDifferentKeyPair(t *testing.T) {
	_, privPEM, _ := generateTestKeyPair(t)
	_, _, otherPubPEM := generateTestKeyPair(t)

	privKey, _ := adapter.ParsePrivateKeyPEM(privPEM)
	otherPubKey, _ := adapter.ParsePublicKeyPEM(otherPubPEM)

	payload := []byte(`{"instance_id":"eu-cluster","summaries":[]}`)
	sig, _ := adapter.Sign(payload, privKey)

	if adapter.Verify(payload, sig, otherPubKey) {
		t.Fatal("expected verification to fail against an unrelated public key")
	}
}

func TestVerify_FailsOnTamperedPayload(t *testing.T) {
	priv, privPEM, pubPEM := generateTestKeyPair(t)
	_ = priv
	privKey, _ := adapter.ParsePrivateKeyPEM(privPEM)
	pubKey, _ := adapter.ParsePublicKeyPEM(pubPEM)

	payload := []byte(`{"instance_id":"eu-cluster","summaries":[]}`)
	sig, _ := adapter.Sign(payload, privKey)

	tampered := append([]byte(nil), payload...)
	tampered[0] = 'X'

	if adapter.Verify(tampered, sig, pubKey) {
		t.Fatal("expected verification to fail on a tampered payload")
	}
}
