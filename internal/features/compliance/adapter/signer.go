package adapter

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParsePrivateKeyPEM/ParsePublicKeyPEM/Sign/Verify are a deliberate local
// duplicate of federation/adapter/signer.go's identically-named
// functions, same RSA-PSS-over-SHA256 scheme -- not a shared import.
// federation/usecase/publisher.go's own rsaSignPSS already establishes
// why: a cross-feature adapter import breaks the feature-sliced "own
// your full vertical" rule (CLAUDE.md) just as much as a usecase
// importing an adapter would. See
// docs/superpowers/specs/2026-08-08-compliance-evidence-export-hardening-design.md
// Scope §1 for why this stays a local duplicate rather than a new
// internal/platform/signing package.

// ParsePrivateKeyPEM parses a PEM-encoded RSA private key in either
// PKCS1 or PKCS8 form.
func ParsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key (tried PKCS1 and PKCS8): %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}
	return rsaKey, nil
}

// ParsePublicKeyPEM parses a PEM-encoded RSA public key in PKIX form.
func ParsePublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an RSA key")
	}
	return rsaKey, nil
}

// Sign produces an RSA-PSS signature over sha256(payload).
func Sign(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}
	return sig, nil
}

// Verify reports whether signature is a valid RSA-PSS signature over
// sha256(payload) under key.
func Verify(payload, signature []byte, key *rsa.PublicKey) bool {
	digest := sha256.Sum256(payload)
	err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, nil)
	return err == nil
}
