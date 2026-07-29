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

// ParsePrivateKeyPEM parses a PEM-encoded RSA private key in either
// PKCS1 or PKCS8 form -- the same two shapes an operator might already
// have from generating credential/adapter's own signing key, but parsed
// independently here rather than importing that (unexported, private-
// key-only) parser. See design doc for why this is a small local
// helper, not a shared platform dependency.
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

// ParsePublicKeyPEM parses a PEM-encoded RSA public key in PKIX form
// (the standard "PUBLIC KEY" PEM block Go's x509.MarshalPKIXPublicKey
// produces).
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

// Sign produces an RSA-PSS signature over sha256(payload) -- PSS rather
// than PKCS1v15 because it's the modern, recommended RSA signature
// scheme (randomized, no known weaknesses PKCS1v15 signing has in
// certain misuse contexts) and Verify below uses the matching PSS
// verification.
func Sign(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}
	return sig, nil
}

// Verify reports whether signature is a valid RSA-PSS signature over
// sha256(payload) under key. Never returns an error -- callers
// (Handler) treat any failure to verify as "reject", not as a
// distinguishable error case, matching the existing credential
// verification posture of collapsing "malformed" and "wrong key" into
// one reject outcome.
func Verify(payload, signature []byte, key *rsa.PublicKey) bool {
	digest := sha256.Sum256(payload)
	err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, nil)
	return err == nil
}
