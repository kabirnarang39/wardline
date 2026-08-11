package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestMultiOIDCBootstrapper_RoutesEachTokenToItsOwnIssuer(t *testing.T) {
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvA := newTestJWKSServer(t, keyA, "key-a")
	defer srvA.Close()
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvB := newTestJWKSServer(t, keyB, "key-b")
	defer srvB.Close()

	m, err := NewMultiOIDCBootstrapper([]OIDCProviderConfig{
		{Issuer: "https://idp-a.example.com/", JWKSURI: srvA.URL, Audience: "wardline", IdentityClaim: "sub", TenantClaim: "tenant"},
		{Issuer: "https://idp-b.example.com/", JWKSURI: srvB.URL, Audience: "wardline", IdentityClaim: "sub", TenantClaim: "tenant"},
	})
	if err != nil {
		t.Fatalf("NewMultiOIDCBootstrapper: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	tokenA := signTestIDToken(t, keyA, "key-a", "https://idp-a.example.com/", "wardline", "alice", "acme")
	identity, tenantName, err := m.Authenticate(tokenA)
	if err != nil || identity != "alice" || tenantName != "acme" {
		t.Fatalf("token from idp-a: got (%q, %q, %v), want (\"alice\", \"acme\", nil)", identity, tenantName, err)
	}

	tokenB := signTestIDToken(t, keyB, "key-b", "https://idp-b.example.com/", "wardline", "bob", "widgets-inc")
	identity, tenantName, err = m.Authenticate(tokenB)
	if err != nil || identity != "bob" || tenantName != "widgets-inc" {
		t.Fatalf("token from idp-b: got (%q, %q, %v), want (\"bob\", \"widgets-inc\", nil)", identity, tenantName, err)
	}
}

// TestMultiOIDCBootstrapper_TokenSignedByWrongProvidersKeyIsRejected is
// the actual security proof for issuer-based routing: a token whose
// "iss" claim names idp-a but is signed with idp-b's key (a forged/
// mismatched combination, not something a legitimate flow ever
// produces) must be rejected -- routing to idp-a's verifier and then
// failing signature verification there, never silently accepted.
func TestMultiOIDCBootstrapper_TokenSignedByWrongProvidersKeyIsRejected(t *testing.T) {
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvA := newTestJWKSServer(t, keyA, "key-a")
	defer srvA.Close()
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvB := newTestJWKSServer(t, keyB, "key-b")
	defer srvB.Close()

	m, err := NewMultiOIDCBootstrapper([]OIDCProviderConfig{
		{Issuer: "https://idp-a.example.com/", JWKSURI: srvA.URL, Audience: "wardline", IdentityClaim: "sub", TenantClaim: "tenant"},
		{Issuer: "https://idp-b.example.com/", JWKSURI: srvB.URL, Audience: "wardline", IdentityClaim: "sub", TenantClaim: "tenant"},
	})
	if err != nil {
		t.Fatalf("NewMultiOIDCBootstrapper: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// Claims "iss": idp-a (routes to idp-a's verifier) but signed with
	// idp-b's key -- idp-a's JWKS has no matching key for this
	// signature, so verification must fail.
	forged := signTestIDToken(t, keyB, "key-b", "https://idp-a.example.com/", "wardline", "mallory", "acme")
	if _, _, err := m.Authenticate(forged); err == nil {
		t.Fatal("expected rejection for a token whose issuer claim doesn't match the key that actually signed it")
	}
}

func TestMultiOIDCBootstrapper_UnknownIssuerRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	m, err := NewMultiOIDCBootstrapper([]OIDCProviderConfig{
		{Issuer: "https://idp-a.example.com/", JWKSURI: srv.URL, Audience: "wardline", IdentityClaim: "sub", TenantClaim: "tenant"},
	})
	if err != nil {
		t.Fatalf("NewMultiOIDCBootstrapper: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	token := signTestIDToken(t, key, "test-key", "https://not-configured.example.com/", "wardline", "alice", "acme")
	if _, _, err := m.Authenticate(token); err == nil {
		t.Fatal("expected rejection for a token from an issuer no provider is configured for")
	}
}

func TestNewMultiOIDCBootstrapper_DuplicateIssuerRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	_, err := NewMultiOIDCBootstrapper([]OIDCProviderConfig{
		{Issuer: "https://idp-a.example.com/", JWKSURI: srv.URL, Audience: "wardline", IdentityClaim: "sub", TenantClaim: "tenant"},
		{Issuer: "https://idp-a.example.com/", JWKSURI: srv.URL, Audience: "other-audience", IdentityClaim: "sub", TenantClaim: "tenant"},
	})
	if err == nil {
		t.Fatal("expected rejection for two providers declaring the same issuer")
	}
}

func TestMultiOIDCBootstrapper_MalformedTokenRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	m, err := NewMultiOIDCBootstrapper([]OIDCProviderConfig{
		{Issuer: "https://idp-a.example.com/", JWKSURI: srv.URL, Audience: "wardline", IdentityClaim: "sub", TenantClaim: "tenant"},
	})
	if err != nil {
		t.Fatalf("NewMultiOIDCBootstrapper: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	if _, _, err := m.Authenticate("not-a-jwt-at-all"); err == nil {
		t.Fatal("expected rejection for a malformed token that isn't even parseable")
	}
}
