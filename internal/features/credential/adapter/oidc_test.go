package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// newTestJWKSServer serves a JWKS containing priv's public key, tagged
// with kid and alg (both required for jwt.WithKeySet's verification to
// pick the right key and trust its algorithm).
func newTestJWKSServer(t *testing.T, priv *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
}

// signTestIDToken signs a JWKS-verifiable ID token. tenantValue == ""
// omits the "tenant" claim entirely (to test the missing-claim path).
func signTestIDToken(t *testing.T, priv *rsa.PrivateKey, kid, issuer, audience, sub, tenantValue string) string {
	t.Helper()
	signingKey, err := jwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}

	b := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{audience}).
		Subject(sub).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour))
	if tenantValue != "" {
		b = b.Claim("tenant", tenantValue)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestOIDCBootstrapper_ValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	token := signTestIDToken(t, key, "test-key", "https://idp.example.com/", "wardline", "alice", "acme")

	identity, tenantName, err := b.Authenticate(token)
	if err != nil || identity != "alice" || tenantName != "acme" {
		t.Fatalf("got (%q, %q, %v), want (\"alice\", \"acme\", nil)", identity, tenantName, err)
	}
}

func TestOIDCBootstrapper_WrongAudienceRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	token := signTestIDToken(t, key, "test-key", "https://idp.example.com/", "someone-else", "alice", "acme")

	if _, _, err := b.Authenticate(token); err == nil {
		t.Fatal("expected rejection for wrong audience")
	}
}

func TestOIDCBootstrapper_MissingTenantClaimRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	token := signTestIDToken(t, key, "test-key", "https://idp.example.com/", "wardline", "alice", "")

	if _, _, err := b.Authenticate(token); err == nil {
		t.Fatal("expected rejection for missing tenant claim")
	}
}
