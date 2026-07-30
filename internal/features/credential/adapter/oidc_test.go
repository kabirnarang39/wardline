package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
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

func TestOIDCBootstrapper_WrongIssuerRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	// Signed with a different issuer than the bootstrapper is configured
	// to require.
	token := signTestIDToken(t, key, "test-key", "https://someone-else.example.com/", "wardline", "alice", "acme")

	if _, _, err := b.Authenticate(token); err == nil {
		t.Fatal("expected rejection for wrong issuer")
	}
}

func TestOIDCBootstrapper_ExpiredTokenRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	signingKey, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "test-key"); err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewBuilder().
		Issuer("https://idp.example.com/").
		Audience([]string{"wardline"}).
		Subject("alice").
		Claim("tenant", "acme").
		IssuedAt(time.Now().Add(-2 * time.Hour)).
		Expiration(time.Now().Add(-time.Hour)).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := b.Authenticate(string(signed)); err == nil {
		t.Fatal("expected rejection for expired token")
	}
}

func TestOIDCBootstrapper_TamperedSignatureRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestJWKSServer(t, key, "test-key")
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	token := signTestIDToken(t, key, "test-key", "https://idp.example.com/", "wardline", "alice", "acme")
	// Flip a byte in the payload segment to invalidate the signature
	// without changing its length/shape.
	tampered := []byte(token)
	for i := len(tampered) - 5; i > 0; i-- {
		if tampered[i] != '.' {
			tampered[i] ^= 0x01
			break
		}
	}

	if _, _, err := b.Authenticate(string(tampered)); err == nil {
		t.Fatal("expected rejection for tampered signature")
	}
}

// TestNewOIDCBootstrapper_BadJWKSURIFailsFast is the C2 regression test:
// before the fix, jwk.Cache.Register's WithWaitReady(true) default
// retried a connection-refused jwks_uri forever because Register was
// given context.Background() (no deadline), hanging NewOIDCBootstrapper
// -- and therefore `wardline serve`/`validate-config` -- indefinitely.
// It must now return an error within jwksBootstrapTimeout, not hang.
func TestNewOIDCBootstrapper_BadJWKSURIFailsFast(t *testing.T) {
	// Bind and immediately close a listener so its port is refusing
	// connections (fast RST), the sharpest of the four failure modes the
	// review probed (black-hole IP, 404, connection-refused, non-JWKS
	// 200) -- all four share the same root cause and the same fix.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	badURI := "http://" + ln.Addr().String() + "/jwks"
	ln.Close()

	done := make(chan error, 1)
	go func() {
		_, err := NewOIDCBootstrapper("https://idp.example.com/", badURI, "wardline", "sub", "tenant")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for a connection-refused jwks_uri")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("NewOIDCBootstrapper hung past jwksBootstrapTimeout on a connection-refused jwks_uri")
	}
}

// TestNewOIDCBootstrapper_404JWKSURIFailsFast covers the same bug via a
// reachable host returning 404 -- the review found this hangs too, not
// just an unreachable host, because Register retries regardless of the
// specific HTTP failure.
func TestNewOIDCBootstrapper_404JWKSURIFailsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	done := make(chan error, 1)
	go func() {
		_, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for a 404 jwks_uri")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("NewOIDCBootstrapper hung past jwksBootstrapTimeout on a 404 jwks_uri")
	}
}
