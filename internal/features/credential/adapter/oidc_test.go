package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
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
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

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

// newTestDiscoveryServer serves both a JWKS (containing priv's public
// key) and a standard OIDC discovery document at
// /.well-known/openid-configuration whose jwks_uri points back at its
// own /jwks path -- one server standing in for a real IdP that serves
// both endpoints. issuerOverride, if non-empty, is what the discovery
// document claims as its own "issuer" -- empty means "the server's own
// URL" (the normal, matching case); tests that need to prove a mismatch
// is rejected pass a different value.
func newTestDiscoveryServer(t *testing.T, priv *rsa.PrivateKey, kid, issuerOverride string) *httptest.Server {
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

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := issuerOverride
		if issuer == "" {
			issuer = srv.URL
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"jwks_uri":               srv.URL + "/jwks",
			"authorization_endpoint": srv.URL + "/authorize", // unused field, proves unknown-field tolerance
		})
	})
	srv = httptest.NewServer(mux)
	return srv
}

// TestNewOIDCBootstrapper_DiscoversJWKSURIWhenEmpty is discovery's actual
// point: leaving OIDCConfig.JWKSURI empty still produces a working
// bootstrapper, end to end (a real token signed by the discovered key
// verifies successfully) -- jwks_uri never named explicitly anywhere in
// this test.
func TestNewOIDCBootstrapper_DiscoversJWKSURIWhenEmpty(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestDiscoveryServer(t, key, "test-key", "")
	defer srv.Close()

	b, err := NewOIDCBootstrapper(srv.URL, "", "wardline", "sub", "tenant")
	if err != nil {
		t.Fatalf("NewOIDCBootstrapper with empty jwks_uri: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	token := signTestIDToken(t, key, "test-key", srv.URL, "wardline", "alice", "acme")
	identity, tenantName, err := b.Authenticate(token)
	if err != nil || identity != "alice" || tenantName != "acme" {
		t.Fatalf("got (%q, %q, %v), want (\"alice\", \"acme\", nil)", identity, tenantName, err)
	}
}

// TestNewOIDCBootstrapper_DiscoveryIssuerMismatchRejected pins
// discoverJWKSURI's own defense-in-depth check (OpenID Connect Discovery
// 1.0 §4.3): a discovery document whose declared issuer doesn't match
// the issuer this bootstrapper was configured to trust must be rejected
// outright, not silently used.
func TestNewOIDCBootstrapper_DiscoveryIssuerMismatchRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newTestDiscoveryServer(t, key, "test-key", "https://attacker.example.com/")
	defer srv.Close()

	_, err := NewOIDCBootstrapper(srv.URL, "", "wardline", "sub", "tenant")
	if err == nil {
		t.Fatal("expected an error for a discovery document declaring a mismatched issuer")
	}
}

// TestNewOIDCBootstrapper_DiscoveryMissingJWKSURIRejected covers a
// malformed discovery document (issuer matches, but no jwks_uri at all)
// -- a real IdP is never expected to omit it, but this bootstrapper must
// fail closed rather than silently registering an empty jwks_uri.
func TestNewOIDCBootstrapper_DiscoveryMissingJWKSURIRejected(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	_, err := NewOIDCBootstrapper(srv.URL, "", "wardline", "sub", "tenant")
	if err == nil {
		t.Fatal("expected an error for a discovery document with no jwks_uri")
	}
}

// TestNewOIDCBootstrapper_Discovery404FailsFast covers an issuer with no
// discovery endpoint at all (a common misconfiguration: issuer set to
// the wrong URL, or an IdP that genuinely doesn't support discovery) --
// must fail fast at construction, not hang or silently proceed with an
// empty jwks_uri.
func TestNewOIDCBootstrapper_Discovery404FailsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := NewOIDCBootstrapper(srv.URL, "", "wardline", "sub", "tenant")
	if err == nil {
		t.Fatal("expected an error for a 404 discovery document")
	}
}

// buildJWKSet mirrors newTestJWKSServer's key-building logic for more
// than one key at once -- newRotatingTestJWKSServer below needs to serve
// a set that grows across a test.
func buildJWKSet(t *testing.T, keys map[string]*rsa.PrivateKey) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	for kid, priv := range keys {
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
		if err := set.AddKey(pub); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

// newRotatingTestJWKSServer serves whatever jwk.Set setFn returns at
// request time (a closure over a variable the test mutates), and counts
// how many times it was actually hit -- newTestJWKSServer's set is fixed
// for the server's whole life, which can't model a real IdP adding a
// signing key mid-run.
func newRotatingTestJWKSServer(t *testing.T, setFn func() jwk.Set) (srv *httptest.Server, hits *atomic.Int64) {
	t.Helper()
	hits = &atomic.Int64{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(setFn())
	}))
	return srv, hits
}

// TestOIDCBootstrapper_KeyRotationForcesRefreshAndVerifies proves the
// real-world Azure AD / Okta / Auth0 key-rollover case: an IdP adds a new
// signing key to its JWKS (real rotations add before removing, so the
// old key stays valid too) and starts issuing tokens signed with it
// immediately -- well before this bootstrapper's own jwksRefreshInterval
// (15 minutes) would have picked it up on its own. Without the forced-
// refresh-on-failure retry, every such token would be spuriously
// rejected for up to 15 minutes after a real rotation.
func TestOIDCBootstrapper_KeyRotationForcesRefreshAndVerifies(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	current := buildJWKSet(t, map[string]*rsa.PrivateKey{"key-a": keyA})
	srv, hits := newRotatingTestJWKSServer(t, func() jwk.Set {
		mu.Lock()
		defer mu.Unlock()
		return current
	})
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch at construction, got %d", got)
	}

	// The IdP rotates: key-b is added (key-a stays, matching every real
	// IdP's overlap-window rollover) -- but wardline's cache doesn't know
	// yet, and won't for up to 15 minutes on its own schedule.
	mu.Lock()
	current = buildJWKSet(t, map[string]*rsa.PrivateKey{"key-a": keyA, "key-b": keyB})
	mu.Unlock()

	token := signTestIDToken(t, keyB, "key-b", "https://idp.example.com/", "wardline", "alice", "acme")
	identity, tenantName, err := b.Authenticate(token)
	if err != nil {
		t.Fatalf("expected a token signed with a freshly rotated-in key to verify via forced refresh, got error: %v", err)
	}
	if identity != "alice" || tenantName != "acme" {
		t.Fatalf("got (%q, %q), want (\"alice\", \"acme\")", identity, tenantName)
	}
}

// TestOIDCBootstrapper_ForceRefreshIsRateLimited proves the other half of
// the contract: a flood of tokens signed with a truly-unknown key (an
// attacker's own key, not a real rotation) triggers at most one extra
// JWKS fetch, not one per rejected token -- forceRefreshCooldown must
// actually bound the cost against the IdP.
func TestOIDCBootstrapper_ForceRefreshIsRateLimited(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv, hits := newRotatingTestJWKSServer(t, func() jwk.Set {
		return buildJWKSet(t, map[string]*rsa.PrivateKey{"key-a": keyA})
	})
	defer srv.Close()

	b, err := NewOIDCBootstrapper("https://idp.example.com/", srv.URL, "wardline", "sub", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	hits.Store(0) // ignore the construction-time fetch, count only Authenticate-triggered ones

	bogus := signTestIDToken(t, attackerKey, "attacker-key", "https://idp.example.com/", "wardline", "alice", "acme")
	for range 20 {
		if _, _, err := b.Authenticate(bogus); err == nil {
			t.Fatal("expected every attacker-signed token to be rejected")
		}
	}
	// Exactly one of the 20 rejections should have won the CAS and forced
	// a refresh; the other 19 fall straight through to rejection.
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 forced JWKS refresh across 20 failures within the cooldown, got %d", got)
	}
}

// TestOIDCBootstrapper_MultipleAudiencesAccepted covers a real,
// documented OIDC behavior (RFC 7519 §4.1.3: "aud" MAY be an array, and
// the token is valid for the relying party if its identifier appears
// anywhere in it) that several real IdPs exercise when a token is issued
// for more than one resource at once (Azure AD v1 tokens and
// multi-resource Auth0 configurations both do this) -- wardline's own
// configured audience must not be required to be the *only* entry.
func TestOIDCBootstrapper_MultipleAudiencesAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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
		Audience([]string{"some-other-resource", "wardline"}).
		Subject("alice").
		Claim("tenant", "acme").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}

	identity, tenantName, err := b.Authenticate(string(signed))
	if err != nil {
		t.Fatalf("expected acceptance when wardline's audience is one of several entries, got: %v", err)
	}
	if identity != "alice" || tenantName != "acme" {
		t.Fatalf("got (%q, %q), want (\"alice\", \"acme\")", identity, tenantName)
	}
}

// TestOIDCBootstrapper_BareStringAudienceAccepted covers the other legal
// form RFC 7519 §4.1.3 allows: "aud" as a single non-array string, which
// is what Google's own ID tokens use (aud is the bare client ID, never
// wrapped in a list) rather than the array form jwt.Builder always
// produces (see the wire-format note on signTestIDToken's Audience
// call) -- hand-builds the JWT below since the builder can't produce
// this shape, to prove the underlying jwx parser (not just this
// bootstrapper's own code) accepts it.
func TestOIDCBootstrapper_BareStringAudienceAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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
	now := time.Now()
	payload := fmt.Sprintf(
		`{"iss":"https://idp.example.com/","aud":"wardline","sub":"alice","tenant":"acme","iat":%d,"exp":%d}`,
		now.Unix(), now.Add(time.Hour).Unix(),
	)
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}

	identity, tenantName, err := b.Authenticate(string(signed))
	if err != nil {
		t.Fatalf("expected acceptance of a bare-string (non-array) aud claim, got: %v", err)
	}
	if identity != "alice" || tenantName != "acme" {
		t.Fatalf("got (%q, %q), want (\"alice\", \"acme\")", identity, tenantName)
	}
}
