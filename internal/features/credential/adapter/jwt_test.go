package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

func TestIssueAndVerify_RoundTripsTenant(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, err := iv.Issue("alice", "acme")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := iv.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "alice" || claims.Tenant != "acme" {
		t.Fatalf("got Subject=%q Tenant=%q, want alice/acme", claims.Subject, claims.Tenant)
	}
}

func TestJWTIssuerVerifier_RoundTrip(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token, err := iv.Issue("agent-abc123", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	claims, err := iv.Verify(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "agent-abc123" {
		t.Errorf("expected subject agent-abc123, got %q", claims.Subject)
	}
	if claims.ID == "" {
		t.Error("expected a non-empty jti")
	}
	if !claims.ExpiresAt.After(claims.IssuedAt) {
		t.Errorf("expected ExpiresAt after IssuedAt, got iat=%v exp=%v", claims.IssuedAt, claims.ExpiresAt)
	}
}

// TestJWTIssuerVerifier_Verify_NoTenantClaimDefaultsToTenantDefault is an
// I4 regression test: a pre-upgrade-issued token carries no "tenant"
// claim at all (unlike Issue's own output, which always sets an
// explicit, possibly-empty claim). Verify must default that absence to
// tenant.Default, consistent with every other read boundary in this
// codebase (jsonl_reader.go, postgres_writer.go's scan loop,
// HeaderIdentity.Authenticate) -- not leave it as "", which matches only
// untenanted policy rules and is invisible to every tenant-scoped
// dashboard view.
func TestJWTIssuerVerifier_Verify_NoTenantClaimDefaultsToTenantDefault(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Build a token deliberately without Issue, since Issue always sets
	// an explicit "tenant" claim -- this must simulate a genuinely absent
	// claim, the pre-upgrade-token shape.
	tok, err := jwt.NewBuilder().
		Subject("alice").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(iv.tokenTTL)).
		JwtID("pre-upgrade-jti").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), iv.privateKey))
	if err != nil {
		t.Fatal(err)
	}

	claims, err := iv.Verify(string(signed))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Tenant != tenant.Default {
		t.Fatalf("got Tenant=%q, want %q", claims.Tenant, tenant.Default)
	}
}

func TestJWTIssuerVerifier_TwoTokensHaveDifferentJTIs(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t1, _ := iv.Issue("agent-abc123", "")
	t2, _ := iv.Issue("agent-abc123", "")
	c1, err := iv.Verify(t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c2, err := iv.Verify(t2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c1.ID == c2.ID {
		t.Error("expected two issued tokens to have distinct jti values")
	}
}

func TestJWTIssuerVerifier_TamperedSignatureFails(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token, _ := iv.Issue("agent-abc123", "")
	// Flip the first character of the signature segment rather than the
	// token's last character. Base64url's trailing (partial) group has
	// decode don't-care bits — mutating the last char only changes the
	// decoded signature bytes ~55% of the time, making the test flaky.
	// The first char of the signature segment sits in a full 4-char/3-byte
	// group, so any single-character change there deterministically
	// changes the decoded signature bytes.
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 || len(parts[2]) == 0 {
		t.Fatalf("expected a 3-segment JWT with a non-empty signature, got %q", token)
	}
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	_, err = iv.Verify(tampered)
	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestJWTIssuerVerifier_SignedByDifferentKeyFails(t *testing.T) {
	iv1, _ := NewJWTIssuerVerifier("", time.Hour)
	iv2, _ := NewJWTIssuerVerifier("", time.Hour)
	token, _ := iv1.Issue("agent-abc123", "")
	_, err := iv2.Verify(token)
	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for a token signed by a different keypair, got %v", err)
	}
}

func TestJWTIssuerVerifier_ExpiredTokenFails(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", 15*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	iv.now = func() time.Time {
		return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	token, _ := iv.Issue("agent-abc123", "")
	iv.now = func() time.Time {
		return time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC) // 1h later, past the 15m TTL
	}
	_, err = iv.Verify(token)
	if !errors.Is(err, domain.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestJWTIssuerVerifier_MalformedTokenFails(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = iv.Verify("not-a-jwt-at-all")
	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}

func writeTestRSAKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write test key: %v", err)
	}
	return path
}

// writeTestRSAKeyPKCS1 mirrors writeTestRSAKey but encodes as PKCS1
// ("RSA PRIVATE KEY") instead of PKCS8 -- this is what `openssl genrsa`
// produces by default (the command this project's own README and Helm
// chart tell operators to run), so it needs its own coverage that
// doesn't depend on a real Postgres container to run.
func writeTestRSAKeyPKCS1(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write test key: %v", err)
	}
	return path
}

func TestNewJWTIssuerVerifier_EmptyPathGeneratesFreshKeyAsToday(t *testing.T) {
	j, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatalf("NewJWTIssuerVerifier(\"\"): %v", err)
	}
	token, err := j.Issue("agent-abc123", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := j.Verify(token); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestNewJWTIssuerVerifier_SameKeyFile_TwoInstancesVerifyEachOthersTokens(t *testing.T) {
	keyPath := writeTestRSAKey(t)

	replicaA, err := NewJWTIssuerVerifier(keyPath, time.Hour)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	replicaB, err := NewJWTIssuerVerifier(keyPath, time.Hour)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}

	token, err := replicaA.Issue("agent-abc123", "")
	if err != nil {
		t.Fatalf("Issue on replicaA: %v", err)
	}

	claims, err := replicaB.Verify(token)
	if err != nil {
		t.Fatalf("expected replicaB to verify a token issued by replicaA (same key file), got: %v", err)
	}
	if claims.Subject != "agent-abc123" {
		t.Errorf("unexpected subject: %q", claims.Subject)
	}
}

func TestNewJWTIssuerVerifier_DifferentKeyFiles_TokenFromOneFailsOnTheOther(t *testing.T) {
	keyPathA := writeTestRSAKey(t)
	keyPathB := writeTestRSAKey(t)

	replicaA, err := NewJWTIssuerVerifier(keyPathA, time.Hour)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	replicaB, err := NewJWTIssuerVerifier(keyPathB, time.Hour)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}

	token, err := replicaA.Issue("agent-abc123", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := replicaB.Verify(token); err == nil {
		t.Fatal("expected verification to fail across two different signing keys, got success")
	}
}

func TestNewJWTIssuerVerifier_MissingKeyFileErrors(t *testing.T) {
	_, err := NewJWTIssuerVerifier(filepath.Join(t.TempDir(), "does-not-exist.pem"), time.Hour)
	if err == nil {
		t.Fatal("expected an error for a missing key file")
	}
}

func TestNewJWTIssuerVerifier_MalformedKeyFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-key.pem")
	if err := os.WriteFile(path, []byte("not a real key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewJWTIssuerVerifier(path, time.Hour)
	if err == nil {
		t.Fatal("expected an error for a malformed key file")
	}
}

func TestNewJWTIssuerVerifier_PKCS1KeyFile_RoundTrips(t *testing.T) {
	keyPath := writeTestRSAKeyPKCS1(t, 2048)

	iv, err := NewJWTIssuerVerifier(keyPath, time.Hour)
	if err != nil {
		t.Fatalf("NewJWTIssuerVerifier with a PKCS1-encoded key: %v", err)
	}
	token, err := iv.Issue("agent-abc123", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := iv.Verify(token); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestNewJWTIssuerVerifier_PKCS1SameKeyFile_TwoInstancesVerifyEachOthersTokens(t *testing.T) {
	keyPath := writeTestRSAKeyPKCS1(t, 2048)

	replicaA, err := NewJWTIssuerVerifier(keyPath, time.Hour)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	replicaB, err := NewJWTIssuerVerifier(keyPath, time.Hour)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}

	token, err := replicaA.Issue("agent-abc123", "")
	if err != nil {
		t.Fatalf("Issue on replicaA: %v", err)
	}
	if _, err := replicaB.Verify(token); err != nil {
		t.Fatalf("expected replicaB to verify a PKCS1-key token issued by replicaA, got: %v", err)
	}
}

func TestNewJWTIssuerVerifier_WeakPKCS1KeyRejected(t *testing.T) {
	keyPath := writeTestRSAKeyPKCS1(t, 1024)

	_, err := NewJWTIssuerVerifier(keyPath, time.Hour)
	if err == nil {
		t.Fatal("expected a 1024-bit PKCS1 key to be rejected as below the minimum key size")
	}
}

func TestNewJWTIssuerVerifier_WeakPKCS8KeyRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write test key: %v", err)
	}

	_, err = NewJWTIssuerVerifier(path, time.Hour)
	if err == nil {
		t.Fatal("expected a 1024-bit PKCS8 key to be rejected as below the minimum key size")
	}
}

// TestJWTIssuerVerifier_IssuedTokenExpiresAtConfiguredTTL uses whole-second
// TTLs, not sub-second ones -- lestrrat-go/jwx/v3's NumericDate defaults to
// whole-second JSON precision, so a sub-second TTL is always instantly
// expired at verification regardless of how recently it was issued. This
// can never be reached through real config (CredentialConfig.
// AccessTokenTTLSeconds is an int, so the smallest non-zero configured TTL
// is exactly one whole second), but a test using a sub-second Duration
// directly would spuriously fail on this jwx precision behavior rather
// than testing anything real -- use realistic, config-shaped values here.
func TestJWTIssuerVerifier_IssuedTokenExpiresAtConfiguredTTL(t *testing.T) {
	iv, err := NewJWTIssuerVerifier("", 2*time.Second)
	if err != nil {
		t.Fatalf("NewJWTIssuerVerifier: %v", err)
	}
	token, err := iv.Issue("agent-abc123", "acme")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := iv.Verify(token); err != nil {
		t.Fatalf("expected token to verify immediately after issuance, got %v", err)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err := iv.Verify(token); !errors.Is(err, domain.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired after the configured TTL elapsed, got %v", err)
	}
}

// TestJWTIssuerVerifier_DifferentConfiguredTTLsProduceDifferentExpiryWindows
// also uses a whole-second short TTL, for the same reason (see the
// preceding test's doc comment).
func TestJWTIssuerVerifier_DifferentConfiguredTTLsProduceDifferentExpiryWindows(t *testing.T) {
	short, err := NewJWTIssuerVerifier("", time.Second)
	if err != nil {
		t.Fatalf("NewJWTIssuerVerifier (short): %v", err)
	}
	long, err := NewJWTIssuerVerifier("", time.Hour)
	if err != nil {
		t.Fatalf("NewJWTIssuerVerifier (long): %v", err)
	}
	shortToken, err := short.Issue("agent-abc123", "acme")
	if err != nil {
		t.Fatalf("Issue (short): %v", err)
	}
	longToken, err := long.Issue("agent-abc123", "acme")
	if err != nil {
		t.Fatalf("Issue (long): %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := short.Verify(shortToken); !errors.Is(err, domain.ErrTokenExpired) {
		t.Errorf("expected the short-TTL token to have expired, got %v", err)
	}
	if _, err := long.Verify(longToken); err != nil {
		t.Errorf("expected the long-TTL token to still verify, got %v", err)
	}
}
