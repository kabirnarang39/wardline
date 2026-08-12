package adapter

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// rsaKeyBits is the RSA modulus size for the in-process signing keypair.
// 2048 is the current minimum considered secure for RS256.
const rsaKeyBits = 2048

// verifyKey is one public key accepted for verification, plus its kid.
type verifyKey struct {
	kid    string
	public *rsa.PublicKey
}

// JWTIssuerVerifier signs and verifies RS256 JWTs with an RSA keypair.
// When keyPath is empty, the keypair is generated fresh at construction
// -- restarting the process (or running a second replica) invalidates
// every outstanding token, since no two processes share it. When keyPath
// names a PEM-encoded RSA private key (PKCS1 or PKCS8), every process
// loading the same file signs and verifies with the identical keypair --
// a token issued by one replica verifies correctly on another, since
// they're mounted from the same Kubernetes Secret.
//
// previousKeyPaths (optional) names PEM files whose keys are accepted for
// VERIFICATION ONLY, never for signing new tokens -- the key-rotation
// window. An operator rotates by generating a new key, moving the old
// signing_key_file into previous_signing_key_files, pointing
// signing_key_file at the new key, and redeploying: every outstanding
// token signed under the old key keeps verifying (up to its own TTL)
// while every new token is signed under the new key. See the design doc
// (docs/superpowers/specs/2026-08-08-ha-rotation-blockstate-design.md).
//
// Every issued token carries a "kid" (key ID) header -- a content hash of
// the signing public key's DER encoding, so Verify looks up the exact
// key rather than trying each in turn, and every replica derives an
// identical kid for an identical key file with no operator-facing
// identifier to keep in sync.
type JWTIssuerVerifier struct {
	// signer is whatever holds the signing private key -- a local
	// *rsa.PrivateKey (the default, in-process-generated or loaded from
	// keyPath) or a KMSSigner (credential.kms configured instead of
	// signing_key_file), both of which satisfy crypto.Signer. Sign is
	// the ONLY place this distinction matters: everything else (Verify,
	// JWKS, key rotation) already worked against a public key alone,
	// unaffected by where the private half actually lives. jwx/v3's jws
	// package documents crypto.Signer as a first-class key type
	// specifically for "KMS-backed adapters" -- this is that extension
	// point, not a workaround.
	signer     crypto.Signer
	signingKID string
	// verifyKeys is every public key accepted for verification, keyed by
	// kid -- always includes the signing key's own, plus every
	// previousKeyPaths entry. Ordered (verifyOrder) for a deterministic
	// fallback when a token carries no kid header.
	verifyKeys  map[string]*rsa.PublicKey
	verifyOrder []verifyKey
	tokenTTL    time.Duration
	now         func() time.Time
}

// NewJWTIssuerVerifier builds an issuer/verifier signing with the key at
// keyPath (or a fresh generated key when keyPath is empty), additionally
// accepting the keys at previousKeyPaths for verification only.
func NewJWTIssuerVerifier(keyPath string, previousKeyPaths []string, tokenTTL time.Duration) (*JWTIssuerVerifier, error) {
	var signingKey *rsa.PrivateKey
	if keyPath == "" {
		key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, fmt.Errorf("generate signing keypair: %w", err)
		}
		signingKey = key
	} else {
		key, err := loadRSAPrivateKeyFile(keyPath)
		if err != nil {
			return nil, err
		}
		signingKey = key
	}
	return newJWTIssuerVerifierFromSigner(signingKey, previousKeyPaths, tokenTTL)
}

// NewJWTIssuerVerifierWithSigner builds an issuer/verifier whose signing
// private key lives entirely behind signer (never in this process's own
// memory) -- KMSSigner is the shipped implementation, but any
// crypto.Signer over an RSA key works identically, matching jwx/v3's own
// documented "crypto.Signer (e.g. KMS-backed adapters)" extension point.
// previousKeyPaths still accepts local PEM files for verification-only,
// same rotation-window semantics as NewJWTIssuerVerifier -- a rotation
// FROM a local key TO a KMS-backed one (or the reverse) works exactly
// like rotating between two local keys, since Verify never cares where
// a key's private half lives, only its public half.
func NewJWTIssuerVerifierWithSigner(signer crypto.Signer, previousKeyPaths []string, tokenTTL time.Duration) (*JWTIssuerVerifier, error) {
	return newJWTIssuerVerifierFromSigner(signer, previousKeyPaths, tokenTTL)
}

func newJWTIssuerVerifierFromSigner(signer crypto.Signer, previousKeyPaths []string, tokenTTL time.Duration) (*JWTIssuerVerifier, error) {
	signingPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not an RSA public key (got %T) -- only RS256 is supported", signer.Public())
	}
	if bits := signingPub.N.BitLen(); bits < rsaKeyBits {
		return nil, fmt.Errorf("signing key is %d bits, minimum %d required for RS256 signing", bits, rsaKeyBits)
	}

	signingKID := publicKeyID(signingPub)
	verifyKeys := map[string]*rsa.PublicKey{signingKID: signingPub}
	verifyOrder := []verifyKey{{kid: signingKID, public: signingPub}}

	for _, p := range previousKeyPaths {
		key, err := loadRSAPrivateKeyFile(p)
		if err != nil {
			return nil, fmt.Errorf("previous signing key: %w", err)
		}
		kid := publicKeyID(&key.PublicKey)
		if _, exists := verifyKeys[kid]; exists {
			// The same key listed twice (or a previous key identical to
			// the primary) is harmless -- dedupe rather than error, so an
			// operator mid-rotation who hasn't yet dropped the now-primary
			// key from the previous list isn't blocked from starting.
			continue
		}
		verifyKeys[kid] = &key.PublicKey
		verifyOrder = append(verifyOrder, verifyKey{kid: kid, public: &key.PublicKey})
	}

	return &JWTIssuerVerifier{
		signer:      signer,
		signingKID:  signingKID,
		verifyKeys:  verifyKeys,
		verifyOrder: verifyOrder,
		tokenTTL:    tokenTTL,
		now:         time.Now,
	}, nil
}

// loadRSAPrivateKeyFile reads and parses a PEM RSA private key file.
func loadRSAPrivateKeyFile(keyPath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read signing key file %s: %w", keyPath, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing key file %s: no PEM block found", keyPath)
	}
	key, err := parseRSAPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key file %s: %w", keyPath, err)
	}
	return key, nil
}

// publicKeyID derives a stable key ID from an RSA public key: the first
// 16 bytes of SHA-256 over its PKIX DER encoding, hex-encoded. Every
// process derives the identical kid for the identical key, with no
// operator-facing identifier to configure -- the same "content, not a
// configured name, is the identity" property cross-replica verification
// already relies on for the key material itself.
func publicKeyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// MarshalPKIXPublicKey only errors on an unsupported key type;
		// *rsa.PublicKey is always supported, so this is unreachable.
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:16])
}

// parseRSAPrivateKey accepts both PKCS1 ("RSA PRIVATE KEY") and PKCS8
// ("PRIVATE KEY") PEM encodings -- openssl genrsa produces PKCS1 by
// default, but PKCS8 is the more modern/general encoding, so both are
// worth accepting rather than forcing an operator to know which their
// tool produced. Every key returned from here, however it was encoded,
// is checked against rsaKeyBits -- unlike the generated-fresh path
// (which always produces a 2048-bit key by construction), an
// operator-supplied key file could be anything, and a long-lived,
// cross-replica-shared signing key is exactly the wrong place to
// silently accept one weaker than what this project generates itself.
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	pkcs1Key, pkcs1Err := x509.ParsePKCS1PrivateKey(der)
	if pkcs1Err == nil {
		return checkRSAKeySize(pkcs1Key)
	}
	parsed, pkcs8Err := x509.ParsePKCS8PrivateKey(der)
	if pkcs8Err != nil {
		return nil, fmt.Errorf("not a valid PKCS1 (%v) or PKCS8 (%w) RSA private key", pkcs1Err, pkcs8Err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key (got %T)", parsed)
	}
	return checkRSAKeySize(rsaKey)
}

// checkRSAKeySize rejects an operator-supplied key weaker than
// rsaKeyBits -- the same floor this package already enforces on the
// keypair it generates itself when keyPath is empty.
func checkRSAKeySize(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if bits := key.N.BitLen(); bits < rsaKeyBits {
		return nil, fmt.Errorf("RSA key is %d bits, minimum %d required for RS256 signing", bits, rsaKeyBits)
	}
	return key, nil
}

func (j *JWTIssuerVerifier) Issue(identity, tenantName string) (string, error) {
	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	now := j.now()
	token, err := jwt.NewBuilder().
		Subject(identity).
		Claim("tenant", tenantName).
		IssuedAt(now).
		Expiration(now.Add(j.tokenTTL)).
		JwtID(jti).
		Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}
	// Embed the signing key's kid in the JWS protected header, so Verify
	// (here or on another replica) can select the exact key rather than
	// trying each in turn.
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, j.signingKID); err != nil {
		return "", fmt.Errorf("set kid header: %w", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), j.signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return string(signed), nil
}

func (j *JWTIssuerVerifier) Verify(token string) (domain.Claims, error) {
	pub, err := j.verifyKeyFor(token)
	if err != nil {
		return domain.Claims{}, fmt.Errorf("%w: %v", domain.ErrTokenInvalid, err)
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256(), pub))
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			return domain.Claims{}, fmt.Errorf("%w: %v", domain.ErrTokenExpired, err)
		}
		return domain.Claims{}, fmt.Errorf("%w: %v", domain.ErrTokenInvalid, err)
	}
	sub, _ := parsed.Subject()
	iat, _ := parsed.IssuedAt()
	exp, _ := parsed.Expiration()
	jti, _ := parsed.JwtID()
	var tenantName string
	_ = parsed.Get("tenant", &tenantName)
	if tenantName == "" {
		// A pre-upgrade-issued token (or any token that otherwise lacks
		// a "tenant" claim) must default the same way every other read
		// boundary in this codebase does (jsonl_reader.go,
		// postgres_writer.go's scan loop, HeaderIdentity.Authenticate)
		// -- an empty tenant is a distinct, dangerous value (it matches
		// only untenanted policy rules and reads as globally-invisible
		// to every tenant-scoped dashboard view), not an equivalent one.
		// This is specific to Wardline's own reissued JWTs: the OIDC
		// bootstrapper's Authenticate deliberately does NOT default an
		// absent tenant claim -- an SSO-sourced identity with no tenant
		// is rejected outright, a different and deliberate design choice.
		tenantName = tenant.Default
	}
	return domain.Claims{Subject: sub, Tenant: tenantName, IssuedAt: iat, ExpiresAt: exp, ID: jti}, nil
}

// verifyKeyFor selects the public key to verify token against: the one
// whose kid matches the token's "kid" header, or -- when the token
// carries no kid (a token issued before this rotation support existed,
// or by a non-Wardline issuer) -- a fallback that accepts any configured
// key. The fallback tries each key in verifyOrder and returns the first
// whose signature validates, so an old, kid-less token still verifies
// under whichever configured key actually signed it.
func (j *JWTIssuerVerifier) verifyKeyFor(token string) (*rsa.PublicKey, error) {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("parse jws: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, errors.New("token has no signature")
	}
	if kid, ok := sigs[0].ProtectedHeaders().KeyID(); ok && kid != "" {
		if pub, found := j.verifyKeys[kid]; found {
			return pub, nil
		}
		return nil, fmt.Errorf("no configured key matches token kid %q", kid)
	}
	// No kid header: fall back to trying each configured key. jwt.Parse
	// does the real cryptographic verification; here we only need to find
	// which key it accepts, so the caller can pass exactly that one.
	for _, vk := range j.verifyOrder {
		if _, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256(), vk.public), jwt.WithValidate(false)); err == nil {
			return vk.public, nil
		}
	}
	return nil, errors.New("no configured key verifies this token")
}

// JWKS returns every currently-valid verification key (the signing key
// plus every previous key) as a JWK set, for serving at
// GET /credentials/jwks. Public keys only -- a JWK set never carries
// private material.
func (j *JWTIssuerVerifier) JWKS() (jwk.Set, error) {
	set := jwk.NewSet()
	for _, vk := range j.verifyOrder {
		key, err := jwk.Import(vk.public)
		if err != nil {
			return nil, fmt.Errorf("import public key %s: %w", vk.kid, err)
		}
		if err := key.Set(jwk.KeyIDKey, vk.kid); err != nil {
			return nil, fmt.Errorf("set kid on jwk: %w", err)
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			return nil, fmt.Errorf("set alg on jwk: %w", err)
		}
		if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
			return nil, fmt.Errorf("set use on jwk: %w", err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("add key to set: %w", err)
		}
	}
	return set, nil
}

func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
