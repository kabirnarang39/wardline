package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// tokenTTL is a fixed 15-minute lifetime for every issued token this
// cycle — not yet operator-configurable, see the design doc's "Out of
// scope". Also read directly by http_handler.go (same package) to size a
// revocation entry's expiry.
const tokenTTL = 15 * time.Minute

// rsaKeyBits is the RSA modulus size for the in-process signing keypair.
// 2048 is the current minimum considered secure for RS256.
const rsaKeyBits = 2048

// JWTIssuerVerifier signs and verifies RS256 JWTs with an RSA keypair.
// When keyPath is empty, the keypair is generated fresh at construction
// -- restarting the process (or running a second replica) invalidates
// every outstanding token, since no two processes share it. When keyPath
// names a PEM-encoded RSA private key (PKCS1 or PKCS8), every process
// loading the same file signs and verifies with the identical keypair --
// a token issued by one replica verifies correctly on another, since
// they're mounted from the same Kubernetes Secret. See the design doc's
// "Config" section for the full HA rationale and the operator-facing
// warning logged when keyPath is empty (cmd/wardline/main.go).
type JWTIssuerVerifier struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewJWTIssuerVerifier(keyPath string) (*JWTIssuerVerifier, error) {
	if keyPath == "" {
		key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, fmt.Errorf("generate signing keypair: %w", err)
		}
		return &JWTIssuerVerifier{privateKey: key, now: time.Now}, nil
	}

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
	return &JWTIssuerVerifier{privateKey: key, now: time.Now}, nil
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
		Expiration(now.Add(tokenTTL)).
		JwtID(jti).
		Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), j.privateKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return string(signed), nil
}

func (j *JWTIssuerVerifier) Verify(token string) (domain.Claims, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256(), &j.privateKey.PublicKey))
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

func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
