package adapter

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// tokenTTL is a fixed 15-minute lifetime for every issued token this
// cycle — not yet operator-configurable, see the design doc's "Out of
// scope". Also read directly by http_handler.go (same package) to size a
// revocation entry's expiry.
const tokenTTL = 15 * time.Minute

// rsaKeyBits is the RSA modulus size for the in-process signing keypair.
// 2048 is the current minimum considered secure for RS256.
const rsaKeyBits = 2048

// JWTIssuerVerifier signs and verifies RS256 JWTs with an RSA keypair
// generated once at construction — restarting the process invalidates
// every outstanding token, an accepted consequence of the "no shared
// state across restarts" posture already true of the budget limiter and
// dashboard ring buffer (see design doc "Config").
type JWTIssuerVerifier struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewJWTIssuerVerifier() (*JWTIssuerVerifier, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate signing keypair: %w", err)
	}
	return &JWTIssuerVerifier{privateKey: key, now: time.Now}, nil
}

func (j *JWTIssuerVerifier) Issue(identity string) (string, error) {
	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	now := j.now()
	token, err := jwt.NewBuilder().
		Subject(identity).
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
	return domain.Claims{Subject: sub, IssuedAt: iat, ExpiresAt: exp, ID: jti}, nil
}

func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
