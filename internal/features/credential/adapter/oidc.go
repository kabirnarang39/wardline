package adapter

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

var _ domain.Bootstrapper = (*OIDCBootstrapper)(nil)

// jwksRefreshInterval bounds how often the OIDC bootstrapper re-fetches
// the IdP's JWKS -- long enough to avoid hammering the IdP on every
// login, short enough that a real key rotation (which every major IdP
// performs periodically) is picked up without an operator restart.
const jwksRefreshInterval = 15 * time.Minute

// jwksBootstrapTimeout bounds the first, blocking JWKS fetch. Any
// jwks_uri problem (unreachable, refused, 404, non-JWKS body) otherwise
// blocks Register forever -- jwk.Cache.Register defaults to
// WithWaitReady(true), which honours only the context it is given.
const jwksBootstrapTimeout = 10 * time.Second

// OIDCBootstrapper verifies an OIDC ID token (passed as the "secret" to
// Authenticate, matching Bootstrapper's existing shape) against a
// statically-configured issuer/JWKS/audience -- no discovery-document
// fetching this cycle (see design doc "Out of scope"). identityClaim and
// tenantClaim name which token claims carry the resolved identity and
// tenant; tenantClaim is required present on every token -- an
// SSO-sourced identity with no tenant is rejected outright, not silently
// defaulted, unlike a credentials.yaml entry (see design doc's OIDC
// architecture note).
type OIDCBootstrapper struct {
	issuer        string
	audience      string
	identityClaim string
	tenantClaim   string
	cache         *jwk.Cache
	jwksURI       string
}

func NewOIDCBootstrapper(issuer, jwksURI, audience, identityClaim, tenantClaim string) (*OIDCBootstrapper, error) {
	// Unbounded on purpose: this context owns the cache's background
	// refresh loop for the process's whole life. Only Register below
	// gets a deadline.
	cache, err := jwk.NewCache(context.Background(), httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("create jwks cache: %w", err)
	}
	regCtx, cancel := context.WithTimeout(context.Background(), jwksBootstrapTimeout)
	defer cancel()
	if err := cache.Register(regCtx, jwksURI, jwk.WithConstantInterval(jwksRefreshInterval)); err != nil {
		_ = cache.Shutdown(context.Background())
		return nil, fmt.Errorf("register jwks uri %s: %w", jwksURI, err)
	}
	return &OIDCBootstrapper{
		issuer:        issuer,
		audience:      audience,
		identityClaim: identityClaim,
		tenantClaim:   tenantClaim,
		cache:         cache,
		jwksURI:       jwksURI,
	}, nil
}

// Close shuts down the JWKS cache's background refresh goroutines.
// main.go must register this as a Closer next to revokerCloser (Task 8),
// same shutdown-hygiene pattern as PostgresRevoker.
func (o *OIDCBootstrapper) Close() error {
	return o.cache.Shutdown(context.Background())
}

func (o *OIDCBootstrapper) Authenticate(idToken string) (string, string, error) {
	keySet, err := o.cache.Lookup(context.Background(), o.jwksURI)
	if err != nil {
		return "", "", fmt.Errorf("fetch jwks: %w", err)
	}
	parsed, err := jwt.Parse([]byte(idToken),
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(o.issuer),
		jwt.WithAudience(o.audience),
	)
	if err != nil {
		// The 401 returned to the caller stays generic/non-enumerable;
		// this internal debug log is the only place the real reason
		// (wrong issuer, expired, tampered signature, wrong audience...)
		// survives for an operator debugging a misconfiguration.
		slog.Default().Debug("oidc: id token rejected", "error", err)
		return "", "", domain.ErrInvalidCredentials
	}
	var identity string
	if o.identityClaim == "sub" {
		var ok bool
		identity, ok = parsed.Subject()
		if !ok {
			return "", "", domain.ErrInvalidCredentials
		}
	} else if err := parsed.Get(o.identityClaim, &identity); err != nil {
		return "", "", domain.ErrInvalidCredentials
	}
	var tenantName string
	if err := parsed.Get(o.tenantClaim, &tenantName); err != nil || tenantName == "" {
		return "", "", domain.ErrInvalidCredentials
	}
	if identity == "" {
		return "", "", domain.ErrInvalidCredentials
	}
	return identity, tenantName, nil
}
