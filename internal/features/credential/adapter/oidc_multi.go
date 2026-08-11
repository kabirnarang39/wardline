package adapter

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

var _ domain.Bootstrapper = (*MultiOIDCBootstrapper)(nil)

// OIDCProviderConfig is one issuer's worth of NewOIDCBootstrapper's
// constructor arguments -- NewMultiOIDCBootstrapper builds one
// *OIDCBootstrapper per entry, reusing NewOIDCBootstrapper unchanged
// (discovery, JWKS caching, verification all identical per provider,
// no longer limited to exactly one).
type OIDCProviderConfig struct {
	Issuer        string
	JWKSURI       string
	Audience      string
	IdentityClaim string
	TenantClaim   string
}

// MultiOIDCBootstrapper composes N single-issuer *OIDCBootstrapper
// instances, one per configured IdP, routing an incoming ID token to
// the right one by its own "iss" claim -- the same issuer-based routing
// every real multi-tenant SSO gateway uses (Auth0's multi-organization
// routing, Okta's multi-IdP routing rules, Azure AD B2C's
// identity-provider selection): a token names which IdP issued it, so
// the router only needs to read that one claim before handing off to
// the matching verifier.
//
// Routing reads the token's issuer via jwt.ParseInsecure -- deliberately
// UNVERIFIED at this point, and that's safe: the parsed, unverified
// claim is used ONLY to pick which OIDCBootstrapper.Authenticate runs
// next, never to make an identity/tenant/authorization decision
// directly. The real verification (signature against THAT issuer's own
// JWKS, audience, expiry, and a second, authoritative WithIssuer check)
// still happens inside the matched OIDCBootstrapper.Authenticate,
// exactly as it does for a single-IdP deployment. An attacker who
// crafts a token with a forged "iss" claim gains nothing from routing
// alone: whichever provider that claim selects still re-verifies the
// signature against ITS OWN real JWKS and re-checks the issuer itself,
// so a token not actually signed by that issuer's real key is rejected
// exactly as it would be without multi-provider routing at all.
type MultiOIDCBootstrapper struct {
	byIssuer map[string]*OIDCBootstrapper
}

// NewMultiOIDCBootstrapper builds one *OIDCBootstrapper per entry in
// configs (via NewOIDCBootstrapper, so each provider gets its own
// optional discovery, its own JWKS cache, its own audience/claims) and
// indexes them by issuer for routing. Rejects a duplicate issuer across
// two entries at construction -- ambiguous routing (which provider's
// audience/claims should a token from that issuer be checked against?)
// is a configuration error, not a runtime coin flip. Fails fast (and
// tears down every JWKS cache already opened) if any single provider
// fails to initialize, the same all-or-nothing startup posture every
// other Postgres/network-backed adapter in this codebase already has.
func NewMultiOIDCBootstrapper(configs []OIDCProviderConfig) (*MultiOIDCBootstrapper, error) {
	byIssuer := make(map[string]*OIDCBootstrapper, len(configs))
	for _, c := range configs {
		if _, dup := byIssuer[c.Issuer]; dup {
			for _, b := range byIssuer {
				_ = b.Close()
			}
			return nil, fmt.Errorf("duplicate oidc_providers issuer %q -- each provider must have a distinct issuer for routing to be unambiguous", c.Issuer)
		}
		b, err := NewOIDCBootstrapper(c.Issuer, c.JWKSURI, c.Audience, c.IdentityClaim, c.TenantClaim)
		if err != nil {
			for _, existing := range byIssuer {
				_ = existing.Close()
			}
			return nil, fmt.Errorf("initialize oidc provider %q: %w", c.Issuer, err)
		}
		byIssuer[c.Issuer] = b
	}
	return &MultiOIDCBootstrapper{byIssuer: byIssuer}, nil
}

// Authenticate routes idToken to the OIDCBootstrapper matching its own
// (unverified, routing-only -- see MultiOIDCBootstrapper's own doc
// comment) issuer claim, then delegates the actual verification to it.
// An issuer that doesn't match any configured provider, or a token
// jwt.ParseInsecure can't even parse, gets the same generic
// ErrInvalidCredentials every other rejection reason in this package
// returns -- no enumeration of which issuers are configured.
func (m *MultiOIDCBootstrapper) Authenticate(idToken string) (string, string, error) {
	unverified, err := jwt.ParseInsecure([]byte(idToken))
	if err != nil {
		return "", "", domain.ErrInvalidCredentials
	}
	iss, ok := unverified.Issuer()
	if !ok || iss == "" {
		return "", "", domain.ErrInvalidCredentials
	}
	b, ok := m.byIssuer[iss]
	if !ok {
		return "", "", domain.ErrInvalidCredentials
	}
	return b.Authenticate(idToken)
}

// Close shuts down every configured provider's JWKS cache background
// refresh goroutines -- main.go registers this the same way it
// registers a single OIDCBootstrapper's own Close.
func (m *MultiOIDCBootstrapper) Close() error {
	var firstErr error
	for issuer, b := range m.byIssuer {
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close oidc provider %q: %w", issuer, err)
		}
	}
	return firstErr
}
