package adapter

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// errMissingBearerToken is returned by bearerIdentity.Authenticate when
// the Authorization header is absent or isn't a "Bearer <token>" value,
// and no SessionCookieName cookie is present either.
var errMissingBearerToken = errors.New("missing or malformed Authorization header")

// SessionCookieName is the httpOnly cookie a browser session (see
// credentialadapter.LoginHandler) carries its access token in --
// bearerIdentity.Authenticate reads it as a fallback token source, so
// a browser that can't attach a custom Authorization header on a plain
// navigation still authenticates. Exported so LoginHandler (a different
// package -- it needs access to credentialusecase.IssuanceService,
// which this package can't import without creating a dependency cycle)
// sets the exact same cookie name this reads.
const SessionCookieName = "wardline_session"

// IdentityAuthenticator resolves the caller's identity and tenant for a
// request, or fails the request outright. HeaderIdentity (today's behavior,
// the default when credential_issuance is off) always succeeds; bearerIdentity
// (credential_issuance on) can reject the request before it ever reaches
// policy or budget evaluation.
type IdentityAuthenticator interface {
	Authenticate(r *http.Request) (identity, tenant string, err error)
}

// HeaderIdentity reads X-Wardline-Identity and X-Wardline-Tenant as-is,
// exactly like every Wardline version before credential issuance existed —
// unauthenticated, always succeeds (empty identity if the header is
// absent). A missing tenant header resolves to tenant.Default, preserving
// every pre-this-cycle deployment's behavior exactly.
type HeaderIdentity struct{}

func (HeaderIdentity) Authenticate(r *http.Request) (string, string, error) {
	t := r.Header.Get("X-Wardline-Tenant")
	if t == "" {
		t = tenant.Default
	}
	return r.Header.Get("X-Wardline-Identity"), t, nil
}

// Authenticator is the subset of credentialusecase.VerificationService's
// behavior bearerIdentity depends on — a narrow interface so proxy/adapter
// doesn't import the credential feature's usecase package by name, same
// pattern as the existing BudgetChecker interface.
type Authenticator interface {
	Authenticate(bearerToken string) (identity, tenant string, err error)
}

// bearerIdentity extracts a Bearer token from the Authorization header
// and delegates to an Authenticator (in practice, the credential
// feature's VerificationService: signature, expiry, and revocation all
// checked before the request reaches policy/budget evaluation).
type bearerIdentity struct {
	authenticator Authenticator
}

// NewBearerIdentity returns an IdentityAuthenticator that requires a
// valid "Authorization: Bearer <jwt>" header, verified by authenticator.
func NewBearerIdentity(authenticator Authenticator) IdentityAuthenticator {
	return bearerIdentity{authenticator: authenticator}
}

// Authenticate tries the Authorization header first -- unchanged for
// every existing API caller, zero behavior change. Only when that
// header is absent/malformed does it fall back to SessionCookieName: a
// browser navigating to /dashboard/ (or a plain HTML form POSTing to
// Blocked's Unblock/Credentials' Revoke) can't attach a custom
// Authorization header, but DOES automatically send a cookie the
// browser already holds -- see credentialadapter.LoginHandler, which
// sets this cookie to the exact same access token an Authorization
// header would carry, minted through the exact same
// IssuanceService.Bootstrap path /credentials/token itself uses. Both
// paths end at the same authenticator.Authenticate call: a cookie
// carries no extra trust, only an extra delivery channel.
func (b bearerIdentity) Authenticate(r *http.Request) (string, string, error) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if token, ok := strings.CutPrefix(header, prefix); ok {
		return b.authenticator.Authenticate(token)
	}
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		return b.authenticator.Authenticate(cookie.Value)
	}
	return "", "", errMissingBearerToken
}
