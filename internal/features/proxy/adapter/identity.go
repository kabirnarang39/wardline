package adapter

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// errMissingBearerToken is returned by bearerIdentity.Authenticate when
// the Authorization header is absent or isn't a "Bearer <token>" value.
var errMissingBearerToken = errors.New("missing or malformed Authorization header")

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

func (b bearerIdentity) Authenticate(r *http.Request) (string, string, error) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return "", "", errMissingBearerToken
	}
	return b.authenticator.Authenticate(strings.TrimPrefix(header, prefix))
}
