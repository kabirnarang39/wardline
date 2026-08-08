package adapter

import (
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// gRPC metadata keys carrying the caller's identity/tenant in header mode,
// the metadata analogue of proxy/adapter's X-Wardline-Identity/-Tenant HTTP
// headers. gRPC lowercases all metadata keys, so these are already lower.
const (
	metaIdentity = "x-wardline-identity"
	metaTenant   = "x-wardline-tenant"
	metaAuth     = "authorization"
)

// errMissingBearerToken mirrors proxy/adapter's HTTP bearer error for the
// gRPC path.
var errMissingBearerToken = errors.New("missing or malformed authorization metadata")

// IdentityResolver resolves the caller's identity and tenant from a gRPC
// request's metadata, or fails the request outright -- the gRPC analogue of
// proxy/adapter.IdentityAuthenticator, which is bound to *http.Request and
// so can't be reused directly.
type IdentityResolver interface {
	Resolve(md metadata.MD) (identity, tenant string, err error)
}

// MetadataIdentity reads x-wardline-identity / x-wardline-tenant as-is,
// unauthenticated -- the gRPC counterpart of HeaderIdentity and the default
// when credential issuance is off. A missing tenant resolves to
// tenant.Default, matching the HTTP path exactly.
type MetadataIdentity struct{}

func (MetadataIdentity) Resolve(md metadata.MD) (string, string, error) {
	t := first(md, metaTenant)
	if t == "" {
		t = tenant.Default
	}
	return first(md, metaIdentity), t, nil
}

// TokenAuthenticator is the subset of the credential feature's
// VerificationService that bearerMetadataIdentity needs -- the same narrow
// (token -> identity, tenant) contract proxy/adapter.Authenticator uses, so
// the credential verification path is shared across both transports.
type TokenAuthenticator interface {
	Authenticate(bearerToken string) (identity, tenant string, err error)
}

// bearerMetadataIdentity extracts a Bearer token from the authorization
// metadata and delegates to a TokenAuthenticator, the gRPC mirror of
// proxy/adapter.bearerIdentity.
type bearerMetadataIdentity struct {
	authenticator TokenAuthenticator
}

// NewBearerIdentity returns an IdentityResolver that requires a valid
// "authorization: Bearer <jwt>" metadata value, verified by authenticator.
func NewBearerIdentity(authenticator TokenAuthenticator) IdentityResolver {
	return bearerMetadataIdentity{authenticator: authenticator}
}

func (b bearerMetadataIdentity) Resolve(md metadata.MD) (string, string, error) {
	const prefix = "Bearer "
	header := first(md, metaAuth)
	if !strings.HasPrefix(header, prefix) {
		return "", "", errMissingBearerToken
	}
	return b.authenticator.Authenticate(strings.TrimPrefix(header, prefix))
}

// first returns the first value for key, or "" if absent.
func first(md metadata.MD, key string) string {
	if vs := md.Get(key); len(vs) > 0 {
		return vs[0]
	}
	return ""
}
