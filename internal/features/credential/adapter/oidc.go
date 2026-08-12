package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
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

// forceRefreshCooldown bounds how often a failed verification is allowed
// to trigger an out-of-band JWKS refresh (see Authenticate) -- at most
// once per this interval, across every concurrent caller, regardless of
// how many tokens fail. Every major IdP's own key-rollover guidance
// (Microsoft's Azure AD signing-key-rollover doc is the most explicit:
// https://learn.microsoft.com/en-us/entra/identity-platform/active-directory-signing-key-rollover)
// documents exactly this "unknown kid -> force a refresh and retry once"
// pattern for a relying party that caches JWKS, because a real rotation
// adds the new key before jwksRefreshInterval's next scheduled fetch
// would otherwise see it. Rate-limited rather than unconditional so a
// flood of garbage bearer tokens can't turn every rejected Authenticate
// call into its own outbound request against the IdP's JWKS endpoint.
const forceRefreshCooldown = 30 * time.Second

// jwksBootstrapTimeout bounds the first, blocking JWKS fetch. Any
// jwks_uri problem (unreachable, refused, 404, non-JWKS body) otherwise
// blocks Register forever -- jwk.Cache.Register defaults to
// WithWaitReady(true), which honours only the context it is given.
const jwksBootstrapTimeout = 10 * time.Second

// discoveryTimeout bounds the one-shot GET against issuer's
// /.well-known/openid-configuration -- same fail-fast-at-startup posture
// as jwksBootstrapTimeout, and deliberately equal to it: both are a
// single blocking HTTP round trip Register/NewOIDCBootstrapper makes
// before the process is allowed to start serving traffic.
const discoveryTimeout = 10 * time.Second

// discoveryDocumentSuffix is the standard OIDC discovery path every
// major IdP (Google, Okta, Azure AD, Auth0, ...) serves relative to its
// issuer URL -- OpenID Connect Discovery 1.0 §4.
const discoveryDocumentSuffix = "/.well-known/openid-configuration"

// discoveryDocument is the handful of fields NewOIDCBootstrapper actually
// needs out of a real discovery document, which carries many more
// (authorization_endpoint, token_endpoint, scopes_supported, ...) this
// bootstrapper has no use for (it never runs an authorization-code flow
// itself -- Authenticate only ever verifies an already-issued ID token,
// see this file's own top-level doc comment). json.Unmarshal ignores
// unknown fields by default, so a real IdP's much larger document
// decodes here without error.
type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverJWKSURI fetches issuer's discovery document and returns its
// jwks_uri -- called by NewOIDCBootstrapper only when the operator left
// OIDCConfig.JWKSURI empty (see that field's own doc comment). Validates
// the document's own "issuer" field matches the issuer this bootstrapper
// was configured to trust, per OpenID Connect Discovery 1.0 §4.3: a
// discovery response whose issuer doesn't match what was requested must
// be rejected outright, the same defense-in-depth an OIDC client library
// would apply to a full discovery flow, even though this bootstrapper
// only borrows one field (jwks_uri) from the document rather than
// trusting the whole thing for endpoint discovery.
func discoverJWKSURI(ctx context.Context, issuer string) (string, error) {
	url := strings.TrimSuffix(issuer, "/") + discoveryDocumentSuffix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch discovery document from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery document at %s returned status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB -- generous for a JSON document with no file uploads
	if err != nil {
		return "", fmt.Errorf("read discovery document from %s: %w", url, err)
	}
	var doc discoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse discovery document from %s: %w", url, err)
	}
	if doc.Issuer != issuer {
		return "", fmt.Errorf("discovery document at %s declares issuer %q, expected %q -- refusing to trust a mismatched discovery response", url, doc.Issuer, issuer)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document at %s has no jwks_uri", url)
	}
	return doc.JWKSURI, nil
}

// OIDCBootstrapper verifies an OIDC ID token (passed as the "secret" to
// Authenticate, matching Bootstrapper's existing shape) against a
// configured issuer/audience and a JWKS resolved either explicitly
// (OIDCConfig.JWKSURI set) or via standard OIDC discovery against
// issuer's own /.well-known/openid-configuration (JWKSURI left empty --
// see discoverJWKSURI). identityClaim and tenantClaim name which token
// claims carry the resolved identity and tenant; tenantClaim is required
// present on every token -- an SSO-sourced identity with no tenant is
// rejected outright, not silently defaulted, unlike a credentials.yaml
// entry (see design doc's OIDC architecture note).
type OIDCBootstrapper struct {
	issuer        string
	audience      string
	identityClaim string
	tenantClaim   string
	cache         *jwk.Cache
	jwksURI       string

	// lastForcedRefresh is a UnixNano timestamp, CAS-guarded so
	// concurrent failed Authenticate calls agree on which one (if any)
	// gets to force a refresh -- see forceRefreshCooldown.
	lastForcedRefresh atomic.Int64
}

func NewOIDCBootstrapper(issuer, jwksURI, audience, identityClaim, tenantClaim string) (*OIDCBootstrapper, error) {
	if jwksURI == "" {
		discoveryCtx, discoveryCancel := context.WithTimeout(context.Background(), discoveryTimeout)
		resolved, err := discoverJWKSURI(discoveryCtx, issuer)
		discoveryCancel()
		if err != nil {
			return nil, fmt.Errorf("resolve jwks_uri via oidc discovery: %w", err)
		}
		jwksURI = resolved
		slog.Default().Info("oidc: resolved jwks_uri via discovery", "issuer", issuer, "jwks_uri", jwksURI)
	}
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

// tryClaimForceRefresh returns true for at most one caller per
// forceRefreshCooldown -- every other concurrent caller within the same
// window gets false and falls through to the normal rejection, so a
// burst of failing verifications forces at most one extra JWKS fetch,
// not one per request.
func (o *OIDCBootstrapper) tryClaimForceRefresh() bool {
	now := time.Now().UnixNano()
	last := o.lastForcedRefresh.Load()
	if now-last < int64(forceRefreshCooldown) {
		return false
	}
	return o.lastForcedRefresh.CompareAndSwap(last, now)
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
	if err != nil && o.tryClaimForceRefresh() {
		// See forceRefreshCooldown's doc comment: this is the one retry
		// a genuine mid-rotation "unknown kid" needs, bounded so it can't
		// be turned into a JWKS-hammering amplifier.
		if _, refreshErr := o.cache.Refresh(context.Background(), o.jwksURI); refreshErr == nil {
			if freshSet, lookupErr := o.cache.Lookup(context.Background(), o.jwksURI); lookupErr == nil {
				if retried, retryErr := jwt.Parse([]byte(idToken),
					jwt.WithKeySet(freshSet),
					jwt.WithIssuer(o.issuer),
					jwt.WithAudience(o.audience),
				); retryErr == nil {
					parsed, err = retried, nil
				}
			}
		}
	}
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
