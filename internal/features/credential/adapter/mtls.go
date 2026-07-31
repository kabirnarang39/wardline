package adapter

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

var _ domain.Bootstrapper = (*MTLSBootstrapper)(nil)

// MTLSBootstrapper resolves an already-verified SPIFFE ID (forwarded by
// a terminating mTLS proxy/mesh via a trusted, operator-configured
// header -- see design doc docs/superpowers/specs/2026-08-01-mtls-spiffe-bootstrap-design.md)
// to the identity and tenant it belongs to, loaded once from a
// credentials.yaml-shaped file at construction -- same fail-fast-at-
// construction posture as presharedsecret.Bootstrapper and
// policy.LoadFile. Wardline never parses X.509 or performs the mTLS
// handshake itself; by the time a request reaches this adapter, its
// caller's SPIFFE ID has already been extracted and verified upstream.
type MTLSBootstrapper struct {
	bySpiffeID map[string]registeredEntry
}

func LoadMTLSBootstrapper(path string) (*MTLSBootstrapper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file %s: %w", path, err)
	}
	var f identitiesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse credentials file %s: %w", path, err)
	}
	bySpiffeID := make(map[string]registeredEntry, len(f.Identities))
	for _, e := range f.Identities {
		if e.Name == "" || e.SpiffeID == "" {
			return nil, fmt.Errorf("credentials file %s: every identity entry must have both name and spiffe_id when using the mtls bootstrap source", path)
		}
		if existing, ok := bySpiffeID[e.SpiffeID]; ok {
			// Unlike presharedsecret.go's deliberate secret-omission, the
			// colliding value itself is safe (and useful) to include here:
			// a SPIFFE ID is a public URI, not a secret.
			return nil, fmt.Errorf("credentials file %s: duplicate spiffe_id %q for identities %q and %q", path, e.SpiffeID, existing.identity, e.Name)
		}
		t := e.Tenant
		if t == "" {
			t = tenant.Default
		}
		bySpiffeID[e.SpiffeID] = registeredEntry{identity: e.Name, tenant: t}
	}
	return &MTLSBootstrapper{bySpiffeID: bySpiffeID}, nil
}

// Authenticate treats secret as the already-verified SPIFFE ID string
// extracted from the trusted header by credential/adapter.Handler --
// Bootstrapper's parameter is named "secret" for interface-shape
// compatibility with credential/domain.Bootstrapper, not because this
// adapter has a real secret to check. An empty input (e.g. the header
// was present but empty) is treated the same as any unmapped value.
func (b *MTLSBootstrapper) Authenticate(secret string) (string, string, error) {
	entry, ok := b.bySpiffeID[secret]
	if !ok {
		return "", "", domain.ErrInvalidCredentials
	}
	return entry.identity, entry.tenant, nil
}

// TenantOf mirrors presharedsecret.Bootstrapper.TenantOf exactly,
// including its ambiguous-name-fails-closed reasoning (ranging over a
// map by value, collecting every distinct tenant a name resolves to,
// returning ("", false) if more than one) -- used for the cross-tenant
// revoke check.
func (b *MTLSBootstrapper) TenantOf(identity string) (string, bool) {
	var found string
	matched := false
	for _, entry := range b.bySpiffeID {
		if entry.identity != identity {
			continue
		}
		if !matched {
			found = entry.tenant
			matched = true
			continue
		}
		if entry.tenant != found {
			return "", false
		}
	}
	if !matched {
		return "", false
	}
	return found, true
}
