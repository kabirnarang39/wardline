package adapter

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

type identitiesFile struct {
	Identities []domain.RegisteredIdentity `yaml:"identities"`
}

type registeredEntry struct {
	identity string
	tenant   string
}

// Bootstrapper resolves a registration secret to the identity and tenant
// it belongs to, loaded once from a credentials.yaml file at construction
// — same fail-fast-at-construction posture as policy.LoadFile.
type Bootstrapper struct {
	bySecret map[string]registeredEntry
}

func LoadBootstrapper(path string) (*Bootstrapper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file %s: %w", path, err)
	}
	var f identitiesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse credentials file %s: %w", path, err)
	}
	bySecret := make(map[string]registeredEntry, len(f.Identities))
	for _, e := range f.Identities {
		if e.Name == "" || e.Secret == "" {
			return nil, fmt.Errorf("credentials file %s: every identity entry must have both name and secret", path)
		}
		if existing, ok := bySecret[e.Secret]; ok {
			return nil, fmt.Errorf("credentials file %s: duplicate secret for identities %q and %q", path, existing.identity, e.Name)
		}
		t := e.Tenant
		if t == "" {
			t = tenant.Default
		}
		bySecret[e.Secret] = registeredEntry{identity: e.Name, tenant: t}
	}
	return &Bootstrapper{bySecret: bySecret}, nil
}

func (b *Bootstrapper) Authenticate(secret string) (string, string, error) {
	entry, ok := b.bySecret[secret]
	if !ok {
		return "", "", domain.ErrInvalidCredentials
	}
	return entry.identity, entry.tenant, nil
}

// TenantOf looks up a registered identity's own tenant by name (not by
// secret) -- used for the cross-tenant revoke check, which needs the
// tenant of the identity being revoked, not of whoever is calling.
func (b *Bootstrapper) TenantOf(identity string) (string, bool) {
	for _, entry := range b.bySecret {
		if entry.identity == identity {
			return entry.tenant, true
		}
	}
	return "", false
}
