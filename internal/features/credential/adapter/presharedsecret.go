package adapter

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

type identitiesFile struct {
	Identities []domain.RegisteredIdentity `yaml:"identities"`
}

// Bootstrapper resolves a registration secret to the identity name it
// belongs to, loaded once from a credentials.yaml file at construction —
// same fail-fast-at-construction posture as policy.LoadFile.
type Bootstrapper struct {
	bySecret map[string]string
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
	bySecret := make(map[string]string, len(f.Identities))
	for _, e := range f.Identities {
		if e.Name == "" || e.Secret == "" {
			return nil, fmt.Errorf("credentials file %s: every identity entry must have both name and secret", path)
		}
		bySecret[e.Secret] = e.Name
	}
	return &Bootstrapper{bySecret: bySecret}, nil
}

func (b *Bootstrapper) Authenticate(secret string) (string, error) {
	identity, ok := b.bySecret[secret]
	if !ok {
		return "", domain.ErrInvalidCredentials
	}
	return identity, nil
}
