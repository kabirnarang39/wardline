package adapter

import (
	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/policypack/domain"
)

// YAMLManifestDecoder is the domain.ManifestDecoder Wardline ships:
// pack.yaml is YAML. Lives here, not in usecase, so the usecase package
// stays free of any concrete parsing library per CLAUDE.md's dependency
// rule -- usecase depends on domain.ManifestDecoder, adapter implements it.
type YAMLManifestDecoder struct{}

type packYAML struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Backend     string `yaml:"backend"`
	PolicyFile  string `yaml:"policy_file"`
	Version     string `yaml:"version"`
}

func (YAMLManifestDecoder) Decode(data []byte) (domain.Manifest, error) {
	var raw packYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return domain.Manifest{}, err
	}
	return domain.Manifest{
		Name:        raw.Name,
		Description: raw.Description,
		Backend:     raw.Backend,
		PolicyFile:  raw.PolicyFile,
		Version:     raw.Version,
	}, nil
}
