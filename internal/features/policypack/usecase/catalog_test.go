package usecase_test

import (
	"testing"
	"testing/fstest"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/policypack/domain"
	"github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

// fakeDecoder is a plain YAML decode, kept local to the test package
// rather than reused from adapter -- per CLAUDE.md, a usecase/ package's
// own tests get a fake for the domain interface it depends on, not the
// real adapter (that belongs to adapter's own tests instead).
type fakeDecoder struct{}

func (fakeDecoder) Decode(data []byte) (domain.Manifest, error) {
	var raw struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Backend     string `yaml:"backend"`
		PolicyFile  string `yaml:"policy_file"`
		Version     string `yaml:"version"`
	}
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

func fakeFS() fstest.MapFS {
	return fstest.MapFS{
		"beta-pack/pack.yaml": &fstest.MapFile{Data: []byte(`
name: beta-pack
description: "the second pack alphabetically by directory, first by name coincidence"
backend: yaml
policy_file: policy.yaml
`)},
		"beta-pack/policy.yaml": &fstest.MapFile{Data: []byte("default: deny\n")},
		"alpha-pack/pack.yaml": &fstest.MapFile{Data: []byte(`
name: alpha-pack
description: "sorts first"
backend: yaml
policy_file: policy.yaml
`)},
		"alpha-pack/policy.yaml": &fstest.MapFile{Data: []byte("default: allow\n")},
	}
}

func TestCatalog_ListReturnsAllPacksSortedByName(t *testing.T) {
	c := usecase.NewCatalog(fakeFS(), fakeDecoder{})

	packs, err := c.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(packs) != 2 {
		t.Fatalf("expected 2 packs, got %d: %+v", len(packs), packs)
	}
	if packs[0].Name != "alpha-pack" || packs[1].Name != "beta-pack" {
		t.Fatalf("expected packs sorted by name [alpha-pack, beta-pack], got [%s, %s]", packs[0].Name, packs[1].Name)
	}
	if packs[0].Description != "sorts first" || packs[0].Backend != "yaml" {
		t.Errorf("unexpected pack fields: %+v", packs[0])
	}
}

func TestCatalog_GetReturnsPackAndPolicySource(t *testing.T) {
	c := usecase.NewCatalog(fakeFS(), fakeDecoder{})

	pack, policySource, err := c.Get("alpha-pack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pack.Name != "alpha-pack" {
		t.Errorf("unexpected pack: %+v", pack)
	}
	if string(policySource) != "default: allow\n" {
		t.Errorf("unexpected policy source: %q", policySource)
	}
}

func TestCatalog_GetUnknownNameReturnsClearError(t *testing.T) {
	c := usecase.NewCatalog(fakeFS(), fakeDecoder{})

	_, _, err := c.Get("does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown pack name")
	}
}

func TestCatalog_VersionDefaultsWhenAbsentFromManifest(t *testing.T) {
	c := usecase.NewCatalog(fakeFS(), fakeDecoder{})

	pack, _, err := c.Get("alpha-pack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pack.Version != "1" {
		t.Errorf("expected an absent version: key to default to %q, got %q", "1", pack.Version)
	}
}

func TestCatalog_VersionPassesThroughWhenPresent(t *testing.T) {
	fsys := fstest.MapFS{
		"versioned/pack.yaml": &fstest.MapFile{Data: []byte(`
name: versioned
description: "has an explicit version"
backend: yaml
policy_file: policy.yaml
version: "2"
`)},
		"versioned/policy.yaml": &fstest.MapFile{Data: []byte("default: deny\n")},
	}
	c := usecase.NewCatalog(fsys, fakeDecoder{})

	pack, _, err := c.Get("versioned")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pack.Version != "2" {
		t.Errorf("expected version %q to pass through unchanged, got %q", "2", pack.Version)
	}
}

func TestCatalog_ListOnEmptyFSReturnsNoPacksNoError(t *testing.T) {
	c := usecase.NewCatalog(fstest.MapFS{}, fakeDecoder{})

	packs, err := c.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packs) != 0 {
		t.Errorf("expected no packs, got %+v", packs)
	}
}
