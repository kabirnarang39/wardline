package usecase_test

import (
	"testing"
	"testing/fstest"

	"github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

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
	c := usecase.NewCatalog(fakeFS())

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
	c := usecase.NewCatalog(fakeFS())

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
	c := usecase.NewCatalog(fakeFS())

	_, _, err := c.Get("does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown pack name")
	}
}

func TestCatalog_ListOnEmptyFSReturnsNoPacksNoError(t *testing.T) {
	c := usecase.NewCatalog(fstest.MapFS{})

	packs, err := c.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packs) != 0 {
		t.Errorf("expected no packs, got %+v", packs)
	}
}
