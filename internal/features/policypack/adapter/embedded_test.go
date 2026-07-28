package adapter_test

import (
	"os"
	"testing"

	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	"github.com/kabirnarang39/wardline/internal/features/policypack/adapter"
	"github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

// expectedPackNames is the exact set of packs this cycle ships -- if a
// pack is added or removed from policy-packs/ without updating this list,
// this test fails instead of the catalog silently drifting from what the
// design doc and README describe.
var expectedPackNames = []string{
	"admin-viewer-split",
	"deny-all-baseline",
	"read-only-single-identity",
	"single-identity-full-access",
}

func TestPacks_EmbeddedCatalogHasExactlyTheExpectedPacks(t *testing.T) {
	catalog := usecase.NewCatalog(adapter.Packs())

	packs, err := catalog.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(packs) != len(expectedPackNames) {
		t.Fatalf("expected %d packs, got %d: %+v", len(expectedPackNames), len(packs), packs)
	}
	for i, want := range expectedPackNames {
		if packs[i].Name != want {
			t.Errorf("pack %d: expected name %q, got %q", i, want, packs[i].Name)
		}
	}
}

// TestPacks_EveryShippedPolicyFileParsesWithTheRealYAMLLoader is the
// cheapest possible regression test for "the thing we're distributing is
// even valid": it runs the actual policy.LoadFile loader wardline serve
// uses, not just yaml.Unmarshal, against every shipped pack's policy file.
func TestPacks_EveryShippedPolicyFileParsesWithTheRealYAMLLoader(t *testing.T) {
	catalog := usecase.NewCatalog(adapter.Packs())
	packs, err := catalog.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, p := range packs {
		t.Run(p.Name, func(t *testing.T) {
			_, policySource, err := catalog.Get(p.Name)
			if err != nil {
				t.Fatalf("Get(%q): %v", p.Name, err)
			}
			tmpFile := t.TempDir() + "/policy.yaml"
			if err := os.WriteFile(tmpFile, policySource, 0600); err != nil {
				t.Fatalf("write temp policy file: %v", err)
			}
			if _, err := policyadapter.LoadFile(tmpFile); err != nil {
				t.Errorf("policy.LoadFile rejected shipped pack %q: %v", p.Name, err)
			}
		})
	}
}
