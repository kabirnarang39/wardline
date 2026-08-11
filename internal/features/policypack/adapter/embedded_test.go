package adapter_test

import (
	"os"
	"strings"
	"testing"

	cedaradapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/cedar"
	opaadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter/opa"

	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/policypack/adapter"
	"github.com/kabirnarang39/wardline/internal/features/policypack/usecase"
)

// expectedPackNames is the exact set of packs this cycle ships -- if a
// pack is added or removed from policy-packs/ without updating this list,
// this test fails instead of the catalog silently drifting from what the
// design doc and README describe.
var expectedPackNames = []string{
	"admin-viewer-split",
	"admin-viewer-split-cedar",
	"admin-viewer-split-opa",
	"deny-all-baseline",
	"deny-all-baseline-cedar",
	"deny-all-baseline-opa",
	"read-only-single-identity",
	"read-only-single-identity-cedar",
	"read-only-single-identity-opa",
	"single-identity-full-access",
	"single-identity-full-access-cedar",
	"single-identity-full-access-opa",
}

func TestPacks_EmbeddedCatalogHasExactlyTheExpectedPacks(t *testing.T) {
	catalog := usecase.NewCatalog(adapter.Packs(), adapter.YAMLManifestDecoder{})

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

// TestPacks_EveryShippedPolicyFileParsesWithItsRealBackendLoader is the
// cheapest possible regression test for "the thing we're distributing is
// even valid": it runs the actual loader wardline serve uses for each
// pack's declared backend (policy.LoadFile for yaml,
// opa.NewOPAEngine for opa, cedar.NewCedarEngine for cedar), not just a
// generic syntax check, against every shipped pack's policy file.
func TestPacks_EveryShippedPolicyFileParsesWithItsRealBackendLoader(t *testing.T) {
	catalog := usecase.NewCatalog(adapter.Packs(), adapter.YAMLManifestDecoder{})
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
			switch p.Backend {
			case "yaml":
				tmpFile := t.TempDir() + "/policy.yaml"
				if err := os.WriteFile(tmpFile, policySource, 0600); err != nil {
					t.Fatalf("write temp policy file: %v", err)
				}
				if _, err := policyadapter.LoadFile(tmpFile); err != nil {
					t.Errorf("policy.LoadFile rejected shipped pack %q: %v", p.Name, err)
				}
			case "opa":
				if _, err := opaadapter.NewOPAEngine(p.Name+".rego", policySource); err != nil {
					t.Errorf("opa.NewOPAEngine rejected shipped pack %q: %v", p.Name, err)
				}
			case "cedar":
				if _, err := cedaradapter.NewCedarEngine(p.Name+".cedar", policySource); err != nil {
					t.Errorf("cedar.NewCedarEngine rejected shipped pack %q: %v", p.Name, err)
				}
			default:
				t.Errorf("pack %q declares unknown backend %q", p.Name, p.Backend)
			}
			// install prints "policy_backend: <backend>" for the operator
			// to paste into wardline.yaml, so a pack's backend has to be a
			// value config.validate actually accepts.
			if p.Backend != "yaml" && p.Backend != "opa" && p.Backend != "cedar" {
				t.Errorf("pack %q declares backend %q, which wardline.yaml won't accept", p.Name, p.Backend)
			}
			if p.Version == "" {
				t.Errorf("pack %q has an empty Version -- Catalog must default an absent pack.yaml version key to %q, never leave it blank", p.Name, "1")
			}
		})
	}
}

// TestPacks_AdminViewerSplit_SameIdentityForBothRolesFailsClosed pins the
// rule ordering in admin-viewer-split. Nothing validates that an operator
// renamed the two placeholder identities to two *different* strings, so
// if they use one string for both, the collision must land on read-only
// (the viewer block, which comes first) rather than silently granting
// full access via the admin wildcard.
func TestPacks_AdminViewerSplit_SameIdentityForBothRolesFailsClosed(t *testing.T) {
	catalog := usecase.NewCatalog(adapter.Packs(), adapter.YAMLManifestDecoder{})
	_, policySource, err := catalog.Get("admin-viewer-split")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	collided := strings.NewReplacer(
		"REPLACE_WITH_ADMIN_IDENTITY", "same-identity",
		"REPLACE_WITH_VIEWER_IDENTITY", "same-identity",
	).Replace(string(policySource))

	tmpFile := t.TempDir() + "/policy.yaml"
	if err := os.WriteFile(tmpFile, []byte(collided), 0600); err != nil {
		t.Fatalf("write temp policy file: %v", err)
	}
	matcher, err := policyadapter.LoadFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if got := matcher.Evaluate(policydomain.Context{Identity: "same-identity", Tool: "read_file"}).Effect; got != policydomain.EffectAllow {
		t.Errorf("expected the collided identity to keep read access, got %q", got)
	}
	if got := matcher.Evaluate(policydomain.Context{Identity: "same-identity", Tool: "delete_file"}).Effect; got != policydomain.EffectDeny {
		t.Errorf("renaming both placeholders to one identity silently granted it full access (got %q for a write tool) -- the admin wildcard rule must stay after the viewer block", got)
	}
}

// TestPacks_AdminViewerSplitOPA_SameIdentityForBothRolesFailsClosed is
// TestPacks_AdminViewerSplit_SameIdentityForBothRolesFailsClosed's OPA
// analog: Rego's allow is an OR of independent rules (not first-match-
// wins), so the admin rule needs its own explicit
// "input.identity != viewer" guard to fail closed on a collision --
// this test proves that guard actually works, not just that it's
// present in the source.
func TestPacks_AdminViewerSplitOPA_SameIdentityForBothRolesFailsClosed(t *testing.T) {
	catalog := usecase.NewCatalog(adapter.Packs(), adapter.YAMLManifestDecoder{})
	_, policySource, err := catalog.Get("admin-viewer-split-opa")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	collided := strings.NewReplacer(
		"REPLACE_WITH_ADMIN_IDENTITY", "same-identity",
		"REPLACE_WITH_VIEWER_IDENTITY", "same-identity",
	).Replace(string(policySource))

	engine, err := opaadapter.NewOPAEngine("collided.rego", []byte(collided))
	if err != nil {
		t.Fatalf("NewOPAEngine: %v", err)
	}
	if got := engine.Evaluate(policydomain.Context{Identity: "same-identity", Tool: "read_file"}).Effect; got != policydomain.EffectAllow {
		t.Errorf("expected the collided identity to keep read access, got %q", got)
	}
	if got := engine.Evaluate(policydomain.Context{Identity: "same-identity", Tool: "delete_file"}).Effect; got != policydomain.EffectDeny {
		t.Errorf("renaming both placeholders to one identity silently granted it full access (got %q for a write tool) -- the admin rule's identity!=viewer guard must hold", got)
	}
}

// TestPacks_AdminViewerSplitCedar_SameIdentityForBothRolesFailsClosed is
// the Cedar analog: permits are additive, so the admin permit needs its
// own "when { principal != viewer }" guard to fail closed on a
// collision.
func TestPacks_AdminViewerSplitCedar_SameIdentityForBothRolesFailsClosed(t *testing.T) {
	catalog := usecase.NewCatalog(adapter.Packs(), adapter.YAMLManifestDecoder{})
	_, policySource, err := catalog.Get("admin-viewer-split-cedar")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	collided := strings.NewReplacer(
		"REPLACE_WITH_ADMIN_IDENTITY", "same-identity",
		"REPLACE_WITH_VIEWER_IDENTITY", "same-identity",
	).Replace(string(policySource))

	engine, err := cedaradapter.NewCedarEngine("collided.cedar", []byte(collided))
	if err != nil {
		t.Fatalf("NewCedarEngine: %v", err)
	}
	if got := engine.Evaluate(policydomain.Context{Identity: "same-identity", Tool: "read_file"}).Effect; got != policydomain.EffectAllow {
		t.Errorf("expected the collided identity to keep read access, got %q", got)
	}
	if got := engine.Evaluate(policydomain.Context{Identity: "same-identity", Tool: "delete_file"}).Effect; got != policydomain.EffectDeny {
		t.Errorf("renaming both placeholders to one identity silently granted it full access (got %q for a write tool) -- the admin permit's when-guard must hold", got)
	}
}
