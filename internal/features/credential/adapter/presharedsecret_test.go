package adapter_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

func writeCredentialsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBootstrapper_ValidSecretResolvesIdentity(t *testing.T) {
	path := writeCredentialsFile(t, `
identities:
  - name: agent-abc123
    secret: "sekret-one"
  - name: agent-def456
    secret: "sekret-two"
`)
	b, err := adapter.LoadBootstrapper(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	identity, _, err := b.Authenticate("sekret-two")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity != "agent-def456" {
		t.Errorf("expected agent-def456, got %q", identity)
	}
}

func TestLoadBootstrapper_WrongSecretIsInvalidCredentials(t *testing.T) {
	path := writeCredentialsFile(t, `
identities:
  - name: agent-abc123
    secret: "sekret-one"
`)
	b, err := adapter.LoadBootstrapper(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, _, err = b.Authenticate("wrong-secret")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoadBootstrapper_UnknownSecretIsInvalidCredentials(t *testing.T) {
	path := writeCredentialsFile(t, `identities: []`)
	b, err := adapter.LoadBootstrapper(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, _, err = b.Authenticate("anything")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoadBootstrapper_MissingFileErrors(t *testing.T) {
	_, err := adapter.LoadBootstrapper(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoadBootstrapper_MalformedYAMLErrors(t *testing.T) {
	path := writeCredentialsFile(t, "not: [valid yaml")
	_, err := adapter.LoadBootstrapper(path)
	if err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoadBootstrapper_EntryMissingNameOrSecretErrors(t *testing.T) {
	path := writeCredentialsFile(t, `
identities:
  - name: agent-abc123
    secret: ""
`)
	_, err := adapter.LoadBootstrapper(path)
	if err == nil {
		t.Fatal("expected an error for an entry missing a secret")
	}
}

func TestLoadBootstrapper_DuplicateSecretErrors(t *testing.T) {
	path := writeCredentialsFile(t, `
identities:
  - name: agent-abc123
    secret: "same-secret"
  - name: agent-def456
    secret: "same-secret"
`)
	_, err := adapter.LoadBootstrapper(path)
	if err == nil {
		t.Fatal("expected an error for two identities sharing a secret")
	}
}

func TestAuthenticate_ReturnsTenant(t *testing.T) {
	path := writeCredentialsFile(t, `
identities:
  - name: alice
    secret: alice-secret
    tenant: acme
  - name: bob
    secret: bob-secret
`)
	b, err := adapter.LoadBootstrapper(path)
	if err != nil {
		t.Fatal(err)
	}

	identity, gotTenant, err := b.Authenticate("alice-secret")
	if err != nil || identity != "alice" || gotTenant != "acme" {
		t.Fatalf("got (%q, %q, %v), want (\"alice\", \"acme\", nil)", identity, gotTenant, err)
	}

	// bob's entry omits tenant -- must default, not come back empty.
	identity, gotTenant, err = b.Authenticate("bob-secret")
	if err != nil || identity != "bob" || gotTenant != tenant.Default {
		t.Fatalf("got (%q, %q, %v), want (\"bob\", %q, nil)", identity, gotTenant, err, tenant.Default)
	}
}

// TestTenantOf_LooksUpByIdentityNotSecret covers the cross-tenant revoke
// check's actual use of TenantOf: looking up a registered identity's own
// tenant by name, independent of whichever secret it was registered
// under (the caller of TenantOf never has that secret -- only the
// identity name, e.g. from a revoke request body).
func TestTenantOf_LooksUpByIdentityNotSecret(t *testing.T) {
	path := writeCredentialsFile(t, `
identities:
  - name: alice
    secret: alice-secret
    tenant: acme
  - name: bob
    secret: bob-secret
`)
	b, err := adapter.LoadBootstrapper(path)
	if err != nil {
		t.Fatal(err)
	}

	if got, ok := b.TenantOf("alice"); !ok || got != "acme" {
		t.Errorf("got (%q, %v), want (\"acme\", true)", got, ok)
	}
	// bob's entry omits tenant -- must default, not come back empty.
	if got, ok := b.TenantOf("bob"); !ok || got != tenant.Default {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, tenant.Default)
	}
	// An identity nobody registered must fail closed, not silently match
	// some tenant.
	if _, ok := b.TenantOf("no-such-identity"); ok {
		t.Error("expected ok=false for an identity that was never registered")
	}
}

// TestTenantOf_AmbiguousIdentityFailsClosed is an I3 regression test.
// bySecret is keyed by secret, so the same identity name ("alice") can
// legitimately be registered in two different tenants -- two SCIM IdPs
// both provisioning "alice", say. Before the fix, TenantOf iterated the
// map directly and returned on first match, so which tenant it returned
// depended on Go's randomized map iteration order -- a coin flip for the
// cross-tenant revoke check that is TenantOf's only caller. It must now
// fail closed: ("", false), every single call, deterministically.
func TestTenantOf_AmbiguousIdentityFailsClosed(t *testing.T) {
	path := writeCredentialsFile(t, `
identities:
  - name: alice
    secret: alice-acme-secret
    tenant: acme
  - name: alice
    secret: alice-widgets-secret
    tenant: widgets-inc
  - name: bob
    secret: bob-secret
    tenant: acme
`)
	b, err := adapter.LoadBootstrapper(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 50; i++ {
		if got, ok := b.TenantOf("alice"); ok {
			t.Fatalf("call %d: expected ambiguous identity to fail closed, got (%q, true)", i, got)
		}
	}
	// An unambiguous name in the same Bootstrapper must still resolve
	// normally -- the fail-closed path must not over-fire.
	if got, ok := b.TenantOf("bob"); !ok || got != "acme" {
		t.Fatalf("got (%q, %v), want (\"acme\", true)", got, ok)
	}
}
