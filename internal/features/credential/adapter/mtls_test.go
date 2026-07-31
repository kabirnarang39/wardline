package adapter_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

func writeMTLSCredentialsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMTLSBootstrapper_ValidSpiffeIDResolvesIdentity(t *testing.T) {
	path := writeMTLSCredentialsFile(t, `
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
    tenant: acme
  - name: billing-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/billing-worker"
`)
	b, err := adapter.LoadMTLSBootstrapper(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	identity, gotTenant, err := b.Authenticate("spiffe://example.org/ns/prod/sa/payments-worker")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity != "payments-worker" || gotTenant != "acme" {
		t.Errorf("got (%q, %q), want (\"payments-worker\", \"acme\")", identity, gotTenant)
	}
	// billing-worker's entry omits tenant -- must default, not come back empty.
	identity, gotTenant, err = b.Authenticate("spiffe://example.org/ns/prod/sa/billing-worker")
	if err != nil || identity != "billing-worker" || gotTenant != tenant.Default {
		t.Fatalf("got (%q, %q, %v), want (\"billing-worker\", %q, nil)", identity, gotTenant, err, tenant.Default)
	}
}

func TestLoadMTLSBootstrapper_UnmappedSpiffeIDIsInvalidCredentials(t *testing.T) {
	path := writeMTLSCredentialsFile(t, `
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
`)
	b, err := adapter.LoadMTLSBootstrapper(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, _, err = b.Authenticate("spiffe://example.org/ns/prod/sa/some-other-worker")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoadMTLSBootstrapper_EmptySpiffeIDInputIsInvalidCredentials(t *testing.T) {
	path := writeMTLSCredentialsFile(t, `
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
`)
	b, err := adapter.LoadMTLSBootstrapper(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, _, err = b.Authenticate("")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for an empty input, got %v", err)
	}
}

func TestLoadMTLSBootstrapper_MissingFileErrors(t *testing.T) {
	_, err := adapter.LoadMTLSBootstrapper(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoadMTLSBootstrapper_MalformedYAMLErrors(t *testing.T) {
	path := writeMTLSCredentialsFile(t, "not: [valid yaml")
	_, err := adapter.LoadMTLSBootstrapper(path)
	if err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoadMTLSBootstrapper_EntryMissingNameOrSpiffeIDErrors(t *testing.T) {
	path := writeMTLSCredentialsFile(t, `
identities:
  - name: payments-worker
    spiffe_id: ""
`)
	_, err := adapter.LoadMTLSBootstrapper(path)
	if err == nil {
		t.Fatal("expected an error for an entry missing a spiffe_id")
	}
}

func TestLoadMTLSBootstrapper_DuplicateSpiffeIDErrors(t *testing.T) {
	path := writeMTLSCredentialsFile(t, `
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/same-id"
  - name: billing-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/same-id"
`)
	_, err := adapter.LoadMTLSBootstrapper(path)
	if err == nil {
		t.Fatal("expected an error for two identities sharing a spiffe_id")
	}
	// A spiffe_id is a public, structured URI, not a secret -- unlike
	// presharedsecret's deliberate secret-omission, the colliding value
	// itself belongs in the error to make a real config mistake debuggable.
	if !strings.Contains(err.Error(), "spiffe://example.org/ns/prod/sa/same-id") {
		t.Errorf("expected the error to name the colliding spiffe_id, got: %v", err)
	}
}

// TestMTLSTenantOf_LooksUpByIdentityNotSpiffeID mirrors
// presharedsecret_test.go's TestTenantOf_LooksUpByIdentityNotSecret.
func TestMTLSTenantOf_LooksUpByIdentityNotSpiffeID(t *testing.T) {
	path := writeMTLSCredentialsFile(t, `
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
    tenant: acme
  - name: billing-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/billing-worker"
`)
	b, err := adapter.LoadMTLSBootstrapper(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := b.TenantOf("payments-worker"); !ok || got != "acme" {
		t.Errorf("got (%q, %v), want (\"acme\", true)", got, ok)
	}
	if got, ok := b.TenantOf("billing-worker"); !ok || got != tenant.Default {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, tenant.Default)
	}
	if _, ok := b.TenantOf("no-such-identity"); ok {
		t.Error("expected ok=false for an identity that was never registered")
	}
}

// TestMTLSTenantOf_AmbiguousIdentityFailsClosed mirrors
// presharedsecret_test.go's TestTenantOf_AmbiguousIdentityFailsClosed.
func TestMTLSTenantOf_AmbiguousIdentityFailsClosed(t *testing.T) {
	path := writeMTLSCredentialsFile(t, `
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/acme/sa/payments-worker"
    tenant: acme
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/widgets/sa/payments-worker"
    tenant: widgets-inc
  - name: billing-worker
    spiffe_id: "spiffe://example.org/ns/acme/sa/billing-worker"
    tenant: acme
`)
	b, err := adapter.LoadMTLSBootstrapper(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if got, ok := b.TenantOf("payments-worker"); ok {
			t.Fatalf("call %d: expected ambiguous identity to fail closed, got (%q, true)", i, got)
		}
	}
	if got, ok := b.TenantOf("billing-worker"); !ok || got != "acme" {
		t.Fatalf("got (%q, %v), want (\"acme\", true)", got, ok)
	}
}
