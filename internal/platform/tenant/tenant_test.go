package tenant_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

func TestDefault(t *testing.T) {
	if tenant.Default != "default" {
		t.Fatalf("tenant.Default = %q, want %q", tenant.Default, "default")
	}
}

func TestKey_DistinguishesTenants(t *testing.T) {
	if tenant.Key("acme", "alice") == tenant.Key("widgets-inc", "alice") {
		t.Fatal("Key(acme, alice) must not equal Key(widgets-inc, alice)")
	}
	if tenant.Key("acme", "alice") != tenant.Key("acme", "alice") {
		t.Fatal("Key must be deterministic for the same (tenant, identity)")
	}
}
