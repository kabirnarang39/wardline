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

// TestKey_LengthPrefixEncodingAvoidsSeparatorCollision is I1's regression
// test (final review, known-limitations-closure): an earlier version of
// Key joined tenantName and identity with a single "\x00" separator byte,
// which is spoofable since both strings are arbitrary JWT-claim/SCIM-UserName
// values with no charset restriction -- Key("acme\x00", "alice") and
// Key("acme", "\x00alice") both produced the identical string
// "acme\x00\x00alice" under that scheme. The length-prefixed encoding
// must keep them distinct regardless of what bytes either half contains.
func TestKey_LengthPrefixEncodingAvoidsSeparatorCollision(t *testing.T) {
	if tenant.Key("acme\x00", "alice") == tenant.Key("acme", "\x00alice") {
		t.Fatal(`Key("acme\x00", "alice") must not collide with Key("acme", "\x00alice")`)
	}
}
