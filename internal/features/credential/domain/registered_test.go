package domain_test

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// TestRegisteredIdentity_SpiffeIDYAMLKeyIsSnakeCase proves the explicit
// yaml:"spiffe_id" tag actually works -- yaml.v3's default field-name
// matching (lowercase, no separator insertion) would otherwise require
// the YAML key "spiffeid", not the snake_case "spiffe_id" every other
// field in this codebase uses.
func TestRegisteredIdentity_SpiffeIDYAMLKeyIsSnakeCase(t *testing.T) {
	var entry domain.RegisteredIdentity
	data := []byte("name: payments-worker\nspiffe_id: \"spiffe://example.org/ns/prod/sa/payments-worker\"\ntenant: acme\n")
	if err := yaml.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.SpiffeID != "spiffe://example.org/ns/prod/sa/payments-worker" {
		t.Errorf("expected SpiffeID to be populated from the spiffe_id key, got %q", entry.SpiffeID)
	}
	if entry.Name != "payments-worker" || entry.Tenant != "acme" {
		t.Errorf("expected existing fields to still parse correctly, got Name=%q Tenant=%q", entry.Name, entry.Tenant)
	}
}

// TestRegisteredIdentity_SecretEntryStillParsesWithSpiffeIDEmpty is a
// regression guard: adding SpiffeID must not disturb parsing of an
// existing presharedsecret-style entry that never sets spiffe_id at all.
func TestRegisteredIdentity_SecretEntryStillParsesWithSpiffeIDEmpty(t *testing.T) {
	var entry domain.RegisteredIdentity
	data := []byte("name: agent-abc123\nsecret: \"sekret-one\"\n")
	if err := yaml.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.SpiffeID != "" {
		t.Errorf("expected SpiffeID to default to empty for a presharedsecret entry, got %q", entry.SpiffeID)
	}
	if entry.Name != "agent-abc123" || entry.Secret != "sekret-one" {
		t.Errorf("expected existing fields to still parse correctly, got Name=%q Secret=%q", entry.Name, entry.Secret)
	}
}
