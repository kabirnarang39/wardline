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
