package adapter_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
)

// TestCredentialsYAMLExample_LoadsUnderDefaultBootstrapSource guards
// against credentials.yaml.example ever again mixing a live secret-based
// entry with a live spiffe_id-based entry -- each loader requires every
// entry in the file to carry its own field, so a shipped example with
// both would be unloadable under the default (presharedsecret) source,
// exactly the regression this test caught once before merge.
func TestCredentialsYAMLExample_LoadsUnderDefaultBootstrapSource(t *testing.T) {
	path := "../../../../credentials.yaml.example"
	if _, err := adapter.LoadBootstrapper(path); err != nil {
		t.Errorf("presharedsecret (default) loader failed on the shipped example file: %v", err)
	}
}
