package version_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/version"
)

func TestVersion_NotEmpty(t *testing.T) {
	if version.Version == "" {
		t.Error("expected a non-empty version string")
	}
}
