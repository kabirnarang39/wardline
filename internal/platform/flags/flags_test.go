package flags_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/flags"
)

func TestStaticProvider_Enabled(t *testing.T) {
	p := flags.NewStaticProvider(map[string]bool{"approval_workflow": true})

	if !p.Enabled("approval_workflow") {
		t.Error("expected approval_workflow to be enabled")
	}
	if p.Enabled("cedar_policy_backend") {
		t.Error("expected unlisted flag to default to false")
	}
}

func TestStaticProvider_NilMap(t *testing.T) {
	p := flags.NewStaticProvider(nil)
	if p.Enabled("anything") {
		t.Error("expected false for any flag with a nil map")
	}
}
