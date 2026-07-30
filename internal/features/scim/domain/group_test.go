package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/scim/domain"
)

func TestParseGroupName(t *testing.T) {
	cases := []struct {
		name       string
		wantTenant string
		wantRole   string
		wantGlobal bool
		wantOK     bool
	}{
		{"wardline:tenant-acme:role-admin", "acme", "admin", false, true},
		{"wardline:role-admin", "", "admin", true, true},
		{"some-other-idp-group", "", "", false, false},
		{"wardline:tenant-acme:role-", "", "", false, false},
	}
	for _, c := range cases {
		gotTenant, gotRole, gotGlobal, gotOK := domain.ParseGroupName(c.name)
		if gotTenant != c.wantTenant || gotRole != c.wantRole || gotGlobal != c.wantGlobal || gotOK != c.wantOK {
			t.Errorf("ParseGroupName(%q) = (%q, %q, %v, %v), want (%q, %q, %v, %v)",
				c.name, gotTenant, gotRole, gotGlobal, gotOK, c.wantTenant, c.wantRole, c.wantGlobal, c.wantOK)
		}
	}
}
