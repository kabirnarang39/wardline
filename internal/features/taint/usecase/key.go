package usecase

import (
	"strconv"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// taintKey composes (tenant, identity, session) into one store key. Every
// taint read/write/iteration must go through this single function — never
// build the composite inline — so two tenants' identically-named identities
// (two IdPs both provisioning "alice") never share taint.
//
// It reuses tenant.Key for the tenant-safe (tenant, identity) prefix, then
// length-prefixes that whole prefix before appending session so the
// prefix/session boundary is unambiguous regardless of what bytes either
// string contains — the same anti-spoofing reasoning tenant.Key applies to
// its own two fields, extended to the third.
func taintKey(tenantName, identity, session string) string {
	base := tenant.Key(tenantName, identity)
	return strconv.Itoa(len(base)) + ":" + base + session
}
