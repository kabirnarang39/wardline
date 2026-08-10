package usecase

import (
	"strconv"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// grantKey composes (tenant, identity, session, tool) into one unambiguous key.
// Reuses tenant.Key for the tenant-safe (tenant, identity) prefix, then
// length-prefixes each further component so no boundary is spoofable — the
// same anti-collision rule taint.taintKey applies.
func grantKey(tenantName, identity, session, tool string) string {
	base := tenant.Key(tenantName, identity)
	return strconv.Itoa(len(base)) + ":" + base +
		strconv.Itoa(len(session)) + ":" + session + tool
}
