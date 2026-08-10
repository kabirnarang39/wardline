package usecase

import (
	"strconv"
	"time"

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

// SessionID derives the session component of a taint key. An explicit
// X-Wardline-Session header wins when present — precise when the agent
// framework stamps one id per run. Absent a header it falls back to a
// per-identity sliding TTL window bucket, stable within the window and
// rolling at the boundary, so Wardline stays drop-in with zero client
// cooperation: the taint TTL is the implicit session boundary in that mode.
func SessionID(headerVal, tenant, identity string, now time.Time, windowSeconds int) string {
	if headerVal != "" {
		return headerVal
	}
	if windowSeconds <= 0 {
		windowSeconds = 1
	}
	return identity + "|" + strconv.FormatInt(now.Unix()/int64(windowSeconds), 10)
}
