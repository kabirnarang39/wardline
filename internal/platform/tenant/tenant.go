// Package tenant holds the one constant every tenant-aware feature
// (credential, rbac, policy, budget, audit, dashboard) needs: the
// implicit tenant a caller resolves to when nothing else specifies one.
// A single shared constant, rather than each package hand-copying the
// string literal "default", so the value can't silently drift between
// packages.
package tenant

// Default is the implicit tenant for any identity/rule/binding that
// doesn't specify one — preserves every pre-this-cycle deployment's
// behavior exactly (see docs/superpowers/specs/2026-07-30-sso-scim-tenant-isolation-design.md).
const Default = "default"

// Key composes a tenant and identity into one map key. \x00 can't appear
// in either a tenant or identity string in practice (both come from JWT
// claims / header values / SCIM UserNames), so this is a safe,
// unambiguous join — avoids a struct key's extra allocation overhead on
// hot paths that run per-request.
//
// Any map or table keyed on a per-identity value that this branch made
// non-globally-unique (anomaly baselines/auto-blocks, the budget
// identity bucket) must key exclusively through this one function --
// never build the composite key inline at a call site. Two
// SCIM-provisioned identities from different tenants can plausibly
// share a raw identity string (two different IdPs both provisioning
// "alice"), so keying on identity alone would let one tenant's
// rate-spike, auto-block, or budget exhaustion poison or lock out the
// other tenant's identically-named identity.
func Key(tenantName, identity string) string {
	return tenantName + "\x00" + identity
}
