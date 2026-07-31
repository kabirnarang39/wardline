package domain

import "time"

// Revoker tracks identities whose outstanding and future tokens must be
// rejected until the revocation itself expires. Keyed by (tenant,
// identity), not per-token jti -- revoking cuts off every token for
// that identity at once, which is what an operator actually wants
// ("cut off agent-X now"). tenantName == "" on Revoke means the
// target's own tenant could not be resolved at revoke time (an
// OIDC-bootstrapped target, or an identity name registered in more
// than one tenant, deliberately ambiguous per presharedsecret.go's
// TenantOf) -- write and check a wildcard, so a legitimate revoke
// still takes effect rather than silently no-op'ing. This is the
// established fail-toward-over-revoking direction: it can over-revoke
// (deny an identity that share a name but not a tenant), never
// under-revoke.
//
// Revoke returns an error because a persistent implementation (a
// Postgres-backed store, say) can genuinely fail to write -- an
// in-memory implementation that can't fail just returns nil. A caller
// that gets a nil error is entitled to believe the revocation is now in
// effect; silently discarding a write failure here would tell an
// operator a compromised identity was cut off when it wasn't.
type Revoker interface {
	Revoke(tenantName, identity string, expiresAt time.Time) error
	IsRevoked(tenantName, identity string) bool
}
