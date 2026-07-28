package domain

import "time"

// Revoker tracks identities whose outstanding and future tokens must be
// rejected until the revocation itself expires. Keyed by identity, not
// per-token jti — revoking cuts off every token for that identity at
// once, which is what an operator actually wants ("cut off agent-X now").
//
// Revoke returns an error because a persistent implementation (a
// Postgres-backed store, say) can genuinely fail to write — an
// in-memory implementation that can't fail just returns nil. A caller
// that gets a nil error is entitled to believe the revocation is now in
// effect; silently discarding a write failure here would tell an
// operator a compromised identity was cut off when it wasn't.
type Revoker interface {
	Revoke(identity string, expiresAt time.Time) error
	IsRevoked(identity string) bool
}
