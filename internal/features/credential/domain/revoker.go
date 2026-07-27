package domain

import "time"

// Revoker tracks identities whose outstanding and future tokens must be
// rejected until the revocation itself expires. Keyed by identity, not
// per-token jti — revoking cuts off every token for that identity at
// once, which is what an operator actually wants ("cut off agent-X now").
type Revoker interface {
	Revoke(identity string, expiresAt time.Time)
	IsRevoked(identity string) bool
}
