package domain

import (
	"errors"
	"time"
)

// ErrRefreshTokenInvalid is returned by RefreshStore.Redeem for any
// reason a refresh token can't be exchanged: not found, already
// redeemed (deleted on first use -- see RefreshStore's doc comment),
// or expired. No distinction surfaced to the caller, matching every
// other credential-rejection path in this codebase's non-enumerable-
// failure posture.
var ErrRefreshTokenInvalid = errors.New("refresh token invalid or already used")

// RefreshToken is an opaque, single-use credential that exchanges for a
// fresh access token without re-presenting the original bootstrap
// credential. Unlike an access token (a self-contained, stateless JWT),
// a refresh token is a random string with no embedded claims -- its
// validity is entirely server-side state (see RefreshStore), so a
// single refresh token can be invalidated immediately and unilaterally,
// which a JWT-shaped access token cannot be without consulting the
// revocation store on every request (already true, and already paid
// for, for access tokens; refresh tokens don't ride the request path at
// all, so statelessness buys nothing here and costs the
// "immediately revocable, cheaply" property instead).
type RefreshToken struct {
	Token     string // the opaque token value itself, never logged
	Identity  string
	Tenant    string
	ExpiresAt time.Time
}

// RefreshStore persists issued refresh tokens and enforces single-use
// rotation: Redeem atomically looks up token, deletes it (so it can
// never be redeemed twice -- replay of an already-used refresh token is
// treated as any other invalid token, not distinguished further; real
// reuse-detection/token-family-revocation is out of scope this cycle,
// see the design doc's "Out of scope"), and returns the identity/tenant
// it was issued for. Issue stores a newly minted token.
// RevokeAllForIdentity deletes every outstanding refresh token for
// (tenantName, identity) -- called by the existing /credentials/revoke
// flow (usecase.RevocationService) so a revoked identity can't silently
// refresh its way back to a valid access token later.
type RefreshStore interface {
	Issue(token, identity, tenantName string, expiresAt time.Time) error
	Redeem(token string) (identity, tenantName string, err error)
	RevokeAllForIdentity(tenantName, identity string) error
}
