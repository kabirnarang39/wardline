package domain

import (
	"errors"
	"time"
)

// ErrRefreshTokenInvalid is returned by RefreshStore.Redeem for any
// ordinary reason a refresh token can't be exchanged: not found or
// expired. No distinction surfaced to the caller, matching every
// other credential-rejection path in this codebase's non-enumerable-
// failure posture.
var ErrRefreshTokenInvalid = errors.New("refresh token invalid or already used")

// ErrRefreshTokenReused is returned by RefreshStore.Redeem when a token
// that was already consumed (redeemed once) is presented again -- the
// classic refresh-token-theft signal. By the time this error is
// returned the store has ALREADY revoked the token's entire family (see
// RefreshStore), so both the legitimate holder's and the attacker's
// outstanding tokens in that lineage are dead. Callers treat this as a
// security event (log it) but must still fail the request closed, and
// must NOT surface the distinction to the remote caller -- an attacker
// probing whether a token was "reused" vs "never existed" learns
// nothing. errors.Is(err, ErrRefreshTokenReused) is how the usecase
// tells the two rejections apart internally.
var ErrRefreshTokenReused = errors.New("refresh token reused")

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
//
// Family is the lineage identifier shared by every token descended from
// one bootstrap: the token minted at bootstrap starts a fresh family,
// and each rotation carries the same Family forward. It is what lets a
// reused (already-consumed) token revoke the whole chain at once.
type RefreshToken struct {
	Token     string // the opaque token value itself, never logged
	Identity  string
	Tenant    string
	Family    string
	ExpiresAt time.Time
}

// RefreshStore persists issued refresh tokens and enforces single-use
// rotation with reuse detection. Redeem atomically:
//   - active, unexpired token -> marks it consumed (kept, not deleted, so
//     a later replay is detectable) and returns its identity/tenant/family.
//   - already-consumed token (a replay) -> revokes the token's entire
//     family (deletes every token sharing its Family) and returns
//     ErrRefreshTokenReused.
//   - unknown or expired token -> returns ErrRefreshTokenInvalid.
//
// Issue stores a newly minted token under the given family.
// RevokeAllForIdentity deletes every outstanding refresh token for
// (tenantName, identity) -- called by the existing /credentials/revoke
// flow (usecase.RevocationService) so a revoked identity can't silently
// refresh its way back to a valid access token later. The atomicity of
// the Redeem state transition (active->consumed, or reuse->family-wipe)
// must hold under concurrent redeems of the same token, including across
// replicas sharing one database.
type RefreshStore interface {
	Issue(token, identity, tenantName, family string, expiresAt time.Time) error
	Redeem(token string) (identity, tenantName, family string, err error)
	RevokeAllForIdentity(tenantName, identity string) error
}
