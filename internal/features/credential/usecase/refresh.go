package usecase

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// RefreshService composes a single, ordered flow: redeem the presented
// refresh token (single-use, deleted on success), re-check revocation
// against the identity it belonged to (NOT skippable -- see design doc
// "Interaction with revocation": this is what keeps a revoked
// identity's revocation actually effective even while it still holds a
// not-yet-expired refresh token), then mint a fresh access token AND a
// fresh refresh token (rotation).
type RefreshService struct {
	store           domain.RefreshStore
	revoker         domain.Revoker
	issuer          domain.Issuer
	refreshTokenTTL time.Duration
	now             func() time.Time
}

func NewRefreshService(store domain.RefreshStore, revoker domain.Revoker, issuer domain.Issuer, refreshTokenTTL time.Duration, now func() time.Time) *RefreshService {
	return &RefreshService{store: store, revoker: revoker, issuer: issuer, refreshTokenTTL: refreshTokenTTL, now: now}
}

// Refresh exchanges refreshToken for a new (accessToken, refreshToken)
// pair, rotating within the same token family. Returns
// domain.ErrRefreshTokenInvalid for ordinary rejections
// (unknown/expired/revoked-identity), and domain.ErrRefreshTokenReused --
// propagated verbatim so the HTTP handler can log the theft signal --
// when a consumed token is replayed (the store has already revoked the
// whole family by then). The caller must map both to the same generic
// client response; no distinction is ever surfaced to the remote caller.
func (s *RefreshService) Refresh(refreshToken string) (accessToken, newRefreshToken string, err error) {
	identity, tenantName, family, err := s.store.Redeem(refreshToken)
	if err != nil {
		return "", "", err
	}
	if s.revoker.IsRevoked(tenantName, identity) {
		return "", "", domain.ErrRefreshTokenInvalid
	}
	accessToken, err = s.issuer.Issue(identity, tenantName)
	if err != nil {
		return "", "", fmt.Errorf("issue access token: %w", err)
	}
	// Rotate within the same family: the new token descends from the one
	// just redeemed, so a later replay of any consumed link in this chain
	// still revokes the whole lineage.
	newRefreshToken, err = mintAndStoreRefreshToken(s.store, identity, tenantName, family, s.now().Add(s.refreshTokenTTL))
	if err != nil {
		return "", "", fmt.Errorf("issue refresh token: %w", err)
	}
	return accessToken, newRefreshToken, nil
}

// mintAndStoreRefreshToken generates a new opaque refresh token
// (32 random bytes, hex-encoded -- same entropy source and encoding as
// jwt.go's randomJTI, exported nowhere since only this package's two
// services need to mint one) and stores it under family. Shared by
// RefreshService (rotation, reusing the redeemed family) and
// IssuanceService (initial bootstrap, which starts a fresh family via
// newRefreshFamily).
func mintAndStoreRefreshToken(store domain.RefreshStore, identity, tenantName, family string, expiresAt time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	token := hex.EncodeToString(b)
	if err := store.Issue(token, identity, tenantName, family, expiresAt); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}

// newRefreshFamily generates a fresh lineage identifier for a
// bootstrap-issued refresh token (16 random bytes, hex-encoded). Only a
// bootstrap starts a new family; every rotation reuses the family it
// redeemed.
func newRefreshFamily() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh token family: %w", err)
	}
	return hex.EncodeToString(b), nil
}
