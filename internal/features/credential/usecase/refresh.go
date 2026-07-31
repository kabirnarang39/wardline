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
// pair. Returns domain.ErrRefreshTokenInvalid for every rejection
// (unknown/expired/already-used/revoked-identity) -- no distinction
// surfaced to the caller, matching every other credential-rejection
// path's non-enumerable-failure posture in this codebase.
func (s *RefreshService) Refresh(refreshToken string) (accessToken, newRefreshToken string, err error) {
	identity, tenantName, err := s.store.Redeem(refreshToken)
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
	newRefreshToken, err = mintAndStoreRefreshToken(s.store, identity, tenantName, s.now().Add(s.refreshTokenTTL))
	if err != nil {
		return "", "", fmt.Errorf("issue refresh token: %w", err)
	}
	return accessToken, newRefreshToken, nil
}

// mintAndStoreRefreshToken generates a new opaque refresh token
// (32 random bytes, hex-encoded -- same entropy source and encoding as
// jwt.go's randomJTI, exported nowhere since only this package's two
// services need to mint one) and stores it. Shared by RefreshService
// (rotation) and IssuanceService (initial bootstrap) so both paths
// generate tokens identically.
func mintAndStoreRefreshToken(store domain.RefreshStore, identity, tenantName string, expiresAt time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	token := hex.EncodeToString(b)
	if err := store.Issue(token, identity, tenantName, expiresAt); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}
