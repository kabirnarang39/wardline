package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// RevocationService is a thin pass-through so the HTTP handler depends
// on a usecase type, not the adapter-level Revoker/RefreshStore
// directly -- Dependency Inversion, same posture as every other
// usecase/adapter boundary in this codebase. refreshStore is required
// (not nil-checked): whenever credential_issuance is on, refresh tokens
// are always available too (no separate feature flag gates them), so a
// real caller never has a nil here -- a construction-time nil would be
// a wiring bug worth panicking on loudly, not silently no-op'ing a
// security-relevant cleanup step.
type RevocationService struct {
	revoker      domain.Revoker
	refreshStore domain.RefreshStore
}

func NewRevocationService(revoker domain.Revoker, refreshStore domain.RefreshStore) *RevocationService {
	return &RevocationService{revoker: revoker, refreshStore: refreshStore}
}

// Revoke writes the (tenant, identity) revocation entry AND wipes every
// outstanding refresh token for that identity -- both matter for
// different windows (see design doc "Interaction with revocation"): the
// Revoker entry rejects the identity's future/outstanding ACCESS
// tokens until it expires; the refresh-token wipe closes the window
// immediately rather than waiting for HandleRefresh's own IsRevoked
// check to catch a still-valid refresh token later.
func (s *RevocationService) Revoke(tenantName, identity string, expiresAt time.Time) error {
	if err := s.revoker.Revoke(tenantName, identity, expiresAt); err != nil {
		return err
	}
	return s.refreshStore.RevokeAllForIdentity(tenantName, identity)
}
