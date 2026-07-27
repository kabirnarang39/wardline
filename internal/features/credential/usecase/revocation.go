package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// RevocationService is a thin pass-through so the HTTP handler (Task 6)
// depends on a usecase type, not the adapter-level Revoker directly —
// Dependency Inversion, same posture as every other usecase/adapter
// boundary in this codebase.
type RevocationService struct {
	revoker domain.Revoker
}

func NewRevocationService(revoker domain.Revoker) *RevocationService {
	return &RevocationService{revoker: revoker}
}

func (s *RevocationService) Revoke(identity string, expiresAt time.Time) {
	s.revoker.Revoke(identity, expiresAt)
}
