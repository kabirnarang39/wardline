package usecase

import (
	"errors"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// ErrRevoked is returned by Authenticate when the token's claimed
// identity is currently revoked — a distinct sentinel from whatever the
// Verifier returns for a bad signature or expiry, so callers/tests can
// tell the two apart without string-matching.
var ErrRevoked = errors.New("identity revoked")

// VerificationService authenticates a bearer token: Verifier checks
// signature/expiry, then Revoker gets the final say.
type VerificationService struct {
	verifier domain.Verifier
	revoker  domain.Revoker
}

func NewVerificationService(verifier domain.Verifier, revoker domain.Revoker) *VerificationService {
	return &VerificationService{verifier: verifier, revoker: revoker}
}

func (s *VerificationService) Authenticate(bearerToken string) (identity, tenant string, err error) {
	claims, err := s.verifier.Verify(bearerToken)
	if err != nil {
		return "", "", err
	}
	if s.revoker.IsRevoked(claims.Subject) {
		return "", "", ErrRevoked
	}
	return claims.Subject, claims.Tenant, nil
}
