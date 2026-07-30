package usecase

import "github.com/kabirnarang39/wardline/internal/features/credential/domain"

// IssuanceService exchanges a registration secret for a signed token:
// Bootstrapper resolves the secret to an identity, Issuer signs a token
// for it.
type IssuanceService struct {
	bootstrapper domain.Bootstrapper
	issuer       domain.Issuer
}

func NewIssuanceService(bootstrapper domain.Bootstrapper, issuer domain.Issuer) *IssuanceService {
	return &IssuanceService{bootstrapper: bootstrapper, issuer: issuer}
}

// Bootstrap returns whatever error the Bootstrapper returns unchanged —
// domain.ErrInvalidCredentials for a bad secret — so the HTTP handler
// (Task 6) can map it to a generic 401 without caring which stage failed.
func (s *IssuanceService) Bootstrap(secret string) (token string, err error) {
	// Tenant is resolved but not yet threaded into the issued token --
	// Issuer.Issue and Claims.Tenant wiring lands in a later task.
	identity, _, err := s.bootstrapper.Authenticate(secret)
	if err != nil {
		return "", err
	}
	return s.issuer.Issue(identity)
}
