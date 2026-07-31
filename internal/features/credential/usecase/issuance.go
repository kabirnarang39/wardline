package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// IssuanceService exchanges a registration secret for a signed access
// token AND an initial refresh token: Bootstrapper resolves the secret
// to an identity, Issuer signs the access token, and a fresh refresh
// token is minted and stored the same way RefreshService.Refresh mints
// one on rotation -- without this, nothing could ever call
// /credentials/refresh, since it has no refresh token to redeem yet.
type IssuanceService struct {
	bootstrapper    domain.Bootstrapper
	issuer          domain.Issuer
	refreshStore    domain.RefreshStore
	refreshTokenTTL time.Duration
}

func NewIssuanceService(bootstrapper domain.Bootstrapper, issuer domain.Issuer, refreshStore domain.RefreshStore, refreshTokenTTL time.Duration) *IssuanceService {
	return &IssuanceService{bootstrapper: bootstrapper, issuer: issuer, refreshStore: refreshStore, refreshTokenTTL: refreshTokenTTL}
}

// Bootstrap returns whatever error the Bootstrapper returns unchanged —
// domain.ErrInvalidCredentials for a bad secret — so the HTTP handler
// can map it to a generic 401 without caring which stage failed.
func (s *IssuanceService) Bootstrap(secret string) (accessToken, refreshToken string, err error) {
	identity, tenantName, err := s.bootstrapper.Authenticate(secret)
	if err != nil {
		return "", "", err
	}
	accessToken, err = s.issuer.Issue(identity, tenantName)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = mintAndStoreRefreshToken(s.refreshStore, identity, tenantName, time.Now().Add(s.refreshTokenTTL))
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}
