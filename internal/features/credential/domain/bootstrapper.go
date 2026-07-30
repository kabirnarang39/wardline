package domain

import "errors"

// ErrInvalidCredentials is returned by Bootstrapper.Authenticate for both
// an unknown identity and a wrong secret — deliberately not distinguished,
// so a caller can't enumerate valid identities by observing which error
// they get back.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Bootstrapper exchanges a registration secret for the identity and
// tenant it belongs to. presharedsecret.Bootstrapper is this cycle's
// adapter; an mtls.Bootstrapper or oidc.OIDCBootstrapper adapter can
// plug in later with zero usecase changes (Open/Closed).
type Bootstrapper interface {
	Authenticate(secret string) (identity, tenant string, err error)
}
