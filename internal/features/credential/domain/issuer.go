package domain

import "errors"

// ErrTokenExpired is returned by Verifier.Verify for a syntactically and
// cryptographically valid token whose exp claim has passed.
var ErrTokenExpired = errors.New("token expired")

// ErrTokenInvalid is returned by Verifier.Verify for anything else that
// makes a token unacceptable: malformed, unparsable, or a signature that
// doesn't verify.
var ErrTokenInvalid = errors.New("token invalid")

// Issuer mints a signed, short-lived token for an already-authenticated
// identity.
type Issuer interface {
	Issue(identity string) (token string, err error)
}

// Verifier checks a bearer token's signature and expiry and returns the
// identity it was issued for.
type Verifier interface {
	Verify(token string) (Claims, error)
}
