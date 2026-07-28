package adapter

import "net/http"

// IdentityResolver resolves the caller's identity for a request.
// Structurally identical to proxyadapter.IdentityAuthenticator — the
// same already-constructed HeaderIdentity{}/bearerIdentity value wired
// for proxied tool calls satisfies this interface too, at the main.go
// composition-root wiring site, with no glue code and no import of
// proxy/adapter from this package (same narrow-local-interface pattern
// as BudgetChecker/Authenticator elsewhere in this codebase).
type IdentityResolver interface {
	Authenticate(r *http.Request) (identity string, err error)
}
