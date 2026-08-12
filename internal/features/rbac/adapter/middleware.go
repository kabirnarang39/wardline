package adapter

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
)

// Checker is the subset of rbac usecase.Checker's behavior
// RequirePermission depends on — a narrow interface so tests can supply
// a fake without importing the real usecase package's flags/authorizer
// wiring, same pattern as proxy/adapter's BudgetChecker.
type Checker interface {
	Check(identity, tenant string, perm domain.Permission) bool
}

// RequirePermission wraps next so it's only reached when identity
// resolves successfully and the resolved identity is authorized for
// perm within its own resolved tenant. Identity-resolution failure -> 401;
// authorization failure -> 403; next is never called on either failure
// path. Both failure paths log a warning (remote-addr only on 401, plus
// the resolved identity on 403 since it's safe/useful once known) — see
// proxy/adapter.Handler's identical "identity authentication failed"
// logging, which this mirrors one layer up.
//
// loginRedirect, when non-empty, turns the 401 into a 303 redirect to
// that path for a plain browser page navigation (a GET whose Accept
// asks for text/html) -- a person who opens /dashboard/ with no session
// lands on the login form instead of a bare "unauthorized" body.
// Everything else on the 401 path (a fetch/XHR from the SPA, a POST
// mutation, any non-HTML client) still gets the 401 so it can handle the
// failure itself. Callers gating API/mutation routes pass "".
func RequirePermission(checker Checker, identity IdentityResolver, perm domain.Permission, next http.Handler, logger *slog.Logger, loginRedirect string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		who, tenantName, err := identity.Authenticate(r)
		if err != nil {
			logger.Warn("identity authentication failed", "remote_addr", r.RemoteAddr)
			if loginRedirect != "" && r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, loginRedirect, http.StatusSeeOther)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !checker.Check(who, tenantName, perm) {
			logger.Warn("rbac authorization denied", "remote_addr", r.RemoteAddr, "identity", who)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
