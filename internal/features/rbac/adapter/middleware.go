package adapter

import (
	"net/http"

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
// perm within tenant. Identity-resolution failure -> 401; authorization
// failure -> 403; next is never called on either failure path.
func RequirePermission(checker Checker, identity IdentityResolver, tenant string, perm domain.Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := identity.Authenticate(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !checker.Check(who, tenant, perm) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
