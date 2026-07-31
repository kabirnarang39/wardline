// Package domain infers a starter policy.domain.Rule set from observed
// audit.domain.Entry history -- the logic behind `wardline infer-policy`.
// It sits between the audit and policy features (consumes one, produces
// the other) without adding new domain types of its own.
package domain

import (
	"sort"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// tripleKey identifies one (tenant, identity, tool) combination -- the
// granularity Infer allow-lists at.
type tripleKey struct {
	Tenant   string
	Identity string
	Tool     string
}

// Infer builds one allow Rule per distinct (Tenant, Identity, Tool)
// triple seen among entries whose Decision is exactly "allow" -- calls
// the policy engine itself already evaluated and blessed, so inference
// can only ever reproduce a grant that was already made, never
// manufacture a new one. Every other Decision is excluded:
//
//   - "deny"/"throttled"/"blocked"/"error": the call did NOT succeed, and
//     allow-listing it would grant access beyond what was observed -- the
//     opposite of a least-privilege starter policy.
//   - "passthrough": the call bypassed policy evaluation entirely (see
//     proxy/adapter.Handler, which forwards non-tools/call JSON-RPC
//     methods unevaluated), so Entry.Tool holds a raw, caller-supplied
//     JSON-RPC method name rather than a policy-evaluated tool name --
//     and on the default HeaderIdentity path Identity/Tenant are
//     caller-supplied too. Treating that as an "observed grant" would let
//     an unauthenticated request plant an arbitrary rule.
//
// Entries are also skipped when Tool == "*" (defense in depth: observed
// traffic must never synthesize the wildcard rule policy/usecase.Matcher
// treats as matching every tool) or when Identity or Tool is empty (the
// default HeaderIdentity authenticator yields Identity == "" when the
// header is absent, and policy/adapter.LoadFile rejects both, so emitting
// one would produce a file the real loader refuses).
//
// An empty Entry.Tenant is normalized to tenant.Default -- the same
// read-time defaulting audit/adapter's JSONL and postgres readers apply.
// Left as "", it would mean "global: matches any tenant" to
// policy.domain.Rule, silently widening one tenant's traffic into a
// cross-tenant allow.
//
// Returned rules are sorted by (Tenant, Identity, Tool) so two calls over
// identical input produce an identical slice.
func Infer(entries []auditdomain.Entry) []policydomain.Rule {
	seen := make(map[tripleKey]bool)
	for _, e := range entries {
		if e.Decision != "allow" || e.Identity == "" || e.Tool == "" || e.Tool == "*" {
			continue
		}
		entryTenant := e.Tenant
		if entryTenant == "" {
			entryTenant = tenant.Default
		}
		seen[tripleKey{Tenant: entryTenant, Identity: e.Identity, Tool: e.Tool}] = true
	}

	rules := make([]policydomain.Rule, 0, len(seen))
	for k := range seen {
		rules = append(rules, policydomain.Rule{
			Identity: k.Identity,
			Tool:     k.Tool,
			Tenant:   k.Tenant,
			Effect:   policydomain.EffectAllow,
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Tenant != rules[j].Tenant {
			return rules[i].Tenant < rules[j].Tenant
		}
		if rules[i].Identity != rules[j].Identity {
			return rules[i].Identity < rules[j].Identity
		}
		return rules[i].Tool < rules[j].Tool
	})
	return rules
}
