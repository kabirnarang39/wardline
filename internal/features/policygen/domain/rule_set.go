// Package domain infers a starter policy.domain.Rule set from observed
// audit.domain.Entry history -- the logic behind `wardline infer-policy`.
// It sits between the audit and policy features (consumes one, produces
// the other) without adding new domain types of its own.
package domain

import (
	"sort"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

// tripleKey identifies one (tenant, identity, tool) combination -- the
// granularity Infer allow-lists at.
type tripleKey struct {
	Tenant   string
	Identity string
	Tool     string
}

// Infer builds one allow Rule per distinct (Tenant, Identity, Tool)
// triple seen among entries whose Decision is "allow" or "passthrough" --
// traffic that actually reached upstream. Entries with any other
// Decision ("deny", "throttled", "blocked", "error") are excluded:
// allow-listing a call that did NOT succeed would grant access beyond
// what was actually observed, the opposite of a least-privilege starter
// policy. Returned rules are sorted by (Tenant, Identity, Tool) so two
// calls over identical input produce an identical slice.
func Infer(entries []auditdomain.Entry) []policydomain.Rule {
	seen := make(map[tripleKey]bool)
	for _, e := range entries {
		if e.Decision != "allow" && e.Decision != "passthrough" {
			continue
		}
		seen[tripleKey{Tenant: e.Tenant, Identity: e.Identity, Tool: e.Tool}] = true
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
