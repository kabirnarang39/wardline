---
title: "Identity and Policy"
weight: 20
---

Every request to Wardline must carry an `X-Wardline-Identity` header.
Policy rules match on this identity plus the MCP tool name
(`params.name` in a `tools/call` JSON-RPC request).

A rule can also carry an optional `tenant:` key, scoping it to a single
tenant; omitting it (or leaving it empty) keeps the rule global, matching
every tenant — the same "no tenant means global" convention used
throughout this codebase (RBAC's `ClusterRoleBinding`, SCIM's group
naming). The caller's tenant comes from whatever identity source is
active: an OIDC ID token's or Wardline-issued JWT's `tenant` claim when
`credential_issuance` is on, or the `X-Wardline-Tenant` header when it's
off. That second case is worth calling out explicitly: `HeaderIdentity`
reads `X-Wardline-Tenant` unauthenticated, so a `tenant:` rule added to a
header-identity-only deployment gets no real enforcement — the caller
can simply send whatever tenant they like. This isn't a new hole
(identity itself is already just as spoofable there), but an operator
adding `tenant:` rules should know they're only meaningfully enforceable
once `credential_issuance` is on.

## Decision types

Every request produces exactly one decision, recorded in the audit log:

- **`allow`** — matched an allow rule (or a policy backend's `allow`
  evaluated true); forwarded upstream.
- **`deny`** — matched a deny rule, or no rule matched and the policy's
  `default` is `deny` (an explicit, required, operator-set choice —
  there's no hardcoded fallback); not forwarded.
- **`throttled`** — budget enforcement rejected the call (see
  [Budget Enforcement](/features/budget-enforcement/)); not forwarded.
- **`passthrough`** — protocol-level MCP methods that aren't `tools/call`
  (the `initialize` handshake, `notifications/initialized`, `tools/list`,
  and, if your upstream exposes them, `resources/*`/`prompts/*`) are
  forwarded to the upstream without a policy or budget check, recorded
  as `passthrough` so they're visible but distinguishable from a real
  `allow`. If your upstream server exposes sensitive resources or
  prompts, be aware they are not currently gated by policy.
- **`error`** — malformed request (unparseable JSON-RPC, missing
  identity header, etc.).
- **`blocked`** — the identity is currently auto-blocked by anomaly
  detection's `ml_score`/`auto_block` feature (see [Anomaly
  Detection](/features/anomaly-detection/)): every call is rejected
  (`403`, JSON-RPC error, `Retry-After` header) until
  `auto_block.block_duration_seconds` elapses since the most recent
  detection, with no manual early unblock this cycle.

Scope note: policy, budget, and audit decisions apply to `tools/call`
only, for the reason above. `auto_block` is the one deliberate exception:
once an identity is blocked, ALL of its calls are rejected, including
protocol-lifecycle passthrough methods like `initialize` — a blocked
identity shouldn't get a handshake either.

Next: [Policy backends](/concepts/policy-backends/).
