---
title: "Identity and Policy"
weight: 20
---

Every request to Wardline must carry an `X-Wardline-Identity` header.
Policy rules match on this identity plus the MCP tool name
(`params.name` in a `tools/call` JSON-RPC request).

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

Scope note: policy, budget, and audit decisions apply to `tools/call`
only, for the reason above.

Next: [Policy backends](/concepts/policy-backends/).
