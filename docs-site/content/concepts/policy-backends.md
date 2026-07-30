---
title: "Policy Backends"
weight: 30
---

Wardline supports three interchangeable policy backends, selected by
`policy_backend` in `wardline.yaml` (defaults to `yaml`):

| Backend | When to pick it |
|---|---|
| `yaml` (default) | Simplest case: a static allow/deny list per identity+tool. No expression language, easiest to audit by reading the file. |
| `opa` | You need conditions beyond identity+tool — time of day, request parameters, arbitrary logic — expressed in Rego, evaluated in-process (no external `opa` server, no network hop). |
| `cedar` | You want AWS Cedar's `permit(...)`/`forbid(...)` policy language, evaluated in-process via `cedar-go`, no external process. |

All three see the same request context. For `opa`, the Rego `input` is
the full request as JSON:

```json
{
  "identity": "agent-abc123",
  "tool": "read_file",
  "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
  "timestamp": "2026-07-27T10:00:00Z",
  "remote_addr": "10.0.0.5:54321",
  "user_agent": "some-agent/1.0",
  "tenant": "acme"
}
```

`input.tenant` is the calling identity's resolved tenant (see [Identity
and Policy](/concepts/identity-and-policy/) for where that comes from) —
write `input.tenant == "acme"` in a Rego rule body to scope it to one
tenant, the same thing the YAML backend's `tenant:` rule key does. Cedar
exposes the same value as `context.tenant` (a `String`), alongside
`context.params`/`context.timestamp`/`context.remote_addr`/`context.user_agent`.

Exact syntax for each backend: [Policy YAML reference](/reference/policy-yaml-reference/),
[Policy Rego reference](/reference/policy-rego-reference/),
[Policy Cedar reference](/reference/policy-cedar-reference/).
