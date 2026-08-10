---
title: "Policy Rego Reference"
weight: 40
---

Policies must declare `package wardline.authz` and export an `allow`
boolean (and optionally a `reason` string):

```rego
package wardline.authz

default allow = false

allow {
    input.identity == "agent-abc123"
    input.tool == "read_file"
}
```

`input` is the full request context — see
[Policy Backends](/concepts/policy-backends/) for the exact JSON shape,
including `input.method`, `input.tainted` (only meaningful when
[taint tracking](/features/taint-tracking/) is on; always `false`
otherwise), and `input.job_over_budget` (only meaningful when [per-job
budget ceiling](/features/job-budget/) is on; always `false` otherwise —
`true` when the calling job has already reached its `requests_per_job`
ceiling based on calls prior to this one). Both `input.tainted` and
`input.job_over_budget` are read-only, request-context fields — not to be
confused with `approval` and `hard_deny` below, which are keys a policy
*returns* in its result object.

## Result keys and precedence

Wardline reads up to four keys from the evaluated result object. Only
`allow` is required — the other three are opt-in, and their absence is
identical to `false`, so an existing policy that only ever returned `allow`
(and optionally `reason`) behaves exactly as before.

| Key | Type | Meaning |
|---|---|---|
| `allow` | bool (required) | Grants the call. Missing or non-boolean → deny. |
| `reason` | string (optional) | Recorded in the audit log only, never sent to the caller. Defaults to `"opa decision"` when absent. |
| `approval` | bool (optional) | When `true` and the call isn't hard-denied, the outcome is `needs_approval` instead of allow — see [Approval workflow](/features/approval-workflow/). |
| `hard_deny` | bool (optional) | Forces a deny even if `approval` or `allow` is also `true`. |

Precedence is **`hard_deny` &gt; `approval` &gt; `allow`**, evaluated in that
order — fail-safe: a policy that both denies and requests approval always
denies. Pairing `approval` with [`input.tainted`](/features/taint-tracking/)
or [`input.job_over_budget`](/features/job-budget/) is the intended use:

```rego
package wardline.authz

default allow = false

is_write { input.method == "tools/call" }

approval {
    input.tainted
    is_write
}

allow {
    input.identity == "agent-abc123"
}
```
