---
title: "Audit Log"
weight: 40
---

Every decision Wardline makes (`allow`, `deny`, `throttled`,
`passthrough`, `error`) is written as one structured JSON line to
`audit.output` — `stdout` by default, or a file path, or (with
`features.postgres_storage: true`) a Postgres table for durable,
queryable storage shared across replicas.

Each entry carries: timestamp, identity, tool, decision, latency (ms),
and — when applicable — a reason and a trace ID. This is the
foundation [Compliance evidence export](/features/compliance-evidence-export/)
and the live dashboard both build on.

(Remote address and user agent are available to the OPA/Rego policy
backend as part of its request context — see
[Policy Backends](/concepts/policy-backends/) — but are not themselves
fields on the audit entry.)
