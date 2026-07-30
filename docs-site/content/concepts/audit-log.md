---
title: "Audit Log"
weight: 40
---

Every decision Wardline makes (`allow`, `deny`, `throttled`,
`passthrough`, `error`, `blocked`) is written as one structured JSON line to
`audit.output` — `stdout` by default, or a file path, or (with
`features.postgres_storage: true`) a Postgres table for durable,
queryable storage shared across replicas.

Each entry carries: timestamp, identity, tenant, tool, decision, latency
(ms), and — when applicable — a reason and a trace ID. This is the
foundation [Compliance evidence export](/features/compliance-evidence-export/)
and the live dashboard both build on. An entry written before tenant
isolation shipped (or one whose resolved tenant was genuinely empty) reads
back as the `default` tenant, not an empty string — both the JSONL and
Postgres readers default it on the way in, so older log lines and older
database rows don't silently disappear from a tenant-scoped view.

(Remote address and user agent are available to the OPA/Rego policy
backend as part of its request context — see
[Policy Backends](/concepts/policy-backends/) — but are not themselves
fields on the audit entry.)
