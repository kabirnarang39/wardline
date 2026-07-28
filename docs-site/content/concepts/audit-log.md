---
title: "Audit Log"
weight: 40
---

Every decision Wardline makes (`allow`, `deny`, `passthrough`, `error`)
is written as one structured JSON line to `audit.output` — `stdout` by
default, or a file path, or (with `features.postgres_storage: true`) a
Postgres table for durable, queryable storage shared across replicas.

Each entry carries: identity, tool, decision, reason, timestamp, and
request metadata (remote address, user agent). This is the foundation
[Compliance evidence export](/features/compliance-evidence-export/) and
the live dashboard both build on.
