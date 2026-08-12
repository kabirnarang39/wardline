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

An allowed call's entry also carries an effect status — whether the
upstream's own response confirms, contradicts, or leaves unconfirmed
whether the call actually took effect (an MCP no-op result, a JSON-RPC
error, or an opaque success are each classified differently). This is
read from a bounded prefix of the upstream's response body, and is
always `unconfirmed` for a streaming response (`Content-Type:
text/event-stream`, MCP's own Streamable HTTP transport for
progressive tool-call results) — a streaming body is deliberately never
read here at all, so that a real, long-running streamed tool call is
forwarded to the caller as it arrives rather than stalled behind an
attempt to peek at it first.
