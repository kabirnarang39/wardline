---
title: "Roadmap"
weight: 20
---

## v1.0 (shipped)

Proxy + policy + audit baseline, credential issuance, RBAC, budget
enforcement, anomaly detection (heuristic), compliance evidence export,
policy-pack marketplace, HA deployment.

## v2.0 (shipped)

- **Federation** — cross-instance signal sharing: instances publish
  anomaly summaries to configured peers and correlate them into
  cross-instance alerts, revisiting the per-replica limitations
  documented on the [Budget Enforcement](/features/budget-enforcement/),
  [Anomaly Detection](/features/anomaly-detection/), and [HA
  Deployment](/features/ha-deployment/) pages. Federation's own
  correlated-alerts view stays instance-scoped, not tenant-scoped (see
  [RBAC](/features/rbac/)'s known limitations).
- **ML-based anomaly detection** — an `ml_score` combined-z-score
  heuristic augmenting the existing rule/statistics detectors, with an
  optional `auto_block`.
- **SSO/SCIM + RBAC tenant isolation** — an OIDC bootstrap adapter and
  a SCIM 2.0-shaped Users/Groups provisioning API give RBAC's admin
  surface IdP-backed identity, and `Tenant` now flows and is enforced
  end to end: policy, budget, audit, anomaly detection, and the
  dashboard are all tenant-aware, not just RBAC's own authorization
  check. See [SSO](/features/sso/), [SCIM](/features/scim/), and
  [RBAC](/features/rbac/)'s known limitations for what's still out of
  scope (OIDC discovery, full SCIM 2.0 compliance).
- **Auto-generated sandbox policy** — `wardline infer-policy` reads the
  audit trail over an operator-chosen range and writes a starter
  `policy.yaml` allow-listing exactly the `(tenant, identity, tool)`
  combinations seen in traffic that reached upstream, defaulting to deny
  for everything else. See [Auto-Generated Sandbox
  Policy](/features/auto-generated-policy/) for what's deliberately out
  of scope (a live/continuous learning mode, tool-argument-aware
  inference).
- **mTLS/SPIFFE credential bootstrap** — a third `credential_issuance`
  bootstrap source that resolves an already-verified SPIFFE ID
  (forwarded by a terminating mTLS proxy or mesh via a trusted header)
  to a registered identity and tenant. Wardline never terminates TLS or
  parses X.509 itself — the existing Ingress-terminates-TLS decision
  stands. See [mTLS/SPIFFE Bootstrap](/features/mtls-bootstrap/) for the
  trust-boundary requirements and what's deliberately out of scope (a
  SPIFFE Workload API client inside Wardline itself, dynamic
  SPIFFE-ID-to-tenant mapping).
- **Refresh tokens + configurable JWT TTL** — `credential.access_token_ttl_seconds`
  replaces a hardcoded 15-minute constant (defaults to 900s,
  unchanged); `POST /credentials/refresh` exchanges a single-use,
  rotating refresh token (`credential.refresh_token_ttl_seconds`,
  default 86400s / 24h) for a new access+refresh pair without
  re-presenting the original bootstrap credential. Revoking an
  identity invalidates its outstanding refresh tokens immediately, not
  just its access tokens. See [Credential
  Issuance](/features/credential-issuance/) for what's deliberately out
  of scope (refresh-token-reuse detection / cascading family
  revocation).
- **Distributed/shared budget-enforcement counters** — a
  Postgres-backed `PostgresLimiter`, enabled by `features.postgres_storage`
  alongside `features.budget_enforcement`, shares identity/tenant/tool
  rate-limit buckets across every replica instead of each replica
  keeping its own independent, in-process counter. Same fixed-window
  algorithm, same config shape (`budget.requests_per_window`,
  `budget.tenants`, `budget.tools`) — only the bucket state moves. See
  [Budget Enforcement](/features/budget-enforcement/) for what's
  deliberately out of scope (a different rate-limiting algorithm,
  cross-database sharding, bucket-row cleanup).
- **Persistent anomaly-detection baseline state + dashboard panel** — a
  Postgres-backed `PostgresBaselineStore`, enabled by
  `features.postgres_storage` alongside `features.anomaly_detection`,
  checkpoints every identity's behavioral baseline on the same interval
  as GC (`anomaly.gc_interval_seconds`) and reloads it at startup, so a
  restart no longer wipes every identity's history at once. A new
  read-only Anomalies panel in the web dashboard surfaces
  `/dashboard/api/anomalies` (previously API-only) in the UI. See
  [Anomaly Detection](/features/anomaly-detection/) for what's
  deliberately out of scope (cross-replica baseline sharing, blob-format
  migration).
- **Widening policy enforcement to MCP resources/* and prompts/* calls** —
  a policy `Rule` and `Context` now carry an optional `method` (blank
  means `tools/call`, so every rule written before this existed keeps
  matching exactly what it matched before); `resources/read`,
  `resources/list`, `prompts/get`, `prompts/list`, and any other
  `resources/*`/`prompts/*` method are policy-evaluated (YAML, OPA, or
  Cedar, all three backends) instead of passing through unconditionally.
  Budget enforcement stays tool-call-scoped only — deliberately out of
  scope, see the design doc for why. Docs:
  `docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md`.

- **Compliance-evidence-export hardening** — cryptographic signing
  (`wardline generate-signing-key`/`export-evidence -sign-key`/
  `verify-evidence`, RSA-PSS/SHA-256, matching federation's existing
  scheme), a live query API (`GET /dashboard/api/compliance`, also a
  dashboard Compliance view — aggregate counts only, never raw entries),
  redacted credential inclusion (`identities.json`: name+tenant only,
  never secrets/SPIFFE IDs), scheduled export
  (`features.compliance_scheduled_export`, a periodic background job
  reusing `export-evidence`'s exact code path), and log retention
  (`features.log_retention`, `audit.retention_days`/
  `anomaly.retention_days`, a periodic purge job — JSONL rewrite or
  Postgres `DELETE`). Docs:
  `docs/superpowers/specs/2026-08-08-compliance-evidence-export-hardening-design.md`.

- **Policy-pack marketplace expansion** — OPA and Cedar variants of all
  four existing packs (twelve packs total), a `version:` metadata field
  on every pack manifest, `wardline policy-pack compose` (merges
  multiple yaml-backend packs' rules into one file, warns on a
  duplicate `(identity, tool, tenant)` grant rather than silently
  dropping one), and `-packs-dir <path>` (merges an operator-owned
  directory of packs with the embedded catalog, on `list`/`show`/
  `install`/`compose`). Deliberately **not** a live network-fetched
  registry — hosting/publishing/trust infrastructure is a business
  decision outside this engineering roadmap, the same reasoning that
  already excludes a hosted cloud tier (see below); `-packs-dir` is
  this cycle's zero-hosting way to get most of that value (an org's own
  curated pack collection, one flag away). Docs:
  `docs/superpowers/specs/2026-08-08-policy-pack-marketplace-expansion-design.md`.

- **HA distributed state + signing-key rotation** — the distributed
  budget counters (`PostgresLimiter`) and anomaly baselines
  (`PostgresBaselineStore`) shipped earlier in v2.0; this closes the two
  remaining gaps. **Distributed auto-block:** a Postgres-backed
  `PostgresBlockStore` (enabled by `postgres_storage` alongside
  `anomaly_detection`) so a block triggered by one HA replica is honored
  by every replica, not dodgeable by load-balancing to a different pod.
  **Signing-key rotation:** `credential.previous_signing_key_files`
  accepts old keys for verification-only during a rotation window (new
  tokens sign under the new key, old-key tokens keep verifying to their
  TTL), a `kid` header on every token, and a `GET /credentials/jwks`
  endpoint. Deliberately **not** a live cloud KMS integration — local
  PEM rotation is the self-hosted-proxy-appropriate default; an operator
  wanting KMS custody sources the PEM bytes through their own Secret
  pipeline. Docs:
  `docs/superpowers/specs/2026-08-08-ha-rotation-blockstate-design.md`.

- **gRPC transport support** — a second listener (feature
  `grpc_transport`, `grpc_listen` + `grpc_upstream`) runs the exact same
  identity → auto-block → policy → budget → audit pipeline as the HTTP
  proxy, reusing the same policy engine, budget, and audit trail. It's a
  transparent reverse proxy: a raw passthrough codec relays message bytes
  verbatim, so Wardline needs no relayed service's protobuf schema, and the
  gRPC full method (`/pkg.Service/Method`) is the audited/policy-keyed
  "tool" under a new policy method namespace `grpc` (a blank-method rule
  still means `tools/call`, so no existing MCP rule accidentally matches a
  gRPC call). Deliberately out of scope for this cut: TLS to the upstream
  (plaintext today; terminate at ingress), and per-message policy
  evaluation (one decision per RPC at stream start, mirroring the HTTP
  transport's one-decision-per-request).

## v2.0 (planned, not yet shipped)

A hosted cloud tier has been explicitly named as a possible future
direction, but is a business/infrastructure decision outside this
project's engineering roadmap — not something this docs site or the
codebase commits to.

This page reflects actual project state as of each release, not
aspirational claims — cross-check against `docs/superpowers/specs/`
before updating it for a new release.
