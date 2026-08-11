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
  scope.

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
  Postgres `DELETE`).

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
  curated pack collection, one flag away).

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
  pipeline.

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

## v2.1 (shipped)

- **Post-condition audit fields** — every write-shaped gated call (`tools/call`)
  now records what it *claimed* to change: target, claimed op, redacted
  claimed args, and the proxy-visible response signal (status, JSON-RPC
  error, no-op detection), classified as `claimed_but_unconfirmed` or
  `claimed_but_contradicted`. A `PostConditionVerifier` interface is
  declared as the Stage-2 seam a domain-aware verifier could implement to
  diff claimed vs. actual state — deliberately **not implemented**: a
  proxy sees request/response, never the upstream's real world-state, so
  that diff needs domain knowledge only an operator's own verifier can
  supply. See [Baseline: Proxy, Policy, and
  Audit](/features/baseline-proxy-policy-audit/).
- **Taint tracking** — a coarse, gateway-level integrity label per
  `(tenant, identity, session)`: a call to a configured untrusted-source
  tool taints the session (TTL-bounded, explicitly declassifiable),
  exposed to policy as `input.tainted`. Session is an explicit
  `X-Wardline-Session` header when the client cooperates, a TTL-window
  fallback otherwise. Deliberately **not** information-flow control — one
  boolean per session, not per-datum flow tracking; that's permanently out
  of scope for a proxy (see [Taint Tracking](/features/taint-tracking/)'s
  boundary section).
- **Approval workflow** — a third policy outcome, `needs_approval`
  (`input.tainted`/`input.job_over_budget` pairs naturally with it), backed
  by an approve-and-retry queue: the flagged call is held (never forwarded)
  and returns 202 with a pending id; an operator approves or denies via
  loopback-guarded endpoints or the dashboard; approval mints a
  single-use, TTL-bounded grant that admits exactly one retry. Fails
  closed (denies) when the flag is off but a policy still emits
  `needs_approval`. See [Approval Workflow](/features/approval-workflow/).
- **Per-job budget ceiling** — a hard cap on total gated calls per
  `(tenant, identity, session)` job, independent of the existing
  per-window budget: a zero-config hard proxy gate (429, decision
  `job_budget_exceeded` — deliberately distinct from `throttled`, so a
  runaway job is greppable as its own diagnostic signal) plus optional
  `input.job_over_budget` policy exposure so an over-budget job can route
  to approval instead of a flat block. Request-count only in this cut, not
  token/cost — a token/cost `Meter` is a possible future adapter behind
  the same interface. In-memory and Postgres-backed (`postgres_storage`)
  meters both ship. See [Per-Job Budget Ceiling](/features/job-budget/).

## v2.2 (shipped)

- **Per-job cost/token budget** — the token/cost `Meter` adapter named in
  per-job budget's own entry above, shipped: a second, independent ceiling
  alongside per-job budget's call count, keyed the same
  `(tenant, identity, session)` way but summing each tool's declared cost
  (`tool_costs`/`default_cost`) instead of counting calls. Same shape as
  per-job budget — zero-config hard proxy gate (429, decision
  `cost_budget_exceeded`), optional `input.cost_over_budget` policy
  exposure, and the same grant-override carve-out an approved retry gets.
  Declared cost only, not response-parsed usage or real-money billing.
  In-memory and Postgres-backed (`postgres_storage`) meters both ship. See
  [Per-Job Cost/Token Budget](/features/cost-budget/).
- **Session TTL fallback made real for job-budget and cost-budget** — both
  features' docs always claimed a job key falls back to a per-identity
  sliding TTL window when no `X-Wardline-Session` header is sent; the code
  didn't apply it (only taint tracking did), so a header-less caller's
  budget key never rotated. Each feature now has its own
  `session_window_seconds` (defaults to 300, matching taint's own
  default) and applies the same fallback taint tracking uses — working
  independently of `taint_tracking` being on.

## v2.3 (shipped)

- **Drift detection (CUSUM)** — a one-sided CUSUM control chart over
  `call_rate` and `tool_diversity`, closing most of `ml_score`'s
  documented low-and-slow blind spot (a per-window z-score test is
  provably strong against abrupt shifts and provably weak against small
  sustained ones — CUSUM is the standard statistical-process-control
  technique for exactly that gap). Requires `ml_score.enabled` (reuses
  its baseline rather than duplicating it). Real, measured recall
  numbers — not a claim — in [Anomaly Detection](/features/anomaly-detection/)'s
  "Recall benchmark" section. Optional `h_jitter_fraction` moving-target
  defense (HMAC-secret-keyed per identity) raises, but does not
  eliminate, the cost of an attack calibrated to the public default
  threshold — see that page's "Adversarial scenarios" for the honest
  numbers on both.
- **Tenant-aggregate anomaly detection** — a new heuristic baselining
  the sum of every identity's call volume within a tenant, closing the
  gap no per-identity heuristic (including drift_detection) can close
  by construction: many identities each individually staying under
  their own threshold. Detection-only (logs, never auto-blocks — there
  is no single identity to block for a tenant-level signal). HA-safe
  with `features.postgres_storage` on — window totals merge atomically
  across replicas, verified against a real Postgres instance with two
  real detectors each seeing only half a coordinated spike. See
  [Anomaly Detection](/features/anomaly-detection/)'s "Adversarial
  scenarios".
- **Identity-churn detection** — a new heuristic baselining the count
  of never-before-seen identities appearing in a tenant per window,
  closing the gap no per-identity mechanism can close by construction
  (including `drift_detection`'s own `h_jitter_fraction`): an attacker
  minting disposable identities to re-roll for a favorable per-identity
  jitter draw, discarding whichever gets caught. Detection-only, same
  "no single identity to block" reasoning as tenant-aggregate detection.
  Measured directly: 30 throwaway identities in one window, 0/30
  individually caught by any per-identity heuristic, flagged by this
  one. In-memory only this cycle — see [Anomaly
  Detection](/features/anomaly-detection/)'s "Adversarial scenarios" and
  "Known limitations".

## Future directions (not committed)

A hosted cloud tier has been explicitly named as a possible future
direction, but is a business/infrastructure decision outside this
project's engineering roadmap — not something this docs site or the
codebase commits to.

This page reflects actual project state as of each release, not
aspirational claims.
