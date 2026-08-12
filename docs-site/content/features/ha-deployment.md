---
title: "HA Deployment"
weight: 80
summary: "Multi-replica correctness for credential issuance, plus real health/readiness."
---

Makes running N replicas of Wardline behind a load balancer actually
correct, not just possible:

- An optional persistent RSA signing key
  (`credential.signing_key_file`) so a token issued by one replica
  verifies on every other replica.
- A Postgres-backed shared revocation store (wired when both
  `credential_issuance` and `postgres_storage` are on) so a revocation
  on one replica is honored by every other replica.
- Real `/healthz` (liveness, always 200 once started, never depends on
  an external dependency) and `/readyz` (readiness — 503 during
  graceful shutdown, and if `postgres_storage` is on, also 503 if the
  database is unreachable).
- Helm chart HA primitives: `httpGet` probes against the endpoints
  above, a `PodDisruptionBudget`, soft pod anti-affinity, and an
  explicit `terminationGracePeriodSeconds`.

See the full operational guide: [High Availability](/deployment/high-availability/).

## Known limitations

- Budget enforcement is per-replica **unless `postgres_storage` is also
  on** — with it, the per-window counters live in the shared Postgres
  database and one configured limit is enforced across the whole fleet,
  the same pattern as credential revocation above. Without it the
  limiter is in-process and the effective budget scales with replica
  count. See [Budget Enforcement](/features/budget-enforcement/).
- Anomaly-detection state is mostly HA-safe when `postgres_storage` is
  also on: `auto_block` decisions are shared across the fleet (a block
  written by one replica is honored by every other replica), per-identity
  baselines persist across restarts (though per-instance, not merged —
  each replica keeps learning from the traffic it itself sees), and
  `tenant_anomaly`'s aggregate window totals merge atomically across
  replicas, so a coordinated spike split across the fleet by the load
  balancer is still caught. What's still per-replica-only: per-identity
  baselines aren't pooled into one fleet-wide baseline (only persisted),
  and `drift_detection`'s CUSUM accumulators follow that same
  per-instance-persisted-not-merged shape. See [Anomaly
  Detection](/features/anomaly-detection/)'s own limitations section for
  the exact per-mechanism breakdown.
- **The dashboard's live audit view is cluster-wide when `postgres_storage`
  is also on** — every replica's `PostgresWriter` inserts into the same
  shared `audit_entries` table, so `GET /dashboard/api/audit` reads every
  replica's traffic through `PostgresWriter.Since`, not just the replica
  that happens to serve that dashboard request. Without `postgres_storage`,
  the live view falls back to the in-memory ring buffer and stays
  per-replica, same as before.
- No automatic session/sticky-affinity load balancing is recommended as
  a workaround for the above — sticky sessions would reintroduce a
  single point of failure per identity.
- Signing-key rotation is supported —
  `credential.previous_signing_key_files` accepts old keys for
  verification-only during a rotation window (new tokens sign under the
  new key, old-key tokens keep verifying to their TTL), every token
  carries a `kid`, and `GET /credentials/jwks` publishes the active keys.
  What's still out of scope is a **live cloud KMS integration**: the keys
  are local PEM files, so an operator wanting KMS custody sources the PEM
  bytes through their own secret pipeline.
