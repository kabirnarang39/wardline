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

- Budget enforcement and anomaly-detection state stay per-replica —
  already-documented limitations, not fixed by this cycle (effective
  budget scales with replica count; anomaly signal is diluted across
  replicas).
- The dashboard's live audit view stays per-replica — no cluster-wide
  aggregation yet.
- No automatic session/sticky-affinity load balancing is recommended as
  a workaround for the above — sticky sessions would reintroduce a
  single point of failure per identity.
- No key rotation/KMS integration for the signing key yet — loading a
  static PEM file from a mounted secret is the v1.0 bar; rotating it
  without invalidating outstanding tokens (e.g. a JWKS endpoint) is
  future work.
