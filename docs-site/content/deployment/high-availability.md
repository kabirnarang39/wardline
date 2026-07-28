---
title: "High Availability"
weight: 30
---

Running more than one Wardline replica behind a load balancer requires
two decisions this guide walks through, plus three Helm primitives that
are on by default once `replicaCount > 1`.

## 1. Give every replica the same signing key

Without `credential.signing_key_file` set, each replica generates its
own fresh in-process RSA key at startup — a token issued by replica A
will fail verification on replica B. Mount the same PEM file (PKCS1 or
PKCS8) to every replica:

```yaml
credential:
  signing_key_file: /etc/wardline/signing-key.pem
```

`wardline validate-config` checks this file exists and parses as a
valid RSA private key before `serve` starts.

## 2. Share revocation state via Postgres

With only `credential_issuance` on, revocation is in-memory and
per-replica — a revocation on replica A is invisible to replica B.
Turn on `postgres_storage` as well to share revocation state through
the same database already used for audit storage:

```yaml
features:
  credential_issuance: true
  postgres_storage: true
audit:
  postgres_dsn: "postgres://user:pass@host:5432/wardline?sslmode=require"
```

## 3. Point probes at the real health endpoints

`/healthz` (liveness — always 200 once started, never depends on an
external dependency) and `/readyz` (readiness — 503 during graceful
shutdown, and 503 if Postgres is unreachable when `postgres_storage` is
on) are always registered, unconditionally. The Helm chart's
`livenessProbe`/`readinessProbe` already point `httpGet` at these paths.

## What's still per-replica

Budget enforcement and anomaly-detection state are **not** shared across
replicas in this release — each replica enforces its own independent
budget and observes its own traffic for anomaly signals. Running N
replicas means the effective request budget scales roughly with N, and
each replica's anomaly detector sees only 1/N of the traffic to a given
identity. This is a documented, deliberate limitation (see
[Budget Enforcement](/features/budget-enforcement/) and
[Anomaly Detection](/features/anomaly-detection/)), not a defect — a
future federation cycle is the natural place to revisit shared state.

## Helm HA primitives

With `replicaCount > 1`, the chart adds, by default:
- A `PodDisruptionBudget` (`minAvailable: 1`, overridable).
- Soft pod anti-affinity, spreading replicas across nodes.
- An explicit `terminationGracePeriodSeconds: 30`, paired with Wardline's
  own graceful-shutdown drain.
