---
title: "High Availability"
weight: 30
---

Running more than one Wardline replica behind a load balancer requires
three decisions this guide walks through, plus three Helm primitives
that are on by default once `replicaCount > 1`.

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

## 4. Set a shutdown delay to protect against Endpoints-propagation lag

`/readyz` flipping to 503 the instant SIGTERM arrives doesn't, by
itself, buy meaningful time — Go's `http.Server.Shutdown()` closes the
listener essentially synchronously once called, so there's only a
narrow window for a *new* connection to actually observe the 503
before the listener stops accepting traffic at all. The real
zero-downtime gap this closes is Kubernetes' Endpoints controller
needing time to propagate this pod's removal from Service routing
*before* the container stops accepting connections.

`shutdown_delay_seconds` (Helm value: `wardline.shutdownDelaySeconds`,
chart default `5`, raw config default `0`) is an in-process substitute
for a Kubernetes `preStop` sleep hook — Wardline's own published image
is `distroless` with no shell, so a shell-based `preStop` hook can't
run on it at all. When set, a replica keeps serving normally (and
`/readyz` stays 200) for this long after receiving SIGTERM/SIGINT,
*before* it begins draining:

```yaml
shutdown_delay_seconds: 5
```

This must stay comfortably smaller than `terminationGracePeriodSeconds`
minus Wardline's own ~15s drain budget (10s HTTP drain + 5s tracing
flush) — the Helm chart's own template refuses to render if the two
numbers don't leave enough room, so misconfiguring this is caught at
`helm install`/`helm template` time, not at runtime.

## Budget enforcement, and what's still per-replica

Budget enforcement follows the same `postgres_storage` pattern as
revocation above: with both `budget_enforcement` and `postgres_storage`
on, the per-window counters live in the shared database and one
configured limit is enforced across the whole fleet. With
`postgres_storage` off, the limiter is in-process and each replica
enforces its own independent budget, so the effective request budget
scales roughly with N. See
[Budget Enforcement](/features/budget-enforcement/).

Anomaly-detection state is **not** shared across replicas in this
release — each replica observes only its own traffic, so a detector
sees roughly 1/N of the traffic to a given identity. This is a
documented, deliberate limitation (see
[Anomaly Detection](/features/anomaly-detection/)), not a defect — a
future federation cycle is the natural place to revisit shared state.

## Helm HA primitives

With `replicaCount > 1`, the chart adds, by default:
- A `PodDisruptionBudget` (`minAvailable: 1`, overridable).
- Soft pod anti-affinity, spreading replicas across nodes.
- An explicit `terminationGracePeriodSeconds: 30`, paired with Wardline's
  own graceful-shutdown drain.
