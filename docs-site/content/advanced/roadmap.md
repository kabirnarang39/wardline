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

## v2.0 (planned, not yet shipped)

- **Refresh tokens + configurable JWT TTL** — issuing short-lived access tokens with refresh token rotation and tunable expiration.
- **Distributed/shared budget-enforcement counters** — sharing budget state across replicas for consistent enforcement.
- **Persistent anomaly-detection baseline state + dashboard panel** — storing detection baselines and surfacing anomalies in a UI panel.
- **Compliance-evidence-export hardening** — cryptographic signing, live query API, redacted credential inclusion, scheduled export, and log retention.
- **Policy-pack marketplace expansion** — OPA/Cedar pack variants, a live registry, versioning, and pack composition.
- **HA distributed budget/anomaly state + signing-key rotation/KMS** — distributing state across HA instances with key rotation support.
- **gRPC transport support** — enabling gRPC as a transport layer alongside HTTP.
- **Widening policy enforcement to MCP resources/* and prompts/* calls** — expanding from current ungated passthrough to full policy coverage.

A hosted cloud tier has been explicitly named as a possible future
direction, but is a business/infrastructure decision outside this
project's engineering roadmap — not something this docs site or the
codebase commits to.

This page reflects actual project state as of each release, not
aspirational claims — cross-check against `docs/superpowers/specs/`
before updating it for a new release.
