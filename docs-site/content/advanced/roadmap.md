---
title: "Roadmap"
weight: 20
---

## v1.0 (shipped)

Proxy + policy + audit baseline, credential issuance, RBAC, budget
enforcement, anomaly detection (heuristic), compliance evidence export,
policy-pack marketplace, HA deployment.

## v2.0 (planned, not yet shipped)

- **Federation** — cross-instance signal sharing, the natural point to revisit the per-replica limitations documented on the [Budget Enforcement](/features/budget-enforcement/), [Anomaly Detection](/features/anomaly-detection/), and [HA Deployment](/features/ha-deployment/) pages.
- **ML-based anomaly detection** — replacing/augmenting today's rule/statistics heuristics.
- **SSO/SCIM** — IdP-backed identity for RBAC's admin surface, instead of preshared-secret bootstrap or a raw header.
- **Auto-generated sandbox policy** — inferring a starter policy from observed traffic.
- **mTLS/SPIFFE credential bootstrap** — as a credential-issuance adapter for secure bootstrapping.
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
