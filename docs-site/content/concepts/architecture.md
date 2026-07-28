---
title: "Architecture"
weight: 10
---

Wardline follows Clean Architecture with a feature-sliced layout: each
capability (proxy, policy, audit, credential issuance, RBAC, budget,
anomaly detection, compliance export, policy-pack marketplace, health)
owns its own `domain/` (entities + interfaces, no I/O), `usecase/`
(business logic, depends only on domain interfaces), and `adapter/`
(translates to/from the outside world — HTTP handlers, file loaders,
Postgres) — rather than one repo-wide `domain/usecase/adapter` split
shared across every feature.

This matters to an operator mainly for one reason: every pluggable engine
(policy backend, identity issuer, budget limiter) is a domain-defined
interface, so adding a new backend never requires changing the business
logic that consumes it — new policy backends (YAML today, OPA and Cedar
already shipped) are a real example of this in production, not a
theoretical claim. See [Writing a policy backend](/advanced/writing-a-policy-backend/)
if you want to extend this yourself.

Everything is wired together once, in `cmd/wardline/main.go` — the
composition root. Nothing outside `main.go` imports a concrete adapter
directly.
