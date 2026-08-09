# Wardline

[![CI](https://github.com/kabirnarang39/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/kabirnarang39/wardline/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/kabirnarang39/wardline.svg)](https://pkg.go.dev/github.com/kabirnarang39/wardline)
[![Release](https://img.shields.io/github/v/release/kabirnarang39/wardline?sort=semver)](https://github.com/kabirnarang39/wardline/releases)
[![Docs](https://img.shields.io/badge/docs-website-15803D)](https://kabirnarang39.github.io/wardline/docs/)
[![License](https://img.shields.io/badge/license-Apache%202.0-15803D)](LICENSE)

**A control-plane proxy for AI agents — identity, policy, budget, and audit for MCP and beyond, in one static Go binary.**

A compromised agent trips Wardline's statistical anomaly detection and gets
auto-blocked in real time — no rule written for the attack, no human in the
loop. Point it at your MCP server; no database, IdP, or sidecar to start.

![Wardline auto-blocking a compromised agent](docs/images/wardline-demo.gif)

```bash
make demo   # mock MCP server + Wardline running the scenario above
```

The same run in the built-in read-only dashboard — the block, the anomaly
that triggered it, and the policy behind it:

![Wardline dashboard: the blocked agent, its ml_score anomaly, and the policy](docs/images/wardline-dashboard-demo.webp)

---

## Why Wardline

AI agents call MCP servers and tools with no identity, policy, budget, or
audit layer in between. Wardline is that layer — a single statically-built Go
binary where every capability below lives in one process, gated by config
flags. Postgres, an IdP, and Kubernetes are optional scaling paths, not day-one
requirements.

- **One binary, no dependencies to start** — vs. gateways that need
  MongoDB + nginx + Keycloak before the first request.
- **Everything Apache-2.0** — RBAC, SSO, SCIM, HA, audit, and the rest ship
  in this repo with **no paid tier** gating any capability described here.
- **Enforcement, not just alerting** — anomaly detection that *blocks* a
  flagged identity for a bounded TTL, not one that only writes a log line.

## Install

```bash
# From source (always works)
go build -o wardline ./cmd/wardline

# Or pull the published multi-arch image (built for each tagged release)
docker pull ghcr.io/kabirnarang39/wardline:latest
```

Prebuilt binaries (linux/darwin/windows, amd64/arm64) and multi-arch
container images are published to
[GitHub Releases](https://github.com/kabirnarang39/wardline/releases) and
[GHCR](https://github.com/kabirnarang39/wardline/pkgs/container/wardline) on
every `v*` tag. For Kubernetes, see the
[Helm chart](https://kabirnarang39.github.io/wardline/docs/deployment/helm-chart/).

## Quickstart

```bash
./wardline validate-policy --file policy.yaml.example
./wardline validate-config --config wardline.yaml.example
./wardline serve --config wardline.yaml.example
```

`wardline.yaml.example`'s `upstream` (`http://localhost:9000`) is illustrative
— proxied calls 502 until you point it at a real MCP server. For a quick test,
stand up a trivial mock upstream first: `python3 -m http.server 9000`.

Every request carries an `X-Wardline-Identity` header; policy matches on that
value plus the MCP tool name:

```bash
curl -X POST http://localhost:8080 \
  -H "X-Wardline-Identity: agent-abc123" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}'
```

Full walkthrough: [Getting Started](https://kabirnarang39.github.io/wardline/docs/getting-started/).

## Features

Everything below is shipped and testable under `internal/features/`. The v0.1
baseline (proxy + policy + audit) is always on; everything else is gated by a
config flag.

| Capability | What it does | Docs |
|---|---|---|
| **Policy backends** | Three interchangeable engines in one binary — static YAML, embedded OPA/Rego, embedded AWS Cedar — switched by `policy_backend`, no external process | [Policy backends](https://kabirnarang39.github.io/wardline/docs/concepts/policy-backends/) |
| **Anomaly detection** | Four self-baselining heuristics (rate spike, novel tool, deny-rate spike, combined `ml_score` z-score via Welford) — no training data, no external model | [Anomaly detection](https://kabirnarang39.github.io/wardline/docs/features/anomaly-detection/) |
| **Auto-block** | Rejects a flagged identity's calls for a bounded TTL — a real enforcement action, not an alert | [Anomaly detection](https://kabirnarang39.github.io/wardline/docs/features/anomaly-detection/) |
| **Budget enforcement** | Two-tier per-identity AND per-tenant rate limits, both must clear | [Budget enforcement](https://kabirnarang39.github.io/wardline/docs/features/budget-enforcement/) |
| **Credential issuance** | Short-lived RS256 JWTs with refresh tokens, revocation, and JWKS key rotation | [Credential issuance](https://kabirnarang39.github.io/wardline/docs/features/credential-issuance/) |
| **SSO / mTLS bootstrap** | OIDC ID-token or SPIFFE-ID bootstrap sources for identity | [SSO](https://kabirnarang39.github.io/wardline/docs/features/sso/) · [mTLS](https://kabirnarang39.github.io/wardline/docs/features/mtls-bootstrap/) |
| **RBAC + SCIM + tenancy** | K8s-style roles/bindings, IdP-driven SCIM provisioning, tenant threaded end to end | [RBAC](https://kabirnarang39.github.io/wardline/docs/features/rbac/) · [SCIM](https://kabirnarang39.github.io/wardline/docs/features/scim/) |
| **Federation** | Peers exchange signed, pseudonymized anomaly summaries; correlate the same fingerprint across instances | [Federation](https://kabirnarang39.github.io/wardline/docs/features/federation/) |
| **Compliance evidence** | `wardline export-evidence` — checksummed, optionally RSA-signed `.tar.gz` bundle for an auditor | [Compliance export](https://kabirnarang39.github.io/wardline/docs/features/compliance-evidence-export/) |
| **Auto-generated policy** | `wardline infer-policy` writes a starter allow-list from observed audit traffic | [Auto-generated policy](https://kabirnarang39.github.io/wardline/docs/features/auto-generated-policy/) |
| **Policy packs** | Twelve starter policies embedded in the binary; `-packs-dir` for your own | [Policy packs](https://kabirnarang39.github.io/wardline/docs/features/policy-pack-marketplace/) |
| **gRPC transport** | Transparent raw-bytes gRPC passthrough under the same control plane | [gRPC transport](https://kabirnarang39.github.io/wardline/docs/features/grpc-transport/) |
| **Postgres storage** | SQL-queryable audit trail + shared state (budget, revocation, baselines) across replicas | [Postgres](https://kabirnarang39.github.io/wardline/docs/deployment/high-availability/) |
| **HA deployment** | Multi-replica with shared counters, JWKS rotation, `/healthz`+`/readyz`, graceful drain | [HA](https://kabirnarang39.github.io/wardline/docs/deployment/high-availability/) |
| **Web dashboard** | Read-only live view — activity, anomalies, blocked, federation, policy, status | [Dashboard](https://kabirnarang39.github.io/wardline/docs/features/web-dashboard/) |
| **OTel tracing** | One span per request, OTLP/HTTP export, W3C traceparent propagation | [Observability](https://kabirnarang39.github.io/wardline/docs/deployment/observability/) |

Framework integration guides (LangChain, LlamaIndex, OpenAI Agents SDK,
CrewAI, raw MCP client): [`docs/integrations/`](docs/integrations/).

## How Wardline compares

Researched 2026-08-02 from each project's own README and star count (numbers
move — treat as order-of-magnitude):

| Project | Stars | What its README claims — and doesn't |
|---|---|---|
| [agentgateway](https://github.com/agentgateway/agentgateway) | ~4k | Rust LLM+MCP+A2A gateway with CEL RBAC, rate limiting, OTel. No statistical anomaly detection, no auto-block, no compliance-evidence export. |
| [mcp-gateway-registry](https://github.com/agentic-community/mcp-gateway-registry) | ~840 | Capable registry+gateway, but requires MongoDB, an nginx data plane, and an external IdP before the first request. No policy-as-code evaluator or anomaly detection. |
| [lunar](https://github.com/TheLunarCompany/lunar) | ~480 | API/MCP gateway; production capability explicitly gated behind commercial tiers, not in the OSS repo. |
| [gate22](https://github.com/aipotheosis-labs/gate22) | ~175 | Ships allow-list permissioning + audit; policy enforcement and quotas are still roadmap. |

Wardline's entire feature set ships under Apache-2.0 in this repo — no paid
tier gating anything above.

## Performance

Reproducible with `go test -bench`, not marketing numbers.
`BenchmarkDecider_Decide` (default YAML backend, Apple Silicon): ~33ns / 0
allocs at 10 rules, ~2.4µs at 1000 rules. The `ml_score` false-positive claim
is regression-guarded by
`TestDetector_MLScore_FalsePositiveRateOnSteadyTraffic` (asserts 0% FP on
steady traffic, budget <2%). See
[Performance docs](https://kabirnarang39.github.io/wardline/docs/).

## Security

The dashboard and the `X-Wardline-Identity` header are **unauthenticated by
default** — pair with `credential_issuance` and/or `rbac` for real security
value. Every optional capability ships off by default and fails closed. Report
vulnerabilities per [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Architecture and engineering
conventions live in [CLAUDE.md](CLAUDE.md). Roadmap:
[docs](https://kabirnarang39.github.io/wardline/docs/advanced/roadmap/).

## License

[Apache 2.0](LICENSE).
