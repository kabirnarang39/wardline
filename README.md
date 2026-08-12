<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/banner-dark.svg">
  <img alt="Wardline" src="docs/images/banner-light.svg" width="460">
</picture>

**The control-plane proxy that auto-blocks compromised AI agents — in one static Go binary.**

[![CI](https://img.shields.io/github/actions/workflow/status/kabirnarang39/wardline/ci.yml?branch=main&style=flat&label=CI&color=15803D)](https://github.com/kabirnarang39/wardline/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/kabirnarang39/wardline?style=flat&label=release&color=15803D)](https://github.com/kabirnarang39/wardline/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/kabirnarang39/wardline?style=flat&logo=go&label=go&color=15803D)](go.mod)
[![Go Reference](https://img.shields.io/badge/go-reference-15803D?logo=go)](https://pkg.go.dev/github.com/kabirnarang39/wardline)
[![Docs](https://img.shields.io/badge/docs-website-15803D)](https://kabirnarang39.github.io/wardline/docs/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/kabirnarang39/wardline)
[![License](https://img.shields.io/badge/license-Apache%202.0-15803D)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-15803D)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/kabirnarang39/wardline?style=flat&logo=github&label=stars&color=15803D)](https://github.com/kabirnarang39/wardline/stargazers)

</div>

---

Your AI agent has a thousand tools and no supervisor. The day it gets prompt-injected, jailbroken, or simply goes wrong, it starts calling things it never should — and you never wrote a rule for *that*, because you didn't see it coming.

**Wardline** sits in front of every call your agents make — MCP servers, tools, gRPC upstreams — and enforces **identity, policy, budget, and audit**. Then it watches: statistical anomaly detection learns each agent's normal behavior and **blocks a compromised one in real time** — no rule written for the attack, no human in the loop. One static Go binary. No database, IdP, or sidecar to start.

### See it happen

A normal agent gets compromised mid-run. Wardline learns its baseline, catches the burst, and auto-blocks it — down to its previously-allowed calls — live:

<div align="center">
  <img alt="Wardline auto-blocking a compromised agent" src="docs/images/wardline-demo.gif" width="800">
</div>

```bash
make demo   # runs exactly this, locally, in ~30s — mock MCP server + Wardline, zero setup
```

Every decision lands in the built-in read-only dashboard — the block, the `ml_score` anomaly that triggered it, and the policy behind it:

<div align="center">
  <img alt="Wardline dashboard: the blocked agent, its ml_score anomaly, and the policy" src="docs/images/wardline-dashboard-demo.webp" width="800">
</div>

## How it works

Any caller — an AI agent, a CLI/IDE, or an app — reaches its MCP/gRPC upstreams only through Wardline, which applies identity, policy, budget, and anomaly detection in-process and writes every decision to the audit trail.

<div align="center">
  <img alt="Wardline control plane: callers pass through identity, policy, budget, and anomaly checks before reaching MCP servers, tools, resources, gRPC, and APIs" src="docs/images/architecture.svg" width="900">
</div>

Full design: [Architecture](https://kabirnarang39.github.io/wardline/docs/concepts/architecture/).

## What it does

- **Real-time anomaly auto-block** — seven self-baselining heuristics (rate spike, novel tool, deny-rate spike, an `ml_score` z-score, a CUSUM drift chart for low-and-slow ramps, cross-tenant aggregation, and identity-churn) learn each agent online — no training data, no external model. A flagged agent is *rejected* for a bounded TTL, not just logged. Real measured recall and honest residuals in the [recall benchmark](https://kabirnarang39.github.io/wardline/docs/features/anomaly-detection/#recall-benchmark).
- **Three policy backends, one binary** — YAML, embedded OPA/Rego, or embedded AWS Cedar, chosen by one config key. No external process, no network hop.
- **Identity & access** — short-lived RS256 JWTs (refresh + JWKS rotation), OIDC / mTLS-SPIFFE bootstrap, Kubernetes-style RBAC, SCIM 2.0, end-to-end tenant isolation.
- **Budget & rate control** — per-identity *and* per-tenant limits; both must clear for a call to pass.
- **Compliance & audit** — structured JSON trail, signed evidence export for auditors, configurable retention, and `infer-policy` to bootstrap an allow-list from real traffic.
- **Federation & observability** — cross-instance correlation over signed, pseudonymized summaries; OpenTelemetry tracing; Prometheus metrics; a live dashboard; Postgres-backed HA.

## Getting Started

```bash
# From source (always works)
go build -o wardline ./cmd/wardline

# Or pull the published multi-arch image (built for each tagged release)
docker pull ghcr.io/kabirnarang39/wardline:latest
```

```bash
./wardline validate-policy --file policy.yaml.example
./wardline validate-config --config wardline.yaml.example
./wardline serve --config wardline.yaml.example
```

Point `upstream` at a real MCP server (a proxied call 502s until you do — for a quick test, `python3 -m http.server 9000`). Every request carries an `X-Wardline-Identity` header; policy matches on that value plus the MCP tool name:

```bash
curl -X POST http://localhost:8080 \
  -H "X-Wardline-Identity: agent-abc123" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}'
```

`X-Wardline-Identity` is a plain, unauthenticated header here — anyone who can reach the proxy can claim to be any identity. That's fine for this local, no-upstream smoke test; it is **not** fine for anything reachable by someone else. Before pointing this at a real upstream, turn on `credential_issuance` (verified RS256 bearer tokens replace the spoofable header) and `rbac` — see [Hardening](#hardening) below.

Prebuilt binaries (linux/darwin/windows · amd64/arm64) and multi-arch images ship on every `v*` tag via [Releases](https://github.com/kabirnarang39/wardline/releases) and [GHCR](https://github.com/kabirnarang39/wardline/pkgs/container/wardline).

## Documentation

Full docs, per-feature design notes, and honest known-limitations live on the docs site:

- [Getting Started](https://kabirnarang39.github.io/wardline/docs/getting-started/) — install, quickstart, configuration
- [Concepts](https://kabirnarang39.github.io/wardline/docs/concepts/) — architecture, policy backends, identity, audit
- [Features](https://kabirnarang39.github.io/wardline/docs/features/) — every capability in depth
- [Deployment](https://kabirnarang39.github.io/wardline/docs/deployment/) — Docker, Helm, HA, observability
- [Framework integrations](docs/integrations/) — LangChain, LlamaIndex, OpenAI Agents SDK, CrewAI, raw MCP

## Full capability list

Everything below is shipped and testable under [`internal/features/`](internal/features/). The v0.1 baseline (proxy + policy + audit) is always on; everything else is gated by a config flag.

| Capability | Docs |
|---|---|
| Policy backends — YAML · OPA/Rego · AWS Cedar | [Policy backends](https://kabirnarang39.github.io/wardline/docs/concepts/policy-backends/) |
| Anomaly detection + auto-block | [Anomaly detection](https://kabirnarang39.github.io/wardline/docs/features/anomaly-detection/) |
| Budget enforcement (per-identity + per-tenant) | [Budget](https://kabirnarang39.github.io/wardline/docs/features/budget-enforcement/) |
| Credential issuance (JWT + refresh + JWKS) | [Credentials](https://kabirnarang39.github.io/wardline/docs/features/credential-issuance/) |
| SSO (OIDC) / mTLS-SPIFFE bootstrap | [SSO](https://kabirnarang39.github.io/wardline/docs/features/sso/) · [mTLS](https://kabirnarang39.github.io/wardline/docs/features/mtls-bootstrap/) |
| RBAC + SCIM + tenancy | [RBAC](https://kabirnarang39.github.io/wardline/docs/features/rbac/) · [SCIM](https://kabirnarang39.github.io/wardline/docs/features/scim/) |
| Federation (cross-instance correlation) | [Federation](https://kabirnarang39.github.io/wardline/docs/features/federation/) |
| Compliance evidence export + retention | [Compliance](https://kabirnarang39.github.io/wardline/docs/features/compliance-evidence-export/) |
| Auto-generated sandbox policy | [infer-policy](https://kabirnarang39.github.io/wardline/docs/features/auto-generated-policy/) |
| Policy packs (12 embedded + `-packs-dir`) | [Policy packs](https://kabirnarang39.github.io/wardline/docs/features/policy-pack-marketplace/) |
| gRPC transport passthrough | [gRPC](https://kabirnarang39.github.io/wardline/docs/features/grpc-transport/) |
| Postgres storage + HA deployment | [HA](https://kabirnarang39.github.io/wardline/docs/deployment/high-availability/) |
| Web dashboard | [Dashboard](https://kabirnarang39.github.io/wardline/docs/features/web-dashboard/) |
| OpenTelemetry tracing | [Observability](https://kabirnarang39.github.io/wardline/docs/deployment/observability/) |
| Prometheus metrics (`GET /metrics`) | [Observability](https://kabirnarang39.github.io/wardline/docs/deployment/observability/#prometheus-metrics) |
| Taint tracking (untrusted-read gating) | [Taint tracking](https://kabirnarang39.github.io/wardline/docs/features/taint-tracking/) |
| Approval workflow (needs_approval + approve-and-retry) | [Approval workflow](https://kabirnarang39.github.io/wardline/docs/features/approval-workflow/) |
| Per-job budget ceiling (hard cap per tenant/identity/session job) | [Per-job budget ceiling](https://kabirnarang39.github.io/wardline/docs/features/job-budget/) |
| Per-job cost/token budget (declared per-tool cost, not just call count) | [Per-job cost/token budget](https://kabirnarang39.github.io/wardline/docs/features/cost-budget/) |

## Performance

Real `go test -bench` numbers, not marketing:

- **Policy decision** — ~33 ns / 0 allocations at 10 rules (default YAML backend, Apple Silicon), ~2.4 µs at 1000 rules.
- **Full seven-heuristic detector** — ~299 ns/op, 5 allocations, with `drift_detection`, `tenant_anomaly`, and `identity_churn` all on (~255 ns/op for the original four).
- **Race-tested** — 205 concurrent goroutines (5 tenants × 40 identities + 5 attackers) against one shared `Detector` under `go test -race`, no data race.
- **False positives** — `ml_score` holds **0 / 6,000 windows** across 20 seeds on steady traffic (budget < 2%).

Per-attack-shape recall curve and the adversarial battery (sybil, mimicry ceiling, burst-pause, disposable-identity rotation) live in the [recall benchmark](https://kabirnarang39.github.io/wardline/docs/features/anomaly-detection/#recall-benchmark).

## Security

The dashboard and the `X-Wardline-Identity` header are **unauthenticated by default** — pair with `credential_issuance` and/or `rbac` for real security value. Every optional capability ships off by default and fails closed. On startup Wardline logs a `WARN` for each insecure default still in effect, so the posture is never silent. Report vulnerabilities per [SECURITY.md](SECURITY.md).

### Hardening

Out of the box the proxy fails closed on *policy*, but identity and the dashboard are open. For any real deployment, turn on:

```yaml
features:
  credential_issuance: true   # verify a signed bearer token instead of trusting X-Wardline-Identity
  rbac: true                  # gate the dashboard and admin actions on real permissions
```

With `credential_issuance` on, the spoofable header is replaced by RS256 bearer-token verification; with `rbac` on, dashboard read views and mutations require an authorized identity. `ml_score`/`auto_block` alone catch *abrupt* abuse but not *low-and-slow* ramps; `drift_detection` (a CUSUM control chart, on by default in the shipped example config) closes most of that gap — real, measured numbers, not a claim, in the [recall benchmark](https://kabirnarang39.github.io/wardline/docs/features/anomaly-detection/#recall-benchmark) — but a real residual (a ~1.15x sustained-forever ceiling for an attacker who's read the public thresholds) remains, see [known limitations](https://kabirnarang39.github.io/wardline/docs/features/anomaly-detection/#known-limitations). Keep explicit policy + budget limits as the hard floor regardless.

## Project status

Wardline is young and moving fast. Every feature's docs page is deliberately blunt about what it does and doesn't do. Feedback, issues, and contributions are welcome — especially on the anomaly-detection approach and threat model.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Architecture and engineering conventions are documented in [CLAUDE.md](CLAUDE.md); the roadmap lives in the [docs](https://kabirnarang39.github.io/wardline/docs/advanced/roadmap/).

<a href="https://github.com/kabirnarang39/wardline/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=kabirnarang39/wardline" />
</a>

## License

[Apache 2.0](LICENSE).
