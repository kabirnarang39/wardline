# Wardline — Engineering Conventions

Wardline is an open source control-plane proxy that sits between AI agents and everything they call (MCP servers, LLM providers, other agents) — enforcing identity, policy, budget, and audit. Go, Apache 2.0.

These conventions apply to all code in this repo. Follow them exactly; they override default behavior.

## Architecture: Clean Architecture, dependency rule inward

Four layers, dependencies point one direction only — outer depends on inner, never the reverse:

```
domain        → entities + interfaces only. No I/O, no frameworks, no imports outside stdlib.
usecase       → business logic (policy evaluation, budget checks, audit decisions).
               Depends on domain interfaces, never on adapters or infra directly.
adapter       → translates between usecase and the outside world (HTTP handlers,
               YAML/OPA loaders, log writers). Implements domain interfaces.
infra         → frameworks, network, filesystem, third-party SDKs. Wired at the
               outermost edge only (cmd/wardline/main.go).
```

A file in `domain/` or `usecase/` that imports `net/http`, a YAML library, or any
adapter package is a violation — stop and fix the dependency direction, don't
add an exception.

## SOLID, applied concretely

- **Single Responsibility** — one package, one reason to change. If a package
  handles both policy matching and audit logging, split it.
- **Open/Closed (the one that matters most here)** — every pluggable engine
  (policy backend, identity issuer, budget meter) is a domain-defined
  `interface`, and adding a new backend means adding a new adapter, never
  editing the usecase that consumes it. Concrete example: `policy.Engine`
  interface has an OPA/Rego adapter today; Cedar arrives later as a second
  adapter, zero changes to `usecase/policy_eval.go`.
- **Liskov** — any implementation of a domain interface must be swappable
  without the caller changing behavior/assumptions. If a new `policy.Engine`
  impl needs the usecase to special-case it, the interface is wrong — fix the
  interface, not the caller.
- **Interface Segregation** — small, single-purpose interfaces
  (`policy.Evaluator`, `audit.Writer`, `budget.Meter`) over one large
  `Engine` god-interface. Consumers depend only on the methods they call.
- **Dependency Inversion** — usecases accept interfaces via constructor
  injection; concrete adapters are wired only in `cmd/wardline/main.go`.
  Never `import` an adapter package from `usecase/`.

## Feature-sliced structure, not layer-sliced

Slice by feature first, Clean Architecture layers second — a feature owns its
full vertical (domain → usecase → adapter), not spread across
repo-wide `domain/`, `usecase/`, `adapter/` folders shared by everything:

```
internal/
  features/
    proxy/
      domain/       # Request, Decision entities; ProxyEngine interface
      usecase/      # request interception + routing logic
      adapter/      # HTTP reverse-proxy adapter
    policy/
      domain/       # Rule, Scope entities; Engine interface
      usecase/      # policy evaluation
      adapter/      # OPA/Rego adapter (Cedar adapter added later, same interface)
    audit/
      domain/       # Entry entity; Writer interface
      usecase/      # decision → audit entry construction
      adapter/      # stdout/file JSON writer
  platform/         # cross-feature shared code only (config loading, logging
                     # setup, flag evaluation) — keep this folder small; if
                     # two features both need something, ask whether it
                     # belongs here or whether one feature should own it
cmd/
  wardline/
    main.go         # composition root: wires adapters into usecases, starts serve/validate-policy
```

A new feature (identity, budget, admin UI backend) gets its own
`internal/features/<name>/` with the same three-layer shape. Don't add a
feature's logic into an existing feature's package because it's convenient —
each feature must be understandable and testable in isolation.

## Feature flags

Every feature beyond the v0.1 baseline (proxy + policy + audit) ships behind
a flag — new capabilities land incrementally without destabilizing what's
already running in someone's proxy.

- v0.1 baseline (proxy, policy, audit) is always on, no flag needed.
- Everything added after v0.1 (short-lived credential issuance, Cedar
  backend, anomaly detection, approval workflows, etc.) is gated by a flag
  in the operator's config file:
  ```yaml
  features:
    approval_workflow: false
    cedar_policy_backend: false
  ```
- Flag evaluation lives in `internal/platform/flags` as a tiny interface
  (`flags.Provider` with `Enabled(name string) bool`), default implementation
  reads the static config map above. Don't reach for a SaaS flag SDK
  (LaunchDarkly, Flagsmith) — this is a self-hosted OSS proxy, a config map
  is the whole requirement until an actual operator asks for runtime
  toggling without redeploy.
- A feature checks its own flag inside its own `usecase/` — never scatter
  `if flags.Enabled(...)` checks across unrelated packages.

## Testing

- Every `usecase/` package gets unit tests with fakes for its domain
  interfaces — no real HTTP, no real files, no real OPA process.
- Every `adapter/` package gets a narrow integration test against the real
  thing it wraps (a mock MCP server, a temp policy file).
- One end-to-end test per feature-flag-off baseline: proxy + policy + audit
  wired together via `cmd/wardline`, hitting an allow path and a deny path.
- No test framework beyond stdlib `testing` + `testify/assert` unless a real
  gap shows up.

## Go conventions

- Errors: wrap with `fmt.Errorf("...: %w", err)`, never swallow silently in
  policy/audit paths — a swallowed error there is a silent security gap.
- No global mutable state. Config and dependencies flow through constructors.
- `golangci-lint` clean before commit (config in `.golangci.yml`).
- Exported identifiers get a doc comment only when the name doesn't already
  say it — don't restate the signature in prose.
