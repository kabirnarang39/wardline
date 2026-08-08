# Wardline

[![Docs](https://img.shields.io/badge/docs-website-15803D)](https://kabirnarang39.github.io/wardline/docs/)
[![License](https://img.shields.io/badge/license-Apache%202.0-15803D)](LICENSE)
[![Deploy site and docs](https://github.com/kabirnarang39/wardline/actions/workflows/docs.yml/badge.svg)](https://github.com/kabirnarang39/wardline/actions/workflows/docs.yml)
[Website](https://kabirnarang39.github.io/wardline/)

Open source control-plane proxy for AI agents: identity, policy, budget, and
audit for MCP and beyond.

v0.1 scope: a reverse proxy in front of one MCP server, a policy backend
(a static YAML allow/deny rule list, or an embedded OPA/Rego evaluator) per
identity+tool, and a structured JSON audit log.

## Why Wardline

Wardline is a single, statically-built Go binary: `go build`, point it at an
MCP upstream, and every capability described in this README — policy,
budget, anomaly detection, RBAC, audit — lives in that one process, gated by
config flags. No database, identity provider, or second service is required
to start; Postgres, an IdP, and Kubernetes are all optional, opt-in scaling
paths (see [Postgres storage](#postgres-storage), [SSO](#sso), and
[Kubernetes / Helm](#kubernetes--helm)), not day-one requirements.

A few capabilities that are real and shipped, not aspirational — verify
directly against `internal/features/`:

- **Three interchangeable policy backends in one binary** — a static YAML
  allow/deny list, an embedded OPA/Rego evaluator, and an embedded AWS Cedar
  evaluator (`policy_backend: yaml|opa|cedar`), switchable per-deployment
  with no external `opa` process or network hop. See [Policy
  backends](#policy-backends).
- **Two-tier budget enforcement** — a per-identity bucket AND an optional
  per-tenant bucket, both of which must clear for a call to proceed. See
  [Budget enforcement](#budget-enforcement).
- **Statistical anomaly detection with a real enforcement action, not just
  an alert** — four independently-toggleable heuristics (rate spike, novel
  tool, deny-rate spike, and a combined z-score `ml_score` across four
  self-baselining features via Welford's algorithm — no training data, no
  external model), plus `auto_block`, which actually rejects a flagged
  identity's calls for a bounded TTL rather than only logging. See [Anomaly
  detection](#anomaly-detection) and [Auto-block](#auto-block).
- **Cross-instance correlation over federation** — peers exchange signed,
  pseudonymized anomaly summaries (never raw identities or audit content),
  and a `Correlator` raises an alert once the same fingerprint is seen by
  multiple instances. See [Federation](#federation).
- **A compliance evidence bundle command** — `wardline export-evidence`
  assembles a checksummed, optionally RSA-signed `.tar.gz` of the audit
  trail, anomaly log, redacted identity list, and policy snapshot for an
  auditor, plus periodic scheduled export, configurable log retention,
  and a live manifest-preview API/dashboard view. See [Compliance
  evidence export](#compliance-evidence-export).

None of this is claimed as "the best" of anything — see the comparison
below for what a claim like that would actually need to survive.

### How Wardline compares to other open-source AI-agent gateways

Researched 2026-08-02 by reading each project's own current README and
GitHub star count (a number that will have moved by the time you read
this) — this is a note about projects actually looked at, not a claim
about ones that weren't:

| Project | Stars (2026-08-02) | What its own README says |
|---|---|---|
| [agentgateway/agentgateway](https://github.com/agentgateway/agentgateway) | 4,182 | A Rust proxy billed as "the first complete connectivity solution for Agentic AI" — an LLM+MCP+A2A gateway with RBAC via a CEL policy engine, rate limiting, and OpenTelemetry. Its README lists no statistical/ML-based anomaly detection, no auto-block enforcement action, and no compliance-evidence export. |
| [aipotheosis-labs/gate22](https://github.com/aipotheosis-labs/gate22) | 175 | Ships function allow-list permissioning and audit today. Its own README lists "Policy enforcement (P0)" under **Near-Term Roadmap**, and "Quotas & budgets" plus "Policy-as-code v2 (OPA/Cedar-style ABAC)" under **Future (design RFCs)** — not yet shipped as of the README read for this comparison. |
| [agentic-community/mcp-gateway-registry](https://github.com/agentic-community/mcp-gateway-registry) | 839 | Scope-based OAuth access control, per-caller/per-target rate limiting, and a quarantine kill-switch — a genuinely capable registry and gateway, but it requires standing up MongoDB/DocumentDB, an nginx data plane, and an external IdP (Keycloak/Entra/Okta/etc.) before the first request. Its README does not mention a policy-as-code evaluator (OPA/Cedar) or statistical anomaly detection. |
| [TheLunarCompany/lunar](https://github.com/TheLunarCompany/lunar) | 477 | An API/MCP gateway with policy enforcement and traffic shaping. Its own README states it is "free for non-production/personal use. For production environments, we offer advanced features through guided onboarding and platform tiers" — production capability is explicitly gated behind a commercial tier, not in the open-source repo. |

Wardline's entire feature set — RBAC, SCIM, SSO, HA/Postgres storage, and
everything else in this README, including the items above — ships under
Apache-2.0 in this repository; there is no separate paid tier gating any
capability described here.

## Quickstart

```bash
go build -o wardline ./cmd/wardline
./wardline validate-policy --file policy.yaml.example
./wardline validate-config --config wardline.yaml.example
./wardline serve --config wardline.yaml.example
```

`wardline.yaml.example`'s `upstream` (`http://localhost:9000`) is illustrative
— nothing listens there by default, so every proxied call will 502 until you
point it at a real MCP server. For a quick first test, stand up a trivial
mock upstream in another terminal first: `python3 -m http.server 9000` (it
200s on anything, good enough to see an allow-path call succeed end-to-end).

## Identity and calling convention

Every request must carry an `X-Wardline-Identity` header; policy rules match
against this value plus the MCP tool name being called.

```bash
curl -X POST http://localhost:8080 \
  -H "X-Wardline-Identity: agent-abc123" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}'
```

(This matches the `agent-abc123` / `read_file` allow rule in
`policy.yaml.example`.)

**Scope note:** policy decisions apply to tool calls (`tools/call`) and,
if your upstream MCP server exposes them, `resources/*`/`prompts/*`
methods (e.g. `resources/read`, `prompts/get`) — a rule can target a
resource URI or prompt name the same way it targets a tool name (see
`policy.yaml.example`'s `method:` key; omitted/blank means `tools/call`,
so every rule written before this existed keeps matching exactly what it
matched before). **Budget enforcement stays tool-call-scoped only** —
budget buckets are keyed by tool name, and widening that key space to
arbitrary resource URIs is a real, separate design question, deliberately
not solved here (see
`docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md`).
True protocol-lifecycle methods — the `initialize` handshake every client
performs, `notifications/initialized`, `tools/list` — are still forwarded
to the upstream server without any policy or budget evaluation, recorded
in the audit log with a `"passthrough"` decision so they're visible but
distinguishable from an actual policy `"allow"`. `auto_block` (see
[Auto-block](#auto-block)) is the one deliberate exception to all of the
above: once an identity is auto-blocked, every one of its calls is
rejected, protocol-lifecycle passthrough included — a blocked identity
shouldn't get a handshake either.

## Policy backends

Wardline supports three policy backends, selected by `policy_backend` in
the config file (defaults to `yaml` if omitted):

- **`yaml`** (default) — a static allow/deny rule list, as in
  `policy.yaml.example`.
- **`opa`** — an embedded OPA/Rego evaluator (no external `opa` process, no
  network hop). Policies must declare `package wardline.authz` and export an
  `allow` boolean (and, optionally, a `reason` string). See
  `policy.rego.example` for the same allow rule expressed in Rego, with
  access to the full request context — tool call parameters, timestamp,
  remote address, and user agent — not just identity and tool name.

The Rego input (`input` in a policy) is the whole request context as JSON:

```json
{
  "identity": "agent-abc123",
  "tool": "read_file",
  "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
  "timestamp": "2026-07-27T10:00:00Z",
  "remote_addr": "10.0.0.5:54321",
  "user_agent": "some-agent/1.0"
}
```

- **`cedar`** — an embedded AWS Cedar evaluator
  (`github.com/cedar-policy/cedar-go`, no external process, no network
  hop). Cedar policies use `permit(...)` statements matching a fixed
  `principal`/`action`/`resource` shape — `principal` is
  `Wardline::Identity::"<identity>"`, `action` is always
  `Wardline::Action::"call_tool"` (Wardline's action space genuinely is
  just "call a tool"), and `resource` is `Wardline::Tool::"<tool>"`.
  Tool call parameters, timestamp, remote address, and user agent are
  available under `context.params`/`context.timestamp`/
  `context.remote_addr`/`context.user_agent` in a `when { ... }` clause.
  See `policy.cedar.example`. Unlike Rego, Cedar is deliberately
  non-Turing-complete (no loops, no recursion, no arbitrary network
  calls) — evaluation terminates by construction, so Wardline doesn't
  need to wrap it in an evaluation timeout the way it does for OPA.

  **Known limitation — no float/null support:** Cedar's type system has
  no float type and no null, and its `Long` integer type is a bounded
  64-bit value. A tool call whose JSON params contain a float (e.g.
  `0.7` for a temperature), a `null` (e.g. an optional field), or an
  integer outside Cedar's `Long` range will fail to decode into a Cedar
  value — the adapter fails closed and denies the call (with a
  decode-error line in the audit log), regardless of what any policy
  says. This is a real behavioral divergence from the `yaml`/`opa`
  backends for common MCP tool arguments (temperatures, coordinates,
  prices, optional-null fields), and it is a deliberate, known
  limitation of the current adapter, not a bug — no automatic
  float/null coercion is performed. If your tools pass floats, nulls,
  or very large integers as arguments, `cedar` is not yet a drop-in
  replacement for `opa`/`yaml`.

Both `opa` and `cedar` link their SDKs into every Wardline binary
unconditionally (selected at runtime by `policy_backend`, not by build
tag), which increases binary size versus `yaml` alone — the OPA SDK
accounts for roughly 29MB of the total binary size; Cedar's SDK is much
lighter, adding only roughly 1MB on top (measured as the size delta
between a build immediately before the Cedar backend existed and a
build with it present — not the total binary size). An operator
building a minimal-size image and using only `yaml` still pays this
cost today; splitting policy backends into optional build tags is
tracked as a future improvement, not solved by this cycle.

```bash
./wardline validate-policy --file policy.rego.example --backend opa
./wardline validate-policy --file policy.cedar.example --backend cedar
```

## Framework integrations

Wardline works as a drop-in reverse proxy for any framework's MCP
client — see [`docs/integrations/`](docs/integrations/) for verified,
runnable guides covering LangChain, LlamaIndex, the OpenAI Agents SDK,
CrewAI, and the raw MCP client.

## Budget enforcement

Off by default. Opt in with `features.budget_enforcement: true` plus a
`budget:` block (`requests_per_window`, `window_seconds`) — see
`wardline.yaml.example`. A throttled call gets HTTP 429 with a generic
message; the audit log records `decision: "throttled"` with the detailed
reason.

The limiter is per-process, in-memory by default — running multiple
`wardline` replicas gives each its own independent budget. Enable
`features.postgres_storage` to share one counter across every replica
instead, the same Postgres-backed pattern already used for credential
revocation and refresh tokens.

This is a request-*rate* limit, not a success-rate limit: a request that's
within budget but then fails upstream (502) still counts against the
caller's window.

Budget enforcement trusts the `X-Wardline-Identity` header as-is — there's
no authentication on it today — so it's only as strong as whatever
validates that header upstream of Wardline (or a future identity
verification feature); a caller that can set arbitrary identity values can
evade rate limiting by rotating identities.

The per-identity bucket above is itself scoped by tenant — two different
tenants' identically-named identities (two IdPs both provisioning
"alice", say) maintain fully independent budgets, never sharing one
bucket. On top of it, an optional `budget.tenants` block adds a *second*,
tenant-wide bucket a request must also clear:

```yaml
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    acme:
      requests_per_window: 500
      window_seconds: 60
```

Both buckets must allow — an AND, not an OR — so a tenant with no
override configured here is simply never checked against a tenant
bucket at all.

## Credential issuance

Off by default. Opt in with `features.credential_issuance: true` plus a
`credential:` block (`identities_file`, pointing at a `credentials.yaml`
mapping identity names to preshared registration secrets — see
`credentials.yaml.example`).

When on, `X-Wardline-Identity` is no longer read. Agents exchange their
registration secret for a short-lived RS256 JWT
(`credential.access_token_ttl_seconds`, default 900s / 15m) via
`POST /credentials/token {"secret": "..."}`, then present it as
`Authorization: Bearer <jwt>` on every proxied call. A missing, malformed,
expired, tampered, or revoked token gets HTTP 401 before the request
reaches policy, budget, or the audit log.

An operator revokes an identity with `POST /credentials/revoke
{"identity": "..."}` — loopback-only by default (not reachable over the
network), since an unauthenticated network-exposed revoke endpoint would
itself reopen the class of gap this feature exists to close. Revocation
cuts off every outstanding and future token for that identity until the
revocation itself expires (worst case, one token TTL later); to prevent
that identity from bootstrapping a fresh token afterward, also remove or
rotate its entry in `credentials.yaml`.

Bootstrapping now also returns a refresh token alongside the access
token; `POST /credentials/refresh {"refresh_token": "..."}` exchanges it
for a new access+refresh pair without re-presenting the original
secret/ID-token/SPIFFE-ID, until the refresh token expires
(`credential.refresh_token_ttl_seconds`, default 86400s / 24h) or its
identity is revoked. Refresh tokens rotate on every use (single-use --
an already-redeemed one is rejected the same as an unknown one) and are
invalidated immediately, for every outstanding refresh token an identity
holds, the moment that identity is revoked.

The signing keypair is generated fresh in-process at `wardline serve`
startup — not persisted, not shared across replicas. Restarting the
process (or running more than one replica) invalidates every outstanding
token, the same "no shared state across restarts" posture already true of
the budget limiter and dashboard ring buffer.

mTLS/SPIFFE-style bootstrap is supported as a third bootstrap source —
see mTLS/SPIFFE bootstrap below. IdP federation (Okta, Entra, generic
OIDC) is supported too — see SSO below.

**Known limitation:** revocation is keyed by `(tenant, identity)`, not
identity name alone — revoking your own tenant's `alice` does not touch
another tenant's `alice`. One residual gap remains: when a target
identity's tenant can't be resolved at revoke time — always true under
`bootstrap_source: oidc` (no static registry to look an arbitrary
identity's tenant up in), and also true under `presharedsecret`/`mtls`
whenever that identity name happens to be registered under more than one
tenant (`Bootstrapper`/`MTLSBootstrapper.TenantOf` deliberately fail
closed on that ambiguity rather than guessing) — the revoke falls back to
a wildcard, revoking every tenant's copy of that identity name at once. A
caller holding a global `credential:revoke` grant (see [RBAC](#rbac)) can
trigger this fallback deliberately — but so can any loopback caller,
since `/credentials/revoke` is reachable from loopback by default with no
RBAC grant at all. See the [Credential
issuance](https://kabirnarang39.github.io/wardline/docs/features/credential-issuance/)
docs page for the full explanation.

## SSO

Off by default. A second `credential_issuance` bootstrap adapter:
instead of a preshared secret matched against `credentials.yaml`, the
presented secret is treated as a raw OIDC ID token, verified against an
IdP's JWKS. Enable by pointing `credential_issuance`'s existing
bootstrap source at `oidc` — there's no separate `sso` feature flag,
since a flag whose only job is to gate the selectability of a config
enum value is a flag that can't be wrong:

```yaml
features:
  credential_issuance: true
credential:
  identities_file: "credentials.yaml"   # still required even for oidc
  bootstrap_source: "oidc"              # "presharedsecret" (default) | "oidc" | "mtls"
  oidc:
    issuer: "https://idp.example.com/"
    jwks_uri: "https://idp.example.com/.well-known/jwks.json"
    audience: "wardline"
    tenant_claim: "tenant"               # required present on every token -- no default, unlike credentials.yaml
```

Unlike a `credentials.yaml` entry (which defaults to tenant `"default"`
when it omits one), an SSO-sourced identity's tenant has no default — a
token missing the configured tenant claim is rejected outright. See the
[SSO docs page](https://kabirnarang39.github.io/wardline/docs/features/sso/)
for the full config shape and known limitations (one IdP at a time, no
OIDC discovery-document fetching).

## mTLS/SPIFFE bootstrap

Off by default. A third [Credential issuance](#credential-issuance)
bootstrap adapter: instead of a preshared secret or an OIDC ID token,
the caller's identity comes from an already-verified SPIFFE ID,
forwarded by a terminating mTLS proxy or service mesh via a trusted HTTP
header. Wardline never terminates TLS or parses an X.509 certificate
itself — the existing Helm-chart decision that an Ingress/LB terminates
TLS stands unchanged; this adapter adopts the same pattern every
SPIFFE-aware mesh already uses (sidecar/gateway verifies the peer cert,
forwards the verified SPIFFE ID as a header). Enable by pointing
`credential_issuance`'s existing bootstrap source at `mtls`:

```yaml
features:
  credential_issuance: true
credential:
  identities_file: "credentials.yaml"   # still required even for mtls
  bootstrap_source: "mtls"              # "presharedsecret" (default) | "oidc" | "mtls"
  mtls:
    header: "X-Wardline-Verified-Spiffe-Id"   # required, no default
```

`credentials.yaml` maps SPIFFE IDs to identities (`spiffe_id` instead of
`secret`):

```yaml
identities:
  - name: payments-worker
    spiffe_id: "spiffe://example.org/ns/prod/sa/payments-worker"
    tenant: acme
```

**Trust boundary:** `credential.mtls.header` has no default value —
Wardline trusts this header completely, so it is only safe when
Wardline is unreachable except through the proxy/mesh that sets it, and
that proxy/mesh strips or overwrites any client-supplied value of the
same header. Wardline cannot verify either condition itself; this is a
deployment requirement your network topology must guarantee. See the
[mTLS/SPIFFE Bootstrap
docs page](https://kabirnarang39.github.io/wardline/docs/features/mtls-bootstrap/)
for the full design and known limitations.

## RBAC

Off by default. Opt in with `features.rbac: true` plus an `rbac:` block
(`config_file`, pointing at an `rbac.yaml` defining custom roles and
bindings — see `rbac.yaml.example`).

Modeled directly on Kubernetes RBAC: a `Role` is a named set of
permissions; a `ClusterRoleBinding` grants a subject a role globally,
a `RoleBinding` grants it scoped to one tenant. Two built-in roles are
always available regardless of `rbac.yaml`'s content — `viewer`
(`dashboard:view`) and `admin` (`dashboard:view`, `credential:revoke`) —
and a custom role may not reuse either name.

When on, every dashboard request must resolve an identity (via whichever
`IdentityAuthenticator` `credential_issuance` has selected — the raw
`X-Wardline-Identity` header, or a verified bearer token) and that
identity must hold `dashboard:view`, else `403`. `POST
/credentials/revoke` keeps its existing loopback-only path completely
unchanged; RBAC only *adds* a second path — a non-loopback caller may
also succeed if authorized for `credential:revoke`.

Tenant isolation is real, not reserved: every request resolves a tenant
(from an OIDC ID token's or Wardline-issued JWT's `tenant` claim when
`credential_issuance` is on, or the `X-Wardline-Identity`/`X-Wardline-Tenant`
headers when it's off), and that tenant is threaded end to end —
`RoleBinding`s only grant within the tenant they name, policy rules can
carry an optional `tenant:` key (or `input.tenant`/`context.tenant` on
the OPA/Cedar backends), audit entries and anomaly baselines carry it,
and the dashboard filters a non-globally-granted caller to their own
tenant's data. A `ClusterRoleBinding` (no tenant segment) still grants
globally, across every tenant — see [SCIM](#scim) below for how SCIM
group naming mirrors this same convention. One known gap: credential
revocation's `(tenant, identity)` scoping falls back to a global
wildcard when a target identity's tenant can't be resolved — see
[Credential issuance](#credential-issuance).

RBAC is only as strong as whatever resolves the caller's identity — the
same disclaimer as budget enforcement's: pair it with `credential_issuance`
for real security value, or it's only as trustworthy as the
unauthenticated `X-Wardline-Identity` header.

## SCIM

Off by default. An IdP-driven provisioning API for RBAC: SCIM Groups map
to `RoleBinding`s (or `ClusterRoleBinding`s) automatically, so a group
added or edited in Okta/Azure AD/Google Workspace takes effect in
Wardline with no `rbac.yaml` edit.

```yaml
features:
  scim: true
  rbac: true                # SCIM provisions bindings for RBAC to consult
scim:
  bearer_token_env: "WARDLINE_SCIM_TOKEN"   # env var, never inline
  persist_postgres: false                     # requires features.postgres_storage when true
```

Serves `POST`/`GET /scim/v2/Users` and `GET`/`DELETE`/`PATCH
/scim/v2/Users/{id}`, plus the same verb set for `/scim/v2/Groups`. A
Group's `displayName` encodes the RBAC grant it provisions:
`wardline:tenant-<tenant>:role-<role>` makes every **`active`** member a
`RoleBinding{Tenant: tenant}`; `wardline:role-<role>` (no tenant
segment) makes every active member a `ClusterRoleBinding` (a global
grant). Deactivating a user (`PATCH {"op":"replace","path":"active","value":false}`)
or deleting one revokes any binding derived from their membership
immediately — the primary offboarding signal from every IdP this
feature targets. In-memory by default; set `scim.persist_postgres: true`
(requires `features.postgres_storage` also on) to persist across
restarts and share across replicas. See the [SCIM docs
page](https://kabirnarang39.github.io/wardline/docs/features/scim/) for
the full known-limitations list (no bulk operations, no `?filter=`
query support, single shared bearer token).

## Anomaly detection

Off by default. Opt in with `features.anomaly_detection: true` plus an
`anomaly:` block (`output`, a JSONL file path or `"stdout"`, required when
the flag is on — and, when it's a file, it must not be the same file as
`audit.output`: anomaly records carry a different schema and would corrupt
the audit trail for anything parsing it).

Three non-ML, rule/statistics heuristics run over the live audit stream,
each independently toggleable:

- **Rate spike** — an identity's call count in the current
  `window_seconds` exceeds `rate_spike.rate_multiplier` times its own
  previous window, with a `rate_spike.min_calls` floor so small absolute
  jumps never fire. Self-baselining per identity, not a global threshold.
- **Novel tool** — an identity's first-ever call to a given tool. Scoped
  to real tool calls: MCP protocol-lifecycle methods (`initialize`,
  `tools/list`, …) and unparsable requests are not tools, so a client's
  handshake never registers as three novel tools.
- **Deny-rate spike** — an identity's deny-decision ratio within the
  current window exceeds `deny_rate_spike.threshold`, with a
  `deny_rate_spike.min_calls` floor. Also tool-call-scoped, so protocol
  chatter can't dilute the ratio out of range.

`rate_spike` and `deny_rate_spike` share one `window_seconds` — both are
volumetric counts over the same identity traffic, so this deliberately
uses one trailing window per identity rather than two independently-sized
ones. Unlike the other two, `rate_spike` counts *all* of an identity's
traffic, protocol methods and malformed requests included — a flood is a
flood whatever shape it takes.

A flagged anomaly is written to `anomaly.output` as a JSON line and, when
`web_ui` is also on, appears via `GET /dashboard/api/anomalies` (subject
to the same RBAC gate as the rest of the dashboard, when `rbac` is on).

### ML-based anomaly scoring

A fourth, independently-toggleable heuristic alongside the three
rule/statistics ones above:

- **`ml_score`** — a combined z-score over four per-identity, per-window
  features (call rate, tool diversity — the count of distinct tools called
  this window, deliberately a raw count rather than a fraction of call
  volume, so a quieter window over an unchanged tool set doesn't read as
  "more diverse" — deny ratio, mean
  inter-arrival time), each scored against its own running mean/variance
  baseline (Welford's algorithm — no stored history, no training data,
  self-baselining exactly like `rate_spike` above). `ml_score.enabled`
  and `ml_score.score_threshold` control it; an anomaly of kind
  `ml_score` fires (once per window, like the other three) when
  `max(|z_rate|, |z_diversity|, |z_deny|, |z_inter_arrival|)` exceeds
  `score_threshold` — `max()` because any one feature swinging wildly is
  itself the anomalous signal, not the average across all four, which
  would dilute a spike in one dimension with three quiet ones.

`ml_score` needs at least 8 completed windows of history per identity
before it can score anything (`onlineStat.ZScore` returns 0 — "not
anomalous" — with fewer than 8 samples or zero variance): a 2- or
3-sample stddev is statistical noise, not signal, and would treat
entirely ordinary traffic variation as a wild outlier. A self-baseline
needs a real amount of normal variation to compare against before it
can tell a window apart from noise.

`ml_score.min_calls` is a second, orthogonal floor — on the *window*
rather than on the history behind it. A completed window with fewer than
`min_calls` calls is neither scored nor folded into any of the four
baselines, because a near-empty window drives a feature to a range
extreme for reasons that have nothing to do with behavior: a window with
exactly one call has no inter-arrival delta at all, so that feature
defaults to 0.0 seconds — the "instantaneous," maximally-bursty low
extreme. That extreme means "no observation," not "wild outlier," and
scoring it is how an identity that simply went quiet for a window gets
flagged — and, under `auto_block`, blocked. `min_calls` must therefore be
at least 2 (config validation rejects 1), the smallest window in which
every feature has a defined value. This is the same kind of floor
`rate_spike.min_calls` and `deny_rate_spike.min_calls` already apply
before trusting their own ratios.

### Auto-block

Opt in with `anomaly.auto_block.enabled: true` — **requires
`ml_score.enabled: true`**, since auto-block acts on `ml_score`'s value
via its own, independently-configured `auto_block.score_threshold`, which
config validation requires to be `>= ml_score.score_threshold` (an
operator can log at a lower sensitivity than they block at, never the
reverse — inverting them would mean an identity gets blocked with no
corresponding `ml_score` anomaly ever logged). When an identity's
`ml_score` clears `auto_block.score_threshold`, every one of that
identity's calls — **including protocol-lifecycle passthrough methods
like `initialize`**, not just `tools/call` (a blocked identity shouldn't
get a handshake either) — is rejected (`403`, JSON-RPC error,
`Retry-After` header, audit `decision: "blocked"`) for
`auto_block.block_duration_seconds` seconds from the most recent
detection — **strictly time-bounded, with no manual early unblock this
cycle**: the block simply expires once its TTL elapses, checked fresh on
every call, no separate invalidation step. `block_duration_seconds` must
stay within `2x` `anomaly.gc_interval_seconds` (config validation
enforces this) so per-identity state GC can't evict a blocked identity's
frozen baseline mid-block. Re-detection while already
blocked extends `until` from that most recent detection, not the
original one. When `web_ui` is also on, currently-blocked identities
(TTL not yet elapsed as of the request) appear via `GET
/dashboard/api/anomalies/blocked` (same RBAC gate as the rest of the
dashboard).

Every identity's baseline (the rate/novel-tool/`ml_score` history above)
is in-memory and per-process by default — reset on every restart —
UNLESS `features.postgres_storage` is also on: baselines are then
persisted to a shared Postgres table and reloaded once at startup,
checkpointed on the same interval as GC (`anomaly.gc_interval_seconds`)
rather than on every call or at shutdown, so a baseline can be up to one
GC interval stale relative to the most recent traffic regardless of
whether the process crashed or stopped cleanly. This is per-instance
persistence, not cross-replica sharing — each replica still checkpoints
and reloads only the traffic it itself has seen, mechanically: every
persisted row is keyed on `(instance_id, tenant, identity)`, not just
`(tenant, identity)`, where `instance_id` defaults to this replica's own
hostname (the same derivation federation's own instance ID uses — see
[Federation](#federation)), so two replicas sharing one Postgres DSN each
get their own row per identity instead of last-writer-wins overwriting
each other's checkpoint. A consequence worth knowing: if a replica's
hostname ever changes (e.g. pod recreation on a rolling deploy), its old
rows are orphaned under the previous hostname — never reloaded again,
and not currently pruned — which is an acceptable, if unbounded, cost
matching this feature's existing "reappears as novel" fallback posture;
see [Anomaly detection](/features/anomaly-detection/)'s Known
Limitations for the pruning caveat. See
[Credential issuance](#credential-issuance) for the same
`postgres_storage`-gated pattern applied to revocation state, and the
"Still per-replica" list in [HA deployment](#ha-deployment) for what
this does not change. When `web_ui` is also on, `GET
/dashboard/api/anomalies` also has a live view in the dashboard's
**Anomalies** panel — see [Dashboard](#dashboard).

## Federation

Off by default. Opt in with `features.federation: true`, which requires
`features.anomaly_detection: true` too — federation shares this
instance's own local anomaly detections with peers, so there must be
local detections to share. Configure with a `federation:` block:

```yaml
federation:
  instance_id: "eu-cluster-1"
  peers_file: "./peers.yaml"
  signing_key_file: "./federation-signing-key.pem"
  shared_secret_file: "./federation-shared-secret"
  publish_interval_seconds: 60
  min_instances_for_correlation: 2
  correlation_window_seconds: 300
  gc_interval_seconds: 600
```

`instance_id` is optional and defaults to `os.Hostname()` when omitted.
Set it explicitly (to something unique) when more than one Wardline
instance runs on the same host — `os.Hostname()` is identical for every
co-located process, which silently caps the Correlator's distinct-
instance count at 1 and makes cross-instance correlation impossible to
ever trip.

Every `publish_interval_seconds`, this instance aggregates its local
anomalies since the last publish into pseudonymized summaries — a
fingerprint, which heuristic fired, a count, and a time window — and
POSTs a signed batch to every peer's `/federation/summaries`. **Only
that summary ever crosses the wire.** No tool name, no detail string, no
raw identity, and no audit entry are ever sent — see
`internal/features/federation/domain/summary.go`'s `AnomalySummary`,
the sole wire shape.

Two independent keys, answering two different questions:

- **`signing_key_file`** (this instance's own RSA private key, PEM,
  PKCS1 or PKCS8 — generate with the same `openssl genrsa` command
  credential issuance uses above) signs every outbound batch, so a peer
  can verify *which configured peer actually sent this* against that
  peer's public key. Every instance needs its own key pair; the public
  half is what `peers_file` below records for each peer.
- **`shared_secret_file`** (opaque key material, not PEM — any random
  bytes) is fed into an HMAC that turns each anomaly's raw identity into
  a pseudonymous fingerprint before it ever leaves this process. Every
  federated instance must share the *same* secret, or the same identity
  produces a different fingerprint at each instance and never
  correlates. This answers "is this the same identity another instance
  also saw", a separate question from "did this peer really send this
  message" — the signing key never sees a raw identity, and the shared
  secret never signs anything.

`peers_file` (`peers.yaml`) lists every other instance this one
federates with, each peer's endpoint, and the PEM file holding that
peer's *public* signing key (used only to verify batches it sends, not
sign anything):

```yaml
peers:
  - id: eu-cluster
    endpoint: "https://eu.example.com/federation/summaries"
    public_key_file: "./eu-cluster-public-key.pem"
  - id: us-cluster
    endpoint: "https://us.example.com/federation/summaries"
    public_key_file: "./us-cluster-public-key.pem"
```

A `Correlator` watches every inbound summary — from peers via `POST
/federation/summaries`, and from this instance's own local detections on
the same publish tick — and emits a `CorrelatedAlert` once a fingerprint
has been sighted by at least `min_instances_for_correlation` distinct
instances within `correlation_window_seconds`. That's the actual value
of federation: an anomaly only one instance ever sees might be noise; the
same identity fingerprint tripping the same heuristic across multiple
instances is a much stronger signal. Each correlated alert is also
logged (`logger.Warn`, "cross-instance correlated anomaly") in addition
to being buffered in memory, so it's visible even with `web_ui` off or
after a restart clears the buffer. A given fingerprint/kind re-alerts at
most once per `correlation_window_seconds` — a sustained cross-instance
condition keeps alerting once per window, not once for its entire
lifetime. State older than 2x
`gc_interval_seconds` is garbage-collected. When `web_ui` is also on,
correlated alerts appear via `GET /dashboard/api/federation/correlated`
(same after-ID pagination as every other dashboard endpoint); the
`/federation/summaries` inbound route itself is always registered when
`federation` is on, regardless of `web_ui` — a peer must be able to
reach it even with the local dashboard off.

## Compliance evidence export

`wardline export-evidence -config wardline.yaml -from <RFC3339> [-to <RFC3339>] [-output <path>]`
assembles a time-ranged evidence bundle for an auditor — no feature flag,
this is an explicitly-invoked offline command like `validate-policy`/
`validate-config`, not passive runtime behavior.

`-from` is required (no "since forever" default); `-to` defaults to now;
`-output` defaults to `./evidence-<from>-<to>.tar.gz`.

The bundle is a `.tar.gz` containing:

- `manifest.json` — Wardline version, the requested range, which feature
  flags were enabled, and audit/anomaly entry counts with a
  decision/kind breakdown.
- `audit.jsonl` — every audit entry in range.
- `anomalies.jsonl` — every anomaly in range, when `anomaly_detection`
  is on and its output isn't `stdout` (omitted otherwise, not empty).
- `policy_snapshot` and `policy_backend.txt` — the policy file's raw
  source and which backend evaluates it (already exposed
  unauthenticated via the dashboard, so this discloses nothing new).
- `rbac_snapshot` — `rbac.yaml`'s raw source, when `rbac` is on (no
  secrets live in that file's schema).
- `identities.json` — every registered identity's name and tenant only,
  when `credential_issuance` is on and `credential.identities_file` is
  set (omitted otherwise). **Never** the identity's secret or SPIFFE ID
  — those two fields are read from `credentials.yaml`'s underlying bytes
  and never even parsed into memory on this codepath, let alone bundled.
- `checksums.txt` — a `sha256sum`-compatible listing of every other
  file in the bundle; verify with `sha256sum -c checksums.txt`.
- `checksums.txt.sig` and `public_key.pem` — present only when
  `-sign-key` is given (see "Signing and verifying bundles" below).

**Never included:** `credentials.yaml`'s raw secrets/SPIFFE IDs in any
form, the full parsed config, or any DSN. Only the files listed above.

### Signing and verifying bundles

`wardline generate-signing-key [-private-key <path>] [-public-key <path>]`
writes a fresh 2048-bit RSA keypair (PEM, PKCS8/PKIX) — an operator with
an existing compliant key from their own PKI never needs this, it just
saves a first-time user a trip to `openssl`.

`export-evidence -sign-key <path>` signs the bundle's `checksums.txt`
(RSA-PSS/SHA-256, the same scheme this project's federation feature
already uses) — since `checksums.txt` already covers every other
bundled file's integrity, signing it transitively authenticates the
whole bundle without a second digest pass. The bundle then carries its
own `public_key.pem`, so casual verification needs no out-of-band key
distribution; an operator wanting real non-repudiation still pins the
key by fingerprint out-of-band, the same trust model as any self-signed
artifact.

`wardline verify-evidence -bundle <path> [-public-key <path>]` re-checks
every file's SHA-256 against `checksums.txt` (works on any bundle,
signed or not) and, when `-public-key` is given, additionally verifies
`checksums.txt.sig` against that key. Exits non-zero on any failure —
a missing signature when `-public-key` is asked for is reported
distinctly ("bundle is not signed") from a signature that fails to
verify, so you can tell "nothing to check" apart from "check failed".

### Log retention

`audit.retention_days`/`anomaly.retention_days` (both default `0`, keep
forever) plus `features.log_retention: true` and, optionally,
`retention.check_interval_seconds` (default 86400 / 24h) run a periodic
background job that purges audit/anomaly entries older than their
configured window from whichever backend is active (JSONL rewrite, or a
Postgres `DELETE`, under `features.postgres_storage`). A line that fails
to parse is always kept, never dropped — retention must never destroy
data it can't confidently place in time. Meaningless (and rejected by
config validation) when the corresponding output is `stdout`. This does
not touch bundles already exported — only the live backing store.

### Scheduled export

`features.compliance_scheduled_export: true` plus
`compliance.scheduled_export_interval_seconds`,
`compliance.scheduled_export_output_dir`, and optionally
`compliance.signing_key_file` run the exact same export logic
`export-evidence` uses on a periodic ticker, writing a bundle into the
output directory every interval — no cron, no external scheduler. A
failed tick logs and retries the same range next tick rather than
silently skipping it, so a transient failure (disk full, a Postgres
blip) never opens a permanent gap in coverage. Requires the same
queryable-audit-trail precondition as `export-evidence`.

### Live query API

`GET /dashboard/api/compliance?from=<RFC3339>&to=<RFC3339>` (also
surfaced in the dashboard's Compliance view) returns the same
`manifest.json` shape a real export would produce — counts and
decision/kind histograms, built live from the active audit/anomaly
readers — **never raw entries**. It's a preview to sanity-check a range
before running the real CLI export, not a replacement for it; gated
identically to every other read-only dashboard route (`dashboard:view`
when RBAC is on). 404s when the audit trail isn't queryable, same
precondition as `export-evidence`.

The bundle is written `0600`, and every file inside it carries mode
`0600` too — it aggregates the whole audit trail into one artifact, so
it should not be world-readable on a shared host. Copy it to the
auditor over a channel you'd trust with the audit log itself.

**Postgres exports need the same DSN `serve` uses.** With
`features.postgres_storage` on, `export-evidence` opens the audit
database through the same connector `serve` does, which runs `CREATE
TABLE IF NOT EXISTS`/`CREATE INDEX IF NOT EXISTS` on connect. A
`SELECT`-only compliance role therefore can't run this command today —
point `-config` at a config whose `audit.postgres_dsn` has the
privileges `serve` has. A dedicated read-only connector (plus a
separate read-only DSN field to make it useful) is a future cycle.

**Requires a queryable audit trail.** `audit.output: stdout` has
nothing to read back — point `audit.output` at a file, or turn on
`features.postgres_storage`, to use this command. See
`docs/superpowers/specs/2026-07-28-compliance-evidence-export-design.md`
for the original design and
`docs/superpowers/specs/2026-08-08-compliance-evidence-export-hardening-design.md`
for signing/retention/scheduled-export/live-query/redacted-identities —
still deliberately deferred: a full raw-entry evidence browser, cron-
expression scheduling, and cross-replica coordination for retention/
scheduled-export in an HA deployment (each replica runs its own
independent ticker today).

## Policy packs

`wardline policy-pack list` shows four starter policy files embedded in
the binary itself — no network fetch, no separate download:

- `deny-all-baseline` — denies everything; the safest starting point.
- `single-identity-full-access` — one identity, full access, everything
  else denied.
- `read-only-single-identity` — one identity limited to read/list-shaped
  tools, everything else denied.
- `admin-viewer-split` — two roles in one file: an admin identity with
  full access, a viewer identity limited to read/list tools. Rename its
  two placeholders to two *different* identities — nothing validates
  that they differ, and reusing one string for both collapses the split
  (that identity ends up read-only, the deliberately safe outcome).

`wardline policy-pack show <name>` prints a pack's full policy source
before you install it. `wardline policy-pack install <name> [-output
<path>]` writes it to `<path>` (default `./policy.yaml`) — it refuses to
overwrite an existing file (or to follow a symlink at that path), and
never edits `wardline.yaml` itself; it prints the
`policy_file`/`policy_backend` lines to add yourself.

**Every pack except `deny-all-baseline` names a placeholder identity**
(`REPLACE_WITH_YOUR_IDENTITY`, etc.) you're expected to rename to your
own before using the installed file — Wardline's YAML policy engine
matches identities exactly, with no wildcard, so no pack can express "any
identity" the way its tool-matching rules can with `"*"`. Treat every
installed pack as a starting template to edit, not a policy to apply
verbatim; `install` warns when the pack it just wrote still contains
placeholders. An unreplaced placeholder matches nothing, so every call
falls through to the pack's `default: deny` — fail-closed, but it looks
like "Wardline blocks everything" until you edit the file. See
`docs/superpowers/specs/2026-07-28-policy-pack-marketplace-design.md` for
the full design, including why this ships as an embedded catalog rather
than a live registry.

## Auto-generated sandbox policy

`wardline infer-policy -config wardline.yaml -from <RFC3339> [-to <RFC3339>] [-output <path>]`
reads the audit trail over a time range and writes a starter
`policy.yaml`-shaped file allow-listing exactly the `(tenant, identity,
tool)` combinations it saw succeed — no feature flag, an explicitly-
invoked offline command like `export-evidence`/`policy-pack`.

Only `allow` audit entries feed the generated rules —
`deny`/`throttled`/`blocked`/`error` entries are excluded, since
allow-listing a call that didn't succeed would grant more than what was
actually observed, and `passthrough` entries are excluded because their
`tool` field holds a raw JSON-RPC method name that policy never
evaluated, so it isn't an observed grant at all. `-output` defaults to `./policy.generated.yaml`, and,
like `policy-pack install`, refuses to overwrite an existing file or
follow a dangling symlink there.

The generated file is a normal `policy.yaml` — load it as-is with
`policy_backend: yaml`. It is a *starting point*: review every rule
before adopting it. See [Auto-Generated Sandbox
Policy](docs-site/content/features/auto-generated-policy.md) for the
full design, including why this deliberately has no live/continuous
mode.

**Requires a queryable audit trail**, same as `export-evidence`:
`audit.output: stdout` has nothing to read back. On the postgres path it
also needs a DDL-capable DSN, not a SELECT-only one — the same requirement
`export-evidence` has, since connecting runs `CREATE TABLE/INDEX IF NOT
EXISTS`.

## Tracing

Off by default. Opt in with `features.otel_tracing: true` plus a `tracing:`
block — `otlp_endpoint` (required, `host:port`, no scheme) and
`service_name` (optional, defaults to `wardline`) — see
`wardline.yaml.example`.

Wardline emits one span per request, exported via OTLP/HTTP (plaintext, no
TLS yet) to whatever collector is listening at `otlp_endpoint`. Incoming
W3C `traceparent` headers are honored — Wardline's span becomes a child of
an existing trace if the caller already has one.

The audit log's `trace_id` field correlates a log line to its trace; it's
empty when tracing is disabled.

`serve` now handles SIGINT/SIGTERM by draining in-flight requests and
flushing the tracer provider before exiting, so buffered spans aren't lost
on shutdown. SIGTERM triggers up to a 10s HTTP drain plus a 5s span-flush
— configure your supervisor's grace period (e.g. Kubernetes
`terminationGracePeriodSeconds`, systemd `TimeoutStopSec`) above 15s, well
above Docker's 10s default, or the last few seconds of spans (and any
in-flight requests) can be lost.

There is no sampling in this version — every request is exported when
tracing is enabled, so turning this on at real production request rates
sends full volume to your collector.

When the collector is unreachable, the OTel SDK retries/drops spans
internally; request handling is never blocked or failed because of it.

Span status descriptions can carry the same detailed policy/budget reason
text that's deliberately kept out of HTTP responses (see the budget
section above) — operators enabling tracing should be aware that reason
text reaches whatever reads their trace backend, which is typically a
wider audience than the audit log.

The `wardline.identity` span attribute is populated from the same
unauthenticated, caller-controlled `X-Wardline-Identity` header discussed
above — a caller rotating identities can inflate cardinality in the trace
backend, not just evade rate limiting.

## Dashboard

An in-browser view of what Wardline is doing right now — eight views,
reached from the sidebar: Overview, Activity, Anomalies, Blocked,
Federation, Credentials, Policy, and Status. Almost entirely read-only
(two narrow, explicitly-gated exceptions below); a live convenience
view over data that lives elsewhere, not a system of record. Off by
default — enable with:

```yaml
features:
  web_ui: true
```

Then visit `http://<listen-addr>/dashboard/`. Full design/token
documentation lives at the [docs site's Web Dashboard
page](https://kabirnarang39.github.io/wardline/docs/features/web-dashboard/);
this section is the quick reference.

**Screenshots** (captured 2026-08-02 against a locally built binary seeded
with `internal/features/dashboard/testdata/seed.sh` — real data, not a
mockup):

| Overview — action-needed state | Anomalies | Blocked |
|---|---|---|
| ![Wardline dashboard Overview view, red action-needed status band, one identity blocked](docs/images/dashboard/overview.png) | ![Wardline dashboard Anomalies view listing detected novel_tool and ml_score anomalies](docs/images/dashboard/anomalies.png) | ![Wardline dashboard Blocked view showing an identity under a time-bounded auto-block with an Unblock button](docs/images/dashboard/blocked.png) |

The status band above is red ("action-needed") because the seeded traffic
includes a genuine rate-spike/enumeration burst that tripped `ml_score` and
a real `auto_block` — see [Anomaly detection](#anomaly-detection) and
[Auto-block](#auto-block) for exactly what puts the band in each of its
three states.

**What it shows:**
- **Overview** — the first view you land on, and the one worth reading
  before any other. A status band at the top reduces everything to one
  of three states, checked in this order (a real block always outranks
  a real anomaly): **action-needed** (red) when at least one identity is
  currently auto-blocked; **attention** (amber) when there are no active
  blocks but at least one recorded anomaly; **nominal** (green,
  "All systems nominal") otherwise. Below that: a KPI row (request
  count, deny rate, anomaly count, blocked count, all computed from the
  same buffers Activity/Anomalies/Blocked poll — nothing here is a
  separately-tracked number that can drift from what those views show),
  a recent-activity bar chart bucketed by day **from the last N buffered
  audit events only** (the same bounded, resets-on-restart buffer
  Activity reads — not a query over the durable JSONL/Postgres audit
  trail, so a busy instance's chart reflects recent traffic, not full
  history), a "needs review" summary with a CTA that jumps straight to
  Anomalies, and a live pulse (requests/sec over the trailing 10
  seconds, with a pause/resume toggle). None of Overview's own elements
  animate on every poll tick — only genuine state transitions (e.g. the
  status band flipping color) trigger motion, and every such transition
  respects `prefers-reduced-motion`.
- **Activity** — a live-updating (polls every 2 seconds) table of the
  most recent proxied calls: identity, tool, decision, latency, trace ID,
  and reason (for denied/throttled/errored calls). Backed by a bounded
  1000-entry in-memory buffer, not the durable audit log — it resets on
  restart. The JSONL file (or wherever `audit.output` points) remains
  the durable, complete record; the dashboard is a live convenience view
  on top of it, not a replacement.
- **Anomalies** — a live-updating table of detected anomalies (same
  after-ID polling pattern as Activity), backed by `GET
  /dashboard/api/anomalies` — see [Anomaly detection](#anomaly-detection).
  The nav item is always shown, even when `anomaly_detection` is off (the
  underlying API then answers `404` on every poll, the same "not wired"
  posture as every other feature-gated dashboard route) — the panel
  itself renders its own "No anomalies detected yet." empty state in
  that case rather than a permanently-blank table, and logs the poll
  failure to the browser console.
- **Blocked** — a live-updating table of identities currently under a
  time-bounded `anomaly.auto_block` (identity, tenant, reason, expiry),
  backed by `GET /dashboard/api/anomalies/blocked`. The nav item is
  always shown, 404s the same "not wired" way when `anomaly.auto_block.enabled`
  is off (which includes `anomaly_detection` being off entirely — a
  sub-feature can't be on without its parent). **This is the first of
  the dashboard's two mutations**: each
  row has an **Unblock** button (`DELETE
  /dashboard/api/anomalies/blocked/{identity}`) that clears the block
  before its TTL expires, after a confirm prompt. Gated separately from
  ordinary read access — see the auth note below.
- **Federation** — a live-updating table of alerts correlated across
  multiple Wardline instances (first/last seen, kind, contributing
  instance IDs, fingerprint), backed by `GET
  /dashboard/api/federation/correlated`. 404s the same "not wired" way
  when `features.federation` is off. Correctly, and expectedly, empty
  ("No cross-instance correlated alerts yet.") on a single-instance
  deployment — correlation needs at least
  `federation.min_instances_for_correlation` peers reporting the same
  fingerprint; see [Federation](#federation).
- **Credentials** — **the dashboard's second and only other mutation:
  revoke a credential, and nothing else.** Deliberately not symmetric
  with issuance/refresh: `POST /credentials/revoke` is the one genuine
  admin action a dashboard operator has legitimate reason to trigger
  from a browser; `POST /credentials/refresh` performs machine-to-machine
  token rotation on a caller-supplied `refresh_token` value, and an
  operator has no legitimate reason to hold or exercise another
  identity's refresh token from a UI, so this view never exposes it, and
  there is no issuance UI either (bootstrapping requires the identity's
  own registration secret, not something to route through an
  operator-facing screen). Enter an identity, confirm, and every
  outstanding and future-until-expiry access token plus any outstanding
  refresh token for that identity is invalidated immediately. **Auth
  requirement — read this before wondering why the button 403s:**
  `/credentials/revoke` reuses the exact same loopback-or-RBAC gate the
  API already has (see [Credential issuance](#credential-issuance) and
  [RBAC](#rbac) above) — it is allowed from `127.0.0.1`/`::1` unconditionally;
  from anywhere else, only when `features.rbac` is on **and** the
  resolved caller holds `credential:revoke` (the `admin` built-in role,
  or a custom role naming that permission). A caller with only
  `dashboard:view` (e.g. the `viewer` role) can load the rest of the
  dashboard fine and will still get `403` here — that is correct, not a
  bug. One sharp edge worth knowing up front: the button's own fetch
  does **not** attach any credential of its own — it relies entirely on
  whatever the browser already sends automatically. That is enough when
  you're loopback, or when identity is resolved from a raw
  `X-Wardline-Identity` header a trusted intermediary injects. It is
  **not** enough when `features.credential_issuance` is on and you're
  not loopback: identity there is a bearer token (`Authorization: Bearer
  <jwt>`), and a plain browser tab has no built-in mechanism to attach
  that header to its own requests (unlike a cookie, which browsers do
  send automatically). In that combination, reach this button through
  something that can attach the header for you (a reverse proxy/mesh
  sidecar, a browser extension that injects the header, or API tooling
  hitting `/credentials/revoke` directly) rather than expecting a bare
  browser tab to work. Note this button's loopback exception is its own —
  `/dashboard/` itself has **no** loopback exception once `features.rbac`
  is on (see [RBAC](#rbac) above), so a bare browser tab may still be
  unable to load the rest of the dashboard even from loopback; see the
  security note below.
- **Policy** — the active policy backend and raw policy file content, as
  loaded at startup (not hot-reloaded — restart Wardline after editing
  the policy file to see the update here).
- **Status** — version, uptime, listen/upstream addresses, and which
  feature flags are on.

**Security note:** the dashboard requires no authentication and every
non-mutating route is read-only **by default** (unless `features.rbac`
is on — see the [RBAC](#rbac) section above; with it on, every dashboard
request must resolve an identity holding `dashboard:view`, else `403`).
**Two narrow exceptions accept writes: Blocked's Unblock button and
Credentials' Revoke button**, both described above — each is a real,
security-relevant mutation (undoing an automated enforcement decision;
invalidating a credential), and each is independently gated by
`credential:revoke` rather than the weaker `dashboard:view` a plain
reader might hold. Neither can influence policy evaluation, budget
accounting, or how a proxied call is decided going forward except
through that one narrow, audited, explicitly-permissioned action. Every
other route remains genuinely read-only. The dashboard does, however,
display audit *reasons* (which can include internal policy-engine
diagnostics normally kept out of proxy responses) and raw policy file
content, both of which may carry information you don't want a stranger
to see. The dashboard shares the exact same listener/port as the proxy
itself, so anyone who can reach Wardline's proxy port — **including
every agent Wardline proxies calls for** — can already `GET
/dashboard/api/audit` and `GET /dashboard/api/policy` on that identical
socket. Binding the listen address to `localhost` does **not** protect
against this: the proxy's own legitimate callers are, by definition,
already on that same port. This is precisely why `web_ui` defaults to
off — only enable it when you're comfortable with every caller the
proxy already accepts also being able to read full audit reasons and
the complete policy source.

## Postgres storage

An alternative to the JSONL audit log: write audit entries directly to
a Postgres database instead, for operators who want a SQL-queryable
audit trail. Off by default — enable with:

```yaml
features:
  postgres_storage: true
audit:
  postgres_dsn: "postgres://user:pass@localhost:5432/wardline?sslmode=disable&connect_timeout=5"
```

`audit.output` is ignored (with a warning logged at startup) when this
flag is on — pick one audit sink, not both.

**What it does:** creates its `audit_entries` table (if it doesn't
already exist) at startup, and writes one row per proxied request —
identical data to the JSONL format, just in a queryable table instead of
log lines. No migration framework; if the schema ever needs to change,
that's a deliberate future decision, not something this handles
automatically.

`postgres_storage` is not audit-only, though: it's the shared flag every
Postgres-backed feature keys off. Each one you also enable (credential
revocation, refresh tokens, budget counters, SCIM group bindings,
anomaly-detection baselines) creates its own table in the same database
on first connection, and manages its own connection pool.

**A real tradeoff, not an oversight:** each audit write is a synchronous
SQL `INSERT` on the client-visible request path — it happens before the
response is sent back to the client, so the audit entry landing in
Postgres is a real network round-trip the caller waits on. For a
co-located database this is single-digit milliseconds, smaller than the
JSON-RPC parsing and policy evaluation Wardline already does per
request; for a database in a meaningfully different region, this
latency is real. A buffered/batched writer is the natural upgrade path
if that ever matters for your deployment — not built preemptively here.

**Startup behavior:** a bad DSN or unreachable database fails fast at
startup (`wardline serve` refuses to start), the same as a bad policy
file — this is deliberate, so a misconfigured database is caught
immediately rather than silently dropping every audit entry at runtime.
Every Postgres operation (the startup ping and every per-request
`INSERT`) is bounded by a 5-second timeout, so a blackholed connection
(as opposed to a fast connection-refused failure) degrades to a bounded
error instead of hanging a request-handling goroutine indefinitely.

**Indexing and retention are the operator's responsibility:** beyond the
one index this feature creates on `timestamp`, any further indexing and
any pruning/retention of the `audit_entries` table over time is not
managed automatically — plan for both if you expect a long-running,
high-volume deployment.

## HA deployment

Running more than one replica behind a load balancer is supported, with
some capabilities staying explicitly per-replica.

**Fully HA-safe today:**
- **Audit trail**, when `features.postgres_storage` is on — every
  replica writes to the same shared database (`audit.output`'s
  JSONL-file mode is NOT shared across replicas; each replica would
  write its own separate file).
- **Credential issuance**, when `credential.signing_key_file` points at
  a PEM RSA private key mounted identically on every replica (e.g. the
  same Kubernetes `Secret`) — without it, every replica generates its
  own signing keypair at startup, and a token issued by one replica
  fails verification on another. Generate one with:
  ```
  openssl genrsa -out signing-key.pem 2048
  ```
- **Credential revocation**, when both `credential_issuance` and
  `postgres_storage` are on — revocation is stored in the same shared
  Postgres database instead of an in-memory map, so a revocation issued
  against one replica is honored by every other replica on its very
  next check.
- **RBAC and policy**, as long as every replica is given the same
  `rbac.yaml`/policy file (the same ConfigMap/Secret mount) and rolled
  together on any change — there's no hot-reload, a config change needs
  a restart on every replica, same as a single-replica deployment.
- **Health and readiness**: `GET /healthz` (liveness — always `200` once
  the process has started; deliberately never depends on an external
  dependency) and `GET /readyz` (readiness — `503` for the entire
  duration of graceful shutdown, and, when `postgres_storage` is on,
  `503` if Postgres is unreachable). Neither route is proxied to the
  upstream or recorded in the audit trail. Point a load balancer or
  Kubernetes readiness probe at `/readyz` — this is what lets a rolling
  deploy pull a draining pod out of rotation before it starts refusing
  connections, instead of dropping in-flight requests.
  - **`/healthz` and `/readyz` are permanently reserved paths**, shadowed
    from every deployment, in every configuration — if your upstream MCP
    server exposes its own routes at these exact paths, they are no
    longer reachable through the proxy. This is unconditional, not
    gated by any feature flag.
  - Registering these two routes means every deployment now routes
    through Go's `http.ServeMux` internally, even one with every
    optional feature off — previously that was only true once a feature
    like the dashboard was enabled. `http.ServeMux` applies its own path
    cleaning (collapsing `//`, resolving `..`) before a request reaches
    the proxy handler; a client sending an already-unclean path now gets
    a redirect it wouldn't have seen before this cycle. Low real-world
    likelihood (MCP traffic is typically one clean path), but worth
    knowing if you're debugging an unexpected redirect on an upgrade.
  - `/readyz`'s Postgres check means a single shared-database blip takes
    **every** replica out of rotation simultaneously when
    `postgres_storage` is on — this is the same fail-closed posture the
    rest of the codebase applies to a broken dependency, but a
    `PodDisruptionBudget` does not protect against a readiness-driven
    removal (only against a voluntary eviction), so all replicas can
    still go unready together in this specific scenario.
- **Shutdown delay** (`shutdown_delay_seconds`, default `0`, Helm default
  `5`): how long a replica keeps serving normally after receiving
  SIGTERM/SIGINT before it starts draining. This is an in-process
  substitute for a Kubernetes `preStop` sleep — it exists because
  Wardline's own published image is `distroless` and has no shell, so a
  shell-based `preStop` hook (`sleep N`) cannot run on it at all. The
  delay buys the same real-world value a `preStop` sleep would: time for
  Kubernetes' Endpoints controller to propagate this pod's removal from
  Service routing before the container actually stops accepting
  connections, since `/readyz` flipping to `503` on its own does not
  reliably achieve this (`http.Server.Shutdown()` closes the listener
  essentially synchronously once called, confirmed by live testing).
- **Budget enforcement**, when both `budget_enforcement` and
  `postgres_storage` are on — the per-window counters live in the same
  shared Postgres database instead of per-process memory, so one
  configured limit is enforced across the whole fleet. With
  `postgres_storage` off the limiter is per-process, in-memory, and
  each replica enforces the configured limit independently (2 replicas
  ≈ 2× the configured per-window limit). See
  [Budget enforcement](#budget-enforcement) above.

**Still per-replica, by design, not yet cluster-aware:**
- **Anomaly detection** — each replica's heuristics only see the
  fraction of an identity's traffic that lands on that replica, so a
  real spike split evenly across replicas may not cross any single
  replica's threshold. A shared/distributed detection store is a larger
  design left for a future cycle.
- **The dashboard's live audit view** — `/dashboard/api/audit` reflects
  only the traffic that landed on the specific replica answering that
  request, not a cluster-wide view.

See `docs/superpowers/specs/2026-07-29-ha-deployment-design.md` for the
full design and rationale.

## Kubernetes / Helm

A Helm chart is available at `charts/wardline/` for deploying Wardline
on Kubernetes.

**No published image exists yet** — `values.yaml`'s default
`image.repository` doesn't resolve to anything CI publishes. Build and
push your own image first:

```bash
docker build -t <your-registry>/wardline:0.5.0-dev .
docker push <your-registry>/wardline:0.5.0-dev
```

then install, pointing the chart at it:

```bash
helm install my-wardline charts/wardline \
  --set image.repository=<your-registry>/wardline \
  --set image.tag=0.5.0-dev \
  --set wardline.upstream=http://your-mcp-server:9000 \
  --set-file wardline.policy=./policy.yaml
```

Most of `internal/platform/config.Config` is exposed under `values.yaml`'s
`wardline:` key — feature flags, budget limits, tracing, Postgres
storage, and (as of the HA-deployment cycle) `credential.signing_key_file`
/ `credential.identities_file` and `shutdown_delay_seconds` all work the
same way they do outside Kubernetes. Two blocks are not yet exposed
there: `rbac:` and `anomaly:` — set either via a mounted/overridden
config file if you need them on Kubernetes today; wiring them into
`values.yaml` is deferred to a future chart cycle.

**Mounting a signing key or identities file:** `wardline.credentialSigningKeyFile`
and `wardline.credentialIdentitiesFile` only set the config *paths* — you
still need to get the actual files into the container yourself, via
`extraVolumes`/`extraVolumeMounts`:

```yaml
extraVolumes:
  - name: signing-key
    secret:
      secretName: wardline-signing-key
extraVolumeMounts:
  - name: signing-key
    mountPath: /etc/wardline-secrets
    readOnly: true
wardline:
  credentialSigningKeyFile: /etc/wardline-secrets/signing-key.pem
```

**Exposing the dashboard:** if you enable `features.web_ui` and also
enable Ingress (or set `service.type` to something other than
`ClusterIP`), you're making the dashboard reachable beyond the cluster —
unauthenticated unless `features.rbac` is also on (see the
[Dashboard](#dashboard) section's security note and the [RBAC](#rbac)
section above before doing this); `helm install`'s post-install notes
warn about this combination too.

**Multiple replicas:** Wardline's budget enforcement and dashboard live
view are both per-process, in-memory state, not shared across replicas
— running `replicaCount > 1` means each pod enforces its own
independent rate limit. `helm install`'s own post-install notes repeat
this warning when `replicaCount` is set above 1. A shared budget store
across replicas is real future work, not something this chart papers
over. Note this multi-pod hazard isn't limited to `replicaCount > 1`:
Kubernetes' default `RollingUpdate` strategy means even a
single-replica deployment briefly runs the old and new pod
simultaneously during any `helm upgrade` that changes the pod spec —
which now includes every policy or config change, since the pod
template carries a checksum annotation over both — each pod with its
own independent budget counters reset to zero.

**Health checks and HA primitives:** the chart's liveness/readiness
probes are real `httpGet` checks against `/healthz`/`/readyz` (see "HA
deployment" above for what each actually verifies). With
`replicaCount > 1`, the chart also renders a `PodDisruptionBudget`
(`podDisruptionBudget.minAvailable`, default `1`) and soft pod
anti-affinity (`podAntiAffinity.enabled`, default `true`) spreading
replicas across nodes. `terminationGracePeriodSeconds` (default `30`)
and `wardline.shutdownDelaySeconds` (default `5`) are both explicit
`values.yaml` fields — see "HA deployment" above for how they relate.

**Resources:** `values.yaml`'s `resources: {}` default ships no
CPU/memory limits or requests — a commented-out example block is
included, but the chart can't guess a sizing that fits your workload.
With no resources set, the pod runs in `BestEffort` QoS (first evicted
under node memory pressure) and will be rejected outright by a
namespace `ResourceQuota` that requires requests — set `resources`
explicitly if either applies to you.

See `CLAUDE.md` for the architecture and engineering conventions this
codebase is built to.
