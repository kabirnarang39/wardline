# Wardline

Open source control-plane proxy for AI agents: identity, policy, budget, and
audit for MCP and beyond.

v0.1 scope: a reverse proxy in front of one MCP server, a policy backend
(a static YAML allow/deny rule list, or an embedded OPA/Rego evaluator) per
identity+tool, and a structured JSON audit log.

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

**Scope note:** policy, budget enforcement, and audit decisions apply to
tool calls (`tools/call`) only. Other MCP protocol methods — the
`initialize` handshake every client performs, `notifications/initialized`,
`tools/list`, and (if your upstream MCP server exposes them) `resources/*`
and `prompts/*` — are forwarded to the upstream server without policy or
budget evaluation, recorded in the audit log with a `"passthrough"`
decision so they're visible but distinguishable from an actual policy
`"allow"`. If your upstream server exposes sensitive resources or
prompts, be aware they are not currently gated by Wardline's policy
engine — only tool calls are.

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

Both `opa` and `cedar` link their SDKs into every Wardline binary
unconditionally (selected at runtime by `policy_backend`, not by build
tag), which increases binary size versus `yaml` alone — the OPA SDK adds
roughly 29MB; Cedar's SDK measured at roughly 44MB with both
already linked in. An operator building a minimal-size image and using
only `yaml` still pays this cost today; splitting policy backends into
optional build tags is tracked as a future improvement, not solved by
this cycle.

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

The limiter is per-process, in-memory — running multiple `wardline`
replicas gives each its own independent budget. This is a known limitation,
not a bug.

This is a request-*rate* limit, not a success-rate limit: a request that's
within budget but then fails upstream (502) still counts against the
caller's window.

Budget enforcement trusts the `X-Wardline-Identity` header as-is — there's
no authentication on it today — so it's only as strong as whatever
validates that header upstream of Wardline (or a future identity
verification feature); a caller that can set arbitrary identity values can
evade rate limiting by rotating identities.

## Credential issuance

Off by default. Opt in with `features.credential_issuance: true` plus a
`credential:` block (`identities_file`, pointing at a `credentials.yaml`
mapping identity names to preshared registration secrets — see
`credentials.yaml.example`).

When on, `X-Wardline-Identity` is no longer read. Agents exchange their
registration secret for a short-lived (15-minute) RS256 JWT via
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

The signing keypair is generated fresh in-process at `wardline serve`
startup — not persisted, not shared across replicas. Restarting the
process (or running more than one replica) invalidates every outstanding
token, the same "no shared state across restarts" posture already true of
the budget limiter and dashboard ring buffer.

mTLS/SPIFFE-style bootstrap and IdP federation (Okta, Entra, generic
OIDC) are explicitly out of scope for this version — see
`docs/superpowers/specs/2026-07-27-credential-issuance-design.md`.

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

This cycle's tenant model is real but only one tenant exists:
`RoleBinding`s are matched against the literal tenant `"default"`
everywhere in Wardline today — true multi-tenant data isolation (a
separate policy/audit/budget per tenant) is a larger, separate future
change, not part of this version. See
`docs/superpowers/specs/2026-07-28-rbac-design.md`.

RBAC is only as strong as whatever resolves the caller's identity — the
same disclaimer as budget enforcement's: pair it with `credential_issuance`
for real security value, or it's only as trustworthy as the
unauthenticated `X-Wardline-Identity` header.

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

A read-only, in-browser view of what Wardline is doing right now:
recent audit activity, the active policy, and basic server status.
Off by default — enable with:

```yaml
features:
  web_ui: true
```

Then visit `http://<listen-addr>/dashboard/`.

**What it shows:**
- **Activity** — a live-updating (polls every 2 seconds) table of the
  most recent proxied calls: identity, tool, decision, latency, trace ID,
  and reason (for denied/throttled/errored calls). Backed by a bounded
  1000-entry in-memory buffer, not the durable audit log — it resets on
  restart. The JSONL file (or wherever `audit.output` points) remains
  the durable, complete record; the dashboard is a live convenience view
  on top of it, not a replacement.
- **Policy** — the active policy backend and raw policy file content, as
  loaded at startup (not hot-reloaded — restart Wardline after editing
  the policy file to see the update here).
- **Status** — version, uptime, listen/upstream addresses, and which
  feature flags are on.

**Security note:** the dashboard has no authentication and is read-only
by design (unless `features.rbac` is on — see the [RBAC](#rbac) section
above; with it on, every dashboard request must resolve an identity
holding `dashboard:view`, else `403`). It does not accept writes and
cannot influence policy, budget, or proxy decisions. It does, however,
display audit *reasons*
(which can include internal policy-engine diagnostics normally kept out
of proxy responses) and raw policy file content, both of which may
carry information you don't want a stranger to see. The dashboard
shares the exact same listener/port as the proxy itself, so anyone who
can reach Wardline's proxy port — **including every agent Wardline
proxies calls for** — can already `GET /dashboard/api/audit` and
`GET /dashboard/api/policy` on that identical socket. Binding the
listen address to `localhost` does **not** protect against this: the
proxy's own legitimate callers are, by definition, already on that
same port. This is precisely why `web_ui` defaults to off — only
enable it when you're comfortable with every caller the proxy already
accepts also being able to read full audit reasons and the complete
policy source.

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

**What it does:** creates a single `audit_entries` table (if it doesn't
already exist) at startup, and writes one row per proxied request —
identical data to the JSONL format, just in a queryable table instead of
log lines. No migration framework; if the schema ever needs to change,
that's a deliberate future decision, not something this handles
automatically.

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
`wardline:` key — feature flags, budget limits, tracing, and Postgres
storage all work the same way they do outside Kubernetes. Two blocks are
not yet exposed there: `credential:` (pre-existing gap) and `rbac:` — set
either via a mounted/overridden config file if you need them on Kubernetes
today; wiring them into `values.yaml` is deferred to a future chart cycle.

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

**Health checks:** the chart's liveness/readiness probes use a TCP
socket check against the listen port, not an HTTP health endpoint —
Wardline doesn't have one yet. This proves the process is listening,
not that policy/upstream/tracing are fully healthy.

**Resources:** `values.yaml`'s `resources: {}` default ships no
CPU/memory limits or requests — a commented-out example block is
included, but the chart can't guess a sizing that fits your workload.
With no resources set, the pod runs in `BestEffort` QoS (first evicted
under node memory pressure) and will be rejected outright by a
namespace `ResourceQuota` that requires requests — set `resources`
explicitly if either applies to you.

See `docs/superpowers/specs/2026-07-26-wardline-v0.1-design.md` for the full
design and `CLAUDE.md` for engineering conventions.
