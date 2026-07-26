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
against this value plus the MCP tool name being called. Only the `tools/call`
JSON-RPC method is proxied in v0.1 — any other method gets a 400.

```bash
curl -X POST http://localhost:8080 \
  -H "X-Wardline-Identity: agent-abc123" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}'
```

(This matches the `agent-abc123` / `read_file` allow rule in
`policy.yaml.example`.)

## Policy backends

Wardline supports two policy backends, selected by `policy_backend` in the
config file (defaults to `yaml` if omitted):

- **`yaml`** (default) — a static allow/deny rule list, as in
  `policy.yaml.example`.
- **`opa`** — an embedded OPA/Rego evaluator (no external `opa` process, no
  network hop). Policies must declare `package wardline.authz` and export an
  `allow` boolean (and, optionally, a `reason` string). See
  `policy.rego.example` for the same allow rule expressed in Rego, with
  access to the full request context — tool call parameters, timestamp,
  remote address, and user agent — not just identity and tool name.

Choosing the `opa` backend links in the OPA Go SDK, which meaningfully
increases binary size — roughly 29MB with OPA linked in vs. a few MB
without — so an operator building a container image should expect the
larger image when opting into it.

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
```

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

See `docs/superpowers/specs/2026-07-26-wardline-v0.1-design.md` for the full
design and `CLAUDE.md` for engineering conventions.
