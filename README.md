# Wardline

Open source control-plane proxy for AI agents: identity, policy, budget, and
audit for MCP and beyond.

v0.1 scope: a reverse proxy in front of one MCP server, a static YAML
allow/deny policy per identity+tool, and a structured JSON audit log.

## Quickstart

```bash
go build -o wardline ./cmd/wardline
./wardline validate-policy --file policy.yaml.example
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

See `docs/superpowers/specs/2026-07-26-wardline-v0.1-design.md` for the full
design and `CLAUDE.md` for engineering conventions.
