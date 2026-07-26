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

See `docs/superpowers/specs/2026-07-26-wardline-v0.1-design.md` for the full
design and `CLAUDE.md` for engineering conventions.
