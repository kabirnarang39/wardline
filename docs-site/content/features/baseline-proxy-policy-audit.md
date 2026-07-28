---
title: "Proxy, Policy & Audit (baseline)"
weight: 10
summary: "Always on — reverse proxy, policy decision, audit log."
---

The v0.1 baseline, always on, no flag: a reverse proxy in front of one MCP
server, one of three policy backends
([YAML](/reference/policy-yaml-reference/), [OPA/Rego](/reference/policy-rego-reference/),
[Cedar](/reference/policy-cedar-reference/)) evaluated per identity+tool
call, and a structured JSON audit log of every decision.

See [Identity and Policy](/concepts/identity-and-policy/) and
[Audit Log](/concepts/audit-log/) for the full model. Minimal config:

```yaml
listen: "0.0.0.0:8080"
upstream: "http://your-mcp-server:9000"
policy_file: "policy.yaml"
audit:
  output: stdout
```
