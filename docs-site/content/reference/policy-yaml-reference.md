---
title: "Policy YAML Reference"
weight: 30
---

```yaml
rules:
  - identity: agent-abc123   # exact match against X-Wardline-Identity
    tool: read_file           # exact match against the tools/call name
    effect: allow             # "allow" or "deny"
```

Rules are evaluated top to bottom; first match wins. No match is an
implicit deny.
