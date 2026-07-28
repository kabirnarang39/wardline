---
title: "Policy YAML Reference"
weight: 30
---

```yaml
rules:
  - identity: agent-abc123   # exact match against X-Wardline-Identity
    tool: read_file           # exact match against the tools/call name
    effect: allow             # "allow" or "deny"
default: deny                 # required -- "allow" or "deny", applied when no rule matches
```

Rules are evaluated top to bottom; first match wins. `default` is
**required**, not optional — the loader rejects a policy file that
omits it. There's no hardcoded fallback; the operator explicitly
chooses whether an unmatched request is allowed or denied.
