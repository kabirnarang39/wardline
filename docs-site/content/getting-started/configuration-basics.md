---
title: "Configuration Basics"
weight: 30
---

Wardline reads two files at startup: a **config file** (`wardline.yaml`)
and a **policy file** (`policy.yaml`, or Rego/Cedar — see
[Policy backends](/concepts/policy-backends/)).

## `wardline.yaml` anatomy

```yaml
listen: "0.0.0.0:8080"
upstream: "http://localhost:9000"
policy_file: "policy.yaml"
policy_backend: yaml   # "yaml" (default), "opa", or "cedar"

audit:
  output: stdout        # or a file path

features:
  credential_issuance: false
  rbac: false
  budget_enforcement: false
  anomaly_detection: false
  compliance_evidence_export: false
  policy_pack_marketplace: false
  postgres_storage: false
```

Every capability beyond the v0.1 baseline (proxy + policy + audit) is
gated by a `features` flag, off by default — see each feature's own page
under [Features](/features/) for what its block adds to this file.

## `policy.yaml` anatomy

```yaml
rules:
  - identity: agent-abc123
    tool: read_file
    effect: allow
  - identity: agent-abc123
    tool: delete_file
    effect: deny
```

Full field-by-field reference: [Config reference](/reference/config-reference/),
[Policy YAML reference](/reference/policy-yaml-reference/).
