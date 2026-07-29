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
  postgres_storage: false
  otel_tracing: false
  web_ui: false
```

Every capability beyond the v0.1 baseline (proxy + policy + audit) is
gated by a `features` flag, off by default — see each feature's own page
under [Features](/features/) for what its block adds to this file
(`otel_tracing` and `web_ui` are covered under
[Observability](/deployment/observability/) instead, alongside the
Helm/Docker deployment material they're most relevant to).
[Compliance evidence export](/features/compliance-evidence-export/) and
[Policy-pack marketplace](/features/policy-pack-marketplace/) are the
two exceptions: both are always-available CLI subcommands
(`export-evidence`, `policy-pack`), not gated by a `features` flag at
all.

## `policy.yaml` anatomy

```yaml
rules:
  - identity: agent-abc123
    tool: read_file
    effect: allow
  - identity: agent-abc123
    tool: delete_file
    effect: deny
default: deny
```

`default` is required — every policy file must explicitly choose
whether an unmatched request is allowed or denied; there's no
hardcoded fallback.

Full field-by-field reference: [Config reference](/reference/config-reference/),
[Policy YAML reference](/reference/policy-yaml-reference/).
