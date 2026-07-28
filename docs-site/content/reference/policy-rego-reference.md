---
title: "Policy Rego Reference"
weight: 40
---

Policies must declare `package wardline.authz` and export an `allow`
boolean (and optionally a `reason` string):

```rego
package wardline.authz

default allow = false

allow {
    input.identity == "agent-abc123"
    input.tool == "read_file"
}
```

`input` is the full request context — see
[Policy Backends](/concepts/policy-backends/) for the exact JSON shape.
