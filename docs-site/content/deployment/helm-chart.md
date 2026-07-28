---
title: "Helm Chart"
weight: 20
---

```bash
helm install wardline ./charts/wardline -f my-values.yaml
```

`values.yaml`'s `wardline:` block mirrors
`internal/platform/config.Config`'s YAML shape exactly — every field
documented in [Config reference](/reference/config-reference/) has a
corresponding `wardline.<field>` Helm value. Key values:

| Value | Purpose |
|---|---|
| `replicaCount` | Number of replicas — see [High Availability](/deployment/high-availability/) before setting above 1. |
| `image.repository` / `image.tag` | Your own pushed image (see [Docker](/deployment/docker/)) — no published image exists yet. |
| `service.type` / `service.port` | Kubernetes Service in front of the proxy. |
| `containerPort` | The port `wardline` actually binds inside the container. |
| `wardline.upstream` | Same as `upstream` in `wardline.yaml`. |
| `wardline.policyBackend` | Same as `policy_backend`. |
