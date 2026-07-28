---
title: "Helm Chart"
weight: 20
---

```bash
helm install wardline ./charts/wardline -f my-values.yaml
```

`values.yaml`'s `wardline:` block mirrors most of
`internal/platform/config.Config`'s YAML shape — but not every field:
`rbac.config_file` and every `anomaly.*` field have no Helm value yet
(set them via a mounted/overridden config file instead — see
[Config reference](/reference/config-reference/)). Key values:

| Value | Purpose |
|---|---|
| `replicaCount` | Number of replicas — see [High Availability](/deployment/high-availability/) before setting above 1. |
| `image.repository` / `image.tag` | Your own pushed image (see [Docker](/deployment/docker/)) — no published image exists yet. |
| `service.type` / `service.port` | Kubernetes Service in front of the proxy. |
| `containerPort` | The port `wardline` actually binds inside the container. |
| `wardline.upstream` | Same as `upstream` in `wardline.yaml`. |
| `wardline.policyBackend` | Same as `policy_backend`. |
| `wardline.shutdownDelaySeconds` | Same as `shutdown_delay_seconds` — see [High Availability](/deployment/high-availability/). |
| `wardline.credentialSigningKeyFile` / `wardline.credentialIdentitiesFile` | Same as `credential.signing_key_file` / `credential.identities_file` — mount the actual files via `extraVolumes`/`extraVolumeMounts` below. |
| `wardline.audit` / `wardline.budget` / `wardline.tracing` | Same as the `audit:` / `budget:` / `tracing:` blocks. |
| `extraVolumes` / `extraVolumeMounts` | Passed through verbatim to the pod spec and container — the supported way to mount a signing-key Secret or an identities file. |
| `terminationGracePeriodSeconds` | Kubernetes grace period before SIGKILL — see [High Availability](/deployment/high-availability/) for how this relates to `shutdownDelaySeconds`. |
| `podDisruptionBudget.minAvailable` | Only takes effect at `replicaCount > 1`. |
| `podAntiAffinity.enabled` | Soft anti-affinity spreading replicas across nodes, only applied at `replicaCount > 1`. |
