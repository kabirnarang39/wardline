---
title: "Config Reference"
weight: 20
---

Every field in `wardline.yaml`, grouped by section. `Config` maps 1:1 to
this shape (`internal/platform/config/config.go`).

## Top level

| Field | Type | Purpose |
|---|---|---|
| `listen` | string | Address Wardline binds to, e.g. `0.0.0.0:8080`. |
| `upstream` | string | Upstream MCP server URL. |
| `policy_file` | string | Path to the policy file. |
| `policy_backend` | string | `yaml` (default), `opa`, or `cedar`. |
| `grpc_listen` | string | `host:port` for the gRPC listener — required when `features.grpc_transport` is true. See [gRPC Transport](/features/grpc-transport/). |
| `grpc_upstream` | string | Upstream gRPC target (`host:port`, plaintext) — required when `features.grpc_transport` is true. |
| `shutdown_delay_seconds` | int | How long a replica keeps serving requests normally after receiving SIGTERM/SIGINT before it begins its own drain sequence. Zero (the default) preserves current shutdown behavior exactly: draining begins the instant the signal arrives. An in-process substitute for a Kubernetes `preStop` hook — see [High Availability](/deployment/high-availability/). |
| `features` | map[string]bool | Feature flags — see each feature's own page. |

## `audit`

| Field | Type | Purpose |
|---|---|---|
| `output` | string | `stdout` or a file path. |
| `postgres_dsn` | string | Only used when `features.postgres_storage` is true. |
| `retention_days` | int | Age past which audit entries are purged by the retention job. Only meaningful when `features.log_retention` is true; see [`retention`](#retention). |

## `budget`

| Field | Type | Purpose |
|---|---|---|
| `requests_per_window` | int | See [Budget Enforcement](/features/budget-enforcement/). |
| `window_seconds` | int | Window length in seconds. |

## `tracing`

| Field | Type | Purpose |
|---|---|---|
| `otlp_endpoint` | string | `host:port`, no scheme. |
| `service_name` | string | Defaults to `"wardline"`. |

## `credential`

| Field | Type | Purpose |
|---|---|---|
| `identities_file` | string | Path to the identities file. |
| `signing_key_file` | string | Optional PEM RSA key path — see [HA Deployment](/deployment/high-availability/). |

## `rbac`

| Field | Type | Purpose |
|---|---|---|
| `config_file` | string | Path to the roles/bindings file. |

## `anomaly`

| Field | Type | Purpose |
|---|---|---|
| `output` | string | Anomaly log output. |
| `buffer_capacity` | int | Ring buffer size. |
| `gc_interval_seconds` | int | State garbage-collection interval. |
| `window_seconds` | int | Detection window. |
| `rate_spike.enabled` / `.rate_multiplier` / `.min_calls` | bool/float/int | Rate-spike heuristic. |
| `novel_tool.enabled` | bool | Novel-tool heuristic. |
| `deny_rate_spike.enabled` / `.threshold` / `.min_calls` | bool/float/int | Deny-rate-spike heuristic. |
| `ml_score.enabled` / `.score_threshold` / `.min_calls` | bool/float/int | Combined z-score heuristic (`min_calls` must be ≥ 2). See [Anomaly Detection](/features/anomaly-detection/). |
| `auto_block.enabled` / `.score_threshold` / `.block_duration_seconds` | bool/float/int | Rejects a flagged identity's calls for a bounded TTL. Requires `ml_score.enabled`. |
| `drift_detection.enabled` / `.k` / `.h` / `.min_calls` | bool/float/float/int | CUSUM control chart over `call_rate` and `tool_diversity`, catching sustained drift a per-window z-score test misses. `k`/`h` are in units of the scored feature's own baseline standard deviation (Montgomery's SPC defaults: `k: 0.5`, `h: 4.0`–`5.0`). Requires `ml_score.enabled`. See [Anomaly Detection](/features/anomaly-detection/)'s "Drift detection" section. |
| `drift_detection.h_jitter_fraction` / `.jitter_secret_file` | float/string | Optional moving-target defense: perturbs each identity's own effective `h` by up to this fraction, keyed by HMAC-SHA256 of a per-deployment secret (`jitter_secret_file`, required whenever the fraction is > 0). Raises the cost of an attack calibrated to the public default `h` — does not defeat an adaptive attacker who can probe the live system repeatedly. See "Adversarial scenarios" in the same doc. |
| `tenant_anomaly.enabled` / `.rate_multiplier` / `.min_calls` | bool/float/int | Detects a coordinated call-volume spike aggregated across every identity in a tenant — closes the gap no per-identity heuristic can (see "Adversarial scenarios"). Logs only, never auto-blocks: there is no single identity to block for a tenant-level signal. HA-safe when `features.postgres_storage` is also on: window totals merge atomically across replicas; falls back to per-replica, in-memory-only aggregation otherwise. |
| `retention_days` | int | Age past which anomaly-log entries are purged. Only meaningful when `features.log_retention` is true. |

## `scim`

| Field | Type | Purpose |
|---|---|---|
| `bearer_token_env` | string | Env var holding the SCIM bearer token (never inline) — required when `features.scim` is true. See [SCIM](/features/scim/). |
| `persist_postgres` | bool | Persist provisioned group→member bindings in Postgres (requires `features.postgres_storage`). Default in-memory. |

## `federation`

Only meaningful when `features.federation` is true (which itself requires `features.anomaly_detection`). See [Federation](/features/federation/).

| Field | Type | Purpose |
|---|---|---|
| `instance_id` | string | Unique instance identifier. Defaults to `os.Hostname()` — set explicitly when co-locating instances. |
| `peers_file` | string | Path to the peers file (`id`, `endpoint`, `public_key_file` per peer) — required. |
| `signing_key_file` | string | PEM RSA private key this instance signs its summaries with — required. |
| `shared_secret_file` | string | Shared secret (byte-identical across peers) for pseudonymizing fingerprints — required. |
| `publish_interval_seconds` | int | How often signed anomaly summaries are published to peers. |
| `min_instances_for_correlation` | int | Distinct instances that must see a fingerprint before an alert (must be ≥ 2). |
| `correlation_window_seconds` | int | Window over which fingerprints from peers are correlated. |
| `gc_interval_seconds` | int | Stale correlation-state eviction interval. |

## `compliance`

Only meaningful when `features.compliance_scheduled_export` is true. See [Compliance Evidence Export](/features/compliance-evidence-export/).

| Field | Type | Purpose |
|---|---|---|
| `scheduled_export_interval_seconds` | int | How often a scheduled evidence bundle is exported. |
| `scheduled_export_output_dir` | string | Directory each tick's bundle is written to — required when the flag is on. |
| `signing_key_file` | string | Optional PEM RSA private key to sign each scheduled bundle. `""` (default) produces unsigned bundles. |

## `retention`

Only meaningful when `features.log_retention` is true. A single shared cadence for both the audit and anomaly retention checks (whichever of `audit.retention_days` / `anomaly.retention_days` is non-zero).

| Field | Type | Purpose |
|---|---|---|
| `check_interval_seconds` | int | How often the retention purge job runs. |
