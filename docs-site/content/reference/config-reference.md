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
| `shutdown_delay_seconds` | int | How long a replica keeps serving requests normally after receiving SIGTERM/SIGINT before it begins its own drain sequence. Zero (the default) preserves current shutdown behavior exactly: draining begins the instant the signal arrives. An in-process substitute for a Kubernetes `preStop` hook — see [High Availability](/deployment/high-availability/). |
| `features` | map[string]bool | Feature flags — see each feature's own page. |

## `audit`

| Field | Type | Purpose |
|---|---|---|
| `output` | string | `stdout` or a file path. |
| `postgres_dsn` | string | Only used when `features.postgres_storage` is true. |

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
