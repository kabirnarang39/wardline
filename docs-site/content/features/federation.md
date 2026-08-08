---
title: "Federation"
weight: 52
summary: "Cross-instance anomaly correlation: peers exchange signed, pseudonymized summaries and raise an alert when the same fingerprint is seen by multiple instances."
---

Federation lets multiple Wardline instances correlate their
[anomaly detection](/features/anomaly-detection/) signals. Each instance
publishes signed, pseudonymized summaries of the anomalies it sees to its
configured peers; a `Correlator` raises a cross-instance alert once the
same fingerprint is reported by enough distinct instances. It never shares
raw identities or audit content — only pseudonymized fingerprints.

Enable it (requires `anomaly_detection` also on):

```yaml
features:
  anomaly_detection: true
  federation: true
federation:
  instance_id: "eu-cluster-1"          # defaults to os.Hostname()
  peers_file: "./peers.yaml"
  signing_key_file: "./federation-signing-key.pem"
  shared_secret_file: "./federation-shared-secret"
  publish_interval_seconds: 60
  min_instances_for_correlation: 2     # must be >= 2
  correlation_window_seconds: 300
  gc_interval_seconds: 600
```

Generate the signing key with `wardline generate-signing-key`. The
`peers_file` lists each peer's `id`, `endpoint`
(`http://<host>/federation/summaries`), and `public_key_file`:

```yaml
peers:
  - id: us-cluster-1
    endpoint: http://wardline-us:8080/federation/summaries
    public_key_file: ./peers/us-cluster-1.pub.pem
```

## How it works

- Every `publish_interval_seconds`, an instance `POST`s a summary of its
  recent anomalies to each peer's `/federation/summaries` endpoint.
- Each summary is signed (RSA-PSS/SHA-256) with the sender's
  `signing_key_file`; a receiver verifies it against that peer's
  `public_key_file` and rejects anything unsigned, wrongly signed, or from
  an unknown peer.
- Fingerprints are pseudonymized with an HMAC keyed on the
  `shared_secret_file`, which must be **byte-identical** across all peers.
  Identical inputs on different instances hash to the same fingerprint —
  that's what lets a fingerprint be matched across instances — while the
  underlying identity and audit content never leave the instance that saw
  them.
- The `Correlator` raises an alert once a fingerprint has been reported by
  at least `min_instances_for_correlation` distinct instances within
  `correlation_window_seconds`. The alert is surfaced in the logs and at
  `GET /dashboard/api/federation/correlated` (and the dashboard's
  Federation view when `web_ui` is on).

## Known limitations

- **The correlated-alerts view is instance-scoped, not tenant-scoped** —
  it reflects fingerprints this instance has correlated, not a
  per-tenant slice (see [RBAC](/features/rbac/)'s known limitations).
- **`shared_secret_file` must be distributed out of band** — Wardline does
  not negotiate or rotate it; treat it like any other shared secret.
- **`min_instances_for_correlation` must be ≥ 2** — a value of 1 would
  "correlate" a single instance with itself, which is not correlation.
