---
title: "Compliance Evidence Export"
weight: 60
summary: "Point-in-time, checksum-verified, optionally RSA-signed evidence bundle — on demand or on a schedule — plus a live aggregate-counts API."
---

A CLI command that exports a point-in-time evidence bundle (audit
entries, anomaly log, policy snapshot, checksums) for a given time range,
for compliance review:

```bash
./wardline export-evidence --config wardline.yaml \
  --from 2026-07-01T00:00:00Z --to 2026-07-31T00:00:00Z \
  --output evidence.tar.gz
```

`--from`/`--to` must be RFC3339 timestamps; `--output` defaults to
`./evidence-<from>-<to>.tar.gz` if omitted. The bundle is a real
`tar.gz` archive (stdlib `archive/tar` + `compress/gzip`), not a ZIP
file — extract it with `tar xzf`, not `unzip`. It always contains a
`manifest.json`, the audit trail, the anomaly log, a policy snapshot, and
a `checksums.txt` covering every file.

## Signing and verification

Pass `--sign-key` to sign the bundle (RSA-PSS/SHA-256, the same scheme
federation uses); generate a keypair with `wardline generate-signing-key`:

```bash
./wardline generate-signing-key --private-key sign.pem --public-key sign.pub.pem
./wardline export-evidence --config wardline.yaml --from 2026-07-01T00:00:00Z \
  --output evidence.tar.gz --sign-key sign.pem
./wardline verify-evidence --bundle evidence.tar.gz --public-key sign.pub.pem
```

`verify-evidence` recomputes every checksum, rejects a bundle with a
missing, tampered, **or unexpected** file (a closed file-set, not just
"listed files match"), and — with `--public-key` — verifies the
signature. A signed bundle carries `checksums.txt.sig` and
`public_key.pem`.

## Redacted identities

When `credential_issuance` is on, the bundle includes an
`identities.json` listing each identity by **name and tenant only** —
never secrets or SPIFFE IDs.

## Scheduled export

Enable `compliance_scheduled_export` to export a bundle on a fixed
interval using the same code path as the CLI:

```yaml
features:
  compliance_scheduled_export: true
compliance:
  scheduled_export_interval_seconds: 86400
  scheduled_export_output_dir: "./evidence"
  signing_key_file: "./sign.pem"   # optional; unsigned if omitted
```

## Log retention

Enable `log_retention` to purge audit/anomaly entries past a configured
age on a shared cadence:

```yaml
features:
  log_retention: true
audit: { retention_days: 90 }
anomaly: { retention_days: 90 }
retention: { check_interval_seconds: 3600 }
```

## Live aggregate view

`GET /dashboard/api/compliance` (and the dashboard's Compliance view when
`web_ui` is on) returns **aggregate counts only** — entry totals, allow/
deny/anomaly breakdowns — never raw entries, so it is safe to expose more
widely than the raw audit trail.

## Known limitations

- **Signing proves integrity + authenticity, not provenance.** The
  RSA-PSS signature covers the bundle's checksums; it is not a full
  in-toto/SLSA provenance attestation tying the bundle to a build system.
- **The live view is aggregate-only by design** — it never serves raw
  audit entries; the signed bundle is the raw-evidence channel.
