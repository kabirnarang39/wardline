---
title: "Compliance Evidence Export"
weight: 60
summary: "Point-in-time signed-checksum evidence bundle export."
---

A CLI command that exports a point-in-time evidence bundle (audit
entries, anomaly log, checksums) for a given time range, for compliance
review:

```bash
./wardline export-evidence --config wardline.yaml --from 2026-07-01 --to 2026-07-31 --output evidence.zip
```

## Known limitations

- No cryptographic signing — `checksums.txt` proves the bundle wasn't
  altered after generation, not who generated it. A signed manifest
  (Ed25519 or in-toto/SLSA-style attestation) is future work.
- No live query API or dashboard evidence browser — this is a CLI-driven,
  point-in-time bundle (matching how AWS Audit Manager and OPA's
  decision-log export both work).
- Redacted credential/identity inclusion is out of scope — the correct
  redaction boundary deserves its own design pass.
- No scheduled/automatic export (cron-like periodic job) — manual CLI
  invocation only; automating it is an operator's own cron/CI concern.
- No compression/retention policy for the underlying JSONL files — this
  reads whatever is currently in `audit.output`/`anomaly.output`, it
  does not manage those files' lifecycle.
