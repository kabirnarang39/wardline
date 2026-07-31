---
title: "Auto-Generated Sandbox Policy"
weight: 65
summary: "Infer a starter policy.yaml from observed audit traffic."
---

A CLI command that reads the audit trail over a time range and writes a
starter policy file allow-listing exactly what it saw succeed, denying
everything else:

```bash
./wardline infer-policy --config wardline.yaml \
  --from 2026-07-24T00:00:00Z --to 2026-07-31T00:00:00Z \
  --output policy.generated.yaml
```

`--from`/`--to` must be RFC3339 timestamps (`--from` is required, `--to`
defaults to now); `--output` defaults to `./policy.generated.yaml`. It
refuses to overwrite an existing file at that path (or to follow a
dangling symlink there), the same convention `policy-pack install` uses.

## What gets learned

Only audit entries whose `decision` is `allow` or `passthrough` — traffic
that actually reached upstream — feed the generated rules. Entries
recorded as `deny`, `throttled`, `blocked`, or `error` are excluded on
purpose: a call that didn't succeed shouldn't be allow-listed just
because it was attempted, or the generated policy would grant more than
was ever actually observed.

The output is one `allow` rule per distinct `(tenant, identity, tool)`
combination seen, sorted for a stable diff across reruns over the same
data, with `default: deny`. It's the exact schema `policy.yaml` already
uses — load it as-is with `policy_backend: yaml` (the default), no
conversion step.

## This is a starting point, not an authority

`infer-policy` never writes to your live policy file, never runs
continuously, and can't tell "traffic you meant to allow" from "traffic
that happened to occur" — it only knows what was recorded. Review every
generated rule before adopting it: run it for a representative window,
generate the file, read it, edit it, *then* point `policy_file` at it.

**Requires a queryable audit trail**, the same requirement
`export-evidence` has: `audit.output: stdout` has nothing to read back —
point `audit.output` at a file, or turn on `features.postgres_storage`.

## Known limitations

- No live/continuous mode — every run is a one-shot, point-in-time
  inference over a range you choose; there is no "keep learning and
  auto-widen the policy" mode, deliberately: doing that from live traffic
  is a privilege-escalation vector if a compromised identity's traffic is
  what gets learned.
- Tool-level granularity only — a rule allows exactly the tool names
  observed; it never infers a `"*"` wildcard rule, and it does not look
  at `Params`/tool arguments at all (the same fields `policy.domain.Context`
  exposes to richer engines like OPA/Cedar go unused here).
- No de-duplication across near-identical tenants or identity naming
  conventions — if the same human used two differently-spelled identity
  strings, they get two separate rules, not one merged rule.
