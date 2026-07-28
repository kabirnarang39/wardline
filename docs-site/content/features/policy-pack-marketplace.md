---
title: "Policy-Pack Marketplace"
weight: 70
summary: "Curated, embedded policy pack catalog with install/list/show."
---

A small, trusted catalog of ready-made policy packs embedded in the
binary — common postures like a deny-all baseline or single-identity
full access — installable without hand-writing YAML from scratch:

```bash
./wardline policy-pack list
./wardline policy-pack show <name>
./wardline policy-pack install <name> --output policy.yaml
```

## Known limitations

- YAML-backend packs only this cycle — Rego/Cedar equivalents of the
  same postures are a natural, low-risk follow-on, not shipped yet.
- No live, network-fetched registry (HTTP/OCI-hosted packs, third-party
  contributions) — this cycle proves the format/UX with a small catalog
  Wardline itself owns and ships.
- No pack versioning/upgrade tooling — with packs shipped inside the
  binary, "upgrade" today means "upgrade Wardline."
- No merging/composing multiple packs into one policy file — `install`
  writes one pack's policy file verbatim; combining packs is left to
  the operator hand-editing the installed file.
