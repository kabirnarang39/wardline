---
title: "Policy-Pack Marketplace"
weight: 70
summary: "Curated, embedded policy-pack catalog (YAML/OPA/Cedar) with list/show/install/compose and an operator-owned pack directory."
---

A small, trusted catalog of ready-made policy packs embedded in the
binary — common postures like a deny-all baseline or single-identity
full access — installable without hand-writing YAML from scratch:

```bash
./wardline policy-pack list
./wardline policy-pack show <name>
./wardline policy-pack install <name> --output policy.yaml
```

`install` refuses to overwrite an existing file, and warns when the pack
it wrote still contains placeholders (an unreplaced placeholder matches
nothing, so every call falls through to the pack's default deny).

## Backends, versioning, compose, and your own packs

- **Three backends.** Every posture ships in YAML, OPA/Rego, and Cedar
  variants (e.g. `admin-viewer-split`, `admin-viewer-split-opa`,
  `admin-viewer-split-cedar`), so a pack matches whatever
  `policy_backend` a deployment runs.
- **Versioning.** Every pack manifest carries a `version` field, shown in
  `policy-pack list`.
- **Compose.** `policy-pack compose <a> <b> --output policy.yaml` merges
  multiple YAML-backend packs' rules into one file, warning on a
  duplicate `(identity, tool, tenant)` grant rather than silently
  dropping one.
- **Your own catalog.** `-packs-dir <path>` merges an operator-owned
  directory of packs with the embedded catalog across
  `list`/`show`/`install`/`compose` — an org's curated collection, one
  flag away, with zero hosting.

## Known limitations

- **No live, network-fetched registry** (HTTP/OCI-hosted packs,
  third-party contributions). Hosting/publishing/trust infrastructure is
  a business decision outside this project's engineering roadmap;
  `-packs-dir` is the zero-hosting way to get most of that value.
