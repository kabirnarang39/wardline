---
title: "CLI Reference"
weight: 10
---

All subcommands: `./wardline <command> [flags]`.

| Command | Purpose |
|---|---|
| `serve --config <file>` | Start the proxy. |
| `validate-config --config <file>` | Validate a config file (and every optional feature's config, e.g. `credential.signing_key_file` parses as a valid key when set) without starting the proxy. |
| `validate-policy --file <file> [--backend yaml\|opa\|cedar]` | Validate a policy file against the given backend's syntax. |
| `export-evidence --config <file> --from <date> [--to <date>] [--output <path>]` | Export a compliance evidence bundle (see [Compliance Evidence Export](/features/compliance-evidence-export/)). `--from` (RFC3339) is required; `--to` defaults to now; `--output` defaults to `./evidence-<from>-<to>.tar.gz`. |
| `policy-pack list` | List the embedded policy-pack catalog. |
| `policy-pack show <name>` | Print a pack's policy content. |
| `policy-pack install <name> --output <path>` | Write a pack's policy file to `<path>`. |
