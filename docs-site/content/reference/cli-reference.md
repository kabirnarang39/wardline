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
| `export-evidence --config <file> --from <date> [--to <date>] [--output <path>] [--sign-key <path>]` | Export a compliance evidence bundle (see [Compliance Evidence Export](/features/compliance-evidence-export/)). `--from` (RFC3339) is required; `--to` defaults to now; `--output` defaults to `./evidence-<from>-<to>.tar.gz`. `--sign-key` (PEM RSA private key, PKCS1 or PKCS8) additionally signs the bundle. |
| `verify-evidence --bundle <file> [--public-key <path>]` | Verify an evidence bundle. Recomputes every checksum and rejects a bundle with an unexpected or tampered file; with `--public-key` (PEM RSA public key) it also verifies the bundle's signature. |
| `generate-signing-key [--private-key <path>] [--public-key <path>]` | Generate an RSA keypair for signing evidence bundles. Defaults: `--private-key ./signing-key.pem`, `--public-key ./signing-key.pub.pem`. |
| `infer-policy --config <file> --from <date> [--to <date>] [--output <path>]` | Infer a starter policy from observed audit traffic (see [Auto-Generated Sandbox Policy](/features/auto-generated-policy/)). `--from` (RFC3339) is required; `--to` defaults to now; `--output` defaults to `./policy.generated.yaml`. |
| `policy-pack list` | List the embedded policy-pack catalog. |
| `policy-pack show <name>` | Print a pack's policy content. |
| `policy-pack install <name> --output <path>` | Write a pack's policy file to `<path>`. |
