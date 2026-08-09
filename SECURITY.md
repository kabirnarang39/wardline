# Security Policy

Wardline is a security control-plane proxy — vulnerabilities in it can affect
every agent call it mediates. Reports are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability
reporting](https://github.com/kabirnarang39/wardline/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab).

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal config / policy / request that triggers it).
- The Wardline version or commit affected.

## What to expect

- Acknowledgement of your report as soon as it is triaged.
- An assessment of severity and affected versions.
- A fix and coordinated disclosure once a patch is available.

## Scope

In scope: the `wardline` binary and everything under `internal/` and
`cmd/` — policy evaluation, budget enforcement, anomaly detection /
auto-block, credential issuance, audit integrity, RBAC/SCIM/SSO, and the
web dashboard's authorization checks.

Out of scope: vulnerabilities in third-party upstreams Wardline proxies to,
and misconfigurations of an operator's own deployment (e.g. running without
TLS, or an over-permissive policy). Reports that a permissive policy allows
what it was written to allow are working-as-configured, not vulnerabilities.

## Supported versions

Wardline is pre-1.0-stable and under active development; security fixes land
on `main` and the latest tagged release. Pin a specific commit or tag for
reproducible deployments.
