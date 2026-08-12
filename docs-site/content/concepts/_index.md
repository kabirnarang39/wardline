---
title: "Concepts"
---

## The five words you'll see on every page

- **Identity** — the name of whoever (or whatever) is making the request.
  For a human that's a login; for an AI agent it's usually a short
  string like `agent-abc123`, proven with a token instead of a password.
- **Policy** — the rule book. A list of "this identity can/can't do this
  specific thing." Wardline checks every request against it.
- **Budget** — a counter with a limit, like a monthly data cap. Once an
  identity uses up its allowance, further requests get turned away until
  the counter resets.
- **Audit** — the receipt. Every decision Wardline makes, allowed or
  denied, gets written down with who/what/when — so nothing happens that
  can't be looked up later.
- **MCP** — Model Context Protocol, the common language AI agents use to
  call external tools. Wardline understands it, but also works with
  plain HTTP and gRPC — MCP is the main case, not the only one.

With those five in hand, the rest of this section is the mental model
behind Wardline: how it's built, how identity and policy decisions work,
which policy backend to pick, and where the audit trail goes. Read this
once — every feature page after this assumes it.
