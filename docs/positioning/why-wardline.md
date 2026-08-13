# Why Wardline, honestly

No single thing in Wardline is unclaimed territory. This page names that directly instead of pretending otherwise, because every specific claim below was checked against a real, named competitor before it was written down — not assumed.

## What isn't a differentiator, and who already has it

- **Single static Go binary, no database required to start.** [Bifrost](https://github.com/maximhq/bifrost) already does this, as both an LLM gateway and an MCP gateway, with published sub-microsecond gateway overhead at 5,000 req/s. If deployment simplicity and raw speed are the whole ask, Bifrost is a real, shipped answer today.
- **Pluggable policy-engine backends behind one interface.** IBM's `mcp-context-forge` has an open feature request for exactly this (Cedar/OPA/native abstraction), and at least one other project already ships three interchangeable backends. Wardline shipping three (YAML/OPA/Cedar) today is ahead of a request, not ahead of the idea.
- **Traffic-to-policy inference** (`infer-policy`). The technique — mine historical logs into an allow-list — is decades old: `audit2allow` for SELinux, `aa-genprof` for AppArmor, and multiple Kubernetes NetworkPolicy generators all do the same thing for their own domain. Applying it to MCP tool-call traffic specifically isn't something the named MCP gateways ship, but the technique itself isn't new.
- **Taint tracking for prompt-injection-style defense.** Google DeepMind's CaMeL (March 2025) and Microsoft Research's FIDES (May 2025) both do information-flow control for agents, with more rigor than Wardline's session-level boolean tainted/not-tainted flag. Wardline's version tracks *at the proxy*, not inside the agent framework — a real architectural difference, not a research-depth advantage.

## What is a differentiator, checked the same way

Not any one piece. **The combination — assembled coherently, in one self-hosted Apache-2.0 binary — is not something any named competitor does:**

| Capability | Wardline | Bifrost | ToolHive | Portkey | Kong AI Gateway | Auth0/Okta MCP |
|---|---|---|---|---|---|---|
| Single static binary, no DB required | Yes | Yes | No (needs identity provider) | No (SaaS-first) | No (K8s-native) | No (managed service) |
| Proxy-layer taint tracking | Yes | No | No | No | No | No |
| Signed, offline, self-verifying compliance bundle | Yes | No | No | No | No | No |
| Privacy-preserving cross-instance correlation | Yes | No | No | No | No | No |
| Human approval workflow (intent, not just identity) | Yes | No | Partial (via external IdP) | No | No | Partial (via external IdP) |
| Policy content portable across 3 engine backends | Yes | No | No (OIDC-scoped tokens only) | Partial (OPA-compatible) | No (own plugin config) | No |
| Self-hosted, unified operator dashboard | Yes | Partial | Yes (enterprise tier) | No (SaaS) | No (SaaS) | No (SaaS) |

Every "No" above is a checked claim about what that project's own documentation and 2026 coverage says it does, not an assumption that it doesn't — see the research this table is drawn from for sourcing.

## Where the real technical edge is, narrowly

Two places, both already shipped and tested, neither claimed as more than it is:

**`approval_workflow`** is a working instance of intent verification distinct from identity verification — the specific gap 2026 security commentary calls out as unaddressed even after the "identity fix" (RFC 8693 token exchange, MCP's 2026-07-28 spec) closes. Full writeup: [docs/incidents/2026-openai-huggingface.md](../incidents/2026-openai-huggingface.md).

**The incident-replay test** (`cmd/wardline/e2e_incident_replay_test.go`) proves the specific failure chain from a real, named, dated 2026 breach doesn't work against Wardline — not a claim to have solved multi-agent security, a claim to have closed one documented, real failure mode.

## What this page is not

Not a claim that Wardline is faster than Bifrost (it isn't, untested either way — no head-to-head benchmark exists yet). Not a claim that taint tracking here is more rigorous than CaMeL or FIDES (it isn't — theirs is deeper, in-framework research; this is a coarser, proxy-layer signal). Not a claim that federation, compliance export, or policy packs are novel inventions (they're careful assembly of known primitives — HMAC pseudonymization, RSA-PSS signing, `go:embed` templates — not new cryptography or new theory).

The claim is narrower and, we think, more durable: this is the one place that has put proxy-layer taint tracking, signed compliance export, privacy-preserving federation, intent-verified approval, and multi-backend policy portability in the same self-hosted binary. Competitors go deep on one or two of these and stop. If that combination stops being true — if a competitor assembles the same set — this page should be rewritten to say so.
