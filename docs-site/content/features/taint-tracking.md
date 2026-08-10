---
title: "Taint Tracking"
weight: 55
summary: "Taint a session after it reads from an untrusted source, so a policy can gate the write that follows."
---

Prompt injection that keeps a client perfectly in-profile — normal-looking
reads whose *content* steers the next call — is invisible to statistical
[anomaly detection]({{< relref "anomaly-detection" >}}): a z-score catches a
compromised client, not compromised content. Taint tracking attacks that gap
at the policy layer instead of statistically.

When an identity calls a tool you've marked untrusted (a web fetch, a scraper,
anything that pulls attacker-influenceable text into the agent's context),
Wardline sets a single integrity taint label on that identity's session. The
label is exposed to policy as `input.tainted`, so a rule can deny — or, later,
route to approval — the write that follows a tainted read. Enable with:

```yaml
features:
  taint_tracking: true
taint:
  untrusted_sources:
    - web_fetch
    - http_get
  declassify_sources:
    - human_approve
  ttl_seconds: 300              # taint expires this long after the untrusted read
  session_window_seconds: 300   # fallback session width (see "Sessions" below)
  session_header: "X-Wardline-Session"
```

A matching OPA/Rego policy:

```rego
package wardline.authz

default allow = false

is_write { input.method == "tools/call" }
deny_tainted_write { input.tainted; is_write }

allow {
  input.identity == "agent-abc123"
  not deny_tainted_write
}
```

The taint is set out of band from the live audit stream (the same mechanism
anomaly detection consumes), then read synchronously at decision time as a
cheap store lookup — it never blocks or slows the request path.

## Sessions

The taint key is `(tenant, identity, session)`. The session is the explicit
`X-Wardline-Session` header when the agent framework stamps one per run; absent
a header it falls back to a per-identity sliding TTL window, so Wardline stays
drop-in with zero client cooperation. In fallback mode the taint TTL *is* the
implicit session boundary.

## Label creep is controlled, not deferred

A taint system that only ever *adds* labels eventually marks everything
tainted and the signal dies. Two controls ship in phase 1, not later:

- **TTL** — a label is treated as untainted once `now > set_at + ttl_seconds`,
  applied lazily on read. No background sweep, no permanently-stuck key.
- **Declassification** — a call to any `declassify_sources` tool (e.g. an
  audited human-approval step) clears the label immediately.

## Boundary — what this is and isn't

Be honest about the model:

- This is a **coarse, gateway-level approximation**, not information-flow
  control. It is not [CaMeL](https://arxiv.org/abs/2503.18813) or IFC: there is
  **one boolean taint bit per session**, not per-datum flow tracking. Wardline
  sees requests and responses at the proxy boundary, not values moving through
  the agent's memory.
- It **over-approximates on purpose**: any write after an untrusted read within
  the TTL is treated as potentially influenced, even when it wasn't. That
  trades false positives for not missing the real case — conservative by
  design.
- The default posture is **fail-open**: a session is untainted unless a source
  you configured actually fired. This favors usability and minimizes label
  creep; it is a deliberate trade-off, not an oversight. A tool you forget to
  list as untrusted taints nothing.
- **Per-datum flow tracking (marking individual values untrusted and following
  them through every downstream call) is permanently out of scope** for the
  proxy. It needs visibility into the agent's internals that a gateway does not
  and should not have; that belongs in the agent framework, not here.

Taint tracking is a **last line of defense, not the only one**. It pairs with
[post-condition audit fields]({{< relref "baseline-proxy-policy-audit" >}}): the
z-score layer catches compromised clients, taint + post-condition checks catch
compromised *content*. They fail differently, so you want both.

Credit to **IronAndCoder** for the threat-model framing that motivated this.
