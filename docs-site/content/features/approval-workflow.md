---
title: "Approval Workflow"
weight: 56
summary: "A third policy outcome between allow and deny: hold a write for a human, then let one approved retry through."
---

Some writes shouldn't be a flat allow or deny — they should wait for a human.
The canonical case is [taint tracking]({{< relref "taint-tracking" >}}): a
write that follows an untrusted read is exactly the shape a semantic
(content-driven) attack produces, and a hard deny is often too blunt — the
write might be legitimate, just unverifiable by the proxy alone. Approval
workflow adds `needs_approval` as a third policy outcome, backed by an
approve-and-retry queue an operator drives from the CLI/API or the
dashboard.

Enable with:

```yaml
features:
  approval_workflow: true
approval:
  grant_ttl_seconds: 300   # how long an approval stays valid for the retry
```

A Rego policy opts into it by returning `approval: true` alongside `allow`
(see the [Rego reference]({{< relref "policy-rego-reference" >}}) for the
full result contract and precedence rules) — pairing naturally with
`input.tainted`:

```rego
package wardline.authz

default allow = false

is_write { input.method == "tools/call" }

approval {
  input.tainted
  is_write
}

allow {
  input.identity == "agent-abc123"
}
```

## The flow

1. A call the policy marks `needs_approval` is **not forwarded upstream**.
   Wardline enqueues a pending request and responds `202 Accepted` with a
   pending id — the caller must retry, not wait on an open connection. No
   held connections, no new async infrastructure: this is why it's
   approve-and-**retry**, not approve-and-continue.
2. An operator lists pending requests and approves or denies:
   ```
   GET  /approvals/pending
   POST /approvals/{id}/approve
   POST /approvals/{id}/deny
   ```
   Loopback-only by default, same posture as `/credentials/revoke`. The
   dashboard (when `web_ui` is also on) shows the same queue with
   Approve/Deny buttons.
3. Approval mints a **single-use, TTL-bounded grant** for that exact
   `(tenant, identity, session, tool)`. The client's retry consumes the grant
   and forwards upstream — the audit entry for that call is marked
   `"approved via grant (pending id consumed)"` so an operator can tell a
   pre-approved write from an ordinary allow. A *second* retry finds no
   grant left and re-enqueues: **one approval authorizes exactly one write.**

## Fail-closed by default

If a policy returns `needs_approval` but `approval_workflow` is off, the call
is **denied**, never allowed — a policy author can't accidentally get a soft
outcome silently upgraded to a hard pass just because an operator forgot to
flip the flag. Turning the feature on only ever adds a path forward for a
call that would otherwise be a flat deny; it never weakens anything already
enforced.

## Boundary

Approval workflow is the human-in-the-loop half of the taint story: taint
tracking flags a session as suspect, approval workflow is what you *do* about
it instead of a flat deny. It doesn't replace [post-condition audit
fields]({{< relref "baseline-proxy-policy-audit" >}}) — an approved write can
still silently no-op upstream, which is exactly what that feature's claimed-vs-
actual signal is for.
