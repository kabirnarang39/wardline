---
title: "Web Dashboard"
weight: 55
summary: "The in-browser Overview/Activity/Anomalies/Blocked/Federation/Credentials/Policy/Status view."
---

An in-browser, largely read-only view of what Wardline is doing right
now. Off by default — enable with:

```yaml
features:
  web_ui: true
```

Then visit `http://<listen-addr>/dashboard/`. Eight views, reached from
the sidebar in this order: **Overview, Activity, Anomalies, Blocked,
Federation, Credentials, Policy, Status**. Live views poll every 2
seconds; Policy and Status are loaded once and reflect state as of
startup / the last poll respectively.

## Overview

The first view you land on, deliberately: a single status band answers
"is anything wrong right now" before you look at anything else. The
band's state is derived client-side, on every poll tick, from the same
data Blocked and Anomalies already show — checked in this fixed order,
**a real block always outranks a real anomaly**:

1. **`action-needed`** (red) — at least one identity is currently under
   an active `anomaly.auto_block`.
2. **`attention`** (amber) — no active blocks, but at least one recorded
   anomaly exists.
3. **`nominal`** (green, "All systems nominal") — neither.

This ordering is intentional, not incidental: a block is Wardline
already having taken automated action against real traffic, which is a
strictly more urgent signal than an anomaly that was merely logged. A
tenant with 500 logged anomalies and zero active blocks still shows
amber, not red — volume of anomalies never escalates the band on its
own, only the presence of an active block does.

Below the band: a KPI row (request count, deny rate, anomaly count,
blocked count — all computed from the exact same buffers the Activity /
Anomalies / Blocked views themselves poll, so nothing here can drift out
of sync with what those views show), a recent-activity bar chart, a
"needs review" summary with a CTA that jumps straight to Anomalies, and
a live pulse (requests/sec over the trailing 10 seconds, with a
pause/resume toggle).

**Chart caveat:** without `features.postgres_storage`, the recent-activity
chart buckets **the last N buffered audit events only** — the same
bounded, in-memory, resets-on-restart ring buffer (default capacity
1000) that the Activity view itself polls, not a query over the durable
audit trail (`audit.output`'s JSONL file). On a busy instance that
cycles through the buffer in minutes, the chart shows *recent* activity,
not a full historical view — do not read it as "today's total traffic"
once request volume exceeds the buffer's capacity. **With
`features.postgres_storage` on, this caveat no longer applies**: the
Activity view and this chart both read from the same durable,
cluster-wide `audit_entries` table every replica writes into (see
`PostgresWriter.Since`) — not a fixed-N in-memory window, and not
per-replica. The chart's own subtitle states however many events the
current poll actually returned, so it reads correctly either way;
this is that caveat's source of truth, not a display bug.

Overview polls at the same 2-second cadence as every other live view,
but nothing on it animates on a routine poll tick — only a genuine state
*transition* (the status band flipping from one severity to another)
triggers motion, and that transition respects
`prefers-reduced-motion` like every other animated element in this
dashboard.

## Activity, Anomalies, Federation

Live-updating tables over the same after-ID polling pattern. Activity
and Anomalies are described in [Anomaly detection](/features/anomaly-detection/);
Federation is empty by design on a single-instance deployment (no peers
to correlate with) and 404s on its API when `features.federation` is
off, same as every other feature-gated dashboard route.

## Blocked

A live-updating table of identities currently under a time-bounded
`anomaly.auto_block` — identity, tenant, reason, and expiry. Each row
carries an **Unblock** button that clears the block early (`DELETE
/dashboard/api/anomalies/blocked/{identity}`), after a confirm prompt.
This is one of the dashboard's only two mutations (see Credentials
below for the other) — see "Auth requirement for mutations" below for
exactly who can press it successfully.

## Credentials

**Revoke only — deliberately not symmetric with issuance or refresh.**
`POST /credentials/revoke` is the one action here: enter an identity,
confirm, and every outstanding and future-until-expiry access token
plus any outstanding refresh token for that identity is invalidated
immediately.

**Why revoke-only:** `/credentials/refresh` performs machine-to-machine
token rotation on a caller-supplied `refresh_token` value — a dashboard
operator has no legitimate reason to hold or exercise *another*
identity's refresh token from a browser UI, so this view never exposes
that path at all. There is no issuance UI either: bootstrapping a new
credential requires that identity's own registration secret (see
[Credential issuance](/features/credential-issuance/)), which is not
something that belongs behind an operator-facing screen reachable by
anyone who can load the dashboard. Revocation is the one genuinely
admin-shaped action left — undoing a credential's standing, not
minting or renewing one — so it is the one this view ships.

### Auth requirement for mutations (Blocked's Unblock, Credentials' Revoke) — read this before assuming a 403 is a bug

Both mutations are gated more strictly than the rest of the dashboard,
and by two *different* mechanisms depending on which button you press:

- **Credentials' Revoke** reuses `/credentials/revoke`'s own existing
  gate, unchanged by this view's existence: allowed unconditionally from
  a loopback caller (`127.0.0.1`/`::1`); from anywhere else, only when
  `features.rbac` is on **and** the resolved caller holds
  `credential:revoke` (the built-in `admin` role, or a custom role
  naming that permission — see [RBAC](/features/rbac/)). A caller
  holding only `dashboard:view` (e.g. the built-in `viewer` role) loads
  the rest of the dashboard fine and gets a clean `403` here — that is
  correct, not a bug, and the view surfaces a specific "You don't have
  permission to revoke credentials." message for exactly that case
  rather than a generic error.
- **Blocked's Unblock** has no loopback exception at all — it is gated
  purely by the same `credential:revoke` permission, checked separately
  from the `dashboard:view` permission the rest of the Blocked view
  relies on to render at all. A caller who can see the Blocked table
  (holds `dashboard:view`) but lacks `credential:revoke` gets a clean
  `403` clicking Unblock, same posture as Credentials' Revoke.

**A sharp edge worth knowing before you rely on either button:**
neither button's own client-side code attaches a credential of its
own — both rely entirely on whatever the browser sends automatically
with every same-origin request. That is sufficient in two common cases:
you're loopback (nothing to attach — the loopback exception on
`/credentials/revoke` needs no identity at all; Blocked's Unblock still
needs a resolvable identity, but a loopback operator typically already
has one via whichever `IdentityAuthenticator` is active), or identity is
resolved from a raw `X-Wardline-Identity` header that a trusted
intermediary (reverse proxy, mesh sidecar) injects on your behalf before
traffic reaches Wardline — browsers don't send that header themselves,
but an intermediary that does makes every request the browser makes
already carry it, including these two.

When `features.credential_issuance` is on, identity is a bearer token
(`Authorization: Bearer <jwt>`), and a plain browser tab has no
built-in mechanism to attach that header to its own requests the way it
automatically attaches cookies. **`GET /dashboard/login` closes this
gap**: a browser-native sign-in form (paste the same bootstrap secret
or OIDC ID token `POST /credentials/token` accepts) that exchanges it
for the exact same access token through the exact same
`IssuanceService.Bootstrap` path, then delivers it as an httpOnly,
`SameSite=Strict` session cookie (`POST /dashboard/login`) instead of a
JSON body — the browser then sends that cookie automatically on every
subsequent request, including these two buttons, the rest of
`/dashboard/`, and (once `features.rbac` is also on)
`rbacadapter.RequirePermission`'s own identity resolution, since all of
these already went through the same `IdentityAuthenticator` that now
checks the cookie as a fallback whenever no `Authorization` header is
present. `POST /dashboard/logout` clears it. Session lifetime is
exactly `credential.access_token_ttl_seconds` (default 15m) — there is
no refresh-token cookie or silent renewal yet, so re-login when it
expires; see "Known limitations" below.

## Policy, Status

Policy shows the active policy backend and raw policy file content as
currently loaded. With `features.config_file_watch` on, an edit to the
policy file on disk applies automatically (see "Known limitations"
below); otherwise trigger `POST /dashboard/api/reload/policy` (gated by
`config:edit` when `rbac` is on) or restart Wardline to refresh it.
Status shows version, uptime, listen/upstream addresses, and which
feature flags are on.

## Security note

The dashboard requires no authentication and every non-mutating route
is read-only **by default** (unless `features.rbac` is on — see
[RBAC](/features/rbac/); with it on, every dashboard request must
resolve an identity holding `dashboard:view`, else `403`). The two
exceptions are Blocked's Unblock and Credentials' Revoke, above — each
is a real, security-relevant mutation, and each is independently gated
by `credential:revoke` rather than the weaker `dashboard:view` a plain
reader might hold. Neither can influence policy evaluation, budget
accounting, or how a proxied call is decided going forward except
through that one narrow, audited, explicitly-permissioned action. The
dashboard shares the exact same listener/port as the proxy itself, so
anyone who can reach Wardline's proxy port — including every agent
Wardline proxies calls for — can already read full audit reasons and
raw policy source over that identical socket; binding to `localhost`
does not change this. This is why `web_ui` defaults to off.

## Known limitations

- Without `features.postgres_storage`, the recent-activity chart on
  Overview reflects the bounded audit ring buffer, not the durable
  audit trail — see the chart caveat above. With `postgres_storage` on,
  it reads the same durable, cluster-wide table the Activity view does.
- **`GET`/`POST /dashboard/login` and `POST /dashboard/logout` now
  deliver a bearer token to the browser** (`features.credential_issuance`
  on) — see "Auth requirement for mutations" above. Session lifetime is
  exactly the access token's own TTL (`credential.access_token_ttl_seconds`,
  default 15m): no refresh-token cookie or silent renewal yet, so an
  expired session requires signing in again through `/dashboard/login`,
  not a transparent background refresh — a deliberately bounded scope
  for this cycle (a real, separate feature: rotating a refresh-token
  cookie plus an auto-refresh flow), not silently incomplete.
- Federation's correlated-alerts view is now tenant-scoped like every
  other dashboard view (see [Federation](/features/federation/)'s known
  limitations for what's still instance-scoped: each Wardline instance
  shows its own `Correlator`'s state, not a fleet-wide merged view).
- **Policy, budget, and RBAC changes auto-apply on file edit when
  `features.config_file_watch` is on** — an `fsnotify` watcher on the
  main config file plus `policy_file`/`rbac.config_file` calls the same
  reload closures `POST /dashboard/api/reload/{domain}` does,
  debounced (300ms) so one logical save doesn't trigger several
  reloads, and robust to an atomic replace-by-rename save (vim and
  most editors' default) — it watches the enclosing directory, not the
  file's own inode, which a rename-over-original save would otherwise
  orphan. Off by default (a new capability beyond the v0.1 baseline);
  without it, trigger a reload manually with `POST
  /dashboard/api/reload/{domain}` (gated by the `config:edit`
  permission when `rbac` is on) after editing, or restart Wardline.
