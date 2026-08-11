// Thin fetch wrappers for the dashboard's read-only JSON API.

export async function fetchAudit(afterID, limit) {
  const url = `api/audit?after=${afterID}&limit=${limit}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`audit fetch failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchAnomalies(afterID, limit) {
  const url = `api/anomalies?after=${afterID}&limit=${limit}`;
  const res = await fetch(url);
  if (!res.ok) {
    const err = new Error(`anomalies fetch failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function fetchPolicy() {
  const res = await fetch('api/policy');
  if (!res.ok) {
    throw new Error(`policy fetch failed: ${res.status}`);
  }
  return res.json();
}

// writePolicy PUTs the Rule editor's edited rules/default to
// /dashboard/api/policy -- "Validate & apply" as one action. Returns
// {ok:true, policy} on success (policy is the fresh, post-write
// PolicyInfo -- no second GET needed) or {ok:false, status, message} on
// a rejected write (400, invalid rules) or an auth/wiring failure (403
// forbidden, 404 not wired), same error-shape convention as
// revokeCredential/unblockIdentity in this file.
export async function writePolicy(rules, def) {
  const res = await fetch('api/policy', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rules, default: def }),
  });
  if (res.status === 200) {
    return { ok: true, policy: await res.json() };
  }
  if (res.status === 403) {
    return { ok: false, status: res.status, message: 'You don’t have permission to edit policy (requires config:edit).' };
  }
  if (res.status === 404) {
    return { ok: false, status: res.status, message: 'Rule editor is not available on this server.' };
  }
  let message = `save failed: ${res.status}`;
  try {
    const body = await res.json();
    if (body && body.error) message = body.error;
  } catch { /* non-JSON error body, keep the generic message */ }
  return { ok: false, status: res.status, message };
}

// writeBudget PUTs the Budget editor's edited default limit and
// tenant/tool overrides to /dashboard/api/budget -- "Validate & apply"
// as one action, same shape/error-handling convention as writePolicy.
export async function writeBudget(def, tenantOverrides, toolOverrides) {
  const res = await fetch('api/budget', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ default: def, tenant_overrides: tenantOverrides, tool_overrides: toolOverrides }),
  });
  if (res.status === 200) {
    return { ok: true, budget: await res.json() };
  }
  if (res.status === 403) {
    return { ok: false, status: res.status, message: 'You don’t have permission to edit budget (requires config:edit).' };
  }
  if (res.status === 404) {
    return { ok: false, status: res.status, message: 'Budget editor is not available on this server.' };
  }
  let message = `save failed: ${res.status}`;
  try {
    const body = await res.json();
    if (body && body.error) message = body.error;
  } catch { /* non-JSON error body, keep the generic message */ }
  return { ok: false, status: res.status, message };
}

// fetchApprovals reads the pending approval queue. Mirrors fetchBlocked:
// a non-ok response throws with err.status set, so pollApprovals can call
// pollerFailed() and stop retrying once a 404 confirms approval_workflow
// is off on this server. Note the endpoint JSON-encodes the raw
// approval/domain.Request (no json tags), so the caller reads capitalized
// fields (ID, Identity, Tenant, Tool, Params, CreatedAt) -- same as the
// Activity view's raw LiveEntry, not the snake_case *Entry wire shapes.
export async function fetchApprovals() {
  const res = await fetch('api/approvals');
  if (!res.ok) {
    const err = new Error(`approvals fetch failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// decideApproval POSTs an approve/deny decision for one pending request.
// Same {ok}/{ok:false,status,message} shape as unblockIdentity: 204 is
// success, 403 (no config:edit), 404 (unknown/already-decided id, or
// feature off), 400 (bad path) all surface as ok:false with a message.
export async function decideApproval(id, action) {
  const res = await fetch(`api/approvals/${encodeURIComponent(id)}/${action}`, { method: 'POST' });
  if (res.status === 204) {
    return { ok: true };
  }
  let message = `${action} failed: ${res.status}`;
  try {
    const body = await res.text();
    if (body) message = body.trim();
  } catch { /* keep the generic message */ }
  return { ok: false, status: res.status, message };
}

// fetchJobBudget reads the read-only job-budget view -- job keys
// nearing/at their per-job ceiling, sorted by count descending. Mirrors
// fetchApprovals: a non-ok response throws with err.status set, so
// pollJobBudget can call pollerFailed() and stop retrying once a 404
// confirms job_budget is off on this server. The endpoint JSON-encodes
// the raw jobbudget/domain.Entry (no json tags), so fields are
// capitalized (e.Key, e.Count) -- same convention as the Approvals view's
// raw approval/domain.Request, not the snake_case dashboard *Entry wire
// shapes. Key is opaque (length-prefixed tenant/identity/session, not
// decomposed for display -- see handler.go's JobBudgetSource doc
// comment), a known, documented limitation.
export async function fetchJobBudget() {
  const res = await fetch('api/job-budget');
  if (!res.ok) {
    const err = new Error(`job-budget fetch failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// fetchCostBudget mirrors fetchJobBudget exactly, for the cost-budget
// view. The endpoint JSON-encodes the raw costbudget/domain.Entry (no
// json tags), so fields are capitalized (e.Key, e.Total) -- Total, not
// Count, is the field name here (job-budget counts requests, cost-budget
// sums cost/token amounts).
export async function fetchCostBudget() {
  const res = await fetch('api/cost-budget');
  if (!res.ok) {
    const err = new Error(`cost-budget fetch failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function fetchStatus() {
  const res = await fetch('api/status');
  if (!res.ok) {
    throw new Error(`status fetch failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchFederationCorrelated(afterID, limit) {
  const url = `api/federation/correlated?after=${afterID}&limit=${limit}`;
  const res = await fetch(url);
  if (!res.ok) {
    const err = new Error(`federation fetch failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function fetchRBAC() {
  const res = await fetch('api/rbac');
  if (!res.ok) {
    throw new Error(`rbac fetch failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchBudget() {
  const res = await fetch('api/budget');
  if (!res.ok) {
    throw new Error(`budget fetch failed: ${res.status}`);
  }
  return res.json();
}

// fetchCompliance queries the live compliance-evidence manifest preview
// for [from, to) (both RFC3339 strings) -- same error-shape convention
// as writePolicy/writeBudget (ok:false + status + message on a
// non-200), since a bad range or an unreachable store are both real
// failure modes here, not just "not wired" (404, still ok:false).
export async function fetchCompliance(from, to) {
  const url = `api/compliance?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
  const res = await fetch(url);
  if (res.status === 200) {
    return { ok: true, manifest: await res.json() };
  }
  if (res.status === 404) {
    return { ok: false, status: res.status, message: 'Compliance evidence is not queryable on this server.' };
  }
  let message = `query failed: ${res.status}`;
  try {
    const body = await res.text();
    if (body) message = body;
  } catch { /* non-text error body, keep the generic message */ }
  return { ok: false, status: res.status, message };
}

export async function fetchReloadHistory(afterID, limit) {
  const url = `api/reload/history?after=${afterID}&limit=${limit}`;
  const res = await fetch(url);
  if (!res.ok) {
    const err = new Error(`reload history fetch failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function fetchBlocked() {
  const res = await fetch('api/anomalies/blocked');
  if (!res.ok) {
    const err = new Error(`blocked fetch failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// revokeCredential hits /credentials/revoke -- a TOP-LEVEL route (leading
// `/`), NOT under `/dashboard/api/` like every other function in this file.
// It's still reached identically via same-origin fetch, so no auth header
// needs adding here: whatever credential this browser session already
// carries to load the dashboard itself is the exact same credential this
// fetch carries -- see task-4-brief.md's auth story.
export async function revokeCredential(identity) {
  const res = await fetch('/credentials/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identity }),
  });
  if (res.status === 204) {
    return { ok: true };
  }
  // 404 here means credential_issuance is off -- the route is registered
  // unconditionally (see main.go's credentialsRouteOrNotFound) but returns
  // a plain-text "not found" 404 instead of a JSON body in that case, so
  // it's called out explicitly rather than falling into the generic
  // `revoke failed: 404` message below.
  if (res.status === 404) {
    return { ok: false, status: res.status, message: 'credential issuance is not enabled on this server' };
  }
  let message = `revoke failed: ${res.status}`;
  try {
    const body = await res.json();
    if (body && body.error) message = body.error;
  } catch { /* non-JSON error body, keep the generic message */ }
  return { ok: false, status: res.status, message };
}

export async function unblockIdentity(identity, tenant) {
  // tenant is appended as a query param so an unscoped caller (rbac off,
  // or a global dashboard:view grant) can satisfy handleUnblock's "name
  // the tenant" requirement -- see handler.go's handleUnblock: targetTenant
  // falls back to ?tenant= only when h.tenantFilter(r) itself returns "".
  // A tenant-scoped caller's own resolved tenant always wins over this
  // value server-side, so echoing back the tenant this same identity's row
  // came from adds no new authorization logic, it just disambiguates for
  // callers the backend can't otherwise scope.
  const url = tenant
    ? `api/anomalies/blocked/${encodeURIComponent(identity)}?tenant=${encodeURIComponent(tenant)}`
    : `api/anomalies/blocked/${encodeURIComponent(identity)}`;
  const res = await fetch(url, { method: 'DELETE' });
  if (res.status === 204) {
    return { ok: true };
  }
  let message = `unblock failed: ${res.status}`;
  try {
    const body = await res.json();
    if (body && body.error) message = body.error;
  } catch { /* non-JSON error body, keep the generic message */ }
  return { ok: false, status: res.status, message };
}
