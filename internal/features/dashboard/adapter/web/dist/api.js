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
    throw new Error(`anomalies fetch failed: ${res.status}`);
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
    throw new Error(`federation fetch failed: ${res.status}`);
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

export async function fetchBlocked() {
  const res = await fetch('api/anomalies/blocked');
  if (!res.ok) {
    throw new Error(`blocked fetch failed: ${res.status}`);
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
