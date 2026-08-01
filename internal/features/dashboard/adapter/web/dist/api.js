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

export async function fetchBlocked() {
  const res = await fetch('api/anomalies/blocked');
  if (!res.ok) {
    throw new Error(`blocked fetch failed: ${res.status}`);
  }
  return res.json();
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
