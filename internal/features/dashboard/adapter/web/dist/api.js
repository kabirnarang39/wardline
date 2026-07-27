// Thin fetch wrappers for the dashboard's read-only JSON API.

export async function fetchAudit(afterID, limit) {
  const url = `api/audit?after=${afterID}&limit=${limit}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`audit fetch failed: ${res.status}`);
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
