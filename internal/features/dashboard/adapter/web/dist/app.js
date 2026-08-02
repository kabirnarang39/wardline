import { fetchAudit, fetchPolicy, fetchStatus, fetchAnomalies, fetchBlocked, unblockIdentity, fetchFederationCorrelated, revokeCredential } from './api.js';
import { mountIcons } from './icons.js';

const POLL_INTERVAL_MS = 2000;
const MAX_CLIENT_ROWS = 500;

let lastSeenNotificationCount = 0;

const state = {
  entries: [],
  lastID: 0,
  filters: { identity: '', tool: '', decisions: new Set() },
  lastPollOK: null,
  anomalies: [],
  lastAnomalyID: 0,
  blocked: [],
  federationAlerts: [],
  lastFederationID: 0,
};

function escapeHTML(s) {
  const div = document.createElement('div');
  div.textContent = s ?? '';
  return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function formatTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString();
}

function passesFilters(entry) {
  const { identity, tool, decisions } = state.filters;
  if (identity && !entry.Identity.toLowerCase().includes(identity.toLowerCase())) return false;
  if (tool && !entry.Tool.toLowerCase().includes(tool.toLowerCase())) return false;
  if (decisions.size > 0 && !decisions.has(entry.Decision)) return false;
  return true;
}

// withScrollAnchor (M10): newest-first row insertion + wholesale
// tbody.innerHTML replacement keeps a table's scrollTop pinned at the same
// PIXEL offset, but the CONTENT under that offset shifts every time new
// rows arrive at the top -- e.g. 40 new rows arriving with scrollTop
// pinned at 3000 slides whatever row the operator was actually reading by
// ~1800px. Re-anchors to whichever row ID was nearest the top of the
// visible viewport before renderRows() runs, instead of a raw pixel
// offset. Shared by every newest-first live-tail table (Activity,
// Anomalies, Federation) since they all hit the same underlying pattern --
// Blocked isn't included: it's a full snapshot of currently-blocked
// identities each poll, not a growing newest-first timeline.
function withScrollAnchor(tbody, renderRows) {
  const container = tbody.closest('.table-wrap');
  if (!container) {
    renderRows();
    return;
  }

  const containerTop = container.getBoundingClientRect().top;
  const anchorRow = Array.from(tbody.querySelectorAll('tr[data-row-id]'))
    .find((tr) => tr.getBoundingClientRect().bottom > containerTop);
  const anchorID = anchorRow?.dataset.rowId;
  const anchorOffset = anchorRow ? anchorRow.getBoundingClientRect().top - containerTop : 0;

  renderRows();

  if (anchorID == null) return;
  const newAnchorRow = tbody.querySelector(`tr[data-row-id="${CSS.escape(anchorID)}"]`);
  if (!newAnchorRow) return;
  container.scrollTop += (newAnchorRow.getBoundingClientRect().top - containerTop) - anchorOffset;
}

function renderActivity() {
  const tbody = document.getElementById('audit-rows');
  const empty = document.getElementById('audit-empty');
  const visible = state.entries.filter(passesFilters);

  if (visible.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  // Newest first for scanning.
  withScrollAnchor(tbody, () => {
    const rows = visible.slice().reverse().map((e) => `
      <tr data-row-id="${escapeHTML(String(e.ID))}">
        <td class="decision-cell" data-decision="${escapeHTML(e.Decision)}"></td>
        <td>${escapeHTML(formatTime(e.Timestamp))}</td>
        <td>${escapeHTML(e.Identity)}</td>
        <td>${escapeHTML(e.Tool)}</td>
        <td>${escapeHTML(e.Decision)}</td>
        <td>${e.LatencyMS}ms</td>
        <td title="${escapeHTML(e.TraceID)}">${escapeHTML(e.TraceID ? e.TraceID.slice(0, 8) : '')}</td>
        <td class="reason-cell" title="${escapeHTML(e.Reason)}">${escapeHTML(e.Reason)}</td>
      </tr>
    `).join('');
    tbody.innerHTML = rows;
  });
}

async function pollAudit() {
  try {
    const fresh = await fetchAudit(state.lastID, 1000);
    if (fresh.length > 0) {
      state.entries.push(...fresh);
      if (state.entries.length > MAX_CLIENT_ROWS) {
        state.entries = state.entries.slice(state.entries.length - MAX_CLIENT_ROWS);
      }
      state.lastID = fresh[fresh.length - 1].ID;
    }
    renderActivity();
    renderOverview();
    setLive(true);
  } catch {
    setLive(false);
  }
}

function renderAnomalies() {
  const tbody = document.getElementById('anomaly-rows');
  const empty = document.getElementById('anomaly-empty');

  if (state.anomalies.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    updateNotificationBadge();
    return;
  }
  empty.hidden = true;

  // Newest first for scanning.
  withScrollAnchor(tbody, () => {
    const rows = state.anomalies.slice().reverse().map((a) => `
      <tr data-row-id="${escapeHTML(String(a.id))}">
        <td>${escapeHTML(formatTime(a.timestamp))}</td>
        <td>${escapeHTML(a.identity)}</td>
        <td>${escapeHTML(a.tenant)}</td>
        <td>${escapeHTML(a.kind)}</td>
        <td title="${escapeHTML(a.detail)}">${escapeHTML(a.detail)}</td>
      </tr>
    `).join('');
    tbody.innerHTML = rows;
  });
  updateNotificationBadge();
}

async function pollAnomalies() {
  try {
    const fresh = await fetchAnomalies(state.lastAnomalyID, 1000);
    if (fresh.length > 0) {
      state.anomalies.push(...fresh);
      if (state.anomalies.length > MAX_CLIENT_ROWS) {
        state.anomalies = state.anomalies.slice(state.anomalies.length - MAX_CLIENT_ROWS);
      }
      state.lastAnomalyID = fresh[fresh.length - 1].id;
    }
    renderAnomalies();
    renderOverview();
  } catch (err) {
    // Anomalies polling failure doesn't affect the shared live-dot
    // indicator -- that's pollAudit's own job; a failed anomalies poll
    // here just means this view doesn't update this tick, silently
    // retried next tick. Still surface it to devtools (a 404 when
    // anomaly_detection is off is expected and constant, but a real
    // 500 or network failure shouldn't be totally silent) and make sure
    // the empty state actually renders instead of leaving a bare table
    // header with no explanation -- a fetch failure on the very first
    // poll otherwise never calls renderAnomalies at all.
    console.error('anomalies poll failed:', err);
    renderAnomalies();
  }
}

function renderFederation() {
  const tbody = document.getElementById('federation-rows');
  const empty = document.getElementById('federation-empty');

  if (state.federationAlerts.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  withScrollAnchor(tbody, () => {
    const rows = state.federationAlerts.slice().reverse().map((a) => `
      <tr data-row-id="${escapeHTML(String(a.id))}">
        <td>${escapeHTML(formatTime(a.first_seen))}</td>
        <td>${escapeHTML(formatTime(a.last_seen))}</td>
        <td>${escapeHTML(a.kind)}</td>
        <td>${escapeHTML(a.instance_ids.join(', '))}</td>
        <td title="${escapeHTML(a.fingerprint)}">${escapeHTML(a.fingerprint.slice(0, 12))}</td>
      </tr>
    `).join('');
    tbody.innerHTML = rows;
  });
}

async function pollFederation() {
  try {
    const fresh = await fetchFederationCorrelated(state.lastFederationID, 1000);
    if (fresh.length > 0) {
      state.federationAlerts.push(...fresh);
      if (state.federationAlerts.length > MAX_CLIENT_ROWS) {
        state.federationAlerts = state.federationAlerts.slice(state.federationAlerts.length - MAX_CLIENT_ROWS);
      }
      state.lastFederationID = fresh[fresh.length - 1].id;
    }
    renderFederation();
  } catch (err) {
    // Same pattern as pollAnomalies: federation is off by default (404),
    // so a failed poll here just means this view doesn't update this
    // tick -- silently retried next tick. Still surface it to devtools,
    // and always render so the empty state shows instead of a bare
    // table header if the very first poll fails.
    console.error('federation poll failed:', err);
    renderFederation();
  }
}

function formatExpiry(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diffMs = d.getTime() - Date.now();
  if (diffMs <= 0) return 'expired';
  const mins = Math.round(diffMs / 60000);
  if (mins < 60) return `in ${mins}m`;
  return `in ${Math.round(mins / 60)}h`;
}

function renderBlockedTable() {
  const tbody = document.getElementById('blocked-rows');
  const empty = document.getElementById('blocked-empty');
  const entries = state.blocked;

  if (entries.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  tbody.innerHTML = entries.map((b) => `
    <tr>
      <td>${escapeHTML(b.identity)}</td>
      <td>${escapeHTML(b.tenant)}</td>
      <td class="reason-cell" title="${escapeHTML(b.reason)}">${escapeHTML(b.reason)}</td>
      <td>${escapeHTML(formatExpiry(b.blocked_until))}</td>
      <td><button class="btn-unblock" data-identity="${escapeHTML(b.identity)}" data-tenant="${escapeHTML(b.tenant)}">Unblock</button></td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.btn-unblock').forEach((btn) => {
    btn.addEventListener('click', () => confirmUnblock(btn.dataset.identity, btn.dataset.tenant));
  });
}

async function pollBlocked() {
  try {
    state.blocked = await fetchBlocked();
  } catch (err) {
    console.error('blocked fetch failed:', err);
  }
  renderBlockedTable();
  updateNotificationBadge();
  renderOverview();
}

async function confirmUnblock(identity, tenant) {
  if (!window.confirm(`Unblock "${identity}" in tenant "${tenant}"? This clears the automated block before it expires.`)) {
    return;
  }
  const result = await unblockIdentity(identity, tenant);
  if (!result.ok) {
    window.alert(`Could not unblock: ${result.message}`);
    return;
  }
  pollBlocked();
}

function renderStatusBand() {
  const band = document.getElementById('status-band');
  const text = document.getElementById('status-text');
  const previousState = band.dataset.state;

  let newState, newText;
  if (state.blocked.length > 0) {
    newState = 'action-needed';
    newText = `${state.blocked.length} identit${state.blocked.length === 1 ? 'y' : 'ies'} blocked`;
  } else if (state.anomalies.length > 0) {
    newState = 'attention';
    newText = `${state.anomalies.length} anomal${state.anomalies.length === 1 ? 'y' : 'ies'} need review`;
  } else {
    newState = 'nominal';
    newText = 'All systems nominal';
  }

  text.textContent = newText;
  band.dataset.state = newState;

  if (previousState && previousState !== newState) {
    band.classList.remove('is-transitioning');
    // Force reflow so re-adding the class restarts the animation even if
    // the state flips back and forth quickly between poll ticks.
    void band.offsetWidth;
    band.classList.add('is-transitioning');
  }
}

function renderKPIs() {
  document.getElementById('kpi-total-requests').textContent = String(state.entries.length);
  const denies = state.entries.filter((e) => e.Decision === 'deny' || e.Decision === 'error').length;
  const denyRate = state.entries.length > 0 ? Math.round((denies / state.entries.length) * 100) : 0;
  document.getElementById('kpi-deny-rate').textContent = `${denyRate}%`;
  document.getElementById('kpi-anomalies').textContent = String(state.anomalies.length);
  document.getElementById('kpi-blocked').textContent = String(state.blocked.length);
}

// BUCKET_MINUTES are candidate bucket widths, smallest first. bucketEntries
// (M7) picks the smallest one that still keeps the observed span at or
// under MAX_BUCKETS bars -- calendar-day bucketing (the old behavior)
// degenerated to a single solid bar on any realistic instance, since the
// actual data source (the 500-entry client-side ring buffer) spans
// minutes to low hours, not days. "Round" minute counts keep bucket
// boundaries and their axis labels legible instead of an arbitrary
// span/7 division.
const BUCKET_MINUTES = [1, 2, 5, 10, 15, 30, 60, 120, 240, 360, 720, 1440];
const MAX_BUCKETS = 12;

function chooseBucketMs(spanMs) {
  for (const minutes of BUCKET_MINUTES) {
    const ms = minutes * 60000;
    if (spanMs / ms <= MAX_BUCKETS) return ms;
  }
  return BUCKET_MINUTES[BUCKET_MINUTES.length - 1] * 60000;
}

function bucketEntries(entries) {
  const times = entries.map((e) => new Date(e.Timestamp).getTime()).filter((t) => !Number.isNaN(t));
  if (times.length === 0) return { buckets: [], bucketMs: 0 };

  const spanMs = Math.max(...times) - Math.min(...times);
  const bucketMs = chooseBucketMs(spanMs || 1);

  const counts = new Map();
  for (const t of times) {
    const key = Math.floor(t / bucketMs) * bucketMs;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const buckets = Array.from(counts.entries()).sort(([a], [b]) => a - b);
  return { buckets, bucketMs };
}

function formatBucketLabel(bucketStartMs, bucketMs) {
  const d = new Date(bucketStartMs);
  // Honest about the real granularity (M7): once the buffer's span pushes
  // bucketing out to whole-day buckets, a date reads better than a
  // time-of-day that would otherwise silently span multiple days.
  return bucketMs >= 24 * 60 * 60 * 1000
    ? d.toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' })
    : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function renderActivityChart() {
  const { buckets, bucketMs } = bucketEntries(state.entries);
  const svg = document.getElementById('activity-chart');
  const caption = document.getElementById('chart-caption');
  caption.textContent = `Based on the last ${state.entries.length} buffered events — not a full historical view.`;

  if (buckets.length === 0) {
    svg.innerHTML = '';
    return;
  }

  const maxCount = Math.max(...buckets.map(([, count]) => count));
  const barWidth = 400 / buckets.length;
  const chartHeight = 140;

  svg.innerHTML = buckets.map(([bucketStart, count], i) => {
    const barHeight = maxCount > 0 ? (count / maxCount) * chartHeight : 0;
    const x = i * barWidth + barWidth * 0.15;
    const w = barWidth * 0.7;
    const y = chartHeight - barHeight + 10;
    const label = formatBucketLabel(bucketStart, bucketMs);
    return `
      <rect class="chart-bar" x="${x}" y="${y}" width="${w}" height="${barHeight}" rx="4"></rect>
      <text class="chart-value-label" x="${x + w / 2}" y="${y - 4}" text-anchor="middle">${count}</text>
      <text class="chart-bar-label" x="${x + w / 2}" y="${chartHeight + 24}" text-anchor="middle">${escapeHTML(label)}</text>
    `;
  }).join('');
}

function renderNeedsReview() {
  const summary = document.getElementById('needs-review-summary');
  const count = state.anomalies.length + state.blocked.length;
  summary.textContent = count === 0
    ? 'Nothing needs review right now.'
    : `${state.anomalies.length} anomal${state.anomalies.length === 1 ? 'y' : 'ies'} and ${state.blocked.length} blocked identit${state.blocked.length === 1 ? 'y' : 'ies'} on record.`;
}

let pulsePaused = false;

function updateLivePulse() {
  if (pulsePaused) return;
  const now = Date.now();
  const windowEntries = state.entries.filter((e) => new Date(e.Timestamp).getTime() >= now - 10000);
  const rate = windowEntries.length / 10;
  document.getElementById('pulse-rate').innerHTML = `${rate.toFixed(1)} <span class="pulse-unit">req/s</span>`;
}

function wireLivePulseToggle() {
  const btn = document.getElementById('pulse-toggle');
  btn.addEventListener('click', () => {
    pulsePaused = !pulsePaused;
    btn.innerHTML = pulsePaused ? '<span data-icon="play" aria-hidden="true"></span>' : '<span data-icon="pause" aria-hidden="true"></span>';
    btn.setAttribute('aria-label', pulsePaused ? 'Resume live updates' : 'Pause live updates');
    mountIcons(btn);
    if (pulsePaused) {
      document.getElementById('pulse-rate').innerHTML = 'Paused';
    } else {
      updateLivePulse();
    }
  });
}

function renderOverview() {
  renderStatusBand();
  renderKPIs();
  renderActivityChart();
  renderNeedsReview();
  updateLivePulse();
}

function wireCredentials() {
  const btn = document.getElementById('revoke-btn');
  const input = document.getElementById('revoke-identity-input');
  const result = document.getElementById('revoke-result');

  btn.addEventListener('click', async () => {
    const identity = input.value.trim();
    if (!identity) {
      result.hidden = false;
      result.textContent = 'Enter an identity to revoke.';
      result.style.color = 'var(--deny)';
      return;
    }
    if (!window.confirm(`Revoke the credential for "${identity}"? This immediately invalidates its access and refresh tokens.`)) {
      return;
    }
    btn.disabled = true;
    const res = await revokeCredential(identity);
    btn.disabled = false;
    result.hidden = false;
    if (res.ok) {
      result.textContent = `Revoked "${identity}".`;
      result.style.color = 'var(--brand)';
      input.value = '';
    } else if (res.status === 403) {
      result.textContent = 'You don’t have permission to revoke credentials.';
      result.style.color = 'var(--deny)';
    } else {
      result.textContent = res.message;
      result.style.color = 'var(--deny)';
    }
  });
}

function updateNotificationBadge() {
  const total = state.anomalies.length + state.blocked.length;
  // state.blocked.length can shrink (auto-block TTL expiry, manual
  // unblock), unlike state.anomalies.length which only grows -- clamp the
  // baseline down whenever total drops below it, so a stale higher
  // baseline can never swallow a later genuine increase.
  lastSeenNotificationCount = Math.min(lastSeenNotificationCount, total);
  const unseen = total - lastSeenNotificationCount;
  const badge = document.getElementById('notification-badge');
  if (unseen > 0) {
    badge.hidden = false;
    badge.textContent = unseen > 99 ? '99+' : String(unseen);
  } else {
    badge.hidden = true;
  }
}

function setLive(ok) {
  state.lastPollOK = ok;
  const dot = document.getElementById('live-dot');
  const label = document.getElementById('live-label');
  if (ok) {
    dot.classList.remove('is-stale');
    label.textContent = 'Live';
  } else {
    dot.classList.add('is-stale');
    label.textContent = 'Reconnecting…';
  }
}

async function loadPolicy() {
  try {
    const policy = await fetchPolicy();
    document.getElementById('policy-backend').textContent = policy.Backend || 'unknown';
    document.getElementById('policy-source').textContent = policy.Source || '';
  } catch {
    document.getElementById('policy-source').textContent = 'Failed to load policy — try refreshing.';
  }
}

async function loadStatus() {
  try {
    const status = await fetchStatus();
    const grid = document.getElementById('status-grid');
    grid.innerHTML = `
      <div><dt>Version</dt><dd>${escapeHTML(status.Version)}</dd></div>
      <div><dt>Uptime</dt><dd>${formatUptime(status.UptimeSeconds)}</dd></div>
      <div><dt>Listening on</dt><dd>${escapeHTML(status.Listen)}</dd></div>
      <div><dt>Upstream</dt><dd>${escapeHTML(status.Upstream)}</dd></div>
    `;

    const featureList = document.getElementById('feature-list');
    const features = status.Features || {};
    const names = Object.keys(features).sort();
    featureList.innerHTML = names.length
      ? names.map((name) => `
          <li>
            <span class="feature-dot ${features[name] ? 'is-on' : 'is-off'}"></span>
            <span>${escapeHTML(name)}</span>
            <span>${features[name] ? 'on' : 'off'}</span>
          </li>
        `).join('')
      : '<li>No optional features configured.</li>';

    const tenantBadge = document.getElementById('identity-tenant-badge');
    if (status.CallerTenant) {
      tenantBadge.hidden = false;
      tenantBadge.textContent = status.CallerTenant;
    } else {
      tenantBadge.hidden = true;
    }
  } catch {
    document.getElementById('status-grid').textContent = 'Failed to load status — try refreshing.';
  }
}

function formatUptime(totalSeconds) {
  const s = totalSeconds % 60;
  const m = Math.floor(totalSeconds / 60) % 60;
  const h = Math.floor(totalSeconds / 3600);
  return `${h}h ${m}m ${s}s`;
}

function switchView(name) {
  document.querySelectorAll('.view').forEach((el) => {
    el.hidden = el.id !== `view-${name}`;
    el.classList.toggle('is-active', el.id === `view-${name}`);
  });
  document.querySelectorAll('.nav-item').forEach((btn) => {
    const active = btn.dataset.view === name;
    btn.classList.toggle('is-active', active);
    if (active) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  });
  if (name === 'overview') renderOverview();
  if (name === 'blocked') renderBlockedTable();
  if (name === 'policy') loadPolicy();
  if (name === 'status') loadStatus();
}

function wireNav() {
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });
}

function wireFilters() {
  document.getElementById('filter-identity').addEventListener('input', (e) => {
    state.filters.identity = e.target.value;
    renderActivity();
  });
  document.getElementById('filter-tool').addEventListener('input', (e) => {
    state.filters.tool = e.target.value;
    renderActivity();
  });
  document.querySelectorAll('.chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const decision = chip.dataset.decision;
      if (state.filters.decisions.has(decision)) {
        state.filters.decisions.delete(decision);
        chip.classList.remove('is-active');
        chip.setAttribute('aria-pressed', 'false');
      } else {
        state.filters.decisions.add(decision);
        chip.classList.add('is-active');
        chip.setAttribute('aria-pressed', 'true');
      }
      renderActivity();
    });
  });
}

function wireTopbar() {
  document.getElementById('notifications-btn').addEventListener('click', () => {
    lastSeenNotificationCount = state.anomalies.length + state.blocked.length;
    updateNotificationBadge();
  });

  document.getElementById('global-search').addEventListener('input', (e) => {
    const activeView = document.querySelector('.view:not([hidden])');
    if (!activeView) return;
    const value = e.target.value;
    if (activeView.id === 'view-activity') {
      state.filters.identity = value;
      document.getElementById('filter-identity').value = value;
      renderActivity();
    }
    // Other views have no client-side filter state to subsume -- YAGNI,
    // matches the design spec's own scope.
  });
}

function init() {
  mountIcons(document);

  const overview = document.getElementById('view-overview');
  document.querySelectorAll('#view-overview .kpi-tile, #view-overview .card').forEach((el, i) => {
    el.classList.add('stagger-in');
    el.style.animationDelay = `${i * 40}ms`;
  });
  // .stagger-in uses fill-mode: forwards so each tile holds its entrance
  // end-state -- but that end-state lives in the CSS Animations cascade
  // origin, which outranks a normal author `:hover` rule, so leaving the
  // class on permanently would silently block the Overview card hover-lift
  // forever after the one-time entrance completes (I2). The stagger only
  // ever needs to exist for its own ~400ms entrance; strip it on
  // `animationend` (delegated on the view, since animationDelay staggers
  // when each tile's own event actually fires) so normal `:hover` rules
  // apply again once the entrance is done.
  overview.addEventListener('animationend', (e) => {
    if (e.animationName === 'stagger-in') {
      e.target.classList.remove('stagger-in');
    }
  });

  wireNav();
  wireFilters();
  wireCredentials();
  wireTopbar();
  wireLivePulseToggle();
  document.getElementById('needs-review-cta').addEventListener('click', () => switchView('anomalies'));
  loadStatus();
  pollAudit();
  pollAnomalies();
  pollFederation();
  pollBlocked();
  renderOverview();
  setInterval(pollAudit, POLL_INTERVAL_MS);
  setInterval(pollAnomalies, POLL_INTERVAL_MS);
  setInterval(pollFederation, POLL_INTERVAL_MS);
  setInterval(pollBlocked, POLL_INTERVAL_MS);
}

init();
