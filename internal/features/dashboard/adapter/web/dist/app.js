import { fetchAudit, fetchPolicy, fetchStatus, fetchAnomalies, fetchBlocked, unblockIdentity, fetchFederationCorrelated, revokeCredential, fetchRBAC, fetchBudget } from './api.js';
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

// wireExpandableRows delegates a single click/keydown listener on tbody
// rather than attaching one per row, so it survives withScrollAnchor's
// wholesale tbody.innerHTML replacement on every poll tick without
// needing to be re-wired after each render -- call it once per table
// right after wiring the table's poll function, not inside the render
// function itself. detailRenderer(rowId) returns the detail row's inner
// HTML (already escaped by the caller); colSpan is how many columns the
// detail row's single <td> must span.
function wireExpandableRows(tbody, colSpan, detailRenderer) {
  // The interactive control is each row's .expand-toggle element, not the
  // <tr> itself -- role="button"/tabindex on a <tr> conflicts with its
  // <td> children's implicit table-cell roles (breaks the row/cell
  // ancestor relationship table-structure a11y rules expect), even though
  // it can look fine under manual inspection. Matches this file's other
  // icon-button controls (.topbar-icon-btn, .pulse-toggle) in spirit: a
  // real focusable/labelled element, just rendered via CSS off
  // data-icon rather than wrapping a nested decorative icon span --
  // so unlike those controls' inner spans, .expand-toggle itself is the
  // interactive control and must NEVER carry aria-hidden (asserted
  // below regardless of what a row template's markup sets). Every row
  // wired through this primitive is expected to render one -- rows
  // without a .expand-toggle simply aren't operable, mouse or keyboard.
  function closeToggle(toggle) {
    if (!toggle) return;
    toggle.classList.remove('is-open');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Expand row details');
  }

  function openToggle(toggle) {
    if (!toggle) return;
    toggle.classList.add('is-open');
    toggle.setAttribute('aria-expanded', 'true');
    toggle.setAttribute('aria-label', 'Collapse row details');
  }

  // A poll-driven re-render replaces tbody.innerHTML wholesale (see
  // withScrollAnchor), which would silently strip tabindex/role/aria off
  // every toggle along with the markup itself -- re-apply them to
  // whatever rows land in the DOM on every render instead of requiring
  // each caller's row template to remember this wiring.
  const markToggleFocusable = (row) => {
    const toggle = row.querySelector('.expand-toggle');
    if (!toggle) return;
    toggle.tabIndex = 0;
    toggle.setAttribute('role', 'button');
    // An interactive control can't also be aria-hidden -- assert this
    // regardless of what the row markup set, so this function stays the
    // single source of truth for the toggle's a11y contract instead of
    // relying on every row template to remember not to set it.
    toggle.removeAttribute('aria-hidden');
    closeToggle(toggle);
  };
  tbody.querySelectorAll('tr[data-row-id]').forEach(markToggleFocusable);
  new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType !== Node.ELEMENT_NODE) return;
        if (node.matches('tr[data-row-id]')) markToggleFocusable(node);
        node.querySelectorAll?.('tr[data-row-id]').forEach(markToggleFocusable);
      });
    }
  }).observe(tbody, { childList: true });

  function toggleRow(row) {
    const toggle = row.querySelector('.expand-toggle');
    const existingDetail = row.nextElementSibling;
    if (existingDetail && existingDetail.classList.contains('detail-row')) {
      existingDetail.remove();
      closeToggle(toggle);
      return;
    }

    // A poll-driven re-render replaces tbody.innerHTML wholesale, which
    // would silently discard any detail row a prior click opened -- close
    // every other open detail row first so at most one is ever open,
    // simplifying what withScrollAnchor's own row-reconciliation has to
    // account for (this deliberately does NOT try to keep a detail row
    // open across a poll tick; it closes on next render, matching this
    // project's "polling never animates or preserves transient UI state"
    // posture already established for the live-pulse widget -- so an
    // operator mid-read of an expanded row will see it silently collapse
    // on the next ~2s poll tick, same as any other transient UI state
    // here).
    tbody.querySelectorAll('.detail-row').forEach((el) => el.remove());
    tbody.querySelectorAll('.expand-toggle.is-open').forEach(closeToggle);

    const rowId = row.dataset.rowId;
    const detail = document.createElement('tr');
    detail.className = 'detail-row';
    detail.innerHTML = `<td colspan="${colSpan}">${detailRenderer(rowId)}</td>`;
    row.after(detail);
    openToggle(toggle);
  }

  tbody.addEventListener('click', (e) => {
    const toggle = e.target.closest('.expand-toggle');
    if (!toggle || !tbody.contains(toggle)) return;
    const row = toggle.closest('tr[data-row-id]');
    if (!row) return;
    toggleRow(row);
  });

  // Enter/Space activate the toggle the same way a click does, matching
  // the WAI-ARIA disclosure-pattern expectation for a role="button"
  // element. Space additionally needs preventDefault so it doesn't
  // scroll the page.
  tbody.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const toggle = e.target.closest('.expand-toggle');
    if (!toggle || !tbody.contains(toggle)) return;
    const row = toggle.closest('tr[data-row-id]');
    if (!row) return;
    e.preventDefault();
    toggleRow(row);
  });
}

// computeFacets/renderFacetGroup/renderFacets (Activity-only, not shared):
// surfaces the distinct identity/tool/decision values actually present in
// the currently-buffered dataset, with counts, alongside the existing
// free-text filters/chips -- both patterns coexist, this doesn't replace
// either. Recomputed every renderActivity call so it reflects the same
// buffered data the table renders from on each poll tick.
function computeFacets(entries) {
  const identity = new Map();
  const tool = new Map();
  const decision = new Map();
  for (const e of entries) {
    identity.set(e.Identity, (identity.get(e.Identity) || 0) + 1);
    tool.set(e.Tool, (tool.get(e.Tool) || 0) + 1);
    decision.set(e.Decision, (decision.get(e.Decision) || 0) + 1);
  }
  const sortByCount = (m) => Array.from(m.entries()).sort(([, a], [, b]) => b - a).slice(0, 10);
  return { identity: sortByCount(identity), tool: sortByCount(tool), decision: sortByCount(decision) };
}

function renderFacetGroup(listID, entries, filterKey) {
  const list = document.getElementById(listID);
  list.innerHTML = entries.map(([value, count]) => {
    const isActive = filterKey === 'decisions'
      ? state.filters.decisions.has(value)
      : state.filters[filterKey] === value;
    return `
      <li>
        <button class="${isActive ? 'is-active' : ''}" data-facet-key="${escapeHTML(filterKey)}" data-facet-value="${escapeHTML(value)}">
          <span>${escapeHTML(value || '(none)')}</span>
          <span class="facet-count">${count}</span>
        </button>
      </li>
    `;
  }).join('');
}

function renderFacets() {
  const { identity, tool, decision } = computeFacets(state.entries);
  renderFacetGroup('facet-identity', identity, 'identity');
  renderFacetGroup('facet-tool', tool, 'tool');
  renderFacetGroup('facet-decision', decision, 'decisions');
}

function activityDetailRenderer(rowId) {
  const entry = state.entries.find((e) => String(e.ID) === rowId);
  if (!entry) return '';
  return `
    <dl>
      <dt>Trace ID</dt><dd>${escapeHTML(entry.TraceID || '—')}</dd>
      <dt>Latency</dt><dd>${entry.LatencyMS}ms</dd>
      <dt>Reason</dt><dd>${escapeHTML(entry.Reason || '—')}</dd>
    </dl>
  `;
}

function renderActivity() {
  renderFacets();
  const tbody = document.getElementById('audit-rows');
  const empty = document.getElementById('audit-empty');
  const visible = state.entries.filter(passesFilters);

  // Real count of everything currently held in the client-side ring
  // buffer (state.entries, capped at MAX_CLIENT_ROWS) -- not the filtered
  // `visible` count, so the subtitle always reflects total buffered
  // events regardless of the active filters.
  const subtitle = document.getElementById('activity-subtitle');
  if (subtitle) {
    subtitle.textContent = `${state.entries.length.toLocaleString()} buffered event${state.entries.length === 1 ? '' : 's'}`;
  }

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
        <td class="decision-cell" data-decision="${escapeHTML(e.Decision)}"><span class="expand-toggle" data-icon="chevron"></span></td>
        <td>${escapeHTML(formatTime(e.Timestamp))}</td>
        <td>${escapeHTML(e.Identity)}</td>
        <td>${escapeHTML(e.Tool)}</td>
        <td><span class="pill" data-decision="${escapeHTML(e.Decision)}">${escapeHTML(e.Decision)}</span></td>
        <td>${e.LatencyMS}ms</td>
        <td title="${escapeHTML(e.TraceID)}">${escapeHTML(e.TraceID ? e.TraceID.slice(0, 8) : '')}</td>
        <td class="reason-cell" title="${escapeHTML(e.Reason)}">${escapeHTML(e.Reason)}</td>
      </tr>
    `).join('');
    tbody.innerHTML = rows;
    mountIcons(tbody);
  });
}

// wireActivityInteractions (called once from init()): wires the shared
// expandable-row primitive onto the Activity table (colSpan 8 matches the
// table's real column count), the facet-panel open/close toggle, and
// click-to-filter delegation from facet buttons -- kept in sync with the
// existing free-text inputs/chips so both filtering patterns always agree
// on the active state.
function wireActivityInteractions() {
  const tbody = document.getElementById('audit-rows');
  wireExpandableRows(tbody, 8, activityDetailRenderer);

  document.getElementById('facet-toggle').addEventListener('click', () => {
    const panel = document.getElementById('facet-panel');
    const btn = document.getElementById('facet-toggle');
    const isOpen = !panel.hidden;
    panel.hidden = isOpen;
    btn.setAttribute('aria-expanded', String(!isOpen));
  });

  document.getElementById('facet-panel').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-facet-key]');
    if (!btn) return;
    const key = btn.dataset.facetKey;
    const value = btn.dataset.facetValue;
    if (key === 'decisions') {
      if (state.filters.decisions.has(value)) state.filters.decisions.delete(value);
      else state.filters.decisions.add(value);
      document.querySelectorAll(`.chip[data-decision="${CSS.escape(value)}"]`).forEach((chip) => {
        chip.classList.toggle('is-active', state.filters.decisions.has(value));
        chip.setAttribute('aria-pressed', String(state.filters.decisions.has(value)));
      });
    } else {
      state.filters[key] = state.filters[key] === value ? '' : value;
      const input = document.getElementById(`filter-${key}`);
      if (input) input.value = state.filters[key];
    }
    renderActivity();
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

  // Every entry BlockedSource.List() returns is by definition a live,
  // time-bounded block (BlockedEntry.BlockedUntil) -- real data, same
  // count already shown by the Overview KPI and status band, so "active
  // time-bounded block(s)" is honest rather than borrowed decoration.
  const subtitle = document.getElementById('blocked-subtitle');
  if (subtitle) {
    subtitle.textContent = `${entries.length} active time-bounded block${entries.length === 1 ? '' : 's'}`;
  }

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

  // Sidebar nav-count badges reuse these exact same counts (state.anomalies
  // .length / state.blocked.length) -- sourced once here, not recomputed
  // independently -- and hide entirely at zero rather than showing "0".
  updateNavCount('nav-count-anomalies', state.anomalies.length);
  updateNavCount('nav-count-blocked', state.blocked.length);
}

function updateNavCount(elementID, count) {
  const el = document.getElementById(elementID);
  if (!el) return;
  if (count > 0) {
    el.hidden = false;
    el.textContent = String(count);
  } else {
    el.hidden = true;
  }
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
    // Floor-aligned bucket boundaries mean the actual number of buckets
    // touched by [minT, maxT] can be one more than spanMs/ms (the span's
    // start/end don't line up with bucket edges) -- cap at MAX_BUCKETS - 1
    // here so the real rendered count never exceeds MAX_BUCKETS.
    if (spanMs / ms <= MAX_BUCKETS - 1) return ms;
  }
  return BUCKET_MINUTES[BUCKET_MINUTES.length - 1] * 60000;
}

function bucketEntries(entries) {
  const times = entries.map((e) => new Date(e.Timestamp).getTime()).filter((t) => !Number.isNaN(t));
  if (times.length === 0) return { buckets: [], bucketMs: 0, spanMs: 0 };

  const spanMs = Math.max(...times) - Math.min(...times);
  const bucketMs = chooseBucketMs(spanMs || 1);

  const counts = new Map();
  for (const t of times) {
    const key = Math.floor(t / bucketMs) * bucketMs;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const buckets = Array.from(counts.entries()).sort(([a], [b]) => a - b);
  return { buckets, bucketMs, spanMs };
}

function formatBucketLabel(bucketStartMs, bucketMs, spanMs) {
  const d = new Date(bucketStartMs);
  const DAY_MS = 24 * 60 * 60 * 1000;
  // Honest about the real granularity (M7). Whole-day buckets never need a
  // time component. Otherwise, ambiguity depends on the TOTAL SPAN the
  // chart covers, not the bucket width: a >=24h span can repeat the same
  // time-of-day label across two different calendar days with sub-day
  // buckets, so once the span could do that, include a date alongside the
  // time to disambiguate.
  if (bucketMs >= DAY_MS) {
    return d.toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' });
  }
  if (spanMs >= DAY_MS) {
    return d.toLocaleString(undefined, { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function renderActivityChart() {
  const { buckets, bucketMs, spanMs } = bucketEntries(state.entries);
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
    const label = formatBucketLabel(bucketStart, bucketMs, spanMs);
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
      result.style.color = 'var(--status-critical)';
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
      result.style.color = 'var(--status-ok)';
      input.value = '';
    } else if (res.status === 403) {
      result.textContent = 'You don’t have permission to revoke credentials.';
      result.style.color = 'var(--status-critical)';
    } else {
      result.textContent = res.message;
      result.style.color = 'var(--status-critical)';
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

// renderRBAC populates the read-only RBAC screen's two panels from a
// single fetchRBAC() response -- this data can't change at runtime today
// (no hot-reload wiring yet, see task-7-rbac-screen-brief.md), so it's
// fetched once per view-switch, same posture as loadPolicy/loadStatus
// above, not polled on an interval like Activity/Anomalies/Federation.
async function renderRBAC() {
  const roleRows = document.getElementById('rbac-role-rows');
  const bindingList = document.getElementById('rbac-binding-list');
  try {
    const { roles, bindings } = await fetchRBAC();
    roleRows.innerHTML = (roles || []).map((role) => {
      const perms = role.permissions.join(', ');
      return `
      <tr>
        <td><strong>${escapeHTML(role.name)}</strong></td>
        <td class="reason-cell" title="${escapeHTML(perms)}">${escapeHTML(perms)}</td>
        <td>${role.binding_count}</td>
      </tr>
    `;
    }).join('');
    bindingList.innerHTML = (bindings || []).map((binding) => `
      <div class="rbac-binding-row">
        <span class="mono">${escapeHTML(binding.subject)}</span>
        <span class="pill info">${escapeHTML(binding.role)}</span>
        <span class="rbac-binding-tenant">${binding.tenant ? escapeHTML(binding.tenant) : '—global—'}</span>
      </div>
    `).join('');
  } catch (err) {
    console.error('rbac fetch failed:', err);
    roleRows.innerHTML = '';
    bindingList.innerHTML = '<p class="empty-state">Failed to load RBAC data — try refreshing.</p>';
  }
}

// renderBudget populates the read-only Budget screen's default-limit grid
// and overrides table from a single fetchBudget() response -- this data
// can't change at runtime today (no hot-reload wiring yet, see
// task-8-budget-screen-brief.md), so it's fetched once per view-switch,
// same posture as renderRBAC/loadPolicy/loadStatus above, not polled on
// an interval like Activity/Anomalies/Federation.
async function renderBudget() {
  const grid = document.getElementById('budget-default-grid');
  const rows = document.getElementById('budget-override-rows');
  const empty = document.getElementById('budget-override-empty');
  try {
    const { default: def, overrides } = await fetchBudget();
    grid.innerHTML = `
      <div><dt>Requests / window</dt><dd>${def.requests_per_window}</dd></div>
      <div><dt>Window</dt><dd>${def.window_seconds}s</dd></div>
    `;
    rows.innerHTML = (overrides || []).map((o) => `
      <tr>
        <td><span class="pill ${o.scope === 'tenant' ? 'info' : 'muted'}">${escapeHTML(o.scope)}</span></td>
        <td>${escapeHTML(o.name)}</td>
        <td>${o.requests_per_window}</td>
        <td>${o.window_seconds}s</td>
      </tr>
    `).join('');
    empty.hidden = (overrides || []).length > 0;
  } catch (err) {
    console.error('budget fetch failed:', err);
    grid.innerHTML = '';
    rows.innerHTML = '';
    empty.hidden = true;
    grid.textContent = 'Failed to load budget data — try refreshing.';
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
  if (name === 'rbac') renderRBAC();
  if (name === 'budget') renderBudget();
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

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('wardline-theme', theme);
  const btn = document.getElementById('theme-toggle-btn');
  btn.setAttribute('aria-label', theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
  btn.innerHTML = `<span data-icon="${theme === 'light' ? 'moon' : 'sun'}" aria-hidden="true"></span>`;
  mountIcons(btn);
}

function wireThemeToggle() {
  const saved = localStorage.getItem('wardline-theme') || 'dark';
  applyTheme(saved);
  document.getElementById('theme-toggle-btn').addEventListener('click', () => {
    const current = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
    applyTheme(current === 'light' ? 'dark' : 'light');
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
  wireActivityInteractions();
  wireCredentials();
  wireTopbar();
  wireThemeToggle();
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
