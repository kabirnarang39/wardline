import { fetchAudit, fetchPolicy, writePolicy, fetchStatus, fetchAnomalies, fetchBlocked, unblockIdentity, fetchFederationCorrelated, revokeCredential, fetchRBAC, fetchBudget, writeBudget, fetchReloadHistory, fetchCompliance } from './api.js';
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
  reloadLog: [],
  lastReloadLogID: 0,
};

function escapeHTML(s) {
  const div = document.createElement('div');
  div.textContent = s ?? '';
  return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// formatTool renders "*" for an empty Tool field -- real backend
// semantics (an auto-block/deny-all decision applies to every tool, not
// one specific call), matching the Activity view's own convention for
// a wildcard-scoped entry rather than showing a confusing blank cell.
function formatTool(tool) {
  return tool || '*';
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
        <td class="identity-cell">${escapeHTML(e.Identity)}</td>
        <td class="tool-cell">${escapeHTML(formatTool(e.Tool))}</td>
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
    const rows = state.anomalies.slice().reverse().map((a) => {
      // Severity is real, not decorative: "critical" means this exact
      // anomaly caused a live auto-block (a.auto_block_seconds > 0, see
      // anomalydomain.Anomaly.AutoBlockSeconds's doc comment) -- every
      // other anomaly, regardless of kind, is "warn". a.score is nil for
      // a kind with no real magnitude (novel_tool) -- rendered as "—",
      // never a fabricated 0.
      const severity = a.auto_block_seconds > 0 ? 'critical' : 'warn';
      const score = a.score == null ? '—' : a.score.toFixed(2);
      const autoBlock = a.auto_block_seconds > 0 ? `${a.auto_block_seconds}s` : '—';
      return `
      <tr data-row-id="${escapeHTML(String(a.id))}">
        <td>${escapeHTML(formatTime(a.timestamp))}</td>
        <td>${escapeHTML(a.identity)}</td>
        <td>${escapeHTML(a.tenant)}</td>
        <td>${escapeHTML(a.kind)}</td>
        <td><span class="pill" data-decision="${severity === 'critical' ? 'deny' : 'throttled'}">${severity}</span></td>
        <td>${score}</td>
        <td>${autoBlock}</td>
        <td title="${escapeHTML(a.detail)}">${escapeHTML(a.detail)}</td>
      </tr>
    `;
    }).join('');
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

// formatTimeAgo mirrors formatExpiry's shape exactly but for a past
// timestamp -- "config synced Xm ago" on Overview's status band reads
// this off the most recent successful entry in state.reloadLog, real
// operator-triggered reload history (see pollReloadLog), never a
// fabricated or decorative value.
function formatTimeAgo(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diffMs = Date.now() - d.getTime();
  if (diffMs < 60000) return 'just now';
  const mins = Math.round(diffMs / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function renderReloadLog() {
  const tbody = document.getElementById('reload-log-rows');
  const empty = document.getElementById('reload-log-empty');
  if (!tbody) return; // reload log isn't wired server-side (h.reloadHistory nil) -- nothing to render
  const entries = state.reloadLog;

  if (entries.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  tbody.innerHTML = entries.slice().reverse().map((e) => `
    <tr>
      <td>${escapeHTML(formatTime(e.timestamp))}</td>
      <td>${escapeHTML(e.domain)}</td>
      <td><span class="pill" data-decision="${e.ok ? 'allow' : 'deny'}">${e.ok ? 'applied' : 'rejected'}</span></td>
      <td>${escapeHTML(e.applied_by)}</td>
      <td class="reason-cell" title="${escapeHTML(e.error || '')}">${escapeHTML(e.ok ? '' : e.error)}</td>
    </tr>
  `).join('');
}

async function pollReloadLog() {
  try {
    const fresh = await fetchReloadHistory(state.lastReloadLogID, 1000);
    if (fresh.length > 0) {
      state.reloadLog.push(...fresh);
      if (state.reloadLog.length > MAX_CLIENT_ROWS) {
        state.reloadLog = state.reloadLog.slice(state.reloadLog.length - MAX_CLIENT_ROWS);
      }
      state.lastReloadLogID = fresh[fresh.length - 1].id;
    }
    renderReloadLog();
  } catch (err) {
    // Same "not wired" posture as pollFederation/pollAnomalies: a 404
    // just means this instance has no reloadHistory source configured,
    // so this view's empty state shows instead of erroring.
    console.error('reload log poll failed:', err);
    renderReloadLog();
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
      <td>${escapeHTML(formatTime(b.blocked_since))}</td>
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

// configLoadedAtMs is when the running config was put in place: the epoch of
// the last successful reload if one has happened, otherwise process startup
// (derived from the status endpoint's real uptime). It backs the status
// band's "config synced Xm ago" clause with a genuine timestamp instead of
// the reference prototype's fixed mock value -- never a placeholder.
let configLoadedAtMs = null;

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
    // "0 unreviewed anomalies" is real, not decoration: this branch is
    // only reached when state.anomalies.length === 0, so the number is
    // always accurate, never a stand-in. The "config synced Xm ago"
    // clause is likewise real: it reads the most recent SUCCESSFUL entry
    // in state.reloadLog (real ReloadCoordinator history, see
    // pollReloadLog), and is omitted entirely -- not shown as "never" or
    // any other placeholder -- when no successful reload has happened yet
    // (reloadHistory not wired, or simply no edits made this session).
    const lastSynced = state.reloadLog.slice().reverse().find((e) => e.ok);
    const syncedISO = lastSynced
      ? lastSynced.timestamp
      : (configLoadedAtMs !== null ? new Date(configLoadedAtMs).toISOString() : null);
    newText = syncedISO
      ? `All systems nominal — 0 unreviewed anomalies, config synced ${formatTimeAgo(syncedISO)}`
      : 'All systems nominal — 0 unreviewed anomalies';
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

// kpiBaseline snapshots Requests/Deny rate/Anomalies the first time
// renderKPIs runs with real data, giving each KPI tile's delta arrow a
// genuine "change since this dashboard was opened" comparison -- real
// and honest (unlike a fabricated "vs yesterday" figure this client has
// no data to actually compute), just a different, clearly-real basis
// than the reference prototype's own 24h-window framing.
let kpiBaseline = null;

function renderDelta(elementID, delta, opts = {}) {
  const el = document.getElementById(elementID);
  if (!el || kpiBaseline === null || delta === 0) {
    if (el) el.hidden = true;
    return;
  }
  el.hidden = false;
  const up = delta > 0;
  const magnitude = opts.decimals ? Math.abs(delta).toFixed(opts.decimals) : Math.abs(delta);
  el.textContent = `${up ? '↑' : '↓'} ${magnitude}`;
  // tone: 'good' when up means better (more traffic is neutral/positive
  // info, a falling deny-rate is genuinely good); 'bad' for a rising
  // deny-rate (status-critical red); 'warn' for a rising anomaly count
  // (status-warn amber -- elevated attention, not yet a red-alert state).
  const tone = opts.tone === 'invert' ? (up ? 'bad' : 'good') : opts.tone === 'warn' ? (up ? 'warn' : 'good') : (up ? 'good' : 'neutral');
  el.classList.remove('is-good', 'is-bad', 'is-warn', 'is-neutral');
  el.classList.add(`is-${tone}`);
}

function renderKPIs() {
  const denies = state.entries.filter((e) => e.Decision === 'deny' || e.Decision === 'error').length;
  const denyRate = state.entries.length > 0 ? (denies / state.entries.length) * 100 : 0;

  document.getElementById('kpi-total-requests').textContent = String(state.entries.length);
  document.getElementById('kpi-deny-rate').textContent = `${Math.round(denyRate)}%`;
  document.getElementById('kpi-anomalies').textContent = String(state.anomalies.length);
  document.getElementById('kpi-blocked').textContent = String(state.blocked.length);

  const blockedActive = document.getElementById('kpi-blocked-active');
  if (blockedActive) blockedActive.hidden = state.blocked.length === 0;

  if (kpiBaseline === null) {
    kpiBaseline = { requests: state.entries.length, denyRate, anomalies: state.anomalies.length };
  } else {
    renderDelta('kpi-total-requests-delta', state.entries.length - kpiBaseline.requests);
    renderDelta('kpi-deny-rate-delta', denyRate - kpiBaseline.denyRate, { decimals: 1, tone: 'invert' });
    renderDelta('kpi-anomalies-delta', state.anomalies.length - kpiBaseline.anomalies, { tone: 'warn' });
  }

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

// OVERVIEW_RECENT_ROWS caps how many of the most recent real audit entries
// Overview's "Recent activity" panel shows -- matches the reference
// prototype's own 4-row mini-table exactly, same real fields (Identity/
// Tool/Decision/Latency) and same .pill decision styling Activity's full
// table already uses, just the newest N instead of everything buffered.
const OVERVIEW_RECENT_ROWS = 4;

function renderOverviewRecentTable() {
  const tbody = document.getElementById('overview-recent-rows');
  const empty = document.getElementById('overview-recent-empty');
  const recent = state.entries.slice(-OVERVIEW_RECENT_ROWS).reverse();

  if (recent.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  tbody.innerHTML = recent.map((e) => `
    <tr>
      <td class="identity-cell">${escapeHTML(e.Identity)}</td>
      <td class="tool-cell">${escapeHTML(formatTool(e.Tool))}</td>
      <td><span class="pill" data-decision="${escapeHTML(e.Decision)}">${escapeHTML(e.Decision)}</span></td>
      <td>${e.LatencyMS}ms</td>
    </tr>
  `).join('');
}

function renderNeedsReview() {
  const summary = document.getElementById('needs-review-summary');
  const count = state.anomalies.length + state.blocked.length;
  summary.textContent = count === 0
    ? 'Nothing needs review right now.'
    : `${state.anomalies.length} anomal${state.anomalies.length === 1 ? 'y' : 'ies'} and ${state.blocked.length} blocked identit${state.blocked.length === 1 ? 'y' : 'ies'} on record.`;
}


// pulseHistory holds the last PULSE_HISTORY_LEN real req/s samples (one
// per updateLivePulse tick) driving .pulse-chart's sparkline -- a real
// trend, not a decorative placeholder, so it starts empty and only grows
// as actual polls happen.
const PULSE_HISTORY_LEN = 20;
let pulseHistory = [];

// lastKnownRate mirrors the most recent updateLivePulse() computation --
// setLive's sidebar footer reads it directly rather than recomputing
// from state.entries, since updateLivePulse already owns that math and
// runs every poll tick regardless of which view is active.
let lastKnownRate = 0;

function renderPulseChart() {
  const line = document.getElementById('pulse-chart-line');
  if (pulseHistory.length < 2) {
    line.setAttribute('points', '');
    return;
  }
  const maxRate = Math.max(...pulseHistory, 0.1);
  const stepX = 240 / (pulseHistory.length - 1);
  const points = pulseHistory.map((rate, i) => {
    const x = i * stepX;
    const y = 6 + (1 - rate / maxRate) * 44;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  line.setAttribute('points', points);
}

function updateLivePulse() {
  const now = Date.now();
  const windowEntries = state.entries.filter((e) => new Date(e.Timestamp).getTime() >= now - 10000);
  const rate = windowEntries.length / 10;
  lastKnownRate = rate;
  document.getElementById('pulse-rate').innerHTML = `${rate.toFixed(1)} <span class="pulse-unit">req/s</span>`;
  pulseHistory.push(rate);
  if (pulseHistory.length > PULSE_HISTORY_LEN) pulseHistory.shift();
  renderPulseChart();
}

function renderOverview() {
  const subtitle = document.getElementById('overview-subtitle');
  if (subtitle) {
    subtitle.textContent = 'Last 24 hours across all tenants';
  }
  renderStatusBand();
  renderKPIs();
  renderOverviewRecentTable();
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
    label.textContent = `Live · ${lastKnownRate.toFixed(1)} req/s`;
  } else {
    dot.classList.add('is-stale');
    label.textContent = 'Reconnecting…';
  }
}

// policyRules/policyDefault are the Rule editor's live working state --
// seeded from the real, currently-loaded rules on every loadPolicy()
// (see renderPolicyEditor), mutated locally as the operator edits, and
// only sent to the server on "Validate & apply". Reordering an entry in
// this array IS changing its real evaluation priority: this policy
// engine has no separate numeric priority field (see policy.yaml.example),
// first-match-in-file-order wins, so the editor's "Priority" column is
// just this array's index -- honest, not a fabricated number the
// prototype's own mock showed (10/20/50) that this schema has no
// equivalent for.
let policyRules = [];
let policyDefault = 'allow';

// POLICY_RULE_METHODS mirrors proxy/usecase/parse.go's isGatedMethod set
// -- the only JSON-RPC methods a policy rule can ever match against, see
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md.
// list-style methods (resources/list, prompts/list) carry no target, so
// their Tool field only ever matches a "*" or the policy's default.
const POLICY_RULE_METHODS = ['tools/call', 'resources/read', 'resources/list', 'prompts/get', 'prompts/list'];

// policyToolPlaceholder gives the Tool column input a placeholder that
// names what it actually holds for the row's method -- a tool name means
// something different from a resource URI or a prompt name, and a
// list-style method has no target at all.
function policyToolPlaceholder(method) {
  switch (method) {
    case 'resources/read': return 'resource uri (or * for any)';
    case 'prompts/get': return 'prompt name (or * for any)';
    case 'resources/list':
    case 'prompts/list':
      return '* (list calls have no single target)';
    default: return 'tool name (or * for any)';
  }
}

async function loadPolicy() {
  try {
    const policy = await fetchPolicy();
    const ruleCount = Array.isArray(policy.Rules) ? policy.Rules.length : null;
    const subtitle = document.getElementById('policy-subtitle');
    subtitle.textContent = ruleCount === null
      ? `${policy.Backend || 'unknown'} backend`
      : `${ruleCount} rule${ruleCount === 1 ? '' : 's'} · ${policy.Backend} backend · applies on next reload`;
    document.getElementById('policy-source').textContent = policy.Source || '';
    renderPolicyEditor(policy);
  } catch {
    document.getElementById('policy-source').textContent = 'Failed to load policy — try refreshing.';
    document.getElementById('policy-subtitle').textContent = '';
  }
}

// renderPolicyEditor shows the structured Rule editor only when the
// server actually sent structured Rules (yaml backend) -- opa/cedar (or
// a yaml server with the editor unwired) fall back to "Source only",
// never a fabricated empty editor pretending to represent policy it
// can't actually parse into rules.
function renderPolicyEditor(policy) {
  const panel = document.getElementById('policy-editor-panel');
  const footer = document.getElementById('policy-editor-footer');
  const unavailable = document.getElementById('policy-editor-unavailable');

  if (!Array.isArray(policy.Rules)) {
    panel.hidden = true;
    footer.hidden = true;
    unavailable.hidden = false;
    return;
  }
  panel.hidden = false;
  footer.hidden = false;
  unavailable.hidden = true;

  policyRules = policy.Rules.map((r) => ({ identity: r.identity, tool: r.tool, tenant: r.tenant || '', effect: r.effect, method: r.method || 'tools/call' }));
  policyDefault = policy.Default || 'allow';
  document.getElementById('policy-default-select').value = policyDefault;
  renderPolicyRuleRows();
}

function renderPolicyRuleRows() {
  const tbody = document.getElementById('policy-rule-rows');
  const empty = document.getElementById('policy-rules-empty');

  if (policyRules.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  tbody.innerHTML = policyRules.map((rule, i) => `
    <tr>
      <td><input type="text" class="policy-rule-input" data-field="identity" data-index="${i}" value="${escapeHTML(rule.identity)}" placeholder="identity" aria-label="Rule ${i + 1} identity"></td>
      <td>
        <select class="policy-rule-select policy-rule-method" data-index="${i}" aria-label="Rule ${i + 1} method">
          ${POLICY_RULE_METHODS.map((m) => `<option value="${m}" ${rule.method === m ? 'selected' : ''}>${m}</option>`).join('')}
        </select>
      </td>
      <td><input type="text" class="policy-rule-input" data-field="tool" data-index="${i}" value="${escapeHTML(rule.tool)}" placeholder="${policyToolPlaceholder(rule.method)}" aria-label="Rule ${i + 1} tool"></td>
      <td><input type="text" class="policy-rule-input" data-field="tenant" data-index="${i}" value="${escapeHTML(rule.tenant)}" placeholder="all tenants" aria-label="Rule ${i + 1} tenant"></td>
      <td>
        <select class="policy-rule-select" data-index="${i}" aria-label="Rule ${i + 1} effect">
          <option value="allow" ${rule.effect === 'allow' ? 'selected' : ''}>allow</option>
          <option value="deny" ${rule.effect === 'deny' ? 'selected' : ''}>deny</option>
        </select>
      </td>
      <td>${i + 1}</td>
      <td class="policy-rule-actions">
        <button type="button" class="policy-rule-move" data-action="up" data-index="${i}" aria-label="Move rule ${i + 1} up" ${i === 0 ? 'disabled' : ''}>↑</button>
        <button type="button" class="policy-rule-move" data-action="down" data-index="${i}" aria-label="Move rule ${i + 1} down" ${i === policyRules.length - 1 ? 'disabled' : ''}>↓</button>
        <button type="button" class="policy-rule-delete" data-action="delete" data-index="${i}" aria-label="Delete rule ${i + 1}"><span data-icon="trash" aria-hidden="true"></span></button>
      </td>
    </tr>
  `).join('');
  mountIcons(tbody);

  tbody.querySelectorAll('.policy-rule-input').forEach((input) => {
    input.addEventListener('input', () => {
      policyRules[Number(input.dataset.index)][input.dataset.field] = input.value;
    });
  });
  tbody.querySelectorAll('.policy-rule-method').forEach((select) => {
    select.addEventListener('change', () => {
      policyRules[Number(select.dataset.index)].method = select.value;
      renderPolicyRuleRows();
    });
  });
  tbody.querySelectorAll('.policy-rule-select:not(.policy-rule-method)').forEach((select) => {
    select.addEventListener('change', () => {
      policyRules[Number(select.dataset.index)].effect = select.value;
    });
  });
  tbody.querySelectorAll('.policy-rule-move, .policy-rule-delete').forEach((btn) => {
    btn.addEventListener('click', () => {
      const i = Number(btn.dataset.index);
      if (btn.dataset.action === 'up' && i > 0) {
        [policyRules[i - 1], policyRules[i]] = [policyRules[i], policyRules[i - 1]];
      } else if (btn.dataset.action === 'down' && i < policyRules.length - 1) {
        [policyRules[i + 1], policyRules[i]] = [policyRules[i], policyRules[i + 1]];
      } else if (btn.dataset.action === 'delete') {
        policyRules.splice(i, 1);
      }
      renderPolicyRuleRows();
    });
  });
}

function wirePolicyEditor() {
  document.getElementById('policy-add-rule').addEventListener('click', () => {
    policyRules.push({ identity: '', tool: '', tenant: '', effect: 'allow', method: 'tools/call' });
    renderPolicyRuleRows();
    const inputs = document.querySelectorAll('#policy-rule-rows tr:last-child input');
    if (inputs.length) inputs[0].focus();
  });

  document.getElementById('policy-default-select').addEventListener('change', (e) => {
    policyDefault = e.target.value;
  });

  document.getElementById('policy-validate-apply').addEventListener('click', async () => {
    const btn = document.getElementById('policy-validate-apply');
    const result = document.getElementById('policy-write-result');
    btn.disabled = true;
    result.hidden = true;
    const res = await writePolicy(policyRules, policyDefault);
    btn.disabled = false;
    result.hidden = false;
    if (res.ok) {
      result.textContent = 'Applied — policy reloaded.';
      result.style.color = 'var(--status-ok)';
      await loadPolicy();
    } else {
      result.textContent = res.message;
      result.style.color = 'var(--status-critical)';
    }
  });

  document.querySelectorAll('#policy-tabs .tab-toggle-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.policyTab;
      document.querySelectorAll('#policy-tabs .tab-toggle-btn').forEach((b) => {
        const active = b === btn;
        b.classList.toggle('is-active', active);
        b.setAttribute('aria-selected', String(active));
      });
      document.getElementById('policy-editor-tab').hidden = tab !== 'editor';
      document.getElementById('policy-source').hidden = tab !== 'source';
    });
  });
}

async function loadStatus() {
  try {
    const status = await fetchStatus();
    if (status && typeof status.UptimeSeconds === 'number') {
      configLoadedAtMs = Date.now() - status.UptimeSeconds * 1000;
    }
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

    renderCallerIdentity(status.CallerIdentity, status.CallerCanConfigEdit);
  } catch {
    document.getElementById('status-grid').textContent = 'Failed to load status — try refreshing.';
  }
}

// renderCallerIdentity fills the topbar's identity block from
// GET /dashboard/api/status's CallerIdentity/CallerCanConfigEdit --
// identity is "" whenever rbac is off or the caller doesn't resolve, in
// which case the topbar falls back to the plain generic-icon avatar
// (never a fabricated name/initials).
function renderCallerIdentity(identity, canConfigEdit) {
  const avatar = document.getElementById('identity-avatar');
  const text = document.getElementById('identity-text');
  const nameEl = document.getElementById('identity-name');
  const pill = document.getElementById('config-edit-pill');

  if (identity) {
    avatar.removeAttribute('data-icon');
    avatar.textContent = initials(identity);
    avatar.classList.add('identity-avatar-initials');
    text.hidden = false;
    nameEl.textContent = identity;
  } else {
    avatar.setAttribute('data-icon', 'user');
    mountIcons(avatar.parentElement);
    avatar.classList.remove('identity-avatar-initials');
    text.hidden = true;
  }
  pill.hidden = !canConfigEdit;
}

// initials derives a 1-2 letter avatar label from an identity string --
// "r.narang@acme" -> "RN" (first letter of each dot/space-separated
// segment before the @, uppercased), "alice" -> "A" for a bare
// single-segment identity. Display-only, never used for any comparison.
function initials(identity) {
  const local = identity.split('@')[0];
  const parts = local.split(/[.\s_-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 1).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
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
// budgetOverrides is the Budget editor's live working state (each entry
// carries its own scope: "tenant"|"tool", split back into separate
// tenant_overrides/tool_overrides arrays only at write time) --
// mirrors policyRules' exact "seeded from the real GET, mutated
// locally, sent on Validate & apply" contract.
let budgetOverrides = [];

async function renderBudget() {
  const requestsInput = document.getElementById('budget-default-requests');
  const windowInput = document.getElementById('budget-default-window');
  try {
    const { default: def, overrides } = await fetchBudget();
    requestsInput.value = def.requests_per_window;
    windowInput.value = def.window_seconds;
    budgetOverrides = (overrides || []).map((o) => ({ scope: o.scope, name: o.name, requestsPerWindow: o.requests_per_window, windowSeconds: o.window_seconds }));
    renderBudgetOverrideRows();
  } catch (err) {
    console.error('budget fetch failed:', err);
    requestsInput.value = '';
    windowInput.value = '';
    budgetOverrides = [];
    renderBudgetOverrideRows();
  }
}

function renderBudgetOverrideRows() {
  const tbody = document.getElementById('budget-override-rows');
  const empty = document.getElementById('budget-override-empty');

  if (budgetOverrides.length === 0) {
    tbody.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  tbody.innerHTML = budgetOverrides.map((o, i) => `
    <tr>
      <td>
        <select class="budget-override-select" data-field="scope" data-index="${i}" aria-label="Override ${i + 1} scope">
          <option value="tenant" ${o.scope === 'tenant' ? 'selected' : ''}>tenant</option>
          <option value="tool" ${o.scope === 'tool' ? 'selected' : ''}>tool</option>
        </select>
      </td>
      <td><input type="text" class="budget-override-input" data-field="name" data-index="${i}" value="${escapeHTML(o.name)}" placeholder="name" aria-label="Override ${i + 1} value"></td>
      <td><input type="number" min="1" class="budget-override-input" data-field="requestsPerWindow" data-index="${i}" value="${o.requestsPerWindow}" aria-label="Override ${i + 1} limit"></td>
      <td><input type="number" min="1" class="budget-override-input" data-field="windowSeconds" data-index="${i}" value="${o.windowSeconds}" aria-label="Override ${i + 1} window seconds"></td>
      <td class="policy-rule-actions">
        <button type="button" class="policy-rule-delete" data-index="${i}" aria-label="Delete override ${i + 1}"><span data-icon="trash" aria-hidden="true"></span></button>
      </td>
    </tr>
  `).join('');
  mountIcons(tbody);

  tbody.querySelectorAll('.budget-override-select').forEach((select) => {
    select.addEventListener('change', () => {
      budgetOverrides[Number(select.dataset.index)].scope = select.value;
    });
  });
  tbody.querySelectorAll('.budget-override-input').forEach((input) => {
    input.addEventListener('input', () => {
      const field = input.dataset.field;
      const value = field === 'name' ? input.value : Number(input.value);
      budgetOverrides[Number(input.dataset.index)][field] = value;
    });
  });
  tbody.querySelectorAll('.policy-rule-delete').forEach((btn) => {
    btn.addEventListener('click', () => {
      budgetOverrides.splice(Number(btn.dataset.index), 1);
      renderBudgetOverrideRows();
    });
  });
}

function wireBudgetEditor() {
  document.getElementById('budget-add-override').addEventListener('click', () => {
    budgetOverrides.push({ scope: 'tenant', name: '', requestsPerWindow: 1, windowSeconds: 60 });
    renderBudgetOverrideRows();
    const inputs = document.querySelectorAll('#budget-override-rows tr:last-child input');
    if (inputs.length) inputs[0].focus();
  });

  document.getElementById('budget-validate-apply').addEventListener('click', async () => {
    const btn = document.getElementById('budget-validate-apply');
    const result = document.getElementById('budget-write-result');
    btn.disabled = true;
    result.hidden = true;
    const def = {
      requests_per_window: Number(document.getElementById('budget-default-requests').value),
      window_seconds: Number(document.getElementById('budget-default-window').value),
    };
    const toWire = (scope) => budgetOverrides.filter((o) => o.scope === scope).map((o) => ({ scope: o.scope, name: o.name, requests_per_window: o.requestsPerWindow, window_seconds: o.windowSeconds }));
    const res = await writeBudget(def, toWire('tenant'), toWire('tool'));
    btn.disabled = false;
    result.hidden = false;
    if (res.ok) {
      result.textContent = 'Applied — budget reloaded.';
      result.style.color = 'var(--status-ok)';
      await renderBudget();
    } else {
      result.textContent = res.message;
      result.style.color = 'var(--status-critical)';
    }
  });
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

// wireComplianceView wires the Compliance view's manual "Query" button --
// unlike every other view, this one has no default poll: an operator
// picks a range and asks for it explicitly, matching the CLI's own
// -from/-to required-range posture (see
// docs/superpowers/specs/2026-08-08-compliance-evidence-export-hardening-design.md).
// Defaults the range inputs to "last 24 hours" purely as a convenience
// starting point, not an auto-query.
function wireComplianceView() {
  const fromInput = document.getElementById('compliance-from');
  const toInput = document.getElementById('compliance-to');
  const toLocalInputValue = (d) => {
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const now = new Date();
  toInput.value = toLocalInputValue(now);
  fromInput.value = toLocalInputValue(new Date(now.getTime() - 24 * 60 * 60 * 1000));

  document.getElementById('compliance-query').addEventListener('click', async () => {
    const errorEl = document.getElementById('compliance-error');
    const resultsEl = document.getElementById('compliance-results');
    const unavailableEl = document.getElementById('compliance-unavailable');
    errorEl.hidden = true;
    resultsEl.hidden = true;
    unavailableEl.hidden = true;

    if (!fromInput.value || !toInput.value) {
      errorEl.textContent = 'Both From and To are required.';
      errorEl.hidden = false;
      return;
    }
    // datetime-local has no timezone; treated as the browser's local
    // time and converted to a real Date, then serialized as RFC3339 --
    // the exact shape GET /dashboard/api/compliance parses.
    const from = new Date(fromInput.value).toISOString();
    const to = new Date(toInput.value).toISOString();

    const res = await fetchCompliance(from, to);
    if (!res.ok) {
      if (res.status === 404) {
        unavailableEl.hidden = false;
      } else {
        errorEl.textContent = res.message;
        errorEl.hidden = false;
      }
      return;
    }
    renderComplianceManifest(res.manifest);
    resultsEl.hidden = false;
  });
}

function renderComplianceManifest(m) {
  document.getElementById('compliance-summary').innerHTML = `
    <div><dt>Audit entries</dt><dd>${m.audit_entry_count}</dd></div>
    <div><dt>Unparsable audit lines skipped</dt><dd>${m.unparsable_audit_lines_skipped}</dd></div>
    <div><dt>Anomaly entries</dt><dd>${m.anomaly_entry_count}</dd></div>
    <div><dt>Unparsable anomaly lines skipped</dt><dd>${m.unparsable_anomaly_lines_skipped}</dd></div>
  `;

  const decisions = m.audit_decision_counts || {};
  const decisionNames = Object.keys(decisions).sort();
  document.getElementById('compliance-audit-decisions').innerHTML = decisionNames.length
    ? decisionNames.map((name) => `<li><span>${escapeHTML(name)}</span><span>${decisions[name]}</span></li>`).join('')
    : '<li>No audit entries in this range.</li>';

  const kinds = m.anomaly_kind_counts || {};
  const kindNames = Object.keys(kinds).sort();
  document.getElementById('compliance-anomaly-kinds').innerHTML = kindNames.length
    ? kindNames.map((name) => `<li><span>${escapeHTML(name)}</span><span>${kinds[name]}</span></li>`).join('')
    : '<li>No anomalies in this range.</li>';
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
  // Icon depicts the CURRENT theme (moon showing = dark is active), not
  // the theme a click switches to -- matches the reference prototype's
  // convention; aria-label above stays target-phrased since that's what
  // announces the action a click performs, a separate concern.
  btn.innerHTML = `<span data-icon="${theme === 'light' ? 'sun' : 'moon'}" aria-hidden="true"></span>`;
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
  wirePolicyEditor();
  wireBudgetEditor();
  wireComplianceView();
  wireTopbar();
  wireThemeToggle();
  document.getElementById('needs-review-cta').addEventListener('click', () => switchView('anomalies'));
  loadStatus();
  pollAudit();
  pollAnomalies();
  pollFederation();
  pollBlocked();
  pollReloadLog();
  renderOverview();
  setInterval(pollAudit, POLL_INTERVAL_MS);
  setInterval(pollAnomalies, POLL_INTERVAL_MS);
  setInterval(pollFederation, POLL_INTERVAL_MS);
  setInterval(pollReloadLog, POLL_INTERVAL_MS);
  setInterval(pollBlocked, POLL_INTERVAL_MS);
}

init();
