import { fetchAudit, fetchPolicy, fetchStatus } from './api.js';
import { mountIcons } from './icons.js';

const POLL_INTERVAL_MS = 2000;
const MAX_CLIENT_ROWS = 500;

const state = {
  entries: [],
  lastID: 0,
  filters: { identity: '', tool: '', decisions: new Set() },
  lastPollOK: null,
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
  const rows = visible.slice().reverse().map((e) => `
    <tr>
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
}

async function pollAudit() {
  try {
    const fresh = await fetchAudit(state.lastID, 200);
    if (fresh.length > 0) {
      state.entries.push(...fresh);
      if (state.entries.length > MAX_CLIENT_ROWS) {
        state.entries = state.entries.slice(state.entries.length - MAX_CLIENT_ROWS);
      }
      state.lastID = fresh[fresh.length - 1].ID;
      renderActivity();
    }
    setLive(true);
  } catch {
    setLive(false);
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

function init() {
  mountIcons(document);
  wireNav();
  wireFilters();
  pollAudit();
  setInterval(pollAudit, POLL_INTERVAL_MS);
}

init();
