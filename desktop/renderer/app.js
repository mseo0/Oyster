'use strict';
// Oyster renderer — talks to the Python engine via window.oyster (preload).

const api = window.oyster;

// Apply platform class immediately (synchronous, no async needed) so CSS
// Windows overrides are active before the first paint.
if (api.platform === 'win32') document.documentElement.classList.add('platform-win32');
const SEV = { critical: '#E5484D', high: '#F5820A', medium: '#E5B003', low: '#17A98C', info: '#8E938A' };
const sevLabel = (s) => ({ critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' }[s] || s.toUpperCase());
const procColor = (n) => n >= 70 ? SEV.critical : n >= 40 ? SEV.high : n >= 20 ? SEV.medium : SEV.info;
const tint = (hex, a) => { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`; };
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const ICON = {
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><path d="M9 2.5v2M15 2.5v2M9 19.5v2M15 19.5v2M2.5 9h2M2.5 15h2M19.5 9h2M19.5 15h2"/>',
  shield: '<path d="M12 3l7 2.6v5.1c0 4.3-3 7.4-7 8.8-4-1.4-7-4.5-7-8.8V5.6z"/>',
  spark: '<path d="M12 3l1.7 4.9L18.7 9l-4.9 1.7L12 16l-1.7-5.3L5.3 9l5-1.1z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  deep: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5"/>',
  broom: '<path d="M19.4 4.6 13 11M11 8l5 5M8.5 10.5 3 16c-1 1-1 3 0 4s3 1 4 0l5.5-5.5M4 21l3-1"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  sort: '<path d="M3 6h13M3 12h9M3 18h5M17 9l3 3 3-3M20 12V4"/>',
  apps: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
};
const ic = (k, w = 18) => `<svg width="${w}" height="${w}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICON[k]}</svg>`;

const NAV = [
  { key: 'Files', icon: 'folder', sub: 'On-demand file scan with reversible quarantine.', sec: 'scan' },
  { key: 'Processes', icon: 'cpu', sub: 'Running programs, scored by suspicious behaviour.', sec: 'scan' },
  { key: 'Vulnerabilities', icon: 'shield', sub: 'Installed software & OS settings vs. offline CVE data.', sec: 'scan' },
  { key: 'Cleanup', icon: 'broom', sub: 'Find junk, duplicates & clutter — organize with one click.', sec: 'tools' },
  { key: 'Applications', icon: 'apps', sub: 'Clean-uninstall apps — the app plus every related file, reversibly.', sec: 'tools' },
  { key: 'Quarantine', icon: 'trash', sub: 'Files moved to the reversible vault — restore, open, or empty.', sec: 'tools' },
  { key: 'AI Summary', icon: 'spark', sub: 'A plain-English read-out, written locally just now.', sec: 'report' },
];

const S = {
  page: 'Files', model: '…', target: '~/Downloads',
  data: { Files: [], Processes: [], Vulnerabilities: [] },
  sel: { Files: null, Processes: null, Vulnerabilities: null },
  report: null, summary: '', busy: false, scanned: false, downloadedOnly: true,
  organizeTarget: '~/Downloads', organize: null, procTotal: null, apps: null,
  findFilter: 'all', appBusy: null, quar: null, aiOnline: false, aiOnlineWarned: false,
  // multi-select: a Set of the selected finding/process OBJECTS per list (object
  // refs, not indices, so filtering/sorting can't desync the checkboxes).
  checked: { Files: new Set(), Processes: new Set(), Vulnerabilities: new Set() },
};

const $ = (id) => document.getElementById(id);
const content = $('content');

// ---------- init ----------
async function init() {
  buildNav();
  $('gate-recheck').addEventListener('click', refreshGate);
  $('gate-launch').addEventListener('click', launch);
  $('gate-setup').addEventListener('click', runSetup);
  $('full-scan-btn').addEventListener('click', deepScan);

  // Windows custom title bar controls
  if (api.platform === 'win32') {
    $('win-min').addEventListener('click', () => api.winAction('minimize'));
    $('win-max').addEventListener('click', () => api.winAction('maximize'));
    $('win-close').addEventListener('click', () => api.winAction('close'));
  }
  document.querySelectorAll('.seg-btn').forEach((b) =>
    b.addEventListener('click', () => setMode(b.dataset.mode)));
  document.querySelector('.sidebar').addEventListener('click', (e) => {
    const n = e.target.closest('[data-page]'); if (n) showPage(n.dataset.page);
  });
  content.addEventListener('click', onContentClick);
  content.addEventListener('keydown', (e) => {
    if (e.target.id === 'askfile-in' && e.key === 'Enter') askFile();
  });
  // gate "Open Settings" (was dead — no listener on the gate element)
  $('gate').addEventListener('click', (e) => {
    if (e.target.closest('[data-action="open-fda"]')) api.openFDA();
  });
  // stop button lives in the live scan bar
  $('scanbar').addEventListener('click', (e) => {
    if (e.target.closest('[data-action="stop"]') && !scan.canceling) {
      scan.canceling = true;
      api.rpc('cancel');
      setStatus('Stopping…');
      paintScanBar(); // immediately reflect the canceling state
    }
  });
  // cleanup review modal
  $('rv-close').addEventListener('click', closeReview);
  document.addEventListener('keydown', rvKeyNav);   // arrow up/down through the modal list
  document.addEventListener('keydown', listKeyNav); // arrow up/down through the main list
  $('review').addEventListener('click', (e) => {
    if (e.target === $('review')) return closeReview();           // click backdrop
    const rev = e.target.closest('[data-reveal]'); if (rev) return api.reveal(rev.dataset.reveal);
    // shift-click a checkbox: select/deselect the whole range since the last one
    const box = e.target.closest('input[type=checkbox]');
    if (box) {
      if (e.shiftKey && RV.lastPath) rvSelectRange(RV.lastPath, box.dataset.path, box.checked);
      RV.lastPath = box.dataset.path;
      return;   // the change handler updates the single checkbox + count
    }
    // tag tabs are multi-select: "All" clears, the rest toggle in/out
    const tg = e.target.closest('[data-rvtag]');
    if (tg) {
      const k = tg.dataset.rvtag;
      if (k === 'all') RV.tags.clear();
      else if (RV.tags.has(k)) RV.tags.delete(k);
      else RV.tags.add(k);
      return renderReviewBody();
    }
    const all = e.target.closest('[data-rvall]');
    if (all) {
      const on = all.dataset.rvall === '1';
      $('rv-list').querySelectorAll('input[type=checkbox]').forEach((cb) => {
        cb.checked = on; on ? RV.sel.add(cb.dataset.path) : RV.sel.delete(cb.dataset.path);
      });
      return updateRvCount();
    }
    const act = e.target.closest('[data-rvaction]'); if (act) return reviewExecute(act.dataset.rvaction);
  });
  $('review').addEventListener('change', (e) => {
    const cb = e.target.closest('input[type=checkbox]'); if (!cb || !RV) return;
    cb.checked ? RV.sel.add(cb.dataset.path) : RV.sel.delete(cb.dataset.path);
    updateRvCount();
  });
  api.onEvent((m) => {
    if (m.event === 'progress') onProgress(m.data);
    else if (m.event === 'total') { scan.total = m.data; }
  });
  try {
    const h = await api.rpc('hello');
    S.model = h.model; S.target = h.defaultTarget;
    $('model-chip').textContent = 'model · ' + h.model;
  } catch (e) { /* gate still works */ }
  gateLoop();   // auto-check; auto-proceed the moment required checks pass
}

let gateTimer = null;
let setupActive = false, setupOffered = false;
async function gateLoop() {
  const blocked = await refreshGate();
  if (blocked > 0) { gateTimer = setTimeout(gateLoop, 1500); return; }
  // required checks pass — but on first run, offer one-click setup of the
  // scanning definitions + AI model before launching.
  if (!setupOffered) {
    let st = null; try { st = await api.rpc('setup_status'); } catch (e) {}
    if (st && (st.cve === 0 || (st.ollama && !st.modelReady) || !st.clamav)) {
      setupOffered = true;
      $('gate-setup').classList.remove('hidden');
      $('gate-launch').textContent = 'Skip & launch';
      $('gate-msg').textContent = 'Optional: download virus & CVE definitions and a local AI model.';
      $('gate-msg').style.color = 'var(--muted)';
      return;   // wait for the user to choose Set up or Skip
    }
  }
  launch();
}
async function runSetup() {
  setupActive = true;
  $('gate-setup').disabled = true; $('gate-recheck').disabled = true;
  try { await api.rpc('setup_run'); $('gate-msg').textContent = 'Setup complete.'; }
  catch (e) { $('gate-msg').textContent = 'Setup issue: ' + e.message; }
  setupActive = false;
  launch();
}

// ---------- preflight gate ----------
async function refreshGate() {
  let checks = [];
  try { checks = await api.rpc('preflight'); } catch (e) { checks = []; }
  const rows = $('gate-rows');
  rows.innerHTML = checks.map((c) => {
    const color = c.ok ? '#17A98C' : c.required ? '#E5484D' : '#F5820A';
    const label = c.ok ? 'OK' : c.required ? 'REQUIRED' : 'recommended';
    const btn = (!c.ok && c.key === 'fda') ? `<button class="btn primary" data-action="open-fda" style="height:34px">Open Settings</button>` : '';
    return `<div class="g-row"><span class="dot" style="background:${color}"></span>
      <div class="gx"><div class="gn">${esc(c.name)} · <span style="color:${color}">${label}</span></div>
      <div class="gd">${esc(c.detail)}${c.fix ? ' — ' + esc(c.fix) : ''}</div></div>${btn}</div>`;
  }).join('');
  const blocked = checks.filter((c) => c.required && !c.ok);
  $('gate-launch').disabled = blocked.length > 0;
  $('gate-launch').textContent = blocked.length ? 'Waiting for permissions…' : 'Launching…';
  $('gate-msg').textContent = blocked.length
    ? 'Auto-continues the moment Full Disk Access is granted — ' + blocked.map((b) => b.name).join(', ')
    : 'All required permissions granted.';
  $('gate-msg').style.color = blocked.length ? '#E5484D' : '#17A98C';
  return blocked.length;
}
function launch() {
  if (gateTimer) { clearTimeout(gateTimer); gateTimer = null; }
  if ($('gate').classList.contains('hidden')) return;   // already launched
  $('gate').classList.add('hidden'); showPage('Files');
}

// ---------- nav ----------
function buildNav() {
  $('nav-scan').innerHTML = NAV.filter((n) => n.sec === 'scan').map(navBtn).join('');
  $('nav-tools').innerHTML = NAV.filter((n) => n.sec === 'tools').map(navBtn).join('');
  $('nav-report').innerHTML = NAV.filter((n) => n.sec === 'report').map(navBtn).join('');
}
function navBtn(n) {
  return `<button class="nav-btn" data-page="${n.key}">${ic(n.icon)}
    <span class="lbl">${n.key}</span><span class="nav-badge" data-badge="${n.key}"></span></button>`;
}
function updateNav() {
  document.querySelectorAll('.nav-btn').forEach((b) => {
    const on = b.dataset.page === S.page;
    b.classList.toggle('active', on);
    if (b.dataset.page) b.setAttribute('aria-current', on ? 'page' : 'false');
  });
  for (const key of ['Files', 'Processes', 'Vulnerabilities']) {
    const el = document.querySelector(`[data-badge="${key}"]`); if (!el) continue;
    const n = S.data[key].filter((o) => !o.resolved && o.severity !== 'info').length;
    const col = key === 'Processes' ? SEV.high : SEV.critical;
    el.textContent = n ? n : '';
    el.style.background = n ? tint(col, 0.14) : 'transparent';
    el.style.color = col;
  }
}

// ---------- routing ----------
function showPage(key) {
  S.page = key;
  $('h-title').textContent = key;
  $('h-sub').textContent = NAV.find((n) => n.key === key).sub;
  updateNav();
  if (key === 'AI Summary') renderSummary();
  else if (key === 'Cleanup') renderOrganize();
  else if (key === 'Applications') renderApplications();
  else if (key === 'Quarantine') renderQuarantine();
  else renderScan();
}

// ---------- scan view ----------
function renderScan() {
  content.innerHTML = `
    <div class="taskbar panel">${taskbar()}</div>
    <div class="cols">
      <div class="left">
        <div class="strip panel">${strip()}</div>
        <div class="listcard panel">
          <div class="list-head"><span class="t">${listLabel()}</span><span class="r">sorted by severity</span></div>
          ${S.page === 'Files' ? `<div class="find-tabs" id="find-tabs">${findingTabsHtml()}</div>` : ''}
          <div class="bulkbar" id="bulkbar"></div>
          <div class="list-body" id="list"></div>
        </div>
      </div>
      <div class="inspector panel">
        <div class="ins-head"><span class="t">INSPECTOR</span></div>
        <div class="ins-body" id="inspector"></div>
      </div>
    </div>`;
  renderRows(); renderInspector();
  setActionsBusy(S.busy);   // keep buttons disabled if a scan is mid-flight
}

function taskbar() {
  if (S.page === 'Files') return `
    <div class="field"><span style="color:var(--accent);display:flex">${ic('folder', 16)}</span>
      <span class="k">Target</span><span class="v" id="target">${esc(S.target)}</span></div>
    <button class="btn ghost ${S.downloadedOnly ? 'on' : ''}" data-action="toggle-downloaded"
      title="Only flag downloaded files, not ones you created">${S.downloadedOnly ? '✓ ' : ''}Downloaded only</button>
    <button class="btn ghost" data-action="choose">Choose…</button>
    <button class="btn primary" data-action="scan">${ic('search', 15)} Scan</button>
    <button class="btn ghost icon" data-action="deep" title="Deep scan — whole computer">${ic('deep', 16)}</button>`;
  if (S.page === 'Processes') {
    const n = S.data.Processes.length;
    return `<div class="tb-info">${n ? n + ' flagged process(es)' : 'Sweep to inspect running processes'}</div>
      <button class="btn primary" data-action="sweep">${ic('refresh', 15)} Sweep processes</button>`;
  }
  const n = S.data.Vulnerabilities.length;
  return `<div class="tb-info">${n ? n + ' issue(s) found' : 'Audit installed software + OS posture'}</div>
    <button class="btn ghost" data-action="update-defs">${ic('refresh', 15)} Update definitions</button>
    <button class="btn primary" data-action="audit">${ic('shield', 15)} Audit software & OS</button>`;
}

function listLabel() { return { Files: 'FINDINGS', Processes: 'FLAGGED PROCESSES', Vulnerabilities: 'ISSUES' }[S.page]; }

function strip() {
  const d = summaryData();
  const stats = d.stats.map((s) => `<div class="stat"><div class="v">${s.v}</div><div class="l">${s.l}</div></div>`).join('');
  return `<div class="orb"><span class="ring1" style="background:${d.color}"></span>
      <span class="ring2" style="border-color:${d.color}"></span><span class="n" style="color:${d.color}">${d.count}</span></div>
    <div style="min-width:0"><div class="hl">${esc(d.headline)}</div><div class="sub2">${esc(d.sub)}</div></div>
    <div class="stats">${stats}</div>`;
}
function summaryData() {
  if (S.page === 'Files') {
    const f = S.data.Files, n = f.length;
    const crit = f.filter((x) => x.severity === 'critical' || x.severity === 'high').length;
    const color = crit ? SEV.critical : n ? SEV.low : SEV.info;
    const seen = S.report ? S.report.filesSeen : 0, un = S.report ? S.report.filesUnreadable : 0;
    return { count: n, color, headline: n ? 'Review recommended' : 'All clear',
      sub: n ? `${crit} high/critical of ${n} findings` : 'Nothing suspicious in the last scan',
      stats: [{ v: seen.toLocaleString(), l: 'FILES' }, { v: n, l: 'FINDINGS' }, { v: un, l: 'UNREAD' }] };
  }
  if (S.page === 'Processes') {
    const p = S.data.Processes, n = p.length, prot = p.filter((x) => x.protected).length;
    const color = n ? procColor(Math.max(...p.map((x) => x.score))) : SEV.info;
    return { count: n, color, headline: n ? `${n} process(es) flagged` : (S.procTotal != null ? 'All clear' : 'Nothing flagged'),
      sub: S.procTotal != null ? `Swept ${S.procTotal.toLocaleString()} running processes` : 'Sweep to inspect running processes',
      stats: [{ v: (S.procTotal || 0).toLocaleString(), l: 'SWEPT' }, { v: n, l: 'FLAGGED' }, { v: prot, l: 'PROTECTED' }] };
  }
  const v = S.data.Vulnerabilities, n = v.length;
  const cves = v.filter((x) => /cve/i.test(x.rule)).length;
  const color = v.some((x) => x.severity === 'critical' || x.severity === 'high') ? SEV.critical : n ? SEV.low : SEV.info;
  return { count: n, color, headline: n ? `${n} issue(s) found` : 'No known issues',
    sub: n ? `${cves} CVEs, ${n - cves} other` : 'Audit software & OS posture',
    stats: [{ v: n, l: 'ISSUES' }, { v: cves, l: 'CVES' }, { v: n - cves, l: 'OTHER' }] };
}

// per-finding safety recommendation, derived from its severity + suggested
// action — drives the quick-sort tabs on the Files list.
function findingTag(f) {
  if (f.resolved === 'safe' || f.action === 'IGNORE') return 'safe';
  if (f.action === 'QUARANTINE') return 'act';
  return 'review';
}
function findingTabsHtml() {
  const items = S.data.Files;
  const counts = { all: items.length, act: 0, review: 0, safe: 0 };
  items.forEach((f) => counts[findingTag(f)]++);
  const tab = (k, label) => (k === 'all' || counts[k])
    ? `<button class="btn ghost rv-mini rv-tab${S.findFilter === k ? ' on' : ''}" data-action="findtab" data-tag="${k}">${label}${k === 'all' ? '' : ' ' + counts[k]}</button>` : '';
  return `<span class="rv-tabs">${tab('all', 'All')}${tab('act', '🛡 Act')}${tab('review', '⚠ Review')}${tab('safe', '✓ Looks safe')}</span>`;
}

function renderRows() {
  const list = $('list'); const items = S.data[S.page];
  if (!items.length) {
    const msg = {
      Files: 'Run a scan to see findings.',
      Processes: S.procTotal != null ? `✓ Swept ${S.procTotal.toLocaleString()} processes — nothing suspicious flagged.` : 'Sweep to inspect processes.',
      Vulnerabilities: 'Audit to list issues.' }[S.page];
    list.innerHTML = `<div class="empty">${msg}</div>`;
    return;
  }
  // keep original indices so row selection still maps back to S.data
  let rows = items.map((o, i) => [o, i]);
  if (S.page === 'Files' && S.findFilter !== 'all') rows = rows.filter(([o]) => findingTag(o) === S.findFilter);
  list.innerHTML = rows.map(([o, i]) => rowHtml(o, i)).join('')
    || `<div class="empty">No findings in this category.</div>`;
  renderBulkBar();
}

// The currently-VISIBLE rows (respects the Files act/review/safe filter), so
// "Select all" only ever picks what the user can actually see.
function visibleItems() {
  let rows = S.data[S.page];
  if (S.page === 'Files' && S.findFilter !== 'all') rows = rows.filter((o) => findingTag(o) === S.findFilter);
  return rows;
}
// Bulk-action toolbar: appears once one or more rows are checked. The available
// actions depend on the list (quarantine files, suspend/kill processes, ignore
// vulns). Protected/resolved items are skipped by the handlers themselves.
function bulkActionsFor(page) {
  if (page === 'Files') return [
    ['bulk-quarantine', 'danger', 'Quarantine selected'],
    ['bulk-marksafe', 'ghost', 'Mark safe']];
  if (page === 'Processes') return [
    ['bulk-suspend', 'success', 'Suspend selected'],
    ['bulk-kill', 'danger', 'Kill selected']];
  return [['bulk-ignore', 'ghost', 'Ignore selected']];
}
function renderBulkBar() {
  const bar = $('bulkbar'); if (!bar) return;
  const set = S.checked[S.page];
  const n = set.size;
  if (!n) { bar.classList.remove('show'); bar.innerHTML = ''; return; }
  bar.classList.add('show');
  const vis = visibleItems().length;
  const acts = bulkActionsFor(S.page)
    .map(([a, k, label]) => `<button class="btn ${k} sm" data-action="${a}">${label}</button>`).join('');
  bar.innerHTML = `<span class="bulk-n">${n} selected</span>
    <button class="btn ghost sm" data-action="check-all">${n >= vis ? 'Clear all' : 'Select all (' + vis + ')'}</button>
    <span class="bulk-sp"></span>${acts}`;
}
function checkbox(o, i) {
  const on = S.checked[S.page].has(o);
  return `<span class="rowcheck${on ? ' on' : ''}" data-action="check" data-idx="${i}"
    role="checkbox" aria-checked="${on}" title="Select for a bulk action">${on ? '✓' : ''}</span>`;
}
function rowHtml(o, i) {
  const sel = S.sel[S.page] === o ? ' sel' : '';
  if (S.page === 'Processes') {
    const c = procColor(o.score);
    return `<button class="row${sel}" data-action="select" data-idx="${i}">
      ${checkbox(o, i)}<span class="sq" style="background:${tint(c, 0.16)};color:${c}">${o.score}</span>
      <span class="body"><span class="name">${esc(o.name)}<span class="pid">pid ${o.pid}</span>${o.protected ? '<span class="tag">PROTECTED</span>' : ''}</span>
      <span class="meta">${esc(o.reasons.join('; ') || '—')}</span></span></button>`;
  }
  const c = SEV[o.severity] || SEV.info;
  const title = S.page === 'Files' ? o.name : vulnTitle(o);
  const meta = S.page === 'Files' ? `${esc(o.dir)} · ${esc(o.rule)}` : `${esc(o.target)} — ${esc(o.detail || o.rule)}`;
  const done = o.resolved ? ' resolved' : '';
  const RESLABEL = { safe: 'SAFE', quarantined: 'QUAR', ignored: 'IGNORED' };
  const chip = o.resolved
    ? `<span class="chip" style="background:${tint('#17A98C', 0.16)};color:#17A98C">${RESLABEL[o.resolved] || 'DONE'}</span>`
    : `<span class="chip" style="background:${tint(c, 0.16)};color:${c}">${sevLabel(o.severity)}</span>`;
  return `<button class="row${sel}${done}" data-action="select" data-idx="${i}">
    ${checkbox(o, i)}<span class="bar" style="background:${o.resolved ? '#17A98C' : c}"></span>
    <span class="body"><span class="name">${esc(title)}</span><span class="meta">${meta}</span></span>
    ${chip}</button>`;
}

function renderInspector() {
  const box = $('inspector'); const o = S.sel[S.page];
  if (!o) { box.innerHTML = `<div class="empty">Select an item to review it here.</div>`; return; }
  box.innerHTML = S.page === 'Processes' ? inspectProc(o)
    : inspectFinding(o, S.page === 'Vulnerabilities');
}
function aiBox(text, action, color) {
  return `<div class="ai-box"><div class="h">${ic('spark', 14)} Local AI triage</div>
    <p>${esc(text)}</p>${action ? `<span class="act" style="background:${tint(color, 0.16)};color:${color}">→ ${action}</span>` : ''}</div>`;
}
// The off-by-default "Online" switch for the AI chat. When ON, the local model
// is allowed to consult a few public web-search snippets for context. OFF keeps
// Oyster fully offline — its default and the privacy promise.
function onlineToggle() {
  const on = S.aiOnline;
  return `<button class="online-toggle${on ? ' on' : ''}" data-action="toggle-online"
      title="${on ? 'Online: the AI may look things up on the web (only your question leaves the machine).'
                  : 'Offline: nothing leaves your computer. Click to let the AI search the web for context.'}">
      <span class="dot"></span>${on ? 'Online' : 'Offline'}</button>`;
}
function kvTable(pairs) {
  return `<div class="kv">${pairs.map(([k, v]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div>`;
}
const ACT_COLOR = { QUARANTINE: '#E5484D', SUSPEND: '#17A98C', KILL: '#E5484D',
  ASK_USER: '#E5B003', REVIEW: '#E5B003', IGNORE: '#8E938A', OK: '#17A98C' };
// Executable actions for a vulnerability finding, chosen by its type: stop the
// program behind an open port, or copy the command that fixes a CVE / posture gap.
function vulnActions(f) {
  const ev = f.evidence || {};
  // Open listening port → let the user stop the program holding it (closing it).
  if ((f.rule || '').startsWith('open-port') || ev.port) {
    const exe = ev.exe || '';
    return `<div class="ins-actions" style="margin-top:20px">
        <button class="btn danger" data-action="close-port">Stop the program</button>
        ${exe ? `<button class="btn ghost" data-action="reveal" data-path="${esc(exe)}">Reveal program</button>` : ''}
      </div>
      <div class="note-sm">Stops the program listening on port ${esc(ev.port || '')} — which closes it. Protected system processes are never stopped; re-audit to confirm.</div>`;
  }
  // OS posture problem → the one-line command that turns the protection back on.
  if ((f.target || '').startsWith('posture:') && f.severity !== 'info') {
    return `<button class="btn ghost" data-action="copyfix" style="width:100%;height:40px;margin-top:20px">Copy fix command</button>`;
  }
  // Known-CVE / package advisory → the upgrade command.
  if (ev.package || ev.ecosystem) {
    return `<button class="btn ghost" data-action="copyfix" style="width:100%;height:40px;margin-top:20px">Copy upgrade command</button>`;
  }
  return '';
}
// Title/subtitle for a vulnerability finding. Open ports get a plain-language
// label naming the program holding the port instead of a bare "open-port:3001".
function vulnTitle(f) {
  const ev = f.evidence || {};
  if ((f.rule || '').startsWith('open-port') || ev.port) {
    const who = ev.process || 'Unknown program';
    return `Port ${ev.port || '?'} · ${who}`;
  }
  return f.rule;
}
function vulnSubtitle(f) {
  const ev = f.evidence || {};
  if ((f.rule || '').startsWith('open-port') || ev.port) {
    const proto = (ev.protocol || 'tcp').toUpperCase();
    const addr = ev.address || 'listening';
    const where = ev.pid ? `pid ${ev.pid}` : '';
    return `${proto} · ${addr}${where ? ' · ' + where : ''}${ev.exe ? ' · ' + ev.exe : ''}`;
  }
  return f.target;
}
function inspectFinding(f, vuln) {
  const c = SEV[f.severity] || SEV.info;
  const pairs = Object.entries(f.evidence || {}); if (!pairs.length) pairs.push(['rule', f.rule]);
  // richer, server-generated explanation + recommended action
  const ai = aiBox(f.ai || f.detail || 'Reviewed by Oyster.', f.action, ACT_COLOR[f.action]);
  const srcTag = (!vuln && f.source) ? `<span class="tag" style="background:${f.source === 'downloaded' ? tint('#0E7C8C', 0.16) : tint('#E5B003', 0.16)};color:${f.source === 'downloaded' ? 'var(--accent)' : '#E5B003'}">${f.source}</span>` : '';
  const done = f.quarantined ? `<div class="note-sm" style="color:#17A98C">✓ Quarantined — moved to the reversible vault.</div>` : '';
  const actions = vuln
    ? (f.resolved === 'ignored'
        ? `<div class="note-sm" style="color:var(--muted2);margin-top:18px">✓ Ignored — hidden from this list. Re-audit to bring it back.</div>`
        : vulnActions(f) + `<button class="btn ghost" data-action="vuln-ignore" style="width:100%;height:40px;margin-top:10px">Ignore this finding</button>`)
    : (f.quarantined ? done
      : `<div class="ins-actions"><button class="btn danger" data-action="quarantine">Quarantine</button>
       <button class="btn ghost" data-action="marksafe">Mark safe</button></div>
       <div class="note-sm">Quarantine is reversible — files move to a vault, never deleted.</div>`);
  // for the uncertain (heuristic) hits, offer a local-AI second opinion — the
  // engine is unsure here, so a calm metadata-based verdict helps the user decide
  const lowconf = !vuln && f.confidence && f.confidence !== 'high';
  const second = lowconf ? `
    <div class="section">SECOND OPINION</div>
    <div id="second-ans" class="askai-ans">Oyster matched this with <b>${esc(f.confidence)}</b> confidence (a generic pattern, not a named virus). Ask the local AI to weigh in.</div>
    <button class="btn ghost" data-action="second-opinion" style="width:100%;height:40px;margin-top:8px">${ic('spark', 14)} Get a second opinion (local AI)</button>` : '';
  // ask the local AI follow-up questions about this specific file
  const askai = vuln ? '' : `
    <div class="section" style="display:flex;align-items:center;justify-content:space-between">
      <span>ASK AI ABOUT THIS FILE</span>${onlineToggle()}</div>
    <div class="askai">
      <input id="askfile-in" class="chat-input" placeholder="e.g. “is this safe to delete?” or “what does this file do?”">
      <button class="btn primary" data-action="askfile">${ic('spark', 14)} Ask</button>
    </div>
    <div id="askfile-ans" class="askai-ans"></div>`;
  return `<div><span class="chip" style="background:${tint(c, 0.16)};color:${c}">${sevLabel(f.severity)}</span>
      <span class="kind"> ${esc((f.kind || '').replace(/_/g, ' '))}</span>${srcTag}</div>
    <div class="ins-title">${esc(vuln ? vulnTitle(f) : f.name)}</div>
    <div class="ins-dir" style="${vuln ? 'color:var(--accent)' : ''}">${esc(vuln ? vulnSubtitle(f) : f.dir + '/')}</div>
    ${f.detail ? `<p class="ins-detail">${esc(f.detail)}</p>` : ''}
    ${ai}<div class="section">${vuln ? 'DETAILS' : 'EVIDENCE'}</div>${kvTable(pairs)}${actions}${second}${askai}`;
}
function inspectProc(t) {
  const c = procColor(t.score);
  const reasons = (t.reasons.length ? t.reasons : ['No specific reasons recorded.'])
    .map((r) => `<div class="reason"><span class="d" style="background:${c}"></span><span class="x">${esc(r)}</span></div>`).join('');
  const ai = aiBox(t.ai || 'Reviewed by Oyster.', t.action, ACT_COLOR[t.action]);
  return `<div style="display:flex;align-items:center;gap:12px">
      <span class="sq" style="width:44px;height:44px;background:${tint(c, 0.16)};color:${c};font-size:16px">${t.score}</span>
      <div><div style="font:600 16px 'JetBrains Mono'">${esc(t.name)}</div>
      <div style="font:500 11.5px 'JetBrains Mono';color:var(--muted)">pid ${t.pid}</div></div></div>
    <div class="scorebar"><span style="width:${Math.min(t.score, 100)}%;background:${c}"></span></div>
    <div style="font-size:11px;color:var(--muted2)">threat score ${t.score} / 100</div>
    ${t.exe ? `<div style="font:500 12px 'JetBrains Mono';color:var(--muted);margin-top:8px;word-break:break-all">${esc(t.exe)}</div>` : ''}
    <div class="section">WHY IT WAS FLAGGED</div>${reasons}${ai}
    <div class="ins-actions"><button class="btn success" data-action="suspend">Suspend</button>
      <button class="btn danger" data-action="kill">Kill</button></div>
    <div class="note-sm">Suspend freezes the process — reversible. Protected processes are never killed.</div>`;
}

// ---------- Cleanup / Organize ----------
const ORG_ICON = { important: 'shield', organize: 'sort', junk: 'trash', duplicates: 'folder', large: 'deep', stale: 'refresh' };
function renderOrganize() {
  const o = S.organize;
  const recs = o ? o.recs.map((r) => `
    <div class="rec panel">
      <span class="rec-ic" style="color:var(--accent)">${ic(ORG_ICON[r.kind] || 'broom', 18)}</span>
      <div class="rec-x"><div class="rec-t">${esc(r.title)}</div><div class="rec-d">${esc(r.detail)}</div></div>
      ${r.human ? `<div class="rec-sz">${r.human}</div>` : ''}
      <button class="btn ${r.kind === 'organize' || r.kind === 'important' ? 'primary' : 'ghost'}" data-action="review" data-key="${r.key}">
        ${r.kind === 'organize' ? 'Review plan' : r.kind === 'important' ? 'Set aside' : 'Review'}</button>
    </div>`).join('') : '';
  const body = !o
    ? `<div class="empty">Choose a folder and Analyze to get cleanup recommendations.</div>`
    : (o.recs.length
        ? `<div class="rec-head">${o.totalFiles.toLocaleString()} files · ${o.totalHuman} in <span class="mono" style="color:var(--accent)">${esc(o.folder)}</span></div>${recs}`
        : `<div class="empty">Nothing to clean up — this folder looks tidy. ✨</div>`);
  content.innerHTML = `
    <div class="taskbar panel">
      <div class="field"><span style="color:var(--accent);display:flex">${ic('broom', 16)}</span>
        <span class="k">Folder</span><span class="v" id="org-target">${esc(S.organizeTarget)}</span></div>
      <button class="btn ghost" data-action="organize-choose">Choose…</button>
      <button class="btn primary" data-action="organize-analyze">${ic('search', 15)} Analyze</button>
    </div>
    <div class="chatbar panel">
      <span style="color:var(--accent);display:flex">${ic('spark', 16)}</span>
      <input id="chat-in" class="chat-input" placeholder="Ask Oyster… e.g. “remove all files with ENGE in the name” or “archive PDFs older than a year”">
      <button class="btn primary" data-action="chat-send">Ask</button>
    </div>
    <div class="cleanup-body">${body}</div>`;
  const ci = $('chat-in');
  if (ci) ci.addEventListener('keydown', (e) => { if (e.key === 'Enter') chatSend(); });
  setActionsBusy(S.busy);
}

// ---------- Applications cleanup ----------
function renderApplications() {
  const a = S.apps;
  const isWin = a && a.platform && a.platform.startsWith('win');
  let body;
  if (!a) {
    body = `<div class="empty">Scan to list ${isWin ? 'installed programs' : 'installed apps'} and clean-uninstall them — Oyster removes the ${isWin ? 'program' : 'app'} <b>and every related file it left behind</b> (caches, preferences, support data, logs), all reversibly.</div>`;
  } else if (a.note) {
    body = `<div class="empty">${esc(a.note)}</div>`;
  } else if (!a.apps.length) {
    body = `<div class="empty">No removable ${isWin ? 'programs' : 'apps'} found.</div>`;
  } else {
    const total = a.apps.reduce((s, x) => s + (x.bytes || 0), 0);
    const cards = a.apps.map((app, i) => {
      const removing = S.appBusy && app.path === S.appBusy;
      return `
      <div class="rec panel${removing ? ' removing' : ''}">
        <span class="rec-ic" style="color:var(--accent)">${ic('apps', 18)}</span>
        <div class="rec-x"><div class="rec-t">${esc(app.name)}${app.version ? ` <span class="mono" style="color:var(--muted2);font-size:11px">v${esc(app.version)}</span>` : ''}</div>
          <div class="rec-d">${esc(app.bundleId || app.path || '')}${app.leftoverCount ? ` · ${app.leftoverCount} leftover item(s) (${esc(app.leftoverHuman)})` : ' · no leftovers found'}${app.used ? ' · last used ' + esc(app.used) : ''}</div></div>
        ${removing
          ? `<span class="rec-removing"><span class="spin-sm"></span> Removing…</span>`
          : `${app.human ? `<div class="rec-sz">${esc(app.human)}</div>` : ''}
             <button class="btn ghost" data-action="app-review" data-idx="${i}">Review</button>`}
      </div>`;
    }).join('');
    body = `<div class="rec-head">${a.apps.length} ${isWin ? 'program(s)' : 'app(s)'} · ${humanBytes(total)} on disk · Review does a <b>clean uninstall</b> — the ${isWin ? 'program' : 'app'} plus every related file, reversibly</div>${cards}`;
  }
  content.innerHTML = `
    <div class="taskbar panel">
      <div class="field"><span style="color:var(--accent);display:flex">${ic('apps', 16)}</span>
        <span class="k">${isWin ? 'Programs' : 'Applications'}</span>
        <span class="v">${a && !a.note ? `${(a.apps || []).length} found` : 'not scanned yet'}</span></div>
      <button class="btn primary" data-action="apps-scan">${ic('search', 15)} Scan ${isWin ? 'programs' : 'apps'}</button>
    </div>
    <div class="cleanup-body">${body}</div>`;
  setActionsBusy(S.busy);
}
function humanBytes(n) {
  for (const u of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (n < 1024) return u === 'B' ? `${n} B` : `${n.toFixed(1)} ${u}`;
    n /= 1024;
  }
  return `${n.toFixed(1)} PB`;
}
async function appsScan() {
  if (S.busy) return; S.busy = true; startScanUI('Inspecting installed apps…');
  try {
    const r = await api.rpc('apps_scan');
    S.apps = r;
    setStatus(r.note ? r.note : `${(r.apps || []).length} item(s) inspected.`);
  } catch (e) { setStatus('App scan failed: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Applications') renderApplications();
}
function openAppReview(idx) {
  const app = S.apps && S.apps.apps[idx]; if (!app) return;
  const win = !!app.win;
  // mac: the bundle itself is a movable path; windows: the program is removed
  // by its own uninstaller, so only the leftover AppData folders are movable.
  const bundle = { path: app.path, name: win ? app.name : app.name + '.app',
    human: app.bundleHuman, note: win ? 'removed by its own uninstaller' : 'application',
    risk: '', important: '', accessed: '' };
  const items = win ? (app.leftovers || []) : [bundle, ...(app.leftovers || [])];
  openReview({ kind: 'app', appName: app.name, win, uid: app.uid, appPath: app.path,
    headerItem: win ? bundle : null,
    title: 'Clean-uninstall ' + app.name,
    detail: win
      ? `Removes ${app.name} using its own uninstaller, then clean-deletes the leftover app-data folders below. Everything Oyster moves goes to the reversible cleanup vault.`
      : `Clean uninstall — removes ${app.name} and all ${app.leftoverCount || 0} related file(s) it scattered across your system (${app.human} total): caches, preferences, support data, logs. Everything moves to the reversible cleanup vault, so you can restore it.`,
    items });
}

// ---------- review modal ----------
let RV = null;  // { rec, sel: Set(paths) }
function openReview(rec) {
  if (typeof rec === 'string') rec = S.organize && S.organize.recs.find((r) => r.key === rec);
  if (!rec) return;
  // default selection: safe (non-risky) junk/dup/chat pre-selected; important all
  const sel = new Set();
  // default selection follows the suggestion: pre-check only "safe to remove"
  const presafe = (items) => (items || []).forEach((i) => { if (itemTag(i) === 'remove') sel.add(i.path); });
  if (rec.kind === 'junk' || rec.kind === 'chat') presafe(rec.items);
  else if (rec.kind === 'important' || rec.kind === 'app') (rec.items || []).forEach((i) => sel.add(i.path));
  else if (rec.kind === 'duplicates') (rec.groups || []).forEach((g) => g.copies.forEach((c) => { if (itemTag(c) === 'remove') sel.add(c.path); }));
  RV = { rec, sel, tags: new Set(), lastPath: null, opener: document.activeElement };
  $('rv-title').textContent = rec.title;
  $('rv-sub').textContent = rec.detail || '';
  renderReviewBody();
  $('review').classList.remove('hidden');
  const first = $('rv-list').querySelector('input[type=checkbox]');
  if (first) first.focus({ preventScroll: true });   // so arrow keys / space work at once
}
function closeReview() {
  const opener = RV && RV.opener;   // restore focus to whatever opened the modal
  $('review').classList.add('hidden'); RV = null;
  if (opener && opener.focus) { try { opener.focus(); } catch (e) { /* gone */ } }
}

// per-file suggestion — combines important/risky/empty/type/who-made-it into a
// single keep / review / remove recommendation (computed by the engine; the
// fallback covers items that don't carry one, e.g. app leftovers).
const SG_COLOR = { remove: '#17A98C', review: '#F5820A', keep: '#8E5BE5' };
function suggestFallback(i) {
  if (i.important) return { level: 'keep', label: 'Keep', why: i.important };
  if (i.risk) return { level: 'review', label: 'Review first', why: i.risk };
  return { level: 'remove', label: 'Safe to remove', why: '' };
}
function suggestOf(i) { return i.suggest || suggestFallback(i); }

function fileRow(i) {
  const checked = RV.sel.has(i.path);
  const sg = suggestOf(i);
  const col = SG_COLOR[sg.level] || SEV.info;
  const tag = `<span class="rv-risk" style="color:${col};background:${tint(col, 0.15)}" title="${esc(sg.why || sg.label)}">${esc(sg.label)}</span>`;
  return `<label class="rv-row${sg.level === 'review' ? ' risky' : ''}">
    <input type="checkbox" data-path="${esc(i.path)}" ${checked ? 'checked' : ''}>
    <span class="rv-name">${esc(i.name)}</span>${tag}
    <span class="rv-meta">${esc(i.human)}${i.note ? ' · ' + esc(i.note) : ''}${i.accessed ? ' · ' + esc(i.accessed) : ''}</span>
    <span class="rv-dir" title="${esc(i.path)}">${esc(i.path)}</span>
    <button class="rv-reveal" data-reveal="${esc(i.path)}" title="Reveal in Finder">${ic('search', 14)}</button>
  </label>`;
}
// each reviewable file carries one suggestion tag (remove/review/keep). The tag
// tabs let you focus the list on one or several tags at once (multi-select),
// and the list is grouped by tag so the same kinds sit together.
function itemTag(i) { return suggestOf(i).level; }
const _TAG_ORDER = { remove: 0, review: 1, keep: 2 };
function applyFilter(items) {
  const shown = RV.tags.size ? items.filter((i) => RV.tags.has(itemTag(i))) : items;
  return shown.slice().sort((a, b) =>
    (_TAG_ORDER[itemTag(a)] - _TAG_ORDER[itemTag(b)]) || ((b.size || 0) - (a.size || 0)));
}
function tagTabs(items) {
  const counts = { remove: 0, review: 0, keep: 0 };
  items.forEach((i) => counts[itemTag(i)]++);
  const tab = (key, label, on) => `<button class="btn ghost rv-mini rv-tab${on ? ' on' : ''}" data-rvtag="${key}">${label}${key === 'all' ? '' : ' ' + counts[key]}</button>`;
  const t = [tab('all', 'All', RV.tags.size === 0)];
  if (counts.remove) t.push(tab('remove', '✓ Safe', RV.tags.has('remove')));
  if (counts.review) t.push(tab('review', '⚠ Review', RV.tags.has('review')));
  if (counts.keep) t.push(tab('keep', '★ Keep', RV.tags.has('keep')));
  return `<span class="rv-tabs">${t.join('')}</span>`;
}

function renderReviewBody() {
  const r = RV.rec; const list = $('rv-list'); const tools = $('rv-tools'); const foot = $('rv-foot');
  if (r.kind === 'organize') {
    tools.innerHTML = `<span class="rv-count">${r.count} files → ${Object.keys(r.categories).length} folders</span>`;
    list.innerHTML = Object.entries(r.categories).map(([cat, items]) => `
      <div class="rv-cat"><div class="rv-cat-h">${ic('folder', 14)} ${esc(cat)} <span>${items.length}</span></div>
      ${items.slice(0, 200).map((i) => `<div class="rv-row static"><span class="rv-name">${esc(i.name)}</span><span class="rv-meta">${esc(i.human)}</span></div>`).join('')}</div>`).join('');
    foot.innerHTML = `<span class="rv-foot-msg">Moves each file into a same-folder subfolder by type.</span>
      <button class="btn primary" data-rvaction="organize">${ic('sort', 15)} Organize into folders</button>`;
    return;
  }
  if (r.kind === 'duplicates') {
    const copies = r.groups.flatMap((g) => g.copies);
    tools.innerHTML = `<button class="btn ghost rv-mini" data-rvall="1">Select all copies</button><button class="btn ghost rv-mini" data-rvall="0">None</button>${tagTabs(copies)}<span class="rv-count" id="rv-n"></span>`;
    list.innerHTML = r.groups.map((g) => {
      const shown = applyFilter(g.copies);
      if (!shown.length) return '';   // group has nothing in the active filter
      return `<div class="rv-cat"><div class="rv-cat-h">${ic('folder', 14)} ${g.human} each · ${g.copies.length + 1} identical</div>
        <div class="rv-row keep"><span class="rv-name">${esc(g.keep.name)}</span><span class="rv-meta">KEEP · newest</span><span class="rv-dir">${esc(g.keep.path)}</span><button class="rv-reveal" data-reveal="${esc(g.keep.path)}">${ic('search', 14)}</button></div>
        ${shown.map((c) => fileRow(c)).join('')}</div>`;
    }).join('') || `<div class="empty">No copies in this category.</div>`;
    foot.innerHTML = footActions('Delete selected copies', false);
  } else if (r.kind === 'app') {
    tools.innerHTML = `<button class="btn ghost rv-mini" data-rvall="1">All</button><button class="btn ghost rv-mini" data-rvall="0">None</button><span class="rv-count" id="rv-n"></span>`;
    // windows: show the program as a fixed header (its own uninstaller removes
    // it); the checkable list is the leftover folders we can vault afterwards.
    const head = r.win && r.headerItem
      ? `<div class="rv-row keep"><span class="rv-name">${esc(r.headerItem.name)}</span><span class="rv-meta">${esc(r.headerItem.note)}</span></div>` : '';
    list.innerHTML = head + (r.items || []).map((i) => fileRow(i)).join('')
      + (r.win && !(r.items || []).length ? '<div class="empty">No leftover folders found — the uninstaller handles everything.</div>' : '');
    foot.innerHTML = `<span class="rv-foot-msg">${r.win
      ? 'Runs the program’s own uninstaller; any selected app-data folders move to the reversible cleanup vault.'
      : 'Clean uninstall — the app and every selected related file move to the reversible cleanup vault in ~/.oyster/cleanup. Nothing is hard-deleted; restore it if you change your mind.'}</span>
      <button class="btn danger" data-rvaction="uninstall">${ic('trash', 15)} Clean-uninstall ${esc(r.appName)}</button>`;
  } else if (r.kind === 'important') {
    tools.innerHTML = `<button class="btn ghost rv-mini" data-rvall="1">All</button><button class="btn ghost rv-mini" data-rvall="0">None</button><span class="rv-count" id="rv-n"></span>`;
    list.innerHTML = (r.items || []).map((i) => fileRow(i)).join('');
    foot.innerHTML = `<span class="rv-foot-msg">These are kept out of every cleanup suggestion. Move them somewhere safe.</span>
      <button class="btn primary" data-rvaction="important">${ic('shield', 15)} Move to Important folder</button>`;
  } else {  // junk / large / stale / chat
    const shown = applyFilter(r.items || []);
    tools.innerHTML = `<button class="btn ghost rv-mini" data-rvall="1">All</button><button class="btn ghost rv-mini" data-rvall="0">None</button>${tagTabs(r.items || [])}<span class="rv-count" id="rv-n"></span>`;
    list.innerHTML = shown.map((i) => fileRow(i)).join('') || `<div class="empty">No files in this category.</div>`;
    const archive = r.kind === 'large' || r.kind === 'stale' || r.kind === 'chat';
    foot.innerHTML = footActions(r.deleteLabel || 'Delete selected', archive);
  }
  updateRvCount();
}
function footActions(deleteLabel, archive) {
  return `<span class="rv-foot-msg">Reversible — “delete” moves to a restorable vault in ~/.oyster/cleanup. Only files we suggest removing are pre-selected.</span>
    ${archive ? `<button class="btn ghost" data-rvaction="archive">${ic('folder', 15)} Move to archive</button>` : ''}
    <button class="btn danger" data-rvaction="delete">${ic('trash', 15)} ${deleteLabel}</button>`;
}
function updateRvCount() {
  const el = $('rv-n'); if (el) el.textContent = `${RV.sel.size} selected`;
}
// arrow keys move up/down the review list; hold Shift to extend the selection
// as you go, Space (native) toggles the focused row.
function rvKeyNav(e) {
  if (!RV || $('review').classList.contains('hidden')) return;
  if (e.key === 'Escape') { e.preventDefault(); return closeReview(); }
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  const boxes = [...$('rv-list').querySelectorAll('input[type=checkbox]')];
  if (!boxes.length) return;
  e.preventDefault();
  const idx = boxes.indexOf(document.activeElement);
  const next = e.key === 'ArrowDown'
    ? Math.min((idx < 0 ? -1 : idx) + 1, boxes.length - 1)
    : Math.max((idx < 0 ? boxes.length : idx) - 1, 0);
  const b = boxes[next];
  b.focus({ preventScroll: true });
  b.scrollIntoView({ block: 'nearest' });
  if (e.shiftKey) {   // extend selection while arrowing, like shift-click
    b.checked = true; RV.sel.add(b.dataset.path); RV.lastPath = b.dataset.path;
    updateRvCount();
  }
}

// arrow keys move the selection up/down the main Files/Processes/Vulnerabilities
// list — mirrors the review modal, so keyboard navigation is consistent.
function listKeyNav(e) {
  if (!['Files', 'Processes', 'Vulnerabilities'].includes(S.page)) return;
  if (!$('review').classList.contains('hidden')) return;       // modal owns the keys
  const tag = (document.activeElement && document.activeElement.tagName) || '';
  if (tag === 'INPUT' || tag === 'TEXTAREA') return;            // don't hijack typing
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  const list = $('list'); if (!list) return;
  const rows = [...list.querySelectorAll('.row')];
  if (!rows.length) return;
  e.preventDefault();
  const items = S.data[S.page];
  const selIdx = items.indexOf(S.sel[S.page]);
  let pos = rows.findIndex((r) => +r.dataset.idx === selIdx);
  if (pos < 0) pos = e.key === 'ArrowDown' ? 0 : rows.length - 1;
  else pos = e.key === 'ArrowDown' ? Math.min(pos + 1, rows.length - 1) : Math.max(pos - 1, 0);
  S.sel[S.page] = items[+rows[pos].dataset.idx];
  renderRows(); renderInspector();
  const sel = $('list').querySelector('.row.sel'); if (sel) sel.scrollIntoView({ block: 'nearest' });
}

// shift-click range select: set every checkbox between two rows to `checked`
function rvSelectRange(fromPath, toPath, checked) {
  const boxes = [...$('rv-list').querySelectorAll('input[type=checkbox]')];
  const paths = boxes.map((b) => b.dataset.path);
  let a = paths.indexOf(fromPath), b = paths.indexOf(toPath);
  if (a < 0 || b < 0) return;
  if (a > b) [a, b] = [b, a];
  for (let k = a; k <= b; k++) {
    boxes[k].checked = checked;
    checked ? RV.sel.add(paths[k]) : RV.sel.delete(paths[k]);
  }
  updateRvCount();
}

// ---------- AI summary ----------
async function renderSummary() {
  if (!S.scanned) {     // only generate after at least one scan/sweep/audit
    content.innerHTML = `<div class="summary-page"><div class="inner">
      <div class="hero panel"><div class="orb"><span class="ring2" style="border-color:var(--muted2)"></span>
        <span class="n" style="color:var(--muted2)">${ic('spark', 22)}</span></div>
        <div><div class="big">No scan yet</div>
        <div class="sub3">Run a scan, process sweep, or vulnerability audit first — then the local model writes a plain-English summary of what it found.</div></div></div>
      <div class="prose panel" style="color:var(--muted)">The AI summary is generated <b>after</b> a scan completes, from the recorded findings — never speculatively.</div>
    </div></div>`;
    return;
  }
  const n = S.data.Files.length + S.data.Processes.length + S.data.Vulnerabilities.length;
  content.innerHTML = `<div class="summary-page"><div class="inner">
    <div class="hero panel"><div class="orb"><span class="ring1" style="background:var(--accent)"></span>
      <span class="ring2" style="border-color:var(--accent)"></span>
      <span class="n" style="color:var(--accent)">${ic('spark', 22)}</span></div>
      <div><div class="big">${n ? `Scan complete — ${n} thing(s) to review.` : 'Nothing needs your attention.'}</div>
      <div class="sub3">Generated locally by <span class="mono" style="color:var(--accent)">${esc(S.model)}</span> · nothing was uploaded.</div></div></div>
    <div class="prose panel" id="prose">Generating local summary…</div>
    <div class="note"><span style="color:var(--accent);display:flex">${ic('shield', 18)}</span>
      <div><div class="h">This ran entirely on your device.</div>
      <div class="x">No uploads, no account, no telemetry. The scanner never opened a network socket.</div></div></div>
  </div></div>`;
  try { const r = await api.rpc('summary'); $('prose').textContent = r.text; }
  catch (e) { $('prose').textContent = '(summary unavailable: ' + e.message + ')'; }
}

// ---------- actions ----------
async function onContentClick(e) {
  const t = e.target.closest('[data-action]'); if (!t) return;
  const a = t.dataset.action;
  if (a === 'select') { S.sel[S.page] = S.data[S.page][+t.dataset.idx]; renderRows(); renderInspector(); return; }
  if (a === 'check') { e.stopPropagation(); toggleCheck(S.data[S.page][+t.dataset.idx]); return; }
  if (a === 'check-all') return toggleCheckAll();
  if (a === 'bulk-quarantine') return bulkQuarantine();
  if (a === 'bulk-marksafe') return bulkMarkSafe();
  if (a === 'bulk-ignore') return bulkIgnore();
  if (a === 'bulk-suspend') return bulkProc('suspend');
  if (a === 'bulk-kill') return bulkProc('kill');
  if (a === 'findtab') { S.findFilter = t.dataset.tag; const tb = $('find-tabs'); if (tb) tb.innerHTML = findingTabsHtml(); renderRows(); return; }
  if (a === 'open-fda') return api.openFDA();
  if (a === 'toggle-downloaded') { S.downloadedOnly = !S.downloadedOnly; renderScan(); return; }
  if (a === 'choose') { const d = await api.chooseFolder(); if (d) { S.target = d; const el = $('target'); if (el) el.textContent = d; } return; }
  if (a === 'scan') return runScan('scan', { path: S.target, downloadedOnly: S.downloadedOnly });
  if (a === 'deep') return deepScan();
  if (a === 'sweep') return sweep();
  if (a === 'audit') return audit();
  if (a === 'update-defs') return updateDefs();
  if (a === 'quarantine') return quarantine();
  if (a === 'marksafe') return markSafe();
  if (a === 'askfile') return askFile();
  if (a === 'suspend') return procAction('suspend');
  if (a === 'kill') return procAction('kill');
  if (a === 'organize-choose') { const d = await api.chooseFolder(); if (d) { S.organizeTarget = d; const el = $('org-target'); if (el) el.textContent = d; } return; }
  if (a === 'organize-analyze') return organizeAnalyze();
  if (a === 'review') return openReview(t.dataset.key);
  if (a === 'chat-send') return chatSend();
  if (a === 'apps-scan') return appsScan();
  if (a === 'app-review') return openAppReview(+t.dataset.idx);
  if (a === 'quar-open') return quarantineOpen();
  if (a === 'quar-empty') return quarantineEmpty();
  if (a === 'quar-restore') return quarantineRestore(t.dataset.qid);
  if (a === 'allow-remove') return allowlistRemove(t.dataset.key);
  if (a === 'allow-clear') return allowlistClear();
  if (a === 'second-opinion') return secondOpinion();
  if (a === 'reveal') return api.reveal(t.dataset.path);
  if (a === 'close-port') return closePort();
  if (a === 'copyfix') return copyFix();
  if (a === 'open-ext') { e.preventDefault(); return api.openExternal(t.dataset.url); }
  if (a === 'toggle-online') return toggleOnline();
  if (a === 'vuln-ignore') return vulnIgnore();
}

// ---------- vulnerability actions ----------
async function closePort() {
  const f = S.sel.Vulnerabilities; if (!f) return;
  const ev = f.evidence || {};
  const pid = parseInt(ev.pid, 10);
  if (!pid) { setStatus('No process id recorded for this port.'); return; }
  const who = ev.process || 'The program';
  const r = await api.confirm({
    message: 'Stop the program on this port?', type: 'warning', buttons: ['Cancel', 'Stop it'],
    detail: `${who} (pid ${pid}) is listening on port ${ev.port}. Stopping it closes the port. `
      + 'If it’s a system service the OS may relaunch it; protected processes are refused.',
  });
  if (r !== 1) return;
  try {
    await api.rpc('close_port', { pid, name: ev.process || '' });
    setStatus(`Stopped ${who} (pid ${pid}) — port ${ev.port} closed. Re-audit to confirm.`);
  } catch (e) { setStatus('Could not stop it: ' + e.message); }
}
function fixCommand(f) {
  const ev = f.evidence || {};
  const eco = (ev.ecosystem || '').toLowerCase();
  if (ev.package || ev.ecosystem) {
    const pkg = ev.package || '';
    const fixed = ev.fixed_in && ev.fixed_in !== 'unknown' ? ev.fixed_in : '';
    if (eco === 'npm') return `npm install ${pkg}@${fixed || 'latest'}`;
    if (eco === 'pypi') return fixed ? `pip install -U "${pkg}==${fixed}"` : `pip install -U ${pkg}`;
    return `# update ${pkg} to ${fixed || 'the latest fixed version'}`;
  }
  const name = (f.target || '').replace('posture:', '');
  const POSTURE_FIX = {
    'Application Firewall': 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on',
    'FileVault disk encryption': 'sudo fdesetup enable',
    'Gatekeeper': 'sudo spctl --global-enable',
    'System Integrity Protection': '# Reboot into Recovery (hold power), open Terminal, run: csrutil enable',
    'Windows Firewall profiles enabled': 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True',
    'Defender real-time protection': 'Set-MpPreference -DisableRealtimeMonitoring $false',
    'BitLocker (C:)': 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes128 -UsedSpaceOnly',
  };
  return POSTURE_FIX[name] || '';
}
async function copyFix() {
  const f = S.sel.Vulnerabilities; if (!f) return;
  const cmd = fixCommand(f);
  if (!cmd) { setStatus('No automatic fix command is available for this item.'); return; }
  try { await navigator.clipboard.writeText(cmd); setStatus('Copied to clipboard: ' + cmd); }
  catch { setStatus('Run this: ' + cmd); }
}

async function secondOpinion() {
  const f = S.sel.Files; if (!f) return;
  const box = $('second-ans');
  if (box) box.textContent = 'Consulting the local model… (this can take a few seconds)';
  try {
    const r = await api.rpc('second_opinion', { file: {
      name: f.name, dir: f.dir, path: f.target, rule: f.rule, severity: f.severity,
      kind: f.kind, detail: f.detail, source: f.source, evidence: f.evidence } });
    if (!box) return;
    if (!r.available) { box.textContent = r.text; return; }
    const color = r.verdict.includes('harmful') ? '#E5484D'
      : r.verdict.includes('closer') ? '#E5B003' : '#17A98C';
    box.innerHTML = `<div style="color:${color};font-weight:600;margin-bottom:5px">${esc(r.verdict)}</div>`
      + `<div>${esc(r.why)}</div>`
      + (r.suggestion ? `<div class="note-sm" style="margin-top:7px">Suggested: ${esc(r.suggestion)}</div>` : '')
      + `<div class="note-sm" style="margin-top:7px;color:var(--muted2)">A local-AI opinion based on the file’s details — offline, no data left your computer.</div>`;
  } catch (e) { if (box) box.textContent = 'Could not get a second opinion: ' + e.message; }
}

// Toggle the AI's Online mode. Turning it ON breaks Oyster's offline guarantee,
// so the first time in a session we warn and require an explicit confirm.
async function toggleOnline() {
  if (!S.aiOnline && !S.aiOnlineWarned) {
    const r = await api.confirm({
      message: 'Let the AI search the web?', type: 'warning',
      buttons: ['Stay offline', 'Turn on online mode'],
      detail: 'Oyster is fully offline by default — nothing leaves your computer. '
        + 'Online mode lets the AI assistant look things up on the web for extra '
        + 'context.\n\nWhen it’s ON, your typed question (and the file’s name/hash) '
        + 'is sent to a search engine — never the file’s contents. It only ever '
        + 'contacts that one search engine, and your scans always stay 100% offline. '
        + 'You can turn this back off anytime.',
    });
    if (r !== 1) return;            // declined — stay offline
    S.aiOnlineWarned = true;        // don't nag again this session
  }
  S.aiOnline = !S.aiOnline;
  const keep = $('askfile-in') && $('askfile-in').value;   // don't lose typed question
  renderInspector();
  if (keep && $('askfile-in')) $('askfile-in').value = keep;
}
async function askFile() {
  const f = S.sel.Files; if (!f) return;
  const inp = $('askfile-in'); const q = inp && inp.value.trim(); if (!q) return;
  const ans = $('askfile-ans');
  if (ans) ans.textContent = S.aiOnline
    ? 'Searching the web and thinking…' : 'Thinking… (running locally)';
  try {
    const r = await api.rpc('ask_file', { question: q, online: S.aiOnline, file: {
      name: f.name, dir: f.dir, path: f.target, rule: f.rule, severity: f.severity,
      kind: f.kind, detail: f.detail, source: f.source, evidence: f.evidence } });
    if (!$('askfile-ans')) return;
    let html = `<div>${esc(r.text)}</div>`;
    if (r.online && r.sources && r.sources.length) {
      html += `<div class="note-sm" style="margin-top:8px;color:var(--muted2)">Sources consulted online:</div>`
        + r.sources.map((s) => `<div class="src-link"><a href="${esc(s.url)}" data-action="open-ext" data-url="${esc(s.url)}">${esc(s.title || s.url)}</a></div>`).join('');
    } else if (S.aiOnline && !r.online) {
      html += `<div class="note-sm" style="margin-top:8px;color:var(--muted2)">(No web results found — answered offline.)</div>`;
    }
    $('askfile-ans').innerHTML = html;
  } catch (e) { if ($('askfile-ans')) $('askfile-ans').textContent = 'Could not get an answer: ' + e.message; }
}

async function chatSend() {
  const inp = $('chat-in'); const prompt = inp && inp.value.trim(); if (!prompt) return;
  if (S.busy) return; S.busy = true; setActionsBusy(true); setStatus('Asking Oyster…');
  try {
    const r = await api.rpc('assistant', { prompt, folder: S.organizeTarget });
    setStatus(`${r.count} file(s) match · ${r.human}.`);
    if (!r.count) { setStatus(`No files matched “${prompt}”.`); S.busy = false; setActionsBusy(false); return; }
    openReview({ kind: 'chat', title: r.summary,
      detail: `${r.count} files (${r.human}) in ${r.folder}. Review and confirm — nothing happens without your OK.`,
      items: r.files, count: r.count, deleteLabel: 'Delete selected' });
  } catch (e) { setStatus('Assistant failed: ' + e.message); }
  S.busy = false; setActionsBusy(false);
}

async function organizeAnalyze() {
  if (S.busy) return; S.busy = true; startScanUI('Analyzing folder…');
  try {
    const r = await api.rpc('organize_scan', { path: S.organizeTarget });
    S.organize = r; setStatus(`${r.totalFiles.toLocaleString()} files · ${r.recs.length} recommendation(s).`);
  } catch (e) { setStatus('Analyze failed: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Cleanup') renderOrganize();
}
async function reviewExecute(action) {
  const r = RV.rec;
  let paths = [...RV.sel];
  if (action === 'organize') paths = [];
  if (action === 'uninstall') return uninstallApp(r, paths);
  if (action !== 'organize' && !paths.length) { setStatus('Nothing selected.'); return; }
  // safety: a dedicated, explicit warning if any "risky to delete" file is in
  // the selection — these may belong to a program and removing them can break it.
  if (action === 'delete' || action === 'archive') {
    const items = r.groups ? r.groups.flatMap((g) => g.copies) : (r.items || []);
    const risky = items.filter((i) => paths.includes(i.path) && i.risk);
    if (risky.length) {
      const names = risky.slice(0, 6).map((i) => `• ${i.name} — ${i.risk}`).join('\n')
        + (risky.length > 6 ? `\n…and ${risky.length - 6} more.` : '');
      const w = await api.confirm({
        type: 'warning',
        message: `⚠ ${risky.length} risky-to-delete file(s) selected`,
        detail: 'These look like they belong to a program or the system — removing '
          + 'them could stop software from working:\n\n' + names
          + '\n\nThey move to a reversible vault (not erased), but only continue if '
          + 'you are sure you want to touch them.',
        buttons: ['Cancel', 'I understand — continue'],
      });
      if (w !== 1) { setStatus('Cancelled — risky files were kept.'); return; }
    }
  }
  const verb = action === 'organize' ? `Organize ${r.count} files into folders`
    : action === 'important' ? `Move ${paths.length} important file(s) to the Important folder`
    : action === 'archive' ? `Move ${paths.length} file(s) to the archive folder`
    : `Move ${paths.length} file(s) to the reversible cleanup vault`;
  const c = await api.confirm({ message: r.title, detail: verb +
    '\n\nNothing is permanently deleted — everything moves and can be restored.',
    buttons: ['Cancel', action === 'organize' ? 'Organize' : action === 'important' ? 'Move' : action === 'archive' ? 'Archive' : 'Delete'] });
  if (c !== 1) return;
  try {
    const res = await api.rpc('organize_execute', {
      action, paths, folder: S.organize.folder,
      categories: action === 'organize' ? r.categories : undefined,
    });
    setStatus(`Done · moved ${res.moved} file(s)` + (res.human ? ` · freed ${res.human}` : '') + (res.errors ? ` · ${res.errors} skipped` : '') + '.');
    closeReview();
    const re = await api.rpc('organize_scan', { path: S.organizeTarget });
    S.organize = re; if (S.page === 'Cleanup') renderOrganize();
  } catch (e) { setStatus('Cleanup failed: ' + e.message); }
}

async function uninstallApp(r, paths) {
  const c = await api.confirm({
    type: 'warning', message: `Uninstall ${r.appName}?`,
    detail: r.win
      ? `This will open ${r.appName}'s own uninstaller`
        + (paths.length ? ` and move ${paths.length} leftover folder(s) to the reversible cleanup vault.` : '.')
        + '\n\nFollow the uninstaller’s prompts to finish removing the program.'
      : `Move ${r.appName} and ${Math.max(0, paths.length - 1)} leftover file(s) to the reversible cleanup vault.`
        + '\n\nNothing is permanently deleted — it can be restored from ~/.oyster/cleanup.',
    buttons: ['Cancel', `Uninstall ${r.appName}`] });
  if (c !== 1) return;
  // close the modal and show a spinner on the app's card while it's removed
  closeReview();
  S.appBusy = r.appPath; renderApplications();
  setStatus(`Removing ${r.appName}…`);
  try {
    if (r.win) {
      await api.rpc('app_run_uninstaller', { uid: r.uid, name: r.appName });
      if (paths.length) await api.rpc('organize_execute', { action: 'delete', paths });
      setStatus(`Launched ${r.appName}'s uninstaller${paths.length ? ` · moved ${paths.length} leftover folder(s)` : ''}.`);
    } else {
      const res = await api.rpc('organize_execute', { action: 'delete', paths });
      setStatus(`Uninstalled ${r.appName} · moved ${res.moved} item(s)` + (res.human ? ` · freed ${res.human}` : '') + (res.errors ? ` · ${res.errors} skipped` : '') + '.');
    }
    const re = await api.rpc('apps_scan'); S.apps = re;
  } catch (e) { setStatus('Uninstall failed: ' + e.message); }
  S.appBusy = null;
  if (S.page === 'Applications') renderApplications();
}

async function runScan(method, params) {
  if (S.busy) return; S.busy = true; startScanUI('Scanning…');
  try {
    const r = await api.rpc(method, params);
    S.report = r; S.data.Files = r.findings; S.sel.Files = null; S.checked.Files.clear(); S.scanned = true;
    setStatus((r.canceled ? 'Stopped' : 'Done')
      + ` · ${r.filesSeen.toLocaleString()} files in ${r.secs}s · ${r.findings.length} finding(s)`
      + (r.allowlisted ? ` · ${r.allowlisted} marked-safe hidden` : '')
      + (r.filesUnreadable ? ` · ${r.filesUnreadable.toLocaleString()} unreadable` : '') + ' · offline.');
  } catch (e) { setStatus('Scan stopped: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Files') renderScan();
  updateNav();
}
async function deepScan() {
  const r = await api.confirm({
    message: 'Full scan — entire computer', type: 'warning', buttons: ['Cancel', 'Scan everything'],
    detail: 'Runs a deep file scan, process sweep, vulnerability audit, and cleanup analysis back to back. This can take a while.',
  });
  if (r !== 1) return;
  if (S.busy) return;
  S.busy = true;
  showPage('Files');

  // ── 1. Deep file scan ──────────────────────────────────────────────────────
  startScanUI('Full scan — files…');
  try {
    const r = await api.rpc('deep_scan', {});
    S.report = r; S.data.Files = r.findings; S.sel.Files = null; S.checked.Files.clear(); S.scanned = true;
    setStatus(`Files: ${r.findings.length} finding(s) in ${r.secs}s.`);
  } catch (e) { setStatus('File scan error: ' + e.message); }
  if (scan.canceling) { endScanUI(); S.busy = false; updateNav(); renderScan(); return; }

  // ── 2. Process sweep ───────────────────────────────────────────────────────
  scan.label = 'Full scan — processes…'; paintScanBar();
  try {
    const r = await api.rpc('sweep_processes', {});
    S.data.Processes = r.processes; S.procTotal = r.total; S.sel.Processes = null; S.checked.Processes.clear();
    setStatus(`Processes: ${r.processes.length} flagged of ${(r.total || 0).toLocaleString()}.`);
  } catch (e) { setStatus('Process sweep error: ' + e.message); }
  if (scan.canceling) { endScanUI(); S.busy = false; updateNav(); renderScan(); return; }

  // ── 3. Vulnerability audit ─────────────────────────────────────────────────
  scan.label = 'Full scan — vulnerabilities…'; paintScanBar();
  try {
    const r = await api.rpc('audit_vulns', {});
    S.data.Vulnerabilities = r.vulns; S.sel.Vulnerabilities = null; S.checked.Vulnerabilities.clear();
    setStatus(`Vulnerabilities: ${r.vulns.length} issue(s) found.`);
  } catch (e) { setStatus('Vuln audit error: ' + e.message); }
  if (scan.canceling) { endScanUI(); S.busy = false; updateNav(); renderScan(); return; }

  // ── 4. Cleanup analysis ────────────────────────────────────────────────────
  scan.label = 'Full scan — cleanup analysis…'; paintScanBar();
  try {
    const r = await api.rpc('organize_scan', { path: S.organizeTarget });
    S.organize = r;
    setStatus(`Cleanup: ${r.recs.length} recommendation(s) in ${r.totalFiles.toLocaleString()} files.`);
  } catch (e) { setStatus('Cleanup analysis error: ' + e.message); }

  endScanUI(); S.busy = false; S.scanned = true; updateNav();
  const total = S.data.Files.length + S.data.Processes.length + S.data.Vulnerabilities.length;
  setStatus(`Full scan complete · ${total} finding(s) · offline.`);
  if (S.page === 'Files') renderScan();
}
async function sweep() {
  if (S.busy) return; S.busy = true; startScanUI('Inspecting processes…');
  try { const r = await api.rpc('sweep_processes'); S.data.Processes = r.processes; S.procTotal = r.total; S.sel.Processes = null; S.checked.Processes.clear(); S.scanned = true; setStatus(`Swept ${(r.total||0).toLocaleString()} processes · ${r.processes.length} flagged.`); }
  catch (e) { setStatus('Sweep failed: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Processes') renderScan(); updateNav();
}
async function updateDefs() {
  if (S.busy) return; S.busy = true;
  const c = await api.confirm({ message: 'Update vulnerability definitions',
    detail: 'Download the latest OSV CVE snapshot (PyPI + npm). This is the one '
    + 'time Oyster goes online — it tells you exactly which host it contacts.',
    buttons: ['Cancel', 'Download'] });
  if (c !== 1) { S.busy = false; return; }
  startScanUI('Downloading CVE definitions…');
  try { const r = await api.rpc('update_defs'); setStatus(`Definitions updated · ${r.rows.toLocaleString()} advisories. Re-run the audit.`); }
  catch (e) { setStatus('Update failed: ' + e.message); }
  endScanUI(); S.busy = false;
}
async function audit() {
  if (S.busy) return; S.busy = true; startScanUI('Auditing software & OS…');
  try { const r = await api.rpc('audit_vulns'); S.data.Vulnerabilities = r.vulns; S.sel.Vulnerabilities = null; S.checked.Vulnerabilities.clear(); S.scanned = true; setStatus(`${r.vulns.length} vulnerability finding(s)${r.allowlisted ? ` · ${r.allowlisted} hidden by your allowlist` : ''}.`); }
  catch (e) { setStatus('Audit failed: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Vulnerabilities') renderScan(); updateNav();
}
async function quarantine() {
  const f = S.sel.Files; if (!f) return;
  const r = await api.confirm({ message: 'Quarantine (reversible)', detail: f.target + '\n\nReason: ' + f.rule, buttons: ['Cancel', 'Quarantine'] });
  if (r !== 1) return;
  try {
    const x = await api.rpc('quarantine', { target: f.target, rule: f.rule });
    f.quarantined = true; f.resolved = 'quarantined';   // gray it out in the list
    renderRows(); renderInspector(); updateNav();
    setStatus(`Quarantined (${x.qid}). Moved to the reversible vault.`);
  } catch (e) { setStatus('Quarantine failed: ' + e.message); }
}
async function markSafe() {
  const f = S.sel.Files; if (!f) return;
  await api.rpc('mark_safe', allowPayload(f, 'safe'));
  f.resolved = 'safe'; renderRows(); renderInspector();
  setStatus(`${f.name} marked safe — it won’t be flagged again.`);
}
async function vulnIgnore() {
  const f = S.sel.Vulnerabilities; if (!f) return;
  try { await api.rpc('mark_safe', allowPayload(f, 'ignored')); } catch (_e) { /* best-effort */ }
  f.resolved = 'ignored';
  renderRows(); renderInspector(); updateNav();
  setStatus(`Ignored: ${vulnTitle(f)}. Won’t show on future audits (undo in Quarantine).`);
}
// The finding identity the engine needs to remember a Mark-safe / Ignore so it
// persists across scans (it computes the stable key from these fields).
function allowPayload(f, mode) {
  return { mode, finding: { kind: f.kind, target: f.target, name: f.name,
    rule: f.rule, evidence: f.evidence || {} } };
}

// ---------- quarantine vault ----------
function qHuman(b) {
  b = b || 0;
  if (b < 1024) return b + ' B';
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
  do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
  return b.toFixed(b < 10 ? 1 : 0) + ' ' + u[i];
}
async function renderQuarantine() {
  content.innerHTML = `<div class="summary-page"><div class="inner">
    <div class="quar-card panel" id="quar-body"><div class="quar-empty">Loading quarantine vault…</div></div>
    <div class="section" style="margin:22px 4px 10px">TRUSTED &amp; IGNORED</div>
    <div class="quar-card panel" id="allow-body"><div class="quar-empty">Loading…</div></div>
  </div></div>`;
  await Promise.all([refreshQuarantine(), refreshAllowlist()]);
}
// Manage the persisted Mark-safe / Ignore decisions — the undo for "this keeps
// coming back". Removing one lets that finding surface again on the next scan.
async function refreshAllowlist() {
  const body = $('allow-body'); if (!body) return;
  let r;
  try { r = await api.rpc('allowlist_info'); }
  catch (e) { body.innerHTML = `<div class="quar-empty">Couldn’t load: ${esc(e.message)}</div>`; return; }
  const items = r.items || [];
  if (!items.length) {
    body.innerHTML = `<div class="quar-empty">Nothing trusted yet. Files you Mark safe and findings you Ignore are remembered here, so they stay hidden on future scans.</div>`;
    return;
  }
  const head = `
    <div class="quar-top">
      <div class="quar-meta">
        <div class="quar-count">${items.length} trusted item${items.length === 1 ? '' : 's'}</div>
        <div class="quar-path" style="color:var(--muted2)">Hidden from future scans until you remove them.</div>
      </div>
      <div class="quar-acts"><button class="btn ghost" data-action="allow-clear">Clear all</button></div>
    </div>`;
  const modeTag = (m) => `<span class="amode ${m === 'safe' ? 'safe' : 'ign'}">${m === 'safe' ? 'SAFE' : 'IGNORED'}</span>`;
  const rows = items.map((it) => `
    <div class="quar-row">
      <div class="quar-row-x">
        <div class="quar-row-name">${modeTag(it.mode)}${esc(it.label || it.key)}</div>
        <div class="quar-row-sub mono">${esc(it.key)}</div>
      </div>
      <button class="btn ghost sm" data-action="allow-remove" data-key="${esc(it.key)}">Stop ignoring</button>
    </div>`).join('');
  body.innerHTML = head + `<div class="quar-list">${rows}</div>`;
}
async function allowlistRemove(key) {
  try { await api.rpc('allowlist_remove', { key }); setStatus('Removed — it can surface again on the next scan.'); }
  catch (e) { setStatus('Could not remove: ' + e.message); }
  await refreshAllowlist();
}
async function allowlistClear() {
  const c = await api.confirm({ message: 'Clear all trusted items?',
    detail: 'Everything you’ve marked safe or ignored will be able to show up again on the next scan.',
    buttons: ['Cancel', 'Clear all'] });
  if (c !== 1) return;
  try { const x = await api.rpc('allowlist_clear'); setStatus(`Cleared ${x.removed} trusted item(s).`); }
  catch (e) { setStatus('Could not clear: ' + e.message); }
  await refreshAllowlist();
}
async function refreshQuarantine() {
  let r;
  try { r = await api.rpc('quarantine_info'); }
  catch (e) { const b = $('quar-body'); if (b) b.innerHTML = `<div class="quar-empty">Could not read the vault: ${esc(e.message)}</div>`; return; }
  S.quar = r;
  const body = $('quar-body'); if (!body) return;
  const head = `
    <div class="quar-top">
      <div class="quar-meta">
        <div class="quar-count">${r.count} item${r.count === 1 ? '' : 's'} · ${qHuman(r.bytes)}</div>
        <div class="quar-path mono">${esc(r.dir)}</div>
      </div>
      <div class="quar-acts">
        <button class="btn ghost" data-action="quar-open">${ic('folder', 14)} Open folder</button>
        <button class="btn danger" data-action="quar-empty" ${r.count ? '' : 'disabled'}>${ic('trash', 14)} Empty vault</button>
      </div>
    </div>
    <div class="quar-note">Quarantined files are moved here (defanged so they can’t run), never deleted — restore one anytime. <b>Empty vault</b> erases them for good.</div>`;
  if (!r.count) {
    body.innerHTML = head + `<div class="quar-empty">The vault is empty — nothing has been quarantined.</div>`;
    return;
  }
  const rows = r.items.map((it) => `
    <div class="quar-row">
      <div class="quar-row-x">
        <div class="quar-row-name mono">${esc(it.name)}</div>
        <div class="quar-row-sub">${esc(it.original)} · ${qHuman(it.size)}${it.reason ? ' · ' + esc(it.reason) : ''}</div>
      </div>
      <button class="btn ghost sm" data-action="quar-restore" data-qid="${esc(it.qid)}">Restore</button>
    </div>`).join('');
  body.innerHTML = head + `<div class="quar-list">${rows}</div>`;
}
async function quarantineOpen() {
  if (S.quar && S.quar.dir) await api.openPath(S.quar.dir);
}
async function quarantineEmpty() {
  const c = S.quar || {};
  if (!c.count) return;
  const r = await api.confirm({
    message: 'Empty the quarantine vault?', type: 'warning', buttons: ['Cancel', 'Empty vault'],
    detail: `This permanently erases ${c.count} quarantined file(s) (${qHuman(c.bytes)}). This cannot be undone.`,
  });
  if (r !== 1) return;
  try {
    const x = await api.rpc('quarantine_empty');
    setStatus(`Vault emptied · ${x.removed} file(s) erased · ${qHuman(x.bytes)} freed.`);
  } catch (e) { setStatus('Could not empty the vault: ' + e.message); }
  await refreshQuarantine();
}
async function quarantineRestore(qid) {
  const r = await api.confirm({ message: 'Restore this file?', buttons: ['Cancel', 'Restore'],
    detail: 'It will be put back where it was originally found.' });
  if (r !== 1) return;
  try {
    const x = await api.rpc('quarantine_restore', { qid });
    setStatus(`Restored to ${x.original}.`);
  } catch (e) { setStatus('Restore failed: ' + e.message); }
  await refreshQuarantine();
}
async function procAction(kind) {
  const t = S.sel.Processes; if (!t) return;
  if (t.protected) { await api.confirm({ message: 'Protected process', detail: t.name + ' is protected and will not be killed.', buttons: ['OK', 'OK'] }); return; }
  const r = await api.confirm({ message: (kind === 'suspend' ? 'Suspend' : 'KILL') + ` ${t.name} (pid ${t.pid})?`, detail: t.reasons.join('; '), buttons: ['Cancel', kind === 'suspend' ? 'Suspend' : 'Kill'] });
  if (r !== 1) return;
  try { await api.rpc(kind, { pid: t.pid, name: t.name }); setStatus(`${kind} applied to pid ${t.pid}.`); }
  catch (e) { setStatus(kind + ' failed: ' + e.message); }
}

// ---------- multi-select bulk actions ----------
function checkedList() { return Array.from(S.checked[S.page]); }
function toggleCheck(o) {
  if (!o) return;
  const set = S.checked[S.page];
  if (set.has(o)) set.delete(o); else set.add(o);
  renderRows();   // refresh the row's checkmark + the bulk bar
}
function toggleCheckAll() {
  const set = S.checked[S.page];
  const vis = visibleItems();
  if (set.size >= vis.length) set.clear();          // all selected -> clear
  else vis.forEach((o) => set.add(o));              // otherwise select everything visible
  renderRows();
}
async function bulkQuarantine() {
  const items = checkedList().filter((f) => !f.resolved);
  if (!items.length) { setStatus('Nothing to quarantine in the selection.'); return; }
  const r = await api.confirm({ message: `Quarantine ${items.length} file(s)?`, type: 'warning',
    detail: 'Each is moved to the reversible vault — never deleted. You can restore them anytime.',
    buttons: ['Cancel', 'Quarantine all'] });
  if (r !== 1) return;
  let ok = 0, fail = 0;
  for (const f of items) {
    setStatus(`Quarantining ${++ok + fail} of ${items.length}…`);
    try { await api.rpc('quarantine', { target: f.target, rule: f.rule });
      f.quarantined = true; f.resolved = 'quarantined'; }
    catch (_e) { fail++; ok--; }
  }
  S.checked[S.page].clear();
  renderRows(); renderInspector(); updateNav();
  setStatus(`Quarantined ${ok} file(s)${fail ? `, ${fail} failed` : ''}. Moved to the reversible vault.`);
}
async function bulkMarkSafe() {
  const items = checkedList().filter((f) => !f.resolved);
  if (!items.length) { setStatus('Nothing to mark safe in the selection.'); return; }
  for (const f of items) {
    try { await api.rpc('mark_safe', allowPayload(f, 'safe')); } catch (_e) { /* best-effort */ }
    f.resolved = 'safe';
  }
  S.checked[S.page].clear();
  renderRows(); renderInspector(); updateNav();
  setStatus(`Marked ${items.length} file(s) safe — they won’t be flagged again.`);
}
async function bulkIgnore() {
  const items = checkedList().filter((f) => !f.resolved);
  if (!items.length) { setStatus('Nothing to ignore in the selection.'); return; }
  for (const f of items) {
    try { await api.rpc('mark_safe', allowPayload(f, 'ignored')); } catch (_e) { /* best-effort */ }
    f.resolved = 'ignored';
  }
  S.checked[S.page].clear();
  renderRows(); renderInspector(); updateNav();
  setStatus(`Ignored ${items.length} finding(s). Won’t show on future audits (undo in Quarantine).`);
}
async function bulkProc(kind) {
  const all = checkedList();
  const items = all.filter((t) => !t.protected);
  const skipped = all.length - items.length;
  if (!items.length) { setStatus(skipped ? 'All selected processes are protected — skipped.' : 'No processes selected.'); return; }
  const r = await api.confirm({
    message: `${kind === 'suspend' ? 'Suspend' : 'KILL'} ${items.length} process(es)?`, type: 'warning',
    detail: (kind === 'suspend' ? 'Suspending freezes them — reversible.' : 'Killing closes them — not reversible.')
      + (skipped ? `\n\n${skipped} protected process(es) will be skipped.` : ''),
    buttons: ['Cancel', kind === 'suspend' ? 'Suspend all' : 'Kill all'] });
  if (r !== 1) return;
  let ok = 0, fail = 0;
  for (const t of items) {
    try { await api.rpc(kind, { pid: t.pid, name: t.name }); ok++; } catch (_e) { fail++; }
  }
  S.checked[S.page].clear();
  renderRows();
  setStatus(`${kind === 'suspend' ? 'Suspended' : 'Killed'} ${ok} process(es)`
    + `${fail ? `, ${fail} failed` : ''}${skipped ? `, ${skipped} protected skipped` : ''}.`);
}

// ---------- misc ----------
function setMode(mode) {
  document.documentElement.dataset.theme = mode;
  document.querySelectorAll('.seg-btn').forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
  if (api.setTheme) api.setTheme(mode);   // flip the native vibrancy material too
}
function setStatus(s) { $('status').textContent = s; }
// while a scan/analyze/sweep is running, disable the action buttons that would
// start another one (the Stop button lives in the scanbar, so it's untouched).
function setActionsBusy(busy) {
  document.querySelectorAll('.taskbar [data-action], .chatbar [data-action]')
    .forEach((b) => { b.disabled = !!busy; });
}

// ---------- live scan timer / throughput / ETA ----------
let scan = { start: 0, count: 0, total: 0, timer: null, active: false, label: '', canceling: false, samples: [], etaS: null };
function startScanUI(label) {
  scan = { start: Date.now(), count: 0, total: 0, timer: null, active: true, label, canceling: false, samples: [], etaS: null };
  const bar = $('scanbar');
  bar.classList.remove('hidden');
  // Build the bar ONCE. The spinner + track elements then animate continuously
  // instead of being recreated (and restarted) on every repaint; only the label,
  // progress width and numbers below are updated in place.
  bar.innerHTML = `<span class="spin"></span><span class="lbl" id="sb-label"></span>
    <span class="track" id="sb-track"><i></i><b style="width:0%"></b></span>
    <span class="nums" id="sb-nums"></span>
    <button class="btn danger stopbtn" id="sb-stop" data-action="stop">Stop</button>`;
  paintScanBar();
  scan.timer = setInterval(paintScanBar, 250);
  if (api.setBusy) api.setBusy(true);   // let main warn before quitting mid-scan
  setActionsBusy(true);
}
function endScanUI() {
  scan.active = false; if (scan.timer) clearInterval(scan.timer);
  $('scanbar').classList.add('hidden');
  if (api.setBusy) api.setBusy(false);
  setActionsBusy(false);
}
function onProgress(text) {
  setStatus(text);
  if (setupActive) { $('gate-msg').textContent = text; $('gate-msg').style.color = 'var(--accent)'; }
  const m = /([\d,]+)\s+seen/.exec(text); if (m) scan.count = parseInt(m[1].replace(/,/g, ''), 10);
}
function fmtTime(s) { const m = Math.floor(s / 60), ss = Math.floor(s % 60); return m + ':' + String(ss).padStart(2, '0'); }
function fmtEta(s) {
  if (s < 60) return '~' + Math.ceil(s) + 's';
  if (s < 3600) return '~' + Math.round(s / 60) + ' min';
  return '~' + (s / 3600).toFixed(1) + ' hr';
}
function paintScanBar() {
  if (!scan.active) return;
  const now = Date.now();
  const sec = (now - scan.start) / 1000;
  // Rate from a recent window, NOT the lifetime average. The walk+hash phase is
  // fast but ClamAV deep-inspection is slow and stalls the "seen" counter for
  // seconds at a time; a lifetime average is dominated by the fast early phase
  // and badly under-estimates. An ~8s window tracks the *current* throughput, so
  // the estimate rises honestly the moment deep scanning slows things down.
  scan.samples.push({ t: now, c: scan.count });
  while (scan.samples.length > 1 && now - scan.samples[0].t > 8000) scan.samples.shift();
  const head = scan.samples[0];
  const dt = (now - head.t) / 1000, dc = scan.count - head.c;
  const lifetime = sec > 0 ? scan.count / sec : 0;
  // Use the windowed rate once we have a real window; blend toward lifetime when
  // the window momentarily reads zero (a single in-flight ClamAV batch) so the
  // ETA doesn't spike to infinity, then collapse, on every batch boundary.
  let rate = dt >= 1 ? dc / dt : lifetime;
  if (rate <= 0) rate = lifetime * 0.25;   // mid-batch stall: keep a floor, don't divide by ~0
  // ETA from the pre-counted total (only available for targeted scans), smoothed
  // so it counts down steadily instead of jumping around between repaints.
  let eta = '—';
  if (scan.total > 0 && rate > 0 && scan.count < scan.total) {
    const raw = (scan.total - scan.count) / rate;
    scan.etaS = scan.etaS == null ? raw : scan.etaS * 0.6 + raw * 0.4;
    eta = fmtEta(scan.etaS);
  } else if (scan.total > 0 && scan.count >= scan.total) { eta = 'finishing…'; }
  const pct = scan.total > 0 ? Math.min(100, (scan.count / scan.total) * 100) : null;
  // update only the dynamic bits — the spinner element is left alone so it keeps
  // spinning smoothly until the scan ends.
  const lbl = $('sb-label'); if (lbl) lbl.textContent = scan.canceling ? 'Cancelling…' : scan.label;
  const track = $('sb-track');
  if (track) {
    track.classList.toggle('det', pct !== null);
    if (pct !== null) { const b = track.querySelector('b'); if (b) b.style.width = pct.toFixed(1) + '%'; }
  }
  const nums = $('sb-nums');
  if (nums) {
    const stat = (v, l) => `<span class="x"><div class="v">${v}</div><div class="l">${l}</div></span>`;
    nums.innerHTML = `${stat(scan.count.toLocaleString(), 'files')}${stat(fmtTime(sec), 'elapsed')}${stat(eta, 'remaining')}${stat(Math.round(rate).toLocaleString(), '/sec')}`;
  }
  const stop = $('sb-stop');
  if (stop) {
    stop.textContent = scan.canceling ? 'Stopping…' : 'Stop';
    stop.disabled = !!scan.canceling;
    stop.classList.toggle('danger', !scan.canceling);
    stop.classList.toggle('ghost', !!scan.canceling);
  }
}

init();
