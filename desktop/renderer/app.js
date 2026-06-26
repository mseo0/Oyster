'use strict';
// Oyster renderer — talks to the Python engine via window.oyster (preload).

const api = window.oyster;
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
};
const ic = (k, w = 18) => `<svg width="${w}" height="${w}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICON[k]}</svg>`;

const NAV = [
  { key: 'Files', icon: 'folder', sub: 'On-demand file scan with reversible quarantine.', sec: 'scan' },
  { key: 'Processes', icon: 'cpu', sub: 'Running programs, scored by suspicious behaviour.', sec: 'scan' },
  { key: 'Vulnerabilities', icon: 'shield', sub: 'Installed software & OS settings vs. offline CVE data.', sec: 'scan' },
  { key: 'AI Summary', icon: 'spark', sub: 'A plain-English read-out, written locally just now.', sec: 'report' },
];

const S = {
  page: 'Files', model: '…', target: '~/Downloads',
  data: { Files: [], Processes: [], Vulnerabilities: [] },
  sel: { Files: null, Processes: null, Vulnerabilities: null },
  report: null, summary: '', busy: false,
};

const $ = (id) => document.getElementById(id);
const content = $('content');

// ---------- init ----------
async function init() {
  buildNav();
  $('gate-recheck').addEventListener('click', refreshGate);
  $('gate-launch').addEventListener('click', launch);
  document.querySelectorAll('.seg-btn').forEach((b) =>
    b.addEventListener('click', () => setMode(b.dataset.mode)));
  document.querySelector('.sidebar').addEventListener('click', (e) => {
    const n = e.target.closest('[data-page]'); if (n) showPage(n.dataset.page);
  });
  content.addEventListener('click', onContentClick);
  api.onEvent((m) => { if (m.event === 'progress') onProgress(m.data); });
  try {
    const h = await api.rpc('hello');
    S.model = h.model; S.target = h.defaultTarget;
    $('model-chip').textContent = 'model · ' + h.model;
  } catch (e) { /* gate still works */ }
  refreshGate();
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
  $('gate-msg').textContent = blocked.length
    ? 'Required, still missing: ' + blocked.map((b) => b.name).join(', ')
    : 'All required permissions granted.';
  $('gate-msg').style.color = blocked.length ? '#E5484D' : '#17A98C';
}
function launch() { $('gate').classList.add('hidden'); showPage('Files'); }

// ---------- nav ----------
function buildNav() {
  const scan = NAV.filter((n) => n.sec === 'scan').map(navBtn).join('');
  const rep = NAV.filter((n) => n.sec === 'report').map(navBtn).join('');
  $('nav-scan').innerHTML = scan; $('nav-report').innerHTML = rep;
}
function navBtn(n) {
  return `<button class="nav-btn" data-page="${n.key}">${ic(n.icon)}
    <span class="lbl">${n.key}</span><span class="nav-badge" data-badge="${n.key}"></span></button>`;
}
function updateNav() {
  document.querySelectorAll('.nav-btn').forEach((b) =>
    b.classList.toggle('active', b.dataset.page === S.page));
  for (const key of ['Files', 'Processes', 'Vulnerabilities']) {
    const el = document.querySelector(`[data-badge="${key}"]`);
    const n = S.data[key].length;
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
  key === 'AI Summary' ? renderSummary() : renderScan();
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
          <div class="list-body" id="list"></div>
        </div>
      </div>
      <div class="inspector panel">
        <div class="ins-head"><span class="t">INSPECTOR</span></div>
        <div class="ins-body" id="inspector"></div>
      </div>
    </div>`;
  renderRows(); renderInspector();
}

function taskbar() {
  if (S.page === 'Files') return `
    <div class="field"><span style="color:var(--accent);display:flex">${ic('folder', 16)}</span>
      <span class="k">Target</span><span class="v" id="target">${esc(S.target)}</span></div>
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
    return { count: n, color, headline: n ? `${n} process(es) flagged` : 'Nothing flagged',
      sub: n ? 'Highest-scoring shown first' : 'Sweep to inspect running processes',
      stats: [{ v: n, l: 'FLAGGED' }, { v: prot, l: 'PROTECTED' }, { v: 0, l: 'STOPPED' }] };
  }
  const v = S.data.Vulnerabilities, n = v.length;
  const cves = v.filter((x) => /cve/i.test(x.rule)).length;
  const color = v.some((x) => x.severity === 'critical' || x.severity === 'high') ? SEV.critical : n ? SEV.low : SEV.info;
  return { count: n, color, headline: n ? `${n} issue(s) found` : 'No known issues',
    sub: n ? `${cves} CVEs, ${n - cves} other` : 'Audit software & OS posture',
    stats: [{ v: n, l: 'ISSUES' }, { v: cves, l: 'CVES' }, { v: n - cves, l: 'OTHER' }] };
}

function renderRows() {
  const list = $('list'); const items = S.data[S.page];
  if (!items.length) {
    list.innerHTML = `<div class="empty">${{ Files: 'Run a scan to see findings.', Processes: 'Sweep to inspect processes.', Vulnerabilities: 'Audit to list issues.' }[S.page]}</div>`;
    return;
  }
  list.innerHTML = items.map((o, i) => rowHtml(o, i)).join('');
}
function rowHtml(o, i) {
  const sel = S.sel[S.page] === o ? ' sel' : '';
  if (S.page === 'Processes') {
    const c = procColor(o.score);
    return `<button class="row${sel}" data-action="select" data-idx="${i}">
      <span class="sq" style="background:${tint(c, 0.16)};color:${c}">${o.score}</span>
      <span class="body"><span class="name">${esc(o.name)}<span class="pid">pid ${o.pid}</span>${o.protected ? '<span class="tag">PROTECTED</span>' : ''}</span>
      <span class="meta">${esc(o.reasons.join('; ') || '—')}</span></span></button>`;
  }
  const c = SEV[o.severity] || SEV.info;
  const title = S.page === 'Files' ? o.name : o.rule;
  const meta = S.page === 'Files' ? `${esc(o.dir)} · ${esc(o.rule)}` : `${esc(o.target)} — ${esc(o.detail || o.rule)}`;
  return `<button class="row${sel}" data-action="select" data-idx="${i}">
    <span class="bar" style="background:${c}"></span>
    <span class="body"><span class="name">${esc(title)}</span><span class="meta">${meta}</span></span>
    <span class="chip" style="background:${tint(c, 0.16)};color:${c}">${sevLabel(o.severity)}</span></button>`;
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
function kvTable(pairs) {
  return `<div class="kv">${pairs.map(([k, v]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div>`;
}
function inspectFinding(f, vuln) {
  const c = SEV[f.severity] || SEV.info;
  const crit = f.severity === 'critical' || f.severity === 'high';
  const pairs = Object.entries(f.evidence || {}); if (!pairs.length) pairs.push(['rule', f.rule]);
  const ai = vuln ? aiBox(f.detail || 'Known vulnerability in installed software.')
    : aiBox(crit ? 'Strong match — recommend isolating this file.' : 'Low confidence; review before acting.',
            crit ? 'QUARANTINE' : 'ASK_USER', crit ? '#E5484D' : '#E5B003');
  const actions = vuln
    ? `<button class="btn ghost" data-action="copyfix" style="width:100%;height:40px;margin-top:20px">Copy upgrade command</button>`
    : `<div class="ins-actions"><button class="btn danger" data-action="quarantine">Quarantine</button>
       <button class="btn ghost" data-action="marksafe">Mark safe</button></div>
       <div class="note-sm">Quarantine is reversible — files move to a vault, never deleted.</div>`;
  return `<div><span class="chip" style="background:${tint(c, 0.16)};color:${c}">${sevLabel(f.severity)}</span>
      <span class="kind"> ${esc((f.kind || '').replace(/_/g, ' '))}</span></div>
    <div class="ins-title">${esc(vuln ? f.rule : f.name)}</div>
    <div class="ins-dir" style="${vuln ? 'color:var(--accent)' : ''}">${esc(vuln ? f.target : f.dir + '/')}</div>
    ${f.detail ? `<p class="ins-detail">${esc(f.detail)}</p>` : ''}
    ${ai}<div class="section">${vuln ? 'DETAILS' : 'EVIDENCE'}</div>${kvTable(pairs)}${actions}`;
}
function inspectProc(t) {
  const c = procColor(t.score);
  const reasons = (t.reasons.length ? t.reasons : ['No specific reasons recorded.'])
    .map((r) => `<div class="reason"><span class="d" style="background:${c}"></span><span class="x">${esc(r)}</span></div>`).join('');
  const ai = aiBox(t.score >= 50 ? 'Behaviour is consistent with masquerading — suspend and review.' : 'Looks unusual but low risk.',
    t.score >= 50 ? 'SUSPEND' : 'REVIEW', t.score >= 50 ? '#17A98C' : '#E5B003');
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

// ---------- AI summary ----------
async function renderSummary() {
  const n = S.data.Files.length + S.data.Processes.length + S.data.Vulnerabilities.length;
  content.innerHTML = `<div class="summary-page"><div class="inner">
    <div class="hero panel"><div class="orb"><span class="ring1" style="background:var(--accent)"></span>
      <span class="ring2" style="border-color:var(--accent)"></span>
      <span class="n" style="color:var(--accent)">${ic('spark', 22)}</span></div>
      <div><div class="big">${n ? `Scan complete — ${n} thing(s) to review.` : 'Nothing needs your attention.'}</div>
      <div class="sub3">Generated locally by <span class="mono" style="color:var(--accent)">${esc(S.model)}</span> · nothing was uploaded.</div></div></div>
    <div class="prose panel" id="prose">Generating local summary…</div>
    <div class="note"><span style="color:var(--accent);display:flex">${ic('shield', 18)}</span>
      <div><div class="h">This ran entirely on your Mac.</div>
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
  if (a === 'open-fda') return api.rpc('open_settings', { key: 'fda' });
  if (a === 'choose') { const d = await api.chooseFolder(); if (d) { S.target = d; const el = $('target'); if (el) el.textContent = d; } return; }
  if (a === 'scan') return runScan('scan', { path: S.target });
  if (a === 'deep') return deepScan();
  if (a === 'sweep') return sweep();
  if (a === 'audit') return audit();
  if (a === 'quarantine') return quarantine();
  if (a === 'marksafe') return markSafe();
  if (a === 'suspend') return procAction('suspend');
  if (a === 'kill') return procAction('kill');
}

async function runScan(method, params) {
  if (S.busy) return; S.busy = true; startScanUI('Scanning…');
  try {
    const r = await api.rpc(method, params);
    S.report = r; S.data.Files = r.findings; S.sel.Files = null;
    setStatus(`Done · ${r.filesSeen.toLocaleString()} files in ${r.secs}s · ${r.findings.length} finding(s)`
      + (r.filesUnreadable ? ` · ${r.filesUnreadable.toLocaleString()} unreadable` : '') + ' · offline.');
  } catch (e) { setStatus('Scan stopped: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Files') renderScan();
  updateNav();
}
async function deepScan() {
  const r = await api.confirm({
    message: 'Deep scan — entire computer', type: 'warning', buttons: ['Cancel', 'Scan everything'],
    detail: 'Scan the entire filesystem, including system, hidden and cache folders. This can take a long time. macOS: grant Full Disk Access or private folders are skipped.',
  });
  if (r === 1) runScan('deep_scan', {});
}
async function sweep() {
  if (S.busy) return; S.busy = true; startScanUI('Inspecting processes…');
  try { const r = await api.rpc('sweep_processes'); S.data.Processes = r.processes; S.sel.Processes = null; setStatus(`${r.processes.length} suspicious process(es).`); }
  catch (e) { setStatus('Sweep failed: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Processes') renderScan(); updateNav();
}
async function audit() {
  if (S.busy) return; S.busy = true; startScanUI('Auditing software & OS…');
  try { const r = await api.rpc('audit_vulns'); S.data.Vulnerabilities = r.vulns; S.sel.Vulnerabilities = null; setStatus(`${r.vulns.length} vulnerability finding(s).`); }
  catch (e) { setStatus('Audit failed: ' + e.message); }
  endScanUI(); S.busy = false; if (S.page === 'Vulnerabilities') renderScan(); updateNav();
}
async function quarantine() {
  const f = S.sel.Files; if (!f) return;
  const r = await api.confirm({ message: 'Quarantine (reversible)', detail: f.target + '\n\nReason: ' + f.rule, buttons: ['Cancel', 'Quarantine'] });
  if (r !== 1) return;
  try { const x = await api.rpc('quarantine', { target: f.target, rule: f.rule }); setStatus(`Quarantined (${x.qid}). Restorable.`); }
  catch (e) { setStatus('Quarantine failed: ' + e.message); }
}
async function markSafe() { const f = S.sel.Files; if (!f) return; await api.rpc('mark_safe', { target: f.target }); setStatus(`${f.name} marked safe.`); }
async function procAction(kind) {
  const t = S.sel.Processes; if (!t) return;
  if (t.protected) { await api.confirm({ message: 'Protected process', detail: t.name + ' is protected and will not be killed.', buttons: ['OK', 'OK'] }); return; }
  const r = await api.confirm({ message: (kind === 'suspend' ? 'Suspend' : 'KILL') + ` ${t.name} (pid ${t.pid})?`, detail: t.reasons.join('; '), buttons: ['Cancel', kind === 'suspend' ? 'Suspend' : 'Kill'] });
  if (r !== 1) return;
  try { await api.rpc(kind, { pid: t.pid, name: t.name }); setStatus(`${kind} applied to pid ${t.pid}.`); }
  catch (e) { setStatus(kind + ' failed: ' + e.message); }
}

// ---------- misc ----------
function setMode(mode) {
  document.documentElement.dataset.theme = mode;
  document.querySelectorAll('.seg-btn').forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
}
function setStatus(s) { $('status').textContent = s; }

// ---------- live scan timer / throughput ----------
let scan = { start: 0, count: 0, timer: null, active: false, label: '' };
function startScanUI(label) {
  scan = { start: Date.now(), count: 0, timer: null, active: true, label };
  $('scanbar').classList.remove('hidden'); paintScanBar();
  scan.timer = setInterval(paintScanBar, 250);
}
function endScanUI() {
  scan.active = false; if (scan.timer) clearInterval(scan.timer);
  $('scanbar').classList.add('hidden');
}
function onProgress(text) {
  setStatus(text);
  const m = /([\d,]+)\s+seen/.exec(text); if (m) scan.count = parseInt(m[1].replace(/,/g, ''), 10);
}
function fmtTime(s) { const m = Math.floor(s / 60), ss = Math.floor(s % 60); return m + ':' + String(ss).padStart(2, '0'); }
function paintScanBar() {
  if (!scan.active) return;
  const sec = (Date.now() - scan.start) / 1000;
  const rate = sec > 0 ? Math.round(scan.count / sec) : 0;
  const stat = (v, l) => `<span class="x"><div class="v">${v}</div><div class="l">${l}</div></span>`;
  $('scanbar').innerHTML = `<span class="spin"></span><span class="lbl">${scan.label}</span>
    <span class="track"><i></i></span>
    <span class="nums">${stat(scan.count.toLocaleString(), 'files')}${stat(fmtTime(sec), 'elapsed')}${stat(rate.toLocaleString(), '/sec')}</span>`;
}

init();
