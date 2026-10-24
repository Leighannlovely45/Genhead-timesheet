// Genhead Time Tracker v2 — popup
const API = 'https://timesheet.genhead.com/api.php';
const $ = id => document.getElementById(id);
const send = msg => chrome.runtime.sendMessage(msg);
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmtClock = s => { s = Math.max(0, Math.floor(s)); return `${Math.floor(s / 3600)}:${String(Math.floor(s % 3600 / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`; };
const fmtH = h => { h = Number(h) || 0; return h >= 1 ? h.toFixed(2) + ' h' : Math.round(h * 60) + ' min'; };

const REASONS = {
  tracking: 'Tracking',
  signed_out: 'Signed out',
  idle: 'Paused — no activity for 2 minutes',
  locked: 'Paused — computer locked',
  chrome_not_focused: 'Paused — Chrome is in the background',
  not_in_subaccount: 'Not in a client sub-account',
  agency_account: "Paused — Genhead's own account isn't client time"
};

let status = null, ctx = null, ticker = null;

async function api(action, { method = 'GET', body, query = '' } = {}) {
  const r = await fetch(`${API}?action=${action}${query}`, {
    method, headers: { 'Content-Type': 'application/json', 'X-TS-Auth': status.auth.token },
    body: body ? JSON.stringify(body) : undefined
  });
  if (r.status === 401) { await send({ type: 'logout' }); location.reload(); return null; }
  return r.json();
}

function localSecondsFor(loc) {
  const today = status.today;
  return Object.values(status.totals || {}).filter(t => t.date === today && t.loc === loc).reduce((a, t) => a + t.seconds, 0);
}

async function render() {
  status = await send({ type: 'status' });
  if (!status || !status.auth || !status.auth.token) {
    $('login').classList.remove('hidden'); $('main').classList.add('hidden'); $('who').textContent = '';
    if (status && status.lastError) $('loginMsg').textContent = status.lastError;
    return;
  }
  $('login').classList.add('hidden'); $('main').classList.remove('hidden');
  $('who').innerHTML = `${esc(status.auth.user.name)}<br><a id="out">Sign out</a>`;
  $('out').onclick = async () => { await send({ type: 'logout' }); render(); };

  const run = status.run || {};
  $('dot').className = 'dot' + (run.active ? ' on' : '');
  $('statusText').textContent = REASONS[run.reason] || (run.active ? 'Tracking' : 'Paused');

  // What's on screen: the sub-account being tracked, or the last one
  const loc = (run.active || ['idle', 'locked', 'chrome_not_focused'].includes(run.reason)) ? (run.loc || null) : null;
  ctx = null;
  if (loc) {
    ctx = await api('ext_context', { query: `&location_id=${encodeURIComponent(loc)}&date=${status.today}` });
  } else {
    ctx = await api('ext_context', { query: `&date=${status.today}` });
  }
  const linked = ctx && ctx.client;
  $('client').textContent = loc ? (linked ? ctx.client.name : (run.label || 'Unlinked sub-account')) : '—';

  // live timer
  clearInterval(ticker);
  const base = loc ? localSecondsFor(loc) : 0;
  const started = run.active && run.since ? run.since : null;
  const tick = () => { $('timer').textContent = fmtClock(base + (started ? (Date.now() - started) / 1000 : 0)); };
  tick(); if (started) ticker = setInterval(tick, 1000);
  $('timerSub').textContent = loc ? 'today in this account' : 'open a client sub-account to start';

  // notices
  let n = '';
  if (status.lastError) n += `<div class="warn err">${esc(status.lastError)}</div>`;
  if (ctx && ['submitted', 'under_review', 'approved'].includes(ctx.sheet_status))
    n += `<div class="warn err">Your ${esc(ctx.period)} timesheet is already ${ctx.sheet_status === 'approved' ? 'approved' : 'submitted'}, so new time can't be added. Ask your reviewer to return it.</div>`;
  if (loc && ctx && !linked) {
    if (ctx.can_link && ctx.linkable && ctx.linkable.length) {
      n += `<div class="warn">This sub-account isn't linked to a client yet. Your time is saved and will move to the client once it's linked.
        <div class="row" style="margin-top:6px"><select id="linkSel"><option value="">Link to client…</option>${ctx.linkable.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></div>
        <button class="btn btn-p" id="linkBtn" style="margin-top:6px;width:100%">Link sub-account</button></div>`;
    } else {
      n += `<div class="warn">This sub-account isn't linked to a client yet. Your time is still saved — an Admin or HR can link it from this tracker. Sub-account ID: <code>${esc(loc)}</code></div>`;
    }
  }
  $('notice').innerHTML = n;
  if ($('linkBtn')) $('linkBtn').onclick = async () => {
    const cid = $('linkSel').value; if (!cid) return;
    const r = await api('ext_link_location', { method: 'POST', body: { location_id: loc, client_id: Number(cid) } });
    if (r && r.success) { await send({ type: 'syncNow' }); render(); } else alert((r && r.error) || 'Could not link.');
  };

  // task picker
  const tasks = (ctx && ctx.tasks) || [];
  const chosen = String((status.taskByLoc || {})[loc] || '');
  if (!loc || !linked) { $('taskSec').classList.add('hidden'); }
  else {
    $('taskSec').classList.remove('hidden');
    const groups = {};
    tasks.forEach(t => { (groups[t.project_name] = groups[t.project_name] || []).push(t); });
    $('task').innerHTML = `<option value="">General ${esc(ctx.client.name)} work (no task)</option>` +
      Object.entries(groups).map(([p, ts]) => `<optgroup label="${esc(p)}">${ts.map(t => {
        const est = Number(t.estimated_hours) || 0, done = Number(t.logged_hours) || 0;
        return `<option value="${t.id}"${String(t.id) === chosen ? ' selected' : ''}>${esc(t.title)}${est ? ` (${done.toFixed(1)}/${est}h)` : ''}</option>`;
      }).join('')}</optgroup>`).join('');
    $('taskSub').textContent = tasks.length ? 'Time goes to the task you pick, on your timesheet and its progress bar.' : 'No open tasks for you on this client.';
  }

  // today's lines on the timesheet
  const lines = (ctx && ctx.today) || [];
  if (!lines.length) $('today').innerHTML = '<div class="muted">Nothing on your timesheet for today yet.</div>';
  else {
    const total = lines.reduce((a, l) => a + Number(l.hours || 0), 0);
    $('today').innerHTML = lines.map(l => `<div class="entry"><div class="n">${esc(l.client_name || '—')}${l.task_title ? `<div class="t">${esc(l.task_title)}</div>` : (l.deliverable ? `<div class="t">${esc(l.deliverable)}</div>` : '')}</div><div class="h">${fmtH(l.hours)}</div></div>`).join('') +
      `<div class="total"><span>Total today</span><span class="h">${fmtH(total)}</span></div>`;
  }
  $('syncInfo').textContent = status.lastSync ? `Last saved ${new Date(status.lastSync).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}` : '';
}

$('signin').onclick = async () => {
  $('loginMsg').textContent = 'Signing in…';
  const r = await send({ type: 'login', email: $('email').value.trim(), pw: $('pw').value });
  if (r && r.success) { $('pw').value = ''; $('loginMsg').textContent = ''; render(); }
  else $('loginMsg').textContent = (r && r.error) || 'Sign-in failed.';
};
$('pw').addEventListener('keydown', e => { if (e.key === 'Enter') $('signin').click(); });
$('task').onchange = async () => { await send({ type: 'setTask', loc: status.run.loc, taskId: $('task').value || null }); render(); };
$('sync').onclick = async () => { $('syncInfo').textContent = 'Saving…'; await send({ type: 'syncNow' }); render(); };
$('open').onclick = () => chrome.tabs.create({ url: 'https://timesheet.genhead.com/?v=2' });

render();
