// Genhead Time Tracker v2 — background service worker
// Every value lives in chrome.storage, never only in memory: Chrome puts this
// worker to sleep after ~30 seconds, and anything held in a variable is lost.

const API = 'https://timesheet.genhead.com/api.php';
const SUBACCOUNT = /^https:\/\/app\.(?:genhead|gohighlevel)\.com\/v2\/location\/([^/?#]+)/i;
const AGENCY_LOCATION = '6BHLldSrdn5rbbMGKr1n';   // Genhead's own account — not client time
const IDLE_SECONDS = 120;                          // pause after 2 minutes without input
const MAX_GAP_MS = 150 * 1000;                     // longer gaps = computer asleep; not counted
const KEEP_DAYS = 3;

chrome.idle.setDetectionInterval(IDLE_SECONDS);

// ── storage helpers ────────────────────────────────────────────────────────
const get = keys => chrome.storage.local.get(keys);
const set = obj => chrome.storage.local.set(obj);
function localDate(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
const totalKey = (date, loc, taskId) => `${date}|${loc}|${taskId || 0}`;
function cleanTitle(t) {
  return String(t || '').replace(/\s*[-|·]\s*(HighLevel|GoHighLevel|GenSuite|Genhead).*$/i, '').trim().slice(0, 120);
}

// One change at a time: tab, idle and alarm events can arrive together
let chain = Promise.resolve();
const serial = fn => (chain = chain.then(fn, fn).catch(e => console.warn('tracker', e)));

// ── add the running segment to today's totals ─────────────────────────────
async function commit(now) {
  const { run, totals = {} } = await get(['run', 'totals']);
  if (!run || !run.active) return;
  let since = run.since || now;
  let elapsed = now - since;
  if (elapsed > MAX_GAP_MS) elapsed = 0;           // asleep / closed: don't count the gap
  if (elapsed > 0) {
    const k = totalKey(localDate(since), run.loc, run.taskId);
    const t = totals[k] || { date: localDate(since), loc: run.loc, taskId: run.taskId || null, label: run.label || '', seconds: 0, synced: -1 };
    t.seconds += Math.round(elapsed / 1000);
    if (run.label) t.label = run.label;
    totals[k] = t;
  }
  run.since = now;
  await set({ run, totals });
}

// ── decide whether we should be timing right now, and for which client ────
async function evaluate(reasonHint) {
  const now = Date.now();
  await commit(now);
  const { auth, run = {}, taskByLoc = {} } = await get(['auth', 'run', 'taskByLoc']);
  let want = null, reason = reasonHint || '';

  if (!auth || !auth.token) reason = 'signed_out';
  else {
    const idle = await chrome.idle.queryState(IDLE_SECONDS);
    if (idle !== 'active') reason = idle;           // 'idle' or 'locked'
    else {
      const win = await chrome.windows.getLastFocused({ populate: false }).catch(() => null);
      if (!win || !win.focused) reason = 'chrome_not_focused';
      else {
        const [tab] = await chrome.tabs.query({ active: true, windowId: win.id });
        const m = tab && tab.url && tab.url.match(SUBACCOUNT);
        if (!m) reason = 'not_in_subaccount';
        else if (m[1] === AGENCY_LOCATION) reason = 'agency_account';
        else want = { loc: m[1], label: cleanTitle(tab.title) };
      }
    }
  }

  if (want) {
    const taskId = taskByLoc[want.loc] || null;
    const same = run.active && run.loc === want.loc && (run.taskId || null) === taskId;
    await set({ run: { active: true, loc: want.loc, label: want.label || run.label || '', taskId, since: same ? run.since : now, startedAt: same ? run.startedAt : now, reason: 'tracking' } });
  } else {
    await set({ run: { ...run, active: false, since: null, reason } });
  }
  await updateBadge();
}

// ── send totals to the timesheet (the running total, so resends never double-count)
async function sync() {
  const { auth, totals = {} } = await get(['auth', 'totals']);
  if (!auth || !auth.token) return;
  const today = localDate(Date.now());
  const pending = Object.entries(totals).filter(([, t]) => t.seconds !== t.synced && t.seconds >= 30);
  if (!pending.length) return;
  const items = pending.map(([key, t]) => ({ key, date: t.date, location_id: t.loc, task_id: t.taskId, seconds: t.seconds, client_name: t.label }));
  let res;
  try {
    res = await fetch(`${API}?action=ext_track`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-TS-Auth': auth.token },
      body: JSON.stringify({ items })
    });
  } catch (e) { await set({ lastError: 'Offline — time is saved here and will be sent when you reconnect.' }); return; }
  if (res.status === 401) { await set({ auth: null, lastError: 'Your sign-in expired. Open the tracker and sign in again — no time is lost.' }); await evaluate('signed_out'); return; }
  const data = await res.json().catch(() => null);
  if (!data || !data.success) { await set({ lastError: (data && data.error) || 'The timesheet did not accept the update.' }); return; }
  const fresh = (await get('totals')).totals || {};
  let err = '';
  for (const r of data.results || []) {
    const sent = items.find(i => i.key === r.key);
    if (r.ok && fresh[r.key] && sent) { fresh[r.key].synced = sent.seconds; fresh[r.key].client = r.client; fresh[r.key].linked = r.linked; }
    else if (!r.ok) err = r.error || 'Some time was not saved.';
  }
  // drop old days once they're fully sent
  const cutoff = localDate(Date.now() - KEEP_DAYS * 86400000);
  for (const [k, t] of Object.entries(fresh)) if (t.date < cutoff && t.seconds === t.synced) delete fresh[k];
  await set({ totals: fresh, lastError: err, lastSync: Date.now() });
  await updateBadge();
}

async function updateBadge() {
  const { run, lastError, auth } = await get(['run', 'lastError', 'auth']);
  if (!auth || !auth.token) { chrome.action.setBadgeText({ text: '!' }); chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' }); return; }
  if (lastError) { chrome.action.setBadgeText({ text: '!' }); chrome.action.setBadgeBackgroundColor({ color: '#ef4444' }); return; }
  chrome.action.setBadgeText({ text: run && run.active ? '●' : '' });
  chrome.action.setBadgeBackgroundColor({ color: '#03AD8F' });
}

// ── events ─────────────────────────────────────────────────────────────────
function ensureAlarm() { chrome.alarms.create('tick', { periodInMinutes: 0.5 }); }
chrome.runtime.onInstalled.addListener(() => { ensureAlarm(); serial(() => evaluate()); });
chrome.runtime.onStartup.addListener(() => { ensureAlarm(); serial(() => evaluate()); });
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'tick') serial(async () => { await evaluate(); await sync(); }); });
chrome.tabs.onActivated.addListener(() => serial(() => evaluate()));
chrome.tabs.onUpdated.addListener((id, info, tab) => { if (tab.active && (info.url || info.title || info.status === 'complete')) serial(() => evaluate()); });
chrome.windows.onFocusChanged.addListener(() => serial(() => evaluate()));
chrome.idle.onStateChanged.addListener(() => serial(() => evaluate()));

// ── popup messages ─────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const go = async () => {
    if (msg.type === 'status') {
      await evaluate();
      const s = await get(['auth', 'run', 'totals', 'lastError', 'lastSync', 'taskByLoc']);
      return { ...s, today: localDate(Date.now()) };
    }
    if (msg.type === 'login') {
      let data;
      try {
        const r = await fetch(`${API}?action=ext_login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: msg.email, pw: msg.pw }) });
        data = await r.json();
      } catch (e) { return { success: false, error: "Can't reach the timesheet. Check your internet connection." }; }
      if (data && data.success) { await set({ auth: { token: data.token, user: data.user }, lastError: '' }); await evaluate(); await sync(); }
      return data || { success: false, error: 'Sign-in failed.' };
    }
    if (msg.type === 'logout') {
      await commit(Date.now()); await sync();
      await set({ auth: null }); await evaluate('signed_out');
      return { success: true };
    }
    if (msg.type === 'setTask') {
      await commit(Date.now());
      const { taskByLoc = {} } = await get('taskByLoc');
      if (msg.taskId) taskByLoc[msg.loc] = Number(msg.taskId); else delete taskByLoc[msg.loc];
      await set({ taskByLoc });
      await evaluate(); await sync();
      return { success: true };
    }
    if (msg.type === 'syncNow') { await commit(Date.now()); await sync(); return get(['lastError', 'lastSync', 'totals']); }
    return null;
  };
  serial(async () => reply(await go()));
  return true;   // reply comes later
});
