let ticker = null;
let sessionStart = null;

document.getElementById('save-btn').addEventListener('click', async () => {
  const email = document.getElementById('email-inp').value.trim();
  const msg = document.getElementById('email-msg');
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    msg.textContent = 'Enter a valid email address.';
    msg.className = 'msg msg-err';
    return;
  }
  await chrome.storage.local.set({ employeeEmail: email });
  try { await chrome.runtime.sendMessage({ type: 'SET_EMAIL', email }); } catch(e) {}
  msg.textContent = 'Saved! ✓';
  msg.className = 'msg msg-ok';
  setTimeout(() => { document.getElementById('email-block').style.display = 'none'; }, 1200);
});

document.getElementById('open-btn').addEventListener('click', () => {
  chrome.tabs.create({ url: 'https://timesheet.genhead.com' });
});

document.getElementById('refresh-btn').addEventListener('click', () => { init(); });

async function init() {
  const stored = await chrome.storage.local.get(['employeeEmail', 'trackerState']);

  if (stored.employeeEmail) {
    document.getElementById('email-block').style.display = 'none';
  } else {
    document.getElementById('email-block').style.display = 'block';
  }

  const state = stored.trackerState || {};
  const active = state.active || false;
  const currentClient = state.currentClientName || null;
  const entries = state.todayEntries || {};

  const badge = document.getElementById('status-badge');
  badge.textContent = active ? '● Tracking' : 'Inactive';
  badge.className = active ? 'badge badge-active' : 'badge badge-inactive';

  const clientEl = document.getElementById('timer-client');
  if (active && currentClient) {
    clientEl.textContent = currentClient;
    clientEl.style.color = '#fff';
    sessionStart = Date.now();
    startTick();
  } else {
    clientEl.textContent = '—';
    clientEl.style.color = 'rgba(255,255,255,.3)';
    stopTick();
    document.getElementById('timer-time').textContent = '0:00:00';
  }

  const list = document.getElementById('entries-list');
  const today = new Date().toISOString().split('T')[0];
  const todayEntries = Object.values(entries).filter(e => e.date === today);

  if (todayEntries.length === 0) {
    list.innerHTML = '<div class="no-entries">No time tracked yet</div>';
    document.getElementById('total-bar').style.display = 'none';
  } else {
    let html = '';
    let total = 0;
    todayEntries.forEach(e => {
      const secs = e.totalSeconds || 0;
      total += secs;
      const hrs = secs / 3600;
      const display = hrs >= 1 ? hrs.toFixed(2) + ' hrs' : Math.round(secs / 60) + ' min';
      html += `<div class="entry"><span class="entry-name">${e.clientName}</span><span class="entry-hrs">${display}</span></div>`;
    });
    list.innerHTML = html;
    document.getElementById('total-val').textContent = (total / 3600).toFixed(2) + ' hrs';
    document.getElementById('total-bar').style.display = 'flex';
  }

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_TODAY_ENTRIES' });
    if (resp && resp.active) {
      badge.textContent = '● Tracking';
      badge.className = 'badge badge-active';
      if (resp.currentClient) {
        clientEl.textContent = resp.currentClient;
        clientEl.style.color = '#fff';
        sessionStart = Date.now();
        startTick();
      }
    }
  } catch(e) {}
}

function startTick() {
  stopTick();
  ticker = setInterval(() => {
    if (!sessionStart) return;
    const s = Math.floor((Date.now() - sessionStart) / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    document.getElementById('timer-time').textContent =
      `${h}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  }, 1000);
}

function stopTick() {
  if (ticker) { clearInterval(ticker); ticker = null; }
}

init();
