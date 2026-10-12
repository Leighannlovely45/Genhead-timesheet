// ── Genhead Time Tracker — background.js ─────────────────────
// Tracks time spent in GHL client sub-accounts
// Matches: app.genhead.com/v2/location/{LOCATION_ID}/*

const API = 'https://timesheet.genhead.com/api.php';
const IDLE_THRESHOLD = 120; // 2 minutes in seconds
const TICK_INTERVAL = 30;   // save progress every 30 seconds
const GHL_PATTERN = /app\.genhead\.com\/v2\/location\/([^\/]+)/;

// ── State ──────────────────────────────────────────────────────
let state = {
  active: false,
  currentLocationId: null,
  currentClientName: null,
  employeeEmail: null,
  sessionStart: null,
  accumulatedSeconds: 0,
  todayEntries: {}, // { locationId: { clientName, totalSeconds, date } }
};

// ── Init ───────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
  console.log('Genhead Time Tracker installed');
  await loadState();
  setupAlarms();
});

chrome.runtime.onStartup.addListener(async () => {
  await loadState();
  setupAlarms();
});

// ── Alarms ─────────────────────────────────────────────────────
function setupAlarms() {
  chrome.alarms.clearAll();
  // Tick every 30 seconds to save progress
  chrome.alarms.create('tick', { periodInMinutes: 0.5 });
  // Midnight reset — save and clear today's entries
  chrome.alarms.create('midnight', { when: getNextMidnight(), periodInMinutes: 1440 });
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'tick') await tick();
  if (alarm.name === 'midnight') await midnightReset();
});

// ── Tab tracking ───────────────────────────────────────────────
chrome.tabs.onActivated.addListener(async (info) => {
  const tab = await chrome.tabs.get(info.tabId);
  await handleTabChange(tab.url);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url) await handleTabChange(changeInfo.url);
});

chrome.windows.onFocusChanged.addListener(async (windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    // Window lost focus — pause timer
    await pauseTimer('window_blur');
  } else {
    // Window gained focus — check active tab
    const [tab] = await chrome.tabs.query({ active: true, windowId });
    if (tab) await handleTabChange(tab.url);
  }
});

// ── Idle detection ─────────────────────────────────────────────
chrome.idle.onStateChanged.addListener(async (idleState) => {
  if (idleState === 'idle' || idleState === 'locked') {
    await pauseTimer('idle');
  } else if (idleState === 'active') {
    // Check if we should resume
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab) await handleTabChange(tab.url);
  }
});
chrome.idle.setDetectionInterval(IDLE_THRESHOLD);

// ── Core logic ─────────────────────────────────────────────────
async function handleTabChange(url) {
  if (!url) return;
  const match = url.match(GHL_PATTERN);
  if (match) {
    const locationId = match[1];
    // Skip Genhead's own location
    if (locationId === '6BHLldSrdn5rbbMGKr1n') {
      await pauseTimer('own_location');
      return;
    }
    if (locationId !== state.currentLocationId) {
      // Switching to a different client — save current and start new
      await pauseTimer('location_change');
      await startTimer(locationId);
    } else if (!state.active) {
      await resumeTimer();
    }
  } else {
    // Not a client sub-account URL
    await pauseTimer('non_client_url');
  }
}

async function startTimer(locationId) {
  // Get client name — try API first, then cached location names, then use ID
  let clientName = null;
  if (state.locationNames && state.locationNames[locationId]) {
    clientName = state.locationNames[locationId];
  }
  if (!clientName) clientName = await getClientName(locationId);
  if (!clientName && state.locationNames && state.locationNames[locationId]) {
    clientName = state.locationNames[locationId];
  }
  state.currentLocationId = locationId;
  state.currentClientName = clientName || locationId;
  state.sessionStart = Date.now();
  state.active = true;
  state.accumulatedSeconds = getTodaySeconds(locationId);
  await saveState();
  updateBadge(true);
  console.log('Timer started for:', state.currentClientName);
}

async function pauseTimer(reason) {
  if (!state.active || !state.sessionStart) return;
  const elapsed = Math.floor((Date.now() - state.sessionStart) / 1000);
  if (elapsed > 0 && state.currentLocationId) {
    addTodaySeconds(state.currentLocationId, elapsed);
    await saveToTimesheet(state.currentLocationId, state.currentClientName, elapsed);
  }
  state.active = false;
  state.sessionStart = null;
  await saveState();
  updateBadge(false);
  console.log('Timer paused:', reason);
}

async function resumeTimer() {
  if (state.active || !state.currentLocationId) return;
  state.sessionStart = Date.now();
  state.active = true;
  await saveState();
  updateBadge(true);
}

async function tick() {
  if (!state.active || !state.sessionStart) return;
  const elapsed = Math.floor((Date.now() - state.sessionStart) / 1000);
  if (elapsed >= TICK_INTERVAL && state.currentLocationId) {
    // Save incremental time
    addTodaySeconds(state.currentLocationId, elapsed);
    await saveToTimesheet(state.currentLocationId, state.currentClientName, elapsed);
    // Reset session start to now (avoid double counting)
    state.sessionStart = Date.now();
    await saveState();
  }
}

async function midnightReset() {
  await pauseTimer('midnight');
  state.todayEntries = {};
  state.currentLocationId = null;
  state.currentClientName = null;
  await saveState();
  console.log('Midnight reset complete');
}

// ── API calls ──────────────────────────────────────────────────
async function getClientName(locationId) {
  try {
    const res = await fetch(`${API}?action=get_client_by_location&location_id=${locationId}`);
    const data = await res.json();
    return data.success ? data.name : null;
  } catch (e) {
    console.error('getClientName error:', e);
    return null;
  }
}

async function getEmployeeEmail() {
  if (state.employeeEmail) return state.employeeEmail;
  // Try to read from storage first
  const stored = await chrome.storage.local.get('employeeEmail');
  if (stored.employeeEmail) {
    state.employeeEmail = stored.employeeEmail;
    return state.employeeEmail;
  }
  return null;
}

async function saveToTimesheet(locationId, clientName, seconds) {
  const email = await getEmployeeEmail();
  if (!email) { console.warn('No employee email — cannot save time'); return; }
  // Use cached location name if available
  const nameToSave = (state.locationNames && state.locationNames[locationId]) || clientName || locationId;
  const hours = (seconds / 3600).toFixed(4);
  const today = getTodayDate();
  try {
    const res = await fetch(`${API}?action=log_timer_entry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, locationId, clientName: nameToSave, hours, date: today, source: 'extension' })
    });
    const data = await res.json();
    console.log(`Saved ${hours}hrs for ${nameToSave}:`, data.success ? 'OK' : data.error);
  } catch (e) {
    console.error('saveToTimesheet error:', e);
  }
}

// ── Helpers ────────────────────────────────────────────────────
function getTodayDate() {
  return new Date().toISOString().split('T')[0];
}

function getNextMidnight() {
  const now = new Date();
  const midnight = new Date(now);
  midnight.setHours(24, 0, 0, 0);
  return midnight.getTime();
}

function getTodaySeconds(locationId) {
  return state.todayEntries[locationId]?.totalSeconds || 0;
}

function addTodaySeconds(locationId, seconds) {
  if (!state.todayEntries[locationId]) {
    state.todayEntries[locationId] = {
      clientName: state.currentClientName,
      totalSeconds: 0,
      date: getTodayDate()
    };
  }
  state.todayEntries[locationId].totalSeconds += seconds;
}

function updateBadge(active) {
  chrome.action.setBadgeText({ text: active ? '●' : '' });
  chrome.action.setBadgeBackgroundColor({ color: active ? '#03AD8F' : '#64748b' });
}

// ── State persistence ──────────────────────────────────────────
async function saveState() {
  await chrome.storage.local.set({ trackerState: state });
}

async function loadState() {
  const stored = await chrome.storage.local.get(['trackerState', 'employeeEmail']);
  if (stored.trackerState) {
    state = { ...state, ...stored.trackerState };
    // Don't restore active session — start fresh
    state.active = false;
    state.sessionStart = null;
  }
  if (stored.employeeEmail) state.employeeEmail = stored.employeeEmail;
  // Clear entries from previous days
  const today = getTodayDate();
  Object.keys(state.todayEntries || {}).forEach(k => {
    if (state.todayEntries[k].date !== today) delete state.todayEntries[k];
  });
}

// ── Message handler (from popup/content) ──────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'GET_STATE') {
    sendResponse({ state });
  }
  if (msg.type === 'SET_EMAIL') {
    state.employeeEmail = msg.email;
    chrome.storage.local.set({ employeeEmail: msg.email });
    sendResponse({ success: true });
  }
  if (msg.type === 'GET_TODAY_ENTRIES') {
    sendResponse({ entries: state.todayEntries, active: state.active, currentClient: state.currentClientName });
  }
  if (msg.type === 'EMAIL_FROM_PAGE') {
    if (!state.employeeEmail) {
      state.employeeEmail = msg.email;
      chrome.storage.local.set({ employeeEmail: msg.email });
      console.log('Employee email set from page:', msg.email);
    }
  }
  return true;
});

// Handle location name from content script
// (appended to existing message handler)
const _origListener = chrome.runtime.onMessage.hasListeners();
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'LOCATION_NAME') {
    // Cache location name so we don't show location ID
    if (!state.locationNames) state.locationNames = {};
    state.locationNames[msg.locationId] = msg.locationName;
    // If currently tracking this location, update the display name
    if (state.currentLocationId === msg.locationId && !state.currentClientName?.includes('-')) {
      state.currentClientName = msg.locationName;
      saveState();
    }
  }
  return true;
});
