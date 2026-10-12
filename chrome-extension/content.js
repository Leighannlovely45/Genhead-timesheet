// ── Genhead Time Tracker — content.js ────────────────────────
(function() {
  let emailSent = false;

  function getLocationName() {
    const selectors = ['.agency-name','.location-name','.sub-account-name','[data-testid="location-name"]','.nav-location-name','.header-title','.business-name'];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.textContent.trim()) return el.textContent.trim();
    }
    const title = document.title;
    if (title && title !== 'HighLevel' && title !== 'GoHighLevel') {
      return title.replace(/\s*[-|]\s*(HighLevel|GoHighLevel|GHL).*$/i, '').trim();
    }
    return null;
  }

  function sendLocationName() {
    const name = getLocationName();
    const match = window.location.href.match(/\/location\/([^\/]+)/);
    if (match && name) {
      chrome.runtime.sendMessage({ type: 'LOCATION_NAME', locationId: match[1], locationName: name });
    }
  }

  function findEmail() {
    if (emailSent) return;
    try {
      const keys = Object.keys(localStorage);
      for (const key of keys) {
        try {
          const parsed = JSON.parse(localStorage.getItem(key));
          const email = extractEmail(parsed);
          if (email) { sendEmail(email); return; }
        } catch (e) {}
      }
    } catch (e) {}
    try {
      const profileArea = document.querySelector('.user-profile,.user-info,.user-menu,.avatar-wrapper,#user-nav');
      if (profileArea) {
        const m = (profileArea.innerText||profileArea.textContent).match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (m) { sendEmail(m[0]); return; }
      }
    } catch (e) {}
  }

  function extractEmail(obj, depth=0) {
    if (depth>5||!obj) return null;
    if (typeof obj==='string'&&isValidEmail(obj)) return obj;
    if (typeof obj==='object') {
      for (const k of ['email','userEmail','user_email','emailAddress','username']) {
        if (obj[k]&&isValidEmail(obj[k])) return obj[k];
      }
      for (const k of ['user','profile','account','auth','currentUser']) {
        if (obj[k]) { const f=extractEmail(obj[k],depth+1); if(f) return f; }
      }
    }
    return null;
  }

  function isValidEmail(s) { return typeof s==='string'&&/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(s.trim()); }

  function sendEmail(email) {
    if (emailSent) return;
    emailSent = true;
    chrome.runtime.sendMessage({ type: 'EMAIL_FROM_PAGE', email });
  }

  findEmail(); sendLocationName();
  setTimeout(()=>{ findEmail(); sendLocationName(); }, 2000);
  setTimeout(()=>{ findEmail(); sendLocationName(); }, 5000);

  let lastUrl = window.location.href;
  new MutationObserver(()=>{
    if (!emailSent) findEmail();
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      setTimeout(sendLocationName, 500);
    }
  }).observe(document.body, { childList:true, subtree:true });
})();
