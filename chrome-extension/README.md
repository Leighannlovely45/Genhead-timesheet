# Genhead Time Tracker — Chrome Extension

Automatically tracks time spent working in Genhead client sub-accounts.

## How it works

- Detects when you navigate to a client sub-account at `app.genhead.com/v2/location/{ID}/...`
- Starts a timer automatically
- Pauses after 2 minutes of system inactivity
- Saves time entries to your timesheet throughout the day
- You review and add deliverable notes before submitting

## Install Instructions

### Step 1 — Add source column to database
Run this in GoDaddy phpMyAdmin → genhead_timesheet → SQL:

```sql
ALTER TABLE timesheet_entries ADD COLUMN source VARCHAR(20) DEFAULT 'manual' AFTER row_index;
ALTER TABLE timesheet_entries ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
```

### Step 2 — Install the extension in Chrome
1. Open Chrome and go to: `chrome://extensions`
2. Enable **Developer Mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `genhead-extension` folder
5. The Genhead Tracker icon appears in your Chrome toolbar

### Step 3 — First time setup
1. Click the Genhead Tracker icon in your toolbar
2. Enter your Genhead email address (one-time only)
3. Click Save Email

### Step 4 — Use it
- Log into Genhead at `app.genhead.com`
- Navigate to any client sub-account
- The tracker icon shows a green dot ● when timing is active
- Click the icon anytime to see today's tracked time per client

## What gets tracked
- ✅ Time in client sub-accounts only
- ✅ Your own Genhead agency (6BHLldSrdn5rbbMGKr1n) is excluded
- ✅ Each unique client gets its own entry row in your timesheet
- ✅ Pauses automatically when you're idle for 2+ minutes
- ✅ Saves incrementally every 30 seconds

## What you need to do
- Add the **Deliverable** description to each auto-logged entry before submitting
- Review all entries for accuracy — you can edit hours if needed
- Submit your timesheet as normal when the period ends

## Troubleshooting
- **Timer not starting?** Make sure you're logged into `app.genhead.com` (not `app.gohighlevel.com`)
- **Client showing as location ID?** The location needs to be in your Genhead clients list — sync clients first
- **Email not detected automatically?** Enter it manually in the popup

## Files
- `manifest.json` — Extension configuration
- `background.js` — Timer logic, idle detection, API calls  
- `content.js` — Reads logged-in user email from GHL page
- `popup.html` — Status widget showing current timer and today's entries
- `icons/` — Extension icons
