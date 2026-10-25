# Genhead Time Tracker — v2.1

Tracks the time you spend inside GenSuite client sub-accounts and adds it to your
Genhead timesheet automatically.

## Install (2 minutes)

1. Unzip `genhead-time-tracker-v2.1.zip` into a folder you'll keep, e.g. `Documents\Genhead Time Tracker`.
   Don't delete this folder later — Chrome runs the tracker from it.
2. In Chrome go to `chrome://extensions` and turn on **Developer mode** (top right).
3. If you see an older **Genhead Time Tracker**, click **Remove** on it.
4. Click **Load unpacked** and pick the folder from step 1.
5. Click the puzzle-piece icon in Chrome's toolbar and **pin** Genhead Time Tracker.
6. Click the tracker icon and sign in with your **Genhead email and timesheet password**
   (the same password you use at timesheet.genhead.com).

## How it works

- Open any client sub-account in GenSuite (`app.genhead.com` or `app.gohighlevel.com`) and
  the timer starts. Genhead's own agency account isn't counted.
- It pauses when you've been inactive for 2 minutes, your computer is locked or asleep,
  or Chrome isn't the window you're using.
- Time is saved to your timesheet every 30 seconds, under that client.
- **Working on a specific task?** Open the tracker and pick it under *Working on*. Your time
  then goes to that task — on your timesheet and on the task's progress bar.
- The popup shows today's lines on your timesheet. Add notes/deliverables in the timesheet.
- **Sessions:** if you've been away 1 hour or more (idle, locked, asleep, signed out, or
  outside client accounts), coming back starts a **new session** — its own timesheet line
  labeled with its start time — and the task choice resets so it isn't assumed. Signing in
  also starts a new session. Shorter breaks continue the same line.

## Badge on the icon

| Badge | Meaning |
| --- | --- |
| green ● | Tracking |
| none | Paused / not in a client sub-account |
| orange ! | Signed out — open the tracker and sign in |
| red ! | Something needs attention (e.g. timesheet already submitted) — open the tracker |

## Good to know

- **"Sub-account isn't linked to a client"**: your time is still saved. An Admin or HR person
  can link it in one click from the tracker; the time then moves to that client.
- **"Client shows up as its account ID"**: some clients were created with their GenSuite ID
  as the name. Admin/HR can rename them right from the tracker; everyone else should let them know.
- **Submitted timesheet**: new time can't be added to a submitted or approved period. Ask your
  reviewer to return it.
- Tracker lines update live during the day. If you change the hours of a tracker line on the
  timesheet, the tracker will overwrite it while you keep working in that account that day —
  make hour corrections at the end of the day.
- Signed in for 14 days, then it asks again. No time is lost while signed out on this computer.
