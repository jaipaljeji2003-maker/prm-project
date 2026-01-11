# Management Page Training Guide

This guide explains how managers should use the PRM Management page and what each value means.

## 1) What the page is for
The Management page is a live operational dashboard. It shows the full ops-day flight list plus summary metrics, highlights risks, and gives focused lists to act on quickly.

## 2) Top bar controls (always visible)
**Refresh**
- Manually refreshes the data on demand.

**Logout**
- Ends your session and returns to the login page.

**Search**
- Matches **Flight** values only (spaces ignored).
- Auto-refresh pauses while you type so the table does not jump.

**Filter pills (All / ARR / DEP)**
- Limits the table to arrivals, departures, or all flights.

**Problem Only toggle**
- Filters the main table to **at-risk** flights, **past-due shortfall** flights, and (when supported) **unacked changes**.

**Density toggle (Comfortable / Compact)**
- Changes spacing in the table to fit more rows on screen when needed.

**Ops Day selector**
- Switches between the **current** ops day and **next** ops day (when available).

## 3) Metrics (Management Overview)
These tiles summarize the currently loaded dataset.

**Prealerts**
- Shows total WCHR and total WCHC across the dataset.

**Total Scans**
- Sum of PRMGO scans logged for all flights.

**Scan Shortfall (Past Due)**
- Sum of missing scans **only after scan due time**.
- Shortfall = max(0, (WCHR + WCHC) - SCANS) **when past due**.

**0-Scan Flights (Past Due)**
- Count of flights past due with **zero** scans and **prealerts > 0**.

**Unassigned Next 3h (Risk Score)**
- RiskScore sums **(WCHC × 2 + WCHR)** for flights that are:
  - Within the next 3 hours **and**
  - Unassigned **and**
  - Have any prealerted passengers.

**Gate Changes Today**
- Count of flights flagged as gate changes (from alert history or gate change flag).

**Unacked > 5 min**
- Count of change alerts not acknowledged for more than 5 minutes.
- If ack data is not available, the tile shows **—**.

**Void Scans badge**
- Shows unmatched scans not tied to a flight key (when available).
- If unavailable, the badge shows **—**.

## 4) Readiness panels (below metrics)
**Time-to-Scan (Median / P90)**
- Completion latency (median and 90th percentile) measured as:
  - ARR: lastScanTime − ETA
  - DEP: lastScanTime − ETD
- If lastScanTime data is not available, this shows **—**.

**Scanner Data Coverage**
- Count of unique scanners captured in last scan metadata.
- If scanner metadata is not available, this shows **—**.

## 5) Main table columns and meanings
Core columns remain visible on smaller screens; optional columns move into the row **Details** panel.

**Flight / Type / Time (Est)**
- Flight: carrier + flight number.
- Type: ARR or DEP.
- Time (Est): estimated time.

**Time Δ / Sched / Origin-Dest**
- Time Δ: change in minutes (if present).
- Sched: scheduled time.
- Origin/Dest: airport or route.

**Gate / Zone**
- Displayed as badges for quick scanning.

**Status**
- Displays chips for:
  - **At Risk** (unassigned + prealerted + within 3 hours)
  - **Past Due** (scan shortfall after due time)
  - **Gate Change** (alert contains gate change)
  - **Time Change** (time change present)

**WCHR / WCHC**
- Prealert counts by category.

**Assignment**
- Blank means unassigned.

**PRMGO Scans**
- Displays scans, and if past due shows **scans / prealert**.
- Hover to see shortfall when a shortfall exists.

**Last Scanner**
- Shows the last scanner name when the data is available.

## 6) Row highlighting and badges
The table uses subtle visual cues so you can spot issues quickly:

**At Risk row**
- Amber left border and “At Risk” chip.
- Defined as prealerted + within next 3 hours + unassigned.

**Past Due Shortfall row**
- Red left border and “Past Due” chip.
- Appears only when scans are less than prealerts **after** the due time.

**Gate Change / Time Change chips**
- Appear when the row indicates a gate/time change.

## 7) Scan due logic (important)
Scan due time is calculated by flight type:
- **ARR:** ETA + 120 minutes
- **DEP:** ETD + 0 minutes

A scan shortfall is only counted **after** the due time. Overscans are never treated as a problem.

## 8) Sorting and quick triage
Sortable columns:
- **Time (Est)**
- **Time Δ**
- **WCHR**
- **WCHC**
- **PRMGO Scans**

Click a sortable header to toggle ascending/descending order.

## 9) Focus tabs (bottom section)
These tabs give a compact operational list view.

**At-Risk Next 3h**
- Only unassigned, prealerted flights in the next 3 hours.
- Sorted by highest risk score, then soonest time.

**Past-Due Shortfall**
- Only flights past due with a scan shortfall.
- Sorted by WCHC, then shortfall.

**Scanner Focus**
- **Last Scanner per Flight** list.
- **Leaderboard**: scanner name, flights touched, total scans, past-due flights touched.
- If scanner data isn’t available, the panel will show “Scanner data not available.”

## 10) Details expander (mobile/small screens)
On smaller screens, optional columns move into a **Details** drawer per row. Click the triangle expander to view:
- Sched
- Origin/Dest
- Alert
- Comment
- Pax
- Last scanner + last scan time
- Scan due time

## 11) How to verify correct behavior (manager checklist)
- **Problem Only** shows at-risk, past-due shortfall, and unacked changes (when supported).
- **At-risk logic** only includes prealerted + unassigned flights within the next 3 hours.
- **Past-due shortfall** only appears after due time (ARR +120, DEP +0).
- **Sorting** changes the order of rows for the selected header.
- **Responsive details** show hidden columns through the row expander on smaller screens.
