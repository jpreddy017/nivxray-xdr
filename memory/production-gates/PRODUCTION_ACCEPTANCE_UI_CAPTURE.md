# PRODUCTION ACCEPTANCE VIA CONSOLE UI — capture list

Owner selections: UI screenshots (no password, no JWT anywhere) · on failure,
capture + read-only canonical diagnostic, no code change · endpoint
`ep_1989031c8c1d0085812f`, tenant `ten_e759b7288598bd882e3dcac49d`.

Console: `https://workspace.nivxmachines.com` — sign in, confirm the tenant
switcher reads **NivX Machines** before capturing.

Six screenshots. Each line says what I check in it.

---

## S1 · Events page, activity dropdown OPEN — the decisive one
`/edr/events` → set the window to **24h** → click the **Activity** dropdown
(`edr-events-activity-filter`) and screenshot it **open**.

The dropdown renders every known class with its live count, or
`· NOT OBSERVED` when the count is zero. From that one image I read:
- `PROCESS (n)` with n > 0
- `AUTH (n)` with n > 0
- that `AUTHENTICATION` does **not** appear as its own entry (it must arrive
  projected as AUTH)
- which classes are genuinely not observed

Also keep the KPI rail in frame (`Activity classes`, `Events`, `Reporting
computers`).

## S2 · Events filtered to PROCESS
Same page → Activity = **PROCESS**, Computers = the Windows host → screenshot
the table with the **Activity** column visible.
I check: rows returned, every row's chip says PROCESS, and the hostname is the
enrolled Windows machine.

## S3 · Events filtered to AUTH
Same, Activity = **AUTH**.
I check: rows returned and every chip says AUTH (this is Security 4624
arriving projected).

## S4 · One PROCESS event's detail pane
With Activity = PROCESS, click a row to open the right-hand pane
(`edr-event-pane`) and screenshot it fully — I need the **Activity** chip, the
**basis** line, the **canonical event id / derivations** block and the payload
preview.
I check: `canonical_event_id` present, the basis honestly names the Sysmon
Event ID 1 mapping, and the activity was not guessed from the raw text.

## S5 · An unsupported event's detail pane — the honesty test
Clear the Activity filter → in the payload search box type **5379** (repeat for
**4798**, **4648**, **4672** if present) → open one result's pane and
screenshot.
I check the Activity shows **NOT STAMPED** / no class, with a truthful reason.
A 5379 shown as AUTH would be a FAIL — a fabricated classification is worse
than a gap.

## S6 · Device Trajectory
`/edr/device-trajectory` (or `/edr/computers/ep_1989031c8c1d0085812f` →
Trajectory tab) for the Windows host → screenshot the lanes/timeline, and if
you can, click one process node so the evidence panel is in frame.
I check: real process evidence with provenance back to a canonical event, not
placeholder lanes.

---

## Optional S7 · direct build fingerprint
While signed in, open in the same browser tab:

```
https://nivxray.nivxforge.com/api/edr/events?activity=AUTHENTICATION&hours=1&limit=1
```

- patched build → JSON with `"filters_applied": {"activity": "AUTH"}`
- pre-patch build → `422 {"code": "ACTIVITY_INVALID"}`

Screenshot whichever you get. (If the browser session doesn't carry the API
auth header this may show `Not authenticated` — that is not a failure of the
fix, just skip it; S1-S6 already cover acceptance.)

---

Nothing here writes: no response action, no isolate, no policy edit, no
enrollment change. Please do not click anything in the Response surface while
capturing.
