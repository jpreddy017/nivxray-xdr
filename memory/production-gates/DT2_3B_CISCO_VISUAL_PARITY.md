# DT2-3b · CISCO AMP VISUAL / INTERACTION PARITY PASS

Reference: owner-supplied *Cisco Secure Endpoint User Guide* (pp.401-407) and
the owner-supplied Cisco Device Trajectory screenshots.
Device: dev_2adbb41a04a4 · DESKTOP-A9HGFJJ · real Windows corpus.

## THE FILE-EVENT EXPLOSION — CLASSIFICATION: **DOCUMENTED**

Guide p.401, verbatim:

> "Device Trajectory displays the following file types:
>  Executable files · Portable Document Format (PDF) files · MS Cabinet files ·
>  MS Office files · Archive files · Adobe Shockwave Flash · Plain text files ·
>  Rich text files · Script files · Installer files"

p.406, verbatim:

> "Device Trajectory can contain a large amount of data for devices that see
>  heavy use. To narrow Device Trajectory results for a device, you can apply
>  filters to the data or search for specific files, IP addresses, or threats…
>  There are five event filter categories in Device Trajectory: Activity,
>  System, Disposition, Flags, File Type. You must select at least one item
>  from each category to view results."

Cisco's mechanism is therefore a DISPLAYED-FILE-TYPE SET plus the File Type
filter category. It is not grouping, not collapsing and not paging — those
would be INFERRED, so they were not built.

Measured against this corpus: all 57 FILE activities in the acceptance window
are `.ldb` (38), `.tmp` (14), `.log` (5) — Chrome/WhatsApp LevelDB cache
artefacts. **None of them belongs to any of Cisco's ten displayed classes.**
A Cisco trajectory would not carry these rows at all, which is exactly why the
Cisco reference screenshots look compact and process-led while ours looked
like a file dump.

Implemented: `dt2/fileType.js` derives the class from the OBSERVED PATH (the
sensor sends no file-identification verdict, and none is invented), the File
Type filter category now lists the ten classes plus `Other (outside Cisco's
displayed set)` with real counts, and the default selection is Cisco's
documented set. Nothing is deleted: `Other` is one click away, the Activity
pane still lists every observation, and the API still returns everything.

## PARITY TABLE

| # | ELEMENT | CISCO REFERENCE BEHAVIOUR | CURRENT NIVXFORGE | STATE | EVIDENCE AVAILABLE | FIX REQUIRED |
|---|---|---|---|---|---|---|
| 1 | Horizontal process lifeline | solid horizontal line for a running process (p.401) | `<line>` from first→last observed evidence, 1.4 px, `#9CC97E` | MATCH | yes | — |
| 2 | Process row placement | processes on the vertical axis | one row per canonical process identity, parent above child | MATCH | yes | — |
| 3 | File row placement | "files the process acted upon stemming from the line" | FILE row directly beneath its acting process, from the server edge | MATCH | yes | — |
| 4 | Process→process branching | child process stems from the parent line | `PROCESS_PROCESS` edge, elbow stem at the child's own time | MATCH | yes (10 edges) | — |
| 5 | Process→file branching | as above for files | `PROCESS_FILE` edge, 74 in window | MATCH | yes | — |
| 6 | Stem geometry | vertical drop then short horizontal into the row | `M x parentY V childY H x+9` | MATCH | yes | — |
| 7 | Event glyph shape/size | small square (file/process), circle (network/DNS), warning (detection) | same set in `AmpIcons` | MATCH | yes | — |
| 8 | Event placement on lifeline | at the event's own time | X = projected authoritative instant, 0.00 px deviation | MATCH | yes | — |
| 9 | Row spacing | ~18 px, dense | 18 px | MATCH | yes | — |
| 10 | Vertical density | compact; only displayed file types | Cisco's displayed-type set now default | MATCH (was MISSING) | yes | — |
| 11 | Horizontal density | time axis fills the pane | viewport framed to the evidence window | MATCH | yes | — |
| 12 | Graph viewport | one focused interval | `viewport.js`, evidence-framed | MATCH | yes | — |
| 13 | Graph scrolling | vertical row scroll + up/down return arrows (p.402) | `dt2-rows-up` / `dt2-rows-down` + lane window | MATCH | yes | — |
| 14 | Timeline ticks | day label + time ticks | `Sep 22` + adaptive ticks, observed instants added | MATCH | yes | — |
| 15 | System band | "connector events are displayed next to the System label" (p.403) | band present; NivXForge sends no connector-lifecycle events for this device, so it renders empty | PARTIAL | NO — sensor does not emit reboot/scan/policy/definition/connector-update events | telemetry gap, not a UI gap |
| 16 | Files & Network band | band label | present | MATCH | yes | — |
| 17 | Activity pane | "a list of file events is displayed on the right side" (p.401) | right-hand Activity list | MATCH | yes | — |
| 18 | Selected event behaviour | click an event to view details; return arrow (p.403) | select → highlight + `dt2-return-to-event` | MATCH | yes | — |
| 19 | Event Details | name, path, parent process, size, execution context, hashes; network adds dest IP, ports, protocol, PID, SID (p.403) | `AmpEventDetails` shows what the evidence carries; missing fields are stated, not blanked | PARTIAL | partial — no file size, no execution context, SHA-256 only when the sensor sent it | widen sensor fields (separate task) |
| 20 | Filtering / focus | five categories, ≥1 per category (p.406) | Activity, System, Disposition, File Type live; Flags states the gap | PARTIAL | Flags not collected by the sensor | telemetry gap |
| 21 | Dense-event behaviour | filter + search + navigator focus (p.406/402) | displayed-type set, search, navigator click-to-focus | MATCH | yes | — |
| 22 | Navigator → trajectory | circles of varying size, hover gives count and time, click focuses (p.402) | 30-day + 24 h navigator, log-damped radii, `title` count/time, click focuses | MATCH | yes | — |

NOT VERIFIED (therefore NOT built): grouping/collapsing of repeated activity,
result paging inside the trajectory, any "show more" affordance. The guide
describes none of these and no public observation was available.

## RESULT ON THE REAL CORPUS

```
before  47 rows in view, 39 of them .ldb/.tmp/.log file rows, 33 long stems
after    8 process rows, 0 displayable file rows, chrome.exe lifeline
         443.88 → 1032.12 px (15:43:31.770Z → 16:19:36.693Z), 1 span visible
```

Honest consequence: with Cisco's documented display set selected, THIS corpus
has **no displayable file row at all**, because every file observation it
contains is a browser cache artefact. The process→file structure is real and
proven (74 canonical edges) but it is only visible with `Other` selected.

```
PROCESS_FILE_EVIDENCE_IN_CISCO_DISPLAYED_CLASSES: NONE IN THIS CORPUS
```

That is an evidence-coverage gap, not a rendering gap. The W1 synthetic
fixture has `payload.exe` (EXECUTABLE) and would display; the real corpus
carries no executable/script/installer file write in this window.
