# DT2-3 · CISCO SECURE ENDPOINT / AMP DEVICE TRAJECTORY — VISIBLE ELEMENT PARITY TABLE

STATUS: **AUDIT ONLY — NO CODE, UI OR DATA CHANGES MADE.**
Scope audited: the Device Trajectory page and its AMP*/dt2 components only.
Files inventoried:
`EdrDeviceTrajectoryPage.jsx`, `AmpComputerHeader.jsx`, `AmpFilterBar.jsx`,
`AmpNavigator.jsx`, `AmpCanvas.jsx`, `AmpActivityPanel.jsx`,
`AmpEventDetails.jsx`, `AmpIcons.jsx`, `RelationshipCanvas.jsx`
(+ `RelationshipBasis`), `dt2/*`.

Phase rule applied: **NO PUBLICLY VERIFIED CISCO BEHAVIOR = DO NOT SHOW IN THE
AMP-PARITY UI.** Removal means *hidden from the AMP-parity presentation behind a
parked flag*. No engine, resolver, projection, evidence rule, causality state or
internal identity is proposed for deletion.

---

## TOTALS

REV 2 — amended after the owner's navigator ruling and the two Cisco sources it
led to (C12, C13). Superseded REV 1 figures are shown in brackets.

| METRIC | COUNT |
|---|---|
| TOTAL_VISIBLE_ELEMENTS_AUDITED | **140** (was 136) |
| KEEP | **33** (unchanged) |
| CHANGE | **27** (was 25) |
| REMOVE (hide from AMP-parity presentation) | **60** (was 62) |
| MISSING_IN_NIVXFORGE | **20** (was 16) |
| REFERENCE_BEHAVIOR_NOT_VERIFIED | **60** (was 62) |

Classification counts: DOCUMENTED 48 · PUBLICLY_OBSERVED 29 · INFERRED 3 ·
REFERENCE_BEHAVIOR_NOT_VERIFIED 60.

REV 2 deltas: #35 navigator − / + reclassified DOCUMENTED (REMOVE → CHANGE) ·
#115 MITRE tactics/techniques box reclassified DOCUMENTED (REMOVE → CHANGE) ·
#43 upgraded PUBLICLY_OBSERVED → DOCUMENTED · four new MISSING rows #137–#140
(yellow IOC highlighting, separate compromise event, blue halo, search results
as blue dots).

---

## CISCO SOURCE REGISTER

| REF | SOURCE | URL | SECTION / PAGE |
|---|---|---|---|
| C1 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | "Device Trajectory" → "Trajectory View", p.401 |
| C2 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | "Device Trajectory" → "Day and Time Navigator", p.402 |
| C3 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | "Device Trajectory" → "Trajectory Events", p.403 |
| C4 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | "Device Trajectory" (Share > Copy URL, device actions), p.404 |
| C5 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | "Filters", p.406 |
| C6 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | "Search" / "Filters and Search" / "Time Start Filter", p.407–410 |
| C7 | UW–Madison Office of Cybersecurity KB (public walkthrough with live AMP console screenshots) | https://kb.wisc.edu/security/90059 | "Device Trajectory" section |
| C8 | Cisco TechNote — Identify Detection Engine in Secure Endpoint | https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222850-identify-detection-engine-in-secure-endp.html | Device Trajectory icon from Events; engine in details |
| C9 | Cisco TechNote — Troubleshoot Exploit Prevention in Secure Endpoint | https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/218067-troubleshoot-exploit-prevention-in-secur.html | Device Trajectory icon in event details; activity before/after compromise |
| C10 | Cisco Live TACSEC-2012 (2024) | https://www.ciscolive.com/c/dam/r/ciscolive/global-event/docs/2024/pdf/TACSEC-2012.pdf | Device Trajectory filtering / 30-day retention |
| C11 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | "Mobile App Trajectory", p.411 — **negative evidence**: click-to-zoom is documented for *Mobile App* Trajectory, NOT Device Trajectory |
| C12 | Cisco AMP for Endpoints User Guide (PDF) | https://cloudmanaged.ca/wp-content/uploads/2020/05/AMP-for-Endpoints-User-Guide.pdf | "Device Trajectory" → **"The Navigator"**, p.171 and **"Indications of Compromise"**, p.171 |
| C13 | Cisco Secure Endpoint User Guide (PDF) | https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf | **"Trajectory Indications of Compromise"**, p.405 |

REV 2 verbatim anchors:
- C12 p.171 "The Navigator": *"You can collapse the navigator by clicking the - button and expand it again by clicking on the ribbon or the + button."* · *"The navigator enables you to quickly locate and pinpoint events in the Device Trajectory. The upper ribbon displays the last 30 days, and the miniature line graph above it represents the level of activity on the computer over this period. Red dots on the 30-day ribbon represent the occurrence of compromise events. Search results appear as blue dots. The size of the dots are relative to the number of events per day. Below the 30-day ribbon is the 24-hour ribbon, which represents the 24 hours of the selected day."*
- C13 p.405 "Trajectory Indications of Compromise": *"When certain series of events are observed on a single device, they are seen by Secure Endpoint as indications of compromise. In Device Trajectory, these events will be highlighted yellow so they are readily visible. There will also be a separate compromise event in the Trajectory that describes the type of compromise. Clicking on the compromise event will also highlight the individual events that triggered it with a blue halo."* · *"A description of the indicator and the tactics and techniques will also be displayed in the Event Details pane of the trajectory."*

Verbatim anchors used throughout:
- C1: *"The vertical axis of the Device Trajectory shows a list of files and processes observed on the device by the connector and the horizontal axis represents the time. Running processes are represented by a solid horizontal line with child processes and files the process acted upon stemming from the line. A list of file events is displayed on the right side of the device trajectory."*
- C1: *"Device Trajectory stores 30 days of file events… Only the first 500 compromise events are available for a 30-day period."*
- C2: *"If the selected row is off-screen, click up arrow or down arrow button to return to it."* · *"The day and time navigator shows activity as circles of varying size. To view the number of events and the time they were recorded, hover over a circle. To focus the device trajectory display on the events, click the circle."*
- C3: *"The blue line graph above the dates shows the number of cloud queries made by the endpoint each day."* · *"Click an event to view its details."* · *"Click left return arrow button if you scroll away from the selected event in the pane to return to the event."* · *"Secure Endpoint connector events are displayed next to the System label in Device Trajectory."* · *"To view details of the selected device, click the device name in the Device Trajectory view."*
- C5: *"There are five event filter categories in Device Trajectory: Activity, System, Disposition, Flags, File Type. You must select at least one item from each category to view results."*
- C6: *"at:<timestamp>"* time-start filter; *"Right-click a file or process on the vertical axis of the Device Trajectory and select Copy SHA-256 from the menu."*

---

## A · PAGE FRAME

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 1 | Page heading "Device Trajectory" | Page exists and is named Device Trajectory | C1 p.401 | DOCUMENTED | Single-endpoint Device Trajectory page | Same heading | KEEP | Exact parity |
| 2 | Linked XDR incidents chip in header | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Header chip listing XDR incidents referencing the endpoint | REMOVE | NivXForge cross-product surface; park for Phase 2 |
| 3 | Light / Dark theme toggle | none for the DT page | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Per-page theme switch button | REMOVE | Console appearance is not a documented DT control |
| 4 | "Use Legacy Device Trajectory" link | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Opens the older NivXForge trajectory | REMOVE | Product-internal migration affordance |
| 5 | Fullscreen ⤢ toggle | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Expands page to viewport | REMOVE | Not established as AMP DT chrome |
| 6 | Share > Copy URL | *"click Share > Copy URL"* | C4 p.404 | DOCUMENTED | Copy a shareable URL of the current DT view | Absent (URL state exists internally, no Share control) | **MISSING** | Required for parity |
| 7 | Device actions: full scan, flash scan, move to group, Connector Diagnostics | *"run a full or flash scan, move the device to a different group, or initiate Connector Diagnostics"* | C4 p.404 | DOCUMENTED | Endpoint actions from DT | Different action set (see #11) | **MISSING** | Documented action set absent |

## B · COMPUTER / ENDPOINT CONTEXT

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 8 | Computer card: hostname (+ group) | Device name shown in the DT view | C3 p.403; C7 | DOCUMENTED | Device name displayed; clicking it opens device details | Hostname + group displayed | KEEP | Parity |
| 9 | "N compromise events" summary | Compromise events are a first-class DT concept (500 cap / 30 days) | C1 p.401; C7 | DOCUMENTED | Compromise events surfaced on the endpoint | Counts "malicious + detections" from our activity days | CHANGE | Must be Cisco's compromise-event count, not our composite metric |
| 10 | "Show details" button → properties drawer | *"To view details of the selected device, click the device name"* | C3 p.403 | DOCUMENTED | Trigger is the **device name**, not a separate button | Separate "Show details" button opens drawer | CHANGE | Move trigger onto the device name |
| 11 | "Actions ⌄" menu (Events, Process Tree, Campaign Story, Live Query, Take System Snapshot, Device Audit Log) | Device actions exist, but the documented set differs | C4 p.404 | DOCUMENTED (control) / NOT_VERIFIED (items) | Scan, move group, Connector Diagnostics | NivXForge-specific investigation pivots | CHANGE | Keep the menu, replace the items with the documented set; park our pivots |
| 12 | Epistemic state chip (OBSERVED / UNKNOWN) | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Badge stating evidence state of the endpoint | REMOVE | NivXForge provenance vocabulary |
| 13 | "Device IID" property | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Internal endpoint identifier in the drawer | REMOVE | Internal identity in analyst-facing properties |
| 14 | "Identity Confidence" property | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Confidence of endpoint identity resolution | REMOVE | NivXForge-only concept |
| 15 | "Activity Rows" property | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Total lane count of the projection | REMOVE | Architecture metric leaking into UI |
| 16 | "Vulnerabilities — not collected by NivXRay EDR" disclaimer | Vulnerabilities exist in the Cisco computer surface; this disclaimer does not | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Explanatory absence notice | CHANGE | Hide the disclaimer text; leave the section empty/absent |
| 17 | "Related Compromise Events" list in drawer | *computer details drawer gives a chronological event list; clicking an event centres Device Trajectory on it* | C7; C4-adjacent | PUBLICLY_OBSERVED | Click event → DT centres on that event | List rendered, click-to-focus not wired from the drawer | CHANGE | Must become the documented jump-to-event pivot |

## C · FILTERS & SEARCH

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 18 | "Filters ⌄" button (+ active count badge) | *"use the Filters button"* / five filter categories | C5 p.406; C7 | DOCUMENTED (button) / NOT_VERIFIED (badge) | Filters button opens the filter matrix | Button + "(n)" active count | CHANGE | Keep button, drop the invented count badge |
| 19 | Activity type checkboxes | *"Activity describes events that the connector recorded"* | C5 p.406 | DOCUMENTED | Activity category selection | Activity types listed with checkboxes | KEEP | Parity |
| 20 | Per-type observed counts next to each activity type | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Count of persisted observations per type | REMOVE | Our evidence-transparency addition |
| 21 | Disposition checkboxes | *"Disposition allows you to filter events based on their disposition"* | C5 p.406 | DOCUMENTED | Malicious / clean / unknown | MALICIOUS / SUSPICIOUS / UNKNOWN_NOT_ASSESSED | KEEP (values reviewed in #21a of missing list) | Category is parity |
| 22 | **System** filter category | *"five event filter categories… System"* | C5 p.406 | DOCUMENTED | Compromises, reboots, policy/definition updates, scans, uninstalls | Absent | **MISSING** | Required category |
| 23 | **Flags** filter category | *"Flags are modifiers to event types… audit only flag"* | C5 p.406 | DOCUMENTED | Warning / audit-only modifiers | Absent | **MISSING** | Required category |
| 24 | **File Type** filter category | *"File Type allows you to filter… by the type of files involved"* | C5 p.406 | DOCUMENTED | Executables, PDFs, other | Absent | **MISSING** | Required category |
| 25 | "select at least one item from each category" rule | *"You must select at least one item from each category to view results."* | C5 p.406 | DOCUMENTED | Filter semantics gate results | No such rule | **MISSING** | Filter semantics differ from Cisco |
| 26 | "Apply Filters" button | *"select the blue Apply Filters button"* | C7 | PUBLICLY_OBSERVED | Filters are applied explicitly | Filters apply live on change | **MISSING** | Explicit apply step absent |
| 27 | Timeframe presets (Last 24 hours / 7 / 14 / 30 days / All observed) | none as a DT filter category | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Preset buttons inside the filter menu | REMOVE | Time selection in Cisco is the navigator, not presets |
| 28 | Legend block inside the filter menu | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Glyph legend + explanatory sentence | REMOVE | Our documentation embedded in the UI |
| 29 | "Clear all filters" button | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Resets kinds/dispositions/query | REMOVE | Not publicly established |
| 30 | "Search Device Trajectory" input | *"The search field on the Device Trajectory page…"* + supported terms + *"press Enter"* | C6 p.407 | DOCUMENTED | Enter-submitted, case-insensitive, tokenized search | Debounced live search; placeholder lists MITRE technique + command line | CHANGE | Enter-to-submit; placeholder/term set must match the documented list |
| 31 | Search magnifier affordance | Search control present in the DT header | C7 | PUBLICLY_OBSERVED | Search submit affordance | Static icon (non-interactive) | KEEP | Make it the submit action under #30 |
| 32 | `at:<timestamp>` time-start filter | *"at:2023-12-31 to start the device trajectory view at midnight…"* | C6 p.409 | DOCUMENTED | Start DT at a timestamp; `<term> at:<ts>` = logical AND | Absent | **MISSING** | Documented search grammar |
| 33 | Documented search-term coverage (detection name, SHA-256, file name, file path, URL, remote IP, user name, iOS bundle ID, Windows OS API name) + tokenisation rules | C6 tables | C6 p.407–409 | DOCUMENTED | Exact match/tokenisation semantics | Free-text server query, semantics not aligned | **MISSING** | Search semantics parity |
| 34 | "N / M observations" matched counter | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Matched vs all-time observation counter | REMOVE | Our projection metric |
| 35 | Navigator collapse control (currently ▼ / ▶ chevron) | *"You can collapse the navigator by clicking the - button and expand it again by clicking on the ribbon or the + button."* | **C12 p.171 "The Navigator"** | **DOCUMENTED** *(REV 2 — was NOT_VERIFIED)* | Collapse via a **−** button; expand by clicking **the ribbon** or a **+** button | ▼ / ▶ chevron collapses the panel; the collapsed ribbon is not clickable to expand | **CHANGE** *(REV 2 — was REMOVE)* | Control is verified parity, but the glyphs and the click-the-ribbon-to-expand affordance are not. Implement Cisco's − / + and make the collapsed ribbon expand on click. **This is navigator collapse/expand and must NOT be conflated with #36/#37/#62 trajectory zoom, which stay REMOVE.** |
| 36 | Zoom in (magnifier+) icon button | Not documented for Device Trajectory; click-to-zoom is documented only for **Mobile App** Trajectory | C11 p.411 (negative) | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Halves the window span | REMOVE | Explicit negative evidence for DT |
| 37 | Zoom out (magnifier−) icon button | same as #36 | C11 p.411 (negative) | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Doubles the window span | REMOVE | Explicit negative evidence for DT |
| 38 | ◀ / ▶ earlier / later icon buttons | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Pans the window by half a span | REMOVE | Cisco pans by dragging the bars / scrolling the graph |
| 39 | Fit-the-day crosshair button | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Sets window to the selected day | REMOVE | Day selection is the 30-day band's job |

## D · NAVIGATOR (30-DAY + 24-HOUR)

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 40 | Activity density sparkline above the dates | *"The blue line graph above the dates shows the number of cloud queries made by the endpoint each day"* | C3 p.403 | DOCUMENTED (element) | Line graph = **cloud queries per day**, hover shows precise number | Line graph = our per-day observation density | CHANGE | Right element, wrong quantity + no hover readout |
| 41 | 30-day band of day cells | 30 days retained; day navigator | C1 p.401; C2 p.402; C10 | DOCUMENTED | 30-day period navigable by day | 30 day cells anchored on last observed day | KEEP | Parity |
| 42 | Day activity represented as bar height | *"activity as circles of varying size"* | C2 p.402 | DOCUMENTED | Circles of varying size | Vertical bars inside each day cell | CHANGE | Representation must be Cisco's circles |
| 43 | Red strip on days containing malicious/detections | *"Red dots on the 30-day ribbon represent the occurrence of compromise events."* | **C12 p.171** *(REV 2 — upgraded from C7 PUBLICLY_OBSERVED)* | **DOCUMENTED** | Red **dots** on the 30-day ribbon mark compromise events | Red top strip sized by count | CHANGE | Must be red dots on the ribbon, not a strip, and must mean compromise events specifically |
| 44 | Day-of-month numeric labels | Date labels under the band | C7 | PUBLICLY_OBSERVED | Dates labelled | Same | KEEP | Parity |
| 45 | Month labels (e.g. JUL / AUG) | Month labels on the band | C7 | PUBLICLY_OBSERVED | Same | Same | KEEP | Parity |
| 46 | Connector polyline linking selected day → 24-hour band | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Decorative bracket | REMOVE | Invented ornament |
| 47 | 24-hour band with hour cells and 0:00…23 labels | *"sliding date and time bars in the upper timeline window"* | C7 | PUBLICLY_OBSERVED | Selected-day time bar | Same | KEEP | Parity |
| 48 | Circles of varying size per time bin | *"activity as circles of varying size"* | C2 p.402 | DOCUMENTED | Same | Circles sized by log density (red when malicious) | KEEP | Parity |
| 49 | Hover readout: number of events + time recorded | *"To view the number of events and the time they were recorded, hover over a circle."* | C2 p.402 | DOCUMENTED | Hover tooltip with count + time | Native `title` tooltips only, wording is ours | CHANGE | Must be an explicit hover readout with count + recorded time |
| 50 | Click a circle to focus the trajectory on those events | *"To focus the device trajectory display on the events, click the circle."* | C2 p.402 | DOCUMENTED | Click focuses DT | Bin click centres the window on the nearest observed bin | KEEP | Behaviour matches |
| 51 | Hatched "out of view" regions in the hour band | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Diagonal hatch outside the window | REMOVE | Our epistemic marking |
| 52 | Draggable window band | *"sliding date and time bars"* | C7 | PUBLICLY_OBSERVED | Window slides / resizes | Same (drag, resize, cross-midnight day change) | KEEP | Parity |
| 53 | Triangle handles on window edges | Visible handles on the Cisco band | C7 | PUBLICLY_OBSERVED | Same | Same | KEEP | Parity |
| 54 | Dashed window-edge cursor + HH:MM label | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Dashed line + time text | REMOVE | Precision affordance we invented |
| 55 | Selected-event cursor line in the hour band | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Vertical mark at the selected event's time | REMOVE | Not publicly established |
| 56 | "MMM D · N observation(s) on this day" label | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Day summary line | REMOVE | Our counter |
| 57 | "window 24h · ISO → ISO UTC" mono line | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Window span/bounds readout | REMOVE | Engine state as UI text |
| 58 | Red dot → blue "Compromise Events" option → jump into the process detail graph | *"click on the red dot, and then click on the blue Compromise Events option that appears to view the event in the process detail graph"* | C7 | PUBLICLY_OBSERVED | Two-step compromise navigation from the navigator | Absent | **MISSING** | Core documented compromise navigation |
| 59 | Cloud-queries-per-day line with hover precise number | C3 verbatim | C3 p.403 | DOCUMENTED | Distinct data series above the dates | Absent (we plot observation density instead) | **MISSING** | Different series entirely |

## E · DT2 TOOLBAR (NIVXFORGE NAVIGATION STRIP)

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 60 | "◀ Event" / "Event ▶" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Steps to previous/next observation in evidence order | REMOVE | Engine capability, not a Cisco control. Cisco's documented return control is the left return arrow (#87) |
| 61 | "◀ Detection" / "Detection ▶" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Steps between detections | REMOVE | Not publicly established |
| 62 | "Zoom in" / "Zoom out" text buttons | Negative evidence: documented only for Mobile App Trajectory | C11 p.411 | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Zoom the time window | REMOVE | Explicitly not DT behaviour |
| 63 | ISO window label "…Z → …Z" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Current window bounds | REMOVE | Engine state as UI text |
| 64 | "Activity volume:" + density spike count buttons | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Jump to the densest buckets | REMOVE | Navigator already carries activity density |
| 65 | Window-state text (READY / CANCELED / STALE_RESPONSE_DISCARDED / …) | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Request lifecycle label in the toolbar | REMOVE | Internal request state surfaced to analysts |
| 66 | Selection-state banner (SELECTED_OUTSIDE_WINDOW etc. + event_iid) | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Explains selection retention | REMOVE | Internal state + internal identifier |
| 67 | "PROCESS / RELATIONSHIP / TIME" \| "EVENT LANES" mode tabs | none — Cisco has ONE graph | C1 p.401 | REFERENCE_BEHAVIOR_NOT_VERIFIED | Single relationship/chronology graph | Two switchable canvases | REMOVE | Architecture terminology as product UI; parity = one graph |
| 68 | Mode caption "server-derived edges only · dashed span = observed evidence, not a process exit" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Explanatory prose under the tabs | REMOVE | Implementation explanation in the canvas |

## F · TRAJECTORY GRAPH

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 69 | Processes on the vertical axis | C1 verbatim | C1 p.401 | DOCUMENTED | Vertical = files and processes | One row per process | KEEP | Parity (processes half) |
| 70 | **Files** as vertical-axis entries | *"a list of files and processes"* | C1 p.401; C7 | DOCUMENTED | Files occupy vertical-axis rows | Files appear only as glyphs on a process row | CHANGE | Vertical axis must include files |
| 71 | Horizontal time axis | C1 verbatim | C1 p.401 | DOCUMENTED | Horizontal = time | Same | KEEP | Parity |
| 72 | Time tick labels rendered as `HH:MM:SSZ` ISO | Time labels present on the Cisco axis | C7 | PUBLICLY_OBSERVED | Human-readable time ticks | ISO-with-Z mono labels | CHANGE | Label format is ours, not Cisco's |
| 73 | Solid horizontal process lifeline | *"Running processes are represented by a solid horizontal line"* | C1 p.401 | DOCUMENTED | Solid line per running process | Solid when terminated | KEEP | Parity where solid |
| 74 | Dashed lifeline = "observed evidence span, not a process exit" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | Cisco lifelines are solid | Dashes when no termination evidence | REMOVE | NivXForge evidence semantics; keep engine, render Cisco-style |
| 75 | Lifeline start dot / termination tick marks | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Start circle + end tick | REMOVE | Invented lifeline decoration |
| 76 | Child processes / files stemming from the parent line | *"with child processes and files the process acted upon stemming from the line"* | C1 p.401; C7 | DOCUMENTED | Children stem from the parent lifeline, to the right | Parent→child connector drawn only where the server produced an evidence-backed edge | KEEP | Correct relationship presentation |
| 77 | Arrowheads on parent→child connectors | Cisco stems are plain connectors in the observed screenshots | C7 | INFERRED | Stems without arrow glyphs | Arrowhead drawn at the child | CHANGE | Align connector styling with observed Cisco stems |
| 78 | Process row label text | Files/processes named on the vertical axis | C1 p.401; C7 | DOCUMENTED | Process/file name | Label truncated to 22 chars | CHANGE | Cisco shows the name/path with its own truncation; ours is arbitrary |
| 79 | "pid N" printed in the row label | PID is documented in **network Event Details** ("the process ID and SID"), not as a vertical-axis label | C3 p.403 | REFERENCE_BEHAVIOR_NOT_VERIFIED (as a row label) | PID appears in event details | PID rendered on every row | REMOVE from the row label | Belongs in details; keep available there |
| 80 | "· GUID" / "· no GUID" marker on rows | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Identity-completeness marker | REMOVE | Provenance marker as analyst label |
| 81 | Internal `proc_*` / `pnode:` identifiers used as fallback row labels | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Shown when no label/image resolved | REMOVE | Internal identity must not dominate labels |
| 82 | Activity glyph set ▲ DNS · ■ NETWORK · ◆ FILE · ● REGISTRY | Cisco event icons incl. the play-button-shaped detection icon; DT covers file, network and connector events | C1 p.401; C3 p.403; C7 | DOCUMENTED (families) / NOT_VERIFIED (glyph set) | Cisco's own icon set; connector events at "System" | Geometric glyphs, DNS/REGISTRY families | CHANGE | Icon vocabulary and event families must match the documented set |
| 83 | Red marking of malicious / detection events | Red icons / red dots mark compromise | C7 | PUBLICLY_OBSERVED | Compromise in red | Red ring/colour on malicious marks | KEEP | Parity |
| 84 | Selected-event highlight | *"Click an event to view its details"* with the selected icon indicated | C3 p.403; C7 | DOCUMENTED | Selected event visibly current | Selected mark highlighted | KEEP | Parity |
| 85 | Selected-row highlight | *"If the selected row is off-screen…"* implies a selected row | C2 p.402 | DOCUMENTED | Selected row concept exists | Row band + accent bar | KEEP | Parity |
| 86 | Up / down arrow button to return to an off-screen selected row | *"If the selected row is off-screen, click up arrow or down arrow button to return to it."* | C2 p.402 | DOCUMENTED | Return-to-selected-row control | Absent | **MISSING** | Documented control |
| 87 | Left return arrow to return to the selected event in the pane | *"Click left return arrow button if you scroll away from the selected event in the pane to return to the event."* | C3 p.403 | DOCUMENTED | Return-to-selected-event control | Absent | **MISSING** | Documented control (this is Cisco's real "event navigation", unlike #60) |
| 88 | Side-to-side scrolling of the graph | *"Navigate through the event timeline by scrolling side to side on the Process Detail Graph"* | C7 | PUBLICLY_OBSERVED | Horizontal scroll through time | Horizontal scrollbar over the retained period | KEEP | Parity |
| 89 | Wheel zoom / shift-pan / ctrl-zoom on the canvas | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Wheel/modifier viewport navigation | REMOVE | Self-declared NivXForge design decision |
| 90 | Right-click context menu on a vertical-axis row | *"Right-click a file or process on the vertical axis of the Device Trajectory and select Copy SHA-256 from the menu."* | C6 p.409 | DOCUMENTED (menu) / NOT_VERIFIED (items) | SHA-256 File Info Context Menu | 14-item NivXForge pivot menu (Sightings, Campaign Story, XDR, Copy digest…) | CHANGE | Keep the right-click menu, replace the contents with the documented menu |
| 91 | "Copy SHA-256" menu item | C6 verbatim | C6 p.409 | DOCUMENTED | Copies SHA-256 | Absent (we offer "Copy event content digest") | **MISSING** | Documented action |
| 92 | "[System]" section header / connector events row | *"Secure Endpoint connector events are displayed next to the System label in Device Trajectory."* | C3 p.403 | DOCUMENTED | System row carries connector events | Present in EVENT LANES canvas only; absent from the relationship view that ships as default | CHANGE | Must exist in the single parity graph |
| 93 | `[rowTag]` suffix on lane labels | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Internal row classification tag | REMOVE | Internal taxonomy in labels |
| 94 | Hover tooltip on rows / marks | Hover readouts exist in the Cisco console | C2 p.402; C7 | PUBLICLY_OBSERVED | Hover gives counts/times/identity | Tooltip with group, label, image, lineage depth | KEEP | Keep, but strip architecture fields (covered by #93/#80) |
| 95 | Empty graph text "NO PROCESS RELATIONSHIP EVIDENCE IN THIS WINDOW — nothing is drawn rather than guessed." | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Evidence-integrity prose | REMOVE | Replace with a neutral empty state |

## G · RELATIONSHIP BASIS RAIL (ALL NIVXFORGE-ONLY)

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 96 | "↑ PARENT" button | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | Parent/child are expressed **graphically** | Button navigates to parent node | REMOVE | Relationship navigation belongs in the graph |
| 97 | "↓ CHILD (n)" button | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | same | Button navigates to first child | REMOVE | same |
| 98 | "← BEFORE" button | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Ordering step backwards | REMOVE | Engine capability, not a Cisco control |
| 99 | "AFTER →" button | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Ordering step forwards | REMOVE | same |
| 100 | "WHY THIS EDGE · <basis> · n evidence ref(s)" rail | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Derivation basis of the parent edge | REMOVE | Provenance surface — park for Phase 2 |
| 101 | "IDENTITY DOWNGRADED" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Identity-quality flag on an edge | REMOVE | same |
| 102 | "NO PARENT EDGE IN EVIDENCE — nothing is inferred from time, image, user or PID adjacency." | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Absence-of-edge explanation | REMOVE | same |
| 103 | "ORDERING STEP · CAUSALITY_UNKNOWN" + reason | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Causal-state disclosure | REMOVE | same |
| 104 | "SELECT A PROCESS TO SEE ITS RELATIONSHIP BASIS" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Empty-state instruction | REMOVE | same |
| 105 | OBSERVED_EVIDENCE_SPAN semantics text (lifeline legend) | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Explains dashed spans | REMOVE | same (paired with #74) |

## H · RIGHT-SIDE EVENT LIST & DETAILS

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 106 | Right-side event list | *"A list of file events is displayed on the right side of the device trajectory."* | C1 p.401 | DOCUMENTED | Event list on the right | Activity list on the right | KEEP | Parity |
| 107 | "Activity" header + in-window count | List exists; the numeric count does not | C1 p.401 | DOCUMENTED (header) / NOT_VERIFIED (count) | Titled list | "Activity" + count of observations in window | CHANGE | Align the title with Cisco and drop the count |
| 108 | Row layout: actor · glyph · target · time | Cisco rows show actor/target/time with the event icon | C7 | PUBLICLY_OBSERVED | Same shape | Same | KEEP | Parity |
| 109 | Selecting an event/icon shows Event Details on the right | *"if you click on the event icons in the detailed processes graph, the right side of the page will display Event Details"* / *"Click an event to view its details."* | C7; C3 p.403 | DOCUMENTED | In-place details on the right | In-place master→detail with back | KEEP | Parity |
| 110 | Back arrow from details to list | *"Click left return arrow button…"* | C3 p.403 | DOCUMENTED | Left return arrow | Back arrow returns to the list | CHANGE | Cisco's arrow returns to the **selected event**; ours only returns to the list (see #87) |
| 111 | Details: timestamp, disposition, event type | Detail fields documented | C3 p.403 | DOCUMENTED | Shown | Shown | KEEP | Parity |
| 112 | Details: detection name, detecting engine, quarantine action | *"the details also include the detection name, engine that detected the file, and the quarantine action"* | C3 p.403; C8 | DOCUMENTED | Shown for malicious files | "Detected by" + detection record present | KEEP | Parity (field-by-field completeness to be verified in the build step) |
| 113 | Details: file name, path, parent process, file size, execution context, hashes | C3 verbatim | C3 p.403 | DOCUMENTED | Complete file-event field set | Partial / differently named | CHANGE | Field set must match the documented list exactly |
| 114 | Details: network fields — dest IP, source & destination ports, protocol, execution context, file size and age, process ID and SID, hashes | C3 verbatim | C3 p.403 | DOCUMENTED | Complete network-event field set | Partial | CHANGE | Field set must match the documented list exactly |
| 115 | Indicator / tactics / techniques box in Event Details | *"A description of the indicator and the tactics and techniques will also be displayed in the Event Details pane of the trajectory."* | **C13 p.405** *(REV 2 — was "none")* | **DOCUMENTED** | Indicator **description** + tactics + techniques in the DT Event Details pane | MITRE tactics/techniques listed as bare identifiers; no indicator description | **CHANGE** *(REV 2 — was REMOVE)* | The pane is verified parity; ours is missing the indicator description and presents raw MITRE ids rather than Cisco's indicator narrative |
| 116 | "Observables" list with expanders | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Observable rows with expansion | REMOVE | Park for Phase 2 |
| 117 | "Detected by" engine attribution | Detection engine is documented | C3 p.403; C8 | DOCUMENTED | Engine named | Present | KEEP | Parity |
| 118 | Detection record block | Detection info documented, this composite block is ours | C3 p.403 | INFERRED | Detection name/engine/action | NivXForge detection record shape | CHANGE | Reshape to the documented fields |
| 119 | Pivot menu in details (Process Tree, Campaign Story, Investigate in XDR, Sightings, Copy digest…) | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | Cisco's is the SHA-256 File Info Context Menu | 14 NivXForge pivots | REMOVE | Park for Phase 2; replace with #120 |
| 120 | SHA-256 pivot button → "Copy to Clipboard" | *"In the Event Details panel, click the pivot menu button next to the SHA-256 and select Copy to Clipboard"* | C6 p.409 | DOCUMENTED | Documented details action | Absent | **MISSING** | Documented action |
| 121 | "◇ not reported" / "◇ parent not observed" placeholders | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Evidence-absence placeholders in rows | REMOVE | Provenance vocabulary in the list |
| 122 | "No activity was OBSERVED in this window. That is an absence of observation, not an absence of activity." | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Epistemic empty state | CHANGE | Neutral empty state in the parity UI; keep the distinction internally |

## I · STATES, BANNERS, ENTRY POINTS

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 123 | "◇ AMP HANDOFF — <STATE>" banner | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Endpoint/focus resolution failure banner | REMOVE | Internal handoff state |
| 124 | "OPENED FROM DETECTION … exact identifier match, no timestamp inference" banner | The **pivot** is documented; this banner is not | C8; C9 | REFERENCE_BEHAVIOR_NOT_VERIFIED | Event → DT lands on the event | Banner describing the resolution | REMOVE | Keep the behaviour (#133), drop the banner |
| 125 | Handoff diagnostics (observations searched, pages searched, cursor state, identities searched) | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Search diagnostics block | REMOVE | Debug information in the analyst UI |
| 126 | "CANCELED" / "STALE_RESPONSE_DISCARDED" outcome text | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Request-outcome notice | REMOVE | Internal request lifecycle |
| 127 | "Showing the most recent N of M recorded observations…" projection banner | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | BOUNDED_RECENT progress banner | REMOVE | Projection internals |
| 128 | "Loading endpoint evidence…" | A loading state is intrinsic to an on-demand historical view | C7 | INFERRED | Loading indication | Text block | KEEP | Neutral loading state; reword without "evidence" |
| 129 | "Searching the retained period for the deep-linked observation…" | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Locate progress text | REMOVE | Internal resolution step |
| 130 | "Search the retained period" deep-link button | none | — | REFERENCE_BEHAVIOR_NOT_VERIFIED | — | Manual locate trigger | REMOVE | Internal recovery affordance |
| 131 | Endpoint picker shown when no device is selected | Cisco always enters DT for one already-chosen device | C1 p.401; C7; C8 | REFERENCE_BEHAVIOR_NOT_VERIFIED | One endpoint per investigation, chosen upstream | Picker + tenant-boundary prose | CHANGE | Reduce to a minimal "no device selected" state; drop the boundary prose |
| 132 | Error banner | Failure states are intrinsic | — | INFERRED | Error indication | Red banner + epistemic sentence | KEEP | Keep the banner, drop the epistemic sentence |
| 133 | Event → Device Trajectory pivot focuses/selects that event | *"click the Device Trajectory icon… to view the behavior leading up to and following the compromise"*; clicking an event centres DT on that occurrence | C8; C9; C4-adjacent; C7 | DOCUMENTED | DT opens centred on the originating event | Focus resolver selects the exact observation and centres both axes | KEEP | Parity, already correct |
| 134 | Retention statement (30 days / first 500 compromise events) | C1 verbatim | C1 p.401 | DOCUMENTED | Documented limits | Not surfaced | **MISSING** | Optional, but it is documented Cisco DT context |

## J · TRAJECTORY INDICATIONS OF COMPROMISE (REV 2 — NEW GROUP, ALL MISSING)

| # | VISIBLE_ELEMENT | CISCO_PUBLIC_EVIDENCE | SOURCE | CLASSIFICATION | CISCO_BEHAVIOR | CURRENT_NIVXFORGE_BEHAVIOR | VERDICT | REASON |
|---|---|---|---|---|---|---|---|---|
| 137 | **Yellow highlighting of IOC events** in the trajectory | *"In Device Trajectory, these events will be highlighted yellow so they are readily visible."* | C13 p.405; C12 p.171 | DOCUMENTED | IOC-constituent events highlighted yellow in the graph | Absent — we mark malicious/detection events red only | **MISSING** | Core documented IOC presentation |
| 138 | **Separate compromise event** in the trajectory describing the compromise type | *"There will also be a separate compromise event in the Trajectory that describes the type of compromise."* | C13 p.405; C12 p.171 | DOCUMENTED | A distinct compromise event object on the trajectory | Absent — compromise exists only as a red marker/band on an event | **MISSING** | Distinct documented trajectory object |
| 139 | **Blue halo** on the individual triggering events when the compromise event is clicked | *"Clicking on the compromise event will also highlight the individual events that triggered it with a blue halo."* | C13 p.405; C12 p.171 | DOCUMENTED | Click compromise event → halo the constituent events | Absent (our ◀/▶ Detection stepping is a different, unverified interaction) | **MISSING** | This is Cisco's real detection navigation; it replaces #61 |
| 140 | **Search results as blue dots** on the 30-day ribbon | *"Search results appear as blue dots."* | C12 p.171 | DOCUMENTED | Search hits plotted on the navigator ribbon | Absent — search filters the population but is not plotted on the ribbon | **MISSING** | Documented search↔navigator coupling |
| 135 | Vertical scrollbar over rows | Rows scroll; selected row can go off-screen | C2 p.402; C7 | PUBLICLY_OBSERVED | Vertical navigation | Virtualized scrollbar | KEEP | Parity |
| 136 | Horizontal scrollbar over the retained period | *"scrolling side to side on the Process Detail Graph"* | C7 | PUBLICLY_OBSERVED | Horizontal navigation | Scrollbar over observed extent | KEEP | Parity |

---

## CISCO_FEATURES_MISSING_IN_NIVXFORGE (20)

| # | MISSING FEATURE | SOURCE | CLASSIFICATION |
|---|---|---|---|
| 6 | Share > Copy URL | C4 p.404 | DOCUMENTED |
| 7 | Device actions: full scan, flash scan, move to group, Connector Diagnostics | C4 p.404 | DOCUMENTED |
| 22 | Filter category **System** | C5 p.406 | DOCUMENTED |
| 23 | Filter category **Flags** (incl. audit-only, warning) | C5 p.406 | DOCUMENTED |
| 24 | Filter category **File Type** | C5 p.406 | DOCUMENTED |
| 25 | "at least one item from each category" filter semantics | C5 p.406 | DOCUMENTED |
| 26 | Explicit "Apply Filters" action | C7 | PUBLICLY_OBSERVED |
| 32 | `at:<timestamp>` time-start filter (and `<term> at:<ts>` AND semantics) | C6 p.409–410 | DOCUMENTED |
| 33 | Documented search-term coverage + tokenisation / case-insensitivity rules | C6 p.407–409 | DOCUMENTED |
| 58 | Red dot → blue "Compromise Events" → jump into the process detail graph | C7 | PUBLICLY_OBSERVED |
| 59 | Cloud-queries-per-day line graph above the dates, with hover readout | C3 p.403 | DOCUMENTED |
| 86 | Up/down arrow button to return to an off-screen selected row | C2 p.402 | DOCUMENTED |
| 87 | Left return arrow to return to the selected event in the pane | C3 p.403 | DOCUMENTED |
| 91 | "Copy SHA-256" in the vertical-axis right-click menu | C6 p.409 | DOCUMENTED |
| 120 | SHA-256 pivot menu → "Copy to Clipboard" in Event Details | C6 p.409 | DOCUMENTED |
| 134 | Retention context: 30 days of file events; first 500 compromise events | C1 p.401 | DOCUMENTED |
| 137 | Yellow highlighting of the events that constitute an indication of compromise | C13 p.405; C12 p.171 | DOCUMENTED |
| 138 | A separate compromise event in the trajectory describing the compromise type | C13 p.405; C12 p.171 | DOCUMENTED |
| 139 | Blue halo on the individual triggering events when the compromise event is clicked | C13 p.405; C12 p.171 | DOCUMENTED |
| 140 | Search results plotted as blue dots on the 30-day ribbon | C12 p.171 | DOCUMENTED |

Also verified as **already present** (no action): one endpoint per investigation,
computer context, filters control, search field, 30-day navigator, activity
density in the navigator, selected-day/24-hour navigator, click-navigator-to-move-time,
horizontal time axis, processes vertically, solid lifelines, evidence-backed
parent/child stems, real-time event/detection markers, selecting an event shows
right-side details, event→DT focus, before/after-IOC examination, on-demand
historical loading.

---

## NIVXFORGE_ONLY_ELEMENTS_TO_HIDE (60 — engines retained behind a parked flag)

**Toolbar / navigation invented controls**
◀ Event · Event ▶ · ◀ Detection · Detection ▶ · Zoom in · Zoom out (both the
toolbar text buttons and the filter-bar icon buttons) · earlier/later ◀ ▶ ·
fit-day crosshair · ISO window label · "Activity volume: N" spike buttons ·
wheel/shift/ctrl viewport navigation.
*(REV 2: the navigator collapse control is no longer on this list — it is
DOCUMENTED per C12 and moves to CHANGE, row #35.)*

**Mode / architecture terminology**
PROCESS / RELATIONSHIP / TIME · EVENT LANES · the mode caption.

**Relationship basis rail**
↑ PARENT · ↓ CHILD · ← BEFORE · AFTER → · WHY THIS EDGE · basis values ·
evidence-ref counts · IDENTITY DOWNGRADED · NO PARENT EDGE IN EVIDENCE ·
ORDERING STEP · CAUSALITY_UNKNOWN · SELECT A PROCESS TO SEE ITS RELATIONSHIP
BASIS · OBSERVED_EVIDENCE_SPAN legend.

**Graph decoration and internal identity**
Dashed evidence spans · lifeline start dots / termination ticks · connector
arrowheads *(CHANGE)* · `pid N` on rows · GUID / no-GUID marker · `proc_*` /
`pnode:` fallback labels · `[rowTag]` suffix · "NO PROCESS RELATIONSHIP
EVIDENCE IN THIS WINDOW…" empty state.

**Request / projection state**
Window-state text · CANCELED · STALE_RESPONSE_DISCARDED · selection-state
banner · BOUNDED_RECENT projection banner · locating text · "Search the
retained period" button · matched/total counter · per-type observed counts ·
"N observation(s) on this day" · "window … UTC" line.

**Handoff / provenance banners**
◇ AMP HANDOFF · handoff diagnostics (observations/pages/cursor/identities) ·
OPENED FROM DETECTION banner.

**Panels and pivots**
Observables list · details pivot menu (14 items) · canvas
right-click pivot menu contents *(CHANGE — keep the menu, swap contents)* ·
◇ placeholders · epistemic chip · Device IID · Identity Confidence · Activity
Rows · vulnerabilities disclaimer.

**Page chrome**
Theme toggle · fullscreen toggle · Legacy Device Trajectory link · Linked XDR
incidents chip.

**Navigator ornament**
Hatched out-of-view regions · dashed window cursor + HH:MM · selected-event
cursor line · day→hour connector polyline · timeframe presets · legend block ·
clear-all-filters.

---

## AMBIGUOUS_ITEMS_REQUIRING_OWNER_DECISION

1. ~~**Navigator collapse control (#35).**~~ **RESOLVED BY OWNER (REV 2).**
   Owner supplied the citation; confirmed verbatim in C12 p.171 "The Navigator":
   *"You can collapse the navigator by clicking the - button and expand it again
   by clicking on the ribbon or the + button."* Reclassified **DOCUMENTED**,
   verdict **CHANGE** (implement − / + plus click-the-ribbon-to-expand).
   Trajectory Zoom In / Zoom Out (#36, #37, #62) remain **REMOVE** — a different
   interaction, with C11 as negative evidence.

2. **Evidence-integrity messaging (#95, #121, #122, #126, #127).** Strict clone
   says remove; NivXForge truthfulness says a canceled/failed/bounded window
   must never read as "no activity". Options: (a) remove entirely for parity,
   (b) replace with a single neutral one-line notice, (c) keep behind the
   Phase-2 flag and show neutral text in parity mode. My recommendation: (b).

3. **Tenant-boundary prose in the no-endpoint state (#131).** Not Cisco, but it
   is a multi-tenant safety statement. Remove from parity, or retain as a
   minimal line?

4. **Theme toggle (#3).** Cisco ships light and dark consoles, but I found no
   evidence of a theme control **on the Device Trajectory page**. Remove from
   DT and move to the console shell, or remove outright?

5. **Disposition values (#21).** Cisco documents malicious / clean / unknown.
   Ours are MALICIOUS / SUSPICIOUS / UNKNOWN_NOT_ASSESSED. Rename to Cisco's
   three, or keep SUSPICIOUS as an approved exception?

6. **Activity families (#82).** Cisco DT covers file, network and connector
   events. Our DNS and REGISTRY families are real endpoint evidence but are not
   established as DT event families. Fold them into file/network/system, or keep
   them as an approved exception?

7. **Event families vs. vertical axis (#70).** Cisco's vertical axis contains
   **files and processes**. Promoting files to rows is a significant graph
   change. Confirm this is in scope for the parity correction, or defer it to a
   dedicated step (DT2-3b).

---

## STRICT-RULE COMPLIANCE NOTES

- No element was classified as Cisco behaviour on the strength of our own
  implementation.
- Every KEEP row cites a Cisco or publicly observed Cisco-console source.
- Every CHANGE row states what differs from Cisco.
- Every REMOVE row is `REFERENCE_BEHAVIOR_NOT_VERIFIED` and identifies why it is
  not publicly established Device Trajectory behaviour.
- `TrajectoryEngine`, `RelationshipEngine`, temporal/viewport engines,
  `CoverageEngine`, evidence basis, causality state, internal process identity,
  request coordinator, prefetch and cache remain untouched; only presentation is
  proposed for change.

**NEXT STEP: owner line-by-line review. No UI work will begin until the table is
approved.**

---

# REV 2 AMENDMENT — DAY AND TIME NAVIGATOR BEHAVIOUR MATRIX

Checked behaviour-by-behaviour. A ribbon existing is **not** parity.

| # | CISCO_BEHAVIOR | SOURCE | CURRENT_NIVXFORGE | PARITY_STATUS | REQUIRED_CHANGE |
|---|---|---|---|---|---|
| N1 | Activity is represented as **circles of varying size**, *"the size of the dots are relative to the number of events per day"* | C2 p.402; C12 p.171 | 30-day band: vertical **bars** inside day cells, height = log density. 24-hour band: **circles** sized by log density | **PARTIAL** — hour band conforms, day band does not | Replace the 30-day bar cells with circles sized by events-per-day. Decide linear vs log sizing (Cisco says "relative to the number of events per day"; our log scale is ours) |
| N2 | Hover a circle → *"view the number of events and the time they were recorded"* | C2 p.402 | Native `title` tooltips: day cell = `key · N observation(s) · N malicious · N detection(s)`; hour bin = `N observation(s) · <first_timestamp> · click to centre the trajectory here` | **PARTIAL** | Explicit hover readout showing **event count + recorded time** only. Drop malicious/detection composites and our instructional sentence from the tooltip |
| N3 | Click a circle → *"focus the device trajectory display on the events"* | C2 p.402 | Day cell click → selects day and sets the window to that whole day. Hour-bin click → centres on the nearest observed bin's first event | **CONFORMS (hour)** / **PARTIAL (day)** | Day-cell click should focus the display on that day's **events**, not simply set a 24-hour span. Keep the hour behaviour |
| N4 | A line graph sits **above the dates** | C3 p.403; C12 p.171 | Sparkline above the 30-day band | **CONFORMS (placement)** | None for placement |
| N5 | **What the line graph means** — current guide: *"the number of cloud queries made by the endpoint each day"* (C3 p.403); AMP guide: *"the miniature line graph above it represents the level of activity on the computer over this period"* (C12 p.171) | C3 p.403 **vs** C12 p.171 | Our curve = per-day observation **count** (activity level) | **CONFLICTED** — conforms to C12, does **not** conform to C3 | **OWNER RULING REQUIRED** — see NEW AMBIGUITY #8. Cloud-query volume is not an artefact NivXForge collects |
| N6 | Hover the line → *"view the precise number of queries"* | C3 p.403 | No hover readout on the curve at all | **MISSING** | Add a hover readout on the line (quantity per N5's ruling) |
| N7 | *"The upper ribbon displays the last 30 days"* | C12 p.171; C1 p.401 | 30 day cells, anchored on the **last observed day** rather than today | **PARTIAL** | Owner ruling: Cisco says "the last 30 days". Our anchoring avoids 30 empty cells for a stale endpoint but is a deviation. Flagged, not silently kept |
| N8 | *"Red dots on the 30-day ribbon represent the occurrence of compromise events"* | C12 p.171 | Red **strip** at the top of a day cell, height scaled by `malicious + detections` | **NON-CONFORMING** | Red **dots** on the ribbon, meaning **compromise events** specifically — not our malicious+detection composite |
| N9 | *"Search results appear as blue dots"* on the 30-day ribbon | C12 p.171 | Search filters the population; nothing is plotted on the ribbon | **MISSING** | Plot search hits as blue dots on the 30-day ribbon (row #140) |
| N10 | *"Below the 30-day ribbon is the 24-hour ribbon, which represents the 24 hours of the selected day"* | C12 p.171 | 24-hour band for the selected day, with draggable window + triangle handles | **CONFORMS** | None (the extra dashed cursor / hatching / window readout remain REMOVE per #51, #54, #56, #57) |
| N11 | *"You can collapse the navigator by clicking the - button and expand it again by clicking on the ribbon or the + button"* | C12 p.171 | ▼ / ▶ chevron collapses the panel; the collapsed ribbon is not clickable | **NON-CONFORMING (control verified)** | Implement − / + glyphs and make the collapsed ribbon expand on click (row #35) |

Navigator verdict: **1 conforming, 1 conforming in placement, 4 partial,
2 non-conforming, 2 missing, 1 conflicted.** The navigator is *not* currently an
AMP clone.

---

# REV 2 AMENDMENT — THE SEVEN ESCALATED AMBIGUOUS ITEMS (INDIVIDUAL)

### AMBIGUOUS_ITEM_1 — Navigator collapse / expand control (row #35)
- **CURRENT_NIVXFORGE_BEHAVIOR:** `AmpFilterBar` renders a ▼ / ▶ chevron that collapses the whole navigator section. When collapsed, the remaining strip is not clickable to expand.
- **CISCO_EVIDENCE_FOUND:** C12 p.171 "The Navigator" — *"You can collapse the navigator by clicking the - button and expand it again by clicking on the ribbon or the + button."*
- **CISCO_EVIDENCE_NOT_FOUND:** Nothing outstanding. (This wording is absent from the pages of the current Secure Endpoint User Guide I extracted, p.401–411, which is why REV 1 could not verify it.)
- **YOUR_PROPOSED_RULING:** **CHANGE** — DOCUMENTED. Implement − / + and click-the-ribbon-to-expand. Keep trajectory Zoom In / Zoom Out at REMOVE.
- **WHY_AMBIGUOUS:** **NO LONGER AMBIGUOUS — RESOLVED BY OWNER RULING (REV 2).**

### AMBIGUOUS_ITEM_2 — Evidence-integrity messaging (rows #95, #121, #122, #126, #127)
- **CURRENT_NIVXFORGE_BEHAVIOR:** Five distinct texts. Empty graph: *"NO PROCESS RELATIONSHIP EVIDENCE IN THIS WINDOW — nothing is drawn rather than guessed."* Empty list: *"No activity was OBSERVED in this window. That is an absence of observation, not an absence of activity."* Row placeholders `◇ not reported` / `◇ parent not observed`. Request outcome: `CANCELED` / `STALE_RESPONSE_DISCARDED` notice. Projection: *"Showing the most recent N of M recorded observations…"*
- **CISCO_EVIDENCE_FOUND:** None. Cisco documents retention limits (C1 p.401: 30 days, first 500 compromise events) but no epistemic empty-state vocabulary.
- **CISCO_EVIDENCE_NOT_FOUND:** Any Cisco text distinguishing "not observed" from "did not happen"; any request-lifecycle or projection-progress notice in Device Trajectory.
- **YOUR_PROPOSED_RULING:** Option (b) — one neutral single-line empty/failure state in the parity UI; keep the full epistemic distinction in the engine and reinstate the wording in Phase 2.
- **WHY_AMBIGUOUS:** Strict parity says remove, but removing it makes a canceled, failed or bounded window render identically to a genuinely quiet endpoint. That is the one class of removal that could make the parity UI state something untrue. This is a correctness-vs-parity conflict, not a styling choice.

### AMBIGUOUS_ITEM_3 — Tenant-boundary prose in the no-endpoint state (row #131)
- **CURRENT_NIVXFORGE_BEHAVIOR:** With no `device` selected, the page shows an endpoint picker plus *"No endpoint evidence is attributed to <customer>"*, the `edr_tenant_boundary` sentence, and *"Nothing is shown here rather than something borrowed from another customer…"* with the authorised tenant list.
- **CISCO_EVIDENCE_FOUND:** Every documented entry point enters Device Trajectory for an already-chosen device (C1 p.401; C7; C8; C9; C4 p.404). Cisco has no deviceless DT state.
- **CISCO_EVIDENCE_NOT_FOUND:** Any Cisco DT endpoint picker, tenant-scope statement, or multi-customer boundary message.
- **YOUR_PROPOSED_RULING:** CHANGE — minimal "no device selected" state, tenant-boundary prose removed from the parity presentation and retained in the tenancy surfaces that own it.
- **WHY_AMBIGUOUS:** The prose exists because of the closed P0 Tenant Authority gate — it is a deliberate multi-tenant safety statement. Removing it from DT is presentationally correct but touches language that was written to satisfy a security gate, so it needs your explicit approval rather than my judgement.

### AMBIGUOUS_ITEM_4 — Light / Dark theme toggle (row #3)
- **CURRENT_NIVXFORGE_BEHAVIOR:** A per-page Light/Dark button in the DT header that writes `nx.theme` and broadcasts `nx-theme` to the whole console shell.
- **CISCO_EVIDENCE_FOUND:** None for Device Trajectory. Cisco does ship light and dark console appearances (the public screenshots in C7 are light, other public material is dark), so the *capability* is real.
- **CISCO_EVIDENCE_NOT_FOUND:** Any theme control **on the Device Trajectory page** in C1–C13.
- **YOUR_PROPOSED_RULING:** REMOVE from the Device Trajectory page; relocate to the console shell (which is outside this audit's scope, so it needs your instruction before I move it).
- **WHY_AMBIGUOUS:** The feature is legitimate and the theme system is shared; only its *placement* is unverified. Deleting the DT button without relocating it could strip the only theme control the analyst can reach.

### AMBIGUOUS_ITEM_5 — Disposition filter values (row #21)
- **CURRENT_NIVXFORGE_BEHAVIOR:** Three checkboxes — `MALICIOUS`, `SUSPICIOUS`, `UNKNOWN_NOT_ASSESSED`.
- **CISCO_EVIDENCE_FOUND:** C5 p.406 — *"You can choose to view only events that were performed on or by malicious files, clean files, or those with an unknown disposition."* So Cisco's set is **malicious / clean / unknown**.
- **CISCO_EVIDENCE_NOT_FOUND:** Any DT filter value named "suspicious"; any Cisco value equivalent to `UNKNOWN_NOT_ASSESSED`.
- **YOUR_PROPOSED_RULING:** CHANGE the labels to malicious / clean / unknown; treat `SUSPICIOUS` as an exception requiring your approval, since NivXForge genuinely records that verdict and dropping it would hide real evidence.
- **WHY_AMBIGUOUS:** Cisco is missing a "clean" option we do not currently offer, and we have a "suspicious" verdict Cisco does not. This is a data-model divergence, not a label change, so it cannot be resolved as a cosmetic rename.

### AMBIGUOUS_ITEM_6 — Activity families DNS and REGISTRY (row #82)
- **CURRENT_NIVXFORGE_BEHAVIOR:** `RelationshipCanvas` plots four families with geometric glyphs — DNS ▲, NETWORK ■, FILE ◆, REGISTRY ●.
- **CISCO_EVIDENCE_FOUND:** C1 p.401 — DT *"tracks file, network, and connector events"*. C3 p.403 — connector events appear next to the **System** label; network event details enumerate destination IP, ports and protocol. C7 — the detection icon is *"shaped like a play button"*.
- **CISCO_EVIDENCE_NOT_FOUND:** DNS or Registry as Device Trajectory event families; any Cisco use of ▲ ■ ◆ ● as trajectory glyphs.
- **YOUR_PROPOSED_RULING:** CHANGE — fold DNS into network and Registry into the file/system taxonomy for the parity presentation, and adopt Cisco's icon vocabulary. Keep the families intact in the projection.
- **WHY_AMBIGUOUS:** DNS and Registry are real, high-value Windows evidence NivXForge actually collects. Folding them away is presentationally correct but hides genuine telemetry classes, and the alternative (an approved exception) is a deliberate parity break only you can authorise.

### AMBIGUOUS_ITEM_7 — Files as vertical-axis rows (row #70)
- **CURRENT_NIVXFORGE_BEHAVIOR:** The vertical axis is **one row per process**. Files appear as ◆ glyphs positioned on the acting process's row.
- **CISCO_EVIDENCE_FOUND:** C1 p.401 — *"The vertical axis of the Device Trajectory shows a list of files and processes observed on the device by the connector"*, and *"child processes and files the process acted upon stemming from the line"*. C7 confirms the same in the console screenshots.
- **CISCO_EVIDENCE_NOT_FOUND:** Nothing — Cisco is unambiguous here. The ambiguity is about **scope**, not evidence.
- **YOUR_PROPOSED_RULING:** CHANGE, but as its own step (**DT2-3b**): promoting files to first-class rows changes the axis, the row-virtualisation contract, the endpoint-wide lane index and the projection's row identity.
- **WHY_AMBIGUOUS:** It is the single largest item in the audit and is structural rather than presentational. Bundling it into the same pass as ~60 hide-operations would make one reviewable correction into a graph rewrite.

---

# ANY_OTHER_RULING_CHANGED_BY_THIS_CISCO_SOURCE

1. **#115 — Indicator / tactics / techniques box: REMOVE → CHANGE (DOCUMENTED).**
   C13 p.405 states *"A description of the indicator and the tactics and
   techniques will also be displayed in the Event Details pane of the
   trajectory."* Our MITRE box was wrongly proposed for removal in REV 1. It is
   parity — but incomplete: we show bare MITRE identifiers and no indicator
   description.
2. **#61 — ◀ Detection / Detection ▶ stays REMOVE, and its replacement is now
   identified.** Cisco's documented detection navigation is *click the
   compromise event → blue halo on the triggering events* (#139), not
   previous/next stepping.
3. **Four new MISSING rows (#137–#140)** — yellow IOC highlighting, the separate
   compromise event, the blue halo, and search results as blue dots on the
   ribbon. These are Group J.
4. **#43 upgraded to DOCUMENTED** — red dots on the 30-day ribbon mean
   *compromise events*, so our `malicious + detections` composite is also
   semantically wrong, not just visually wrong.
5. **#42 reinforced** — *"the size of the dots are relative to the number of
   events per day"* confirms circles on the 30-day ribbon too, not only in the
   hour band.
6. **NEW AMBIGUITY #8 — the line graph above the dates has two conflicting
   Cisco definitions.** C3 p.403 (current guide): *"the number of cloud queries
   made by the endpoint each day"*. C12 p.171 (AMP guide): *"represents the
   level of activity on the computer over this period"*. Our curve is activity
   level, i.e. it matches the older definition and not the current one.
   NivXForge does not collect cloud-query volume at all, so exact parity with
   C3 is not implementable from our evidence. **OWNER RULING REQUIRED:**
   (a) follow C12 and keep the activity-level curve, (b) follow C3 and render
   nothing until a cloud-query-equivalent metric exists, or (c) render an
   explicitly labelled activity-level curve as an approved exception.
   My recommendation: (a) — it is a verified Cisco definition of the same
   element in the same position.
7. **No KEEP row was invalidated** by C12/C13. #83 (red marking of malicious /
   detection events) remains KEEP but is now subordinate to #137: yellow is the
   documented IOC colour and red is reserved for compromise events.

---

# REV 2 CHANGE CONTROL

CODE_CHANGED: **NO**
UI_CHANGED: **NO**
DATA_CHANGED: **NO**
COMPONENTS_RESTRUCTURED: **NO**
PHASE-2 PARKED FLAG: **NOT DESIGNED, NOT CREATED**
NOTHING HIDDEN, NOTHING DELETED.

Only this document was amended. Awaiting owner rulings on AMBIGUOUS_ITEM_2
through AMBIGUOUS_ITEM_7 and NEW AMBIGUITY #8 before any UI correction pass.

---

# REV 3 — OWNER RULINGS RECORDED (NO UI WORK STARTED)

All eight rulings are accepted and recorded as binding for DT2-3a/b/c.

| ITEM | OWNER RULING | EFFECT ON THE TABLE |
|---|---|---|
| #2 Evidence-integrity messaging | REMOVE NivXForge engineering wording from the AMP-parity presentation; preserve all evidence/relationship/causal/provenance/UNKNOWN semantics underneath; use a Cisco-verified empty/error state where one exists | Rows 95, 100–105, 121, 122, 126, 127 → hide presentation only. Engines untouched |
| #3 Tenant-boundary prose | REMOVE from the Device Trajectory content area; Tenant Authority stays enforced server-side and unchanged; shell-level customer context may remain | Row 131 → CHANGE to a minimal state; prose removed |
| #4 Theme toggle | OUT OF SCOPE. Do not remove, move or redesign the global theme control; exclude global-shell controls from the parity score | Row 3 → **EXCLUDED FROM SCORE** (was REMOVE). Global shell untouched |
| #5 Disposition | Match Cisco's malicious / clean / unknown only where NivXForge evidence truthfully supports it. NEVER map SUSPICIOUS→MALICIOUS/CLEAN or UNKNOWN→CLEAN. Where our model cannot supply a Cisco state, show a truthful unknown/unavailable and record the data-model gap | Row 21 → CHANGE with a no-falsification constraint + recorded gap |
| #6 DNS / REGISTRY | Preserve the telemetry and capability. Do not present custom DNS/REGISTRY glyphs, lanes, labels or categories as Cisco parity. Render through a publicly verified generic Cisco event/details presentation where they fit; otherwise park the NivXForge visualisation for Phase 2 | Row 82 → CHANGE; evidence retained, custom glyph vocabulary parked |
| #7 Files on the vertical axis | REQUIRED for parity. Implement as **DT2-3b — CISCO PROCESS / FILE RELATIONSHIP PRESENTATION**, from real canonical FILE evidence only; no faked file rows from activity labels; no evidence → no relationship | Row 70 → deferred to DT2-3b (in scope, not Phase 2) |
| #8 Upper line graph | Current guide wins over legacy. Cloud-query volume is the parity target; NivXForge has no equivalent metric, so DO NOT relabel our activity curve and DO NOT fabricate. HIDE that line graph; keep the 30-day navigator. Record **CISCO FEATURE DATA SOURCE NOT AVAILABLE IN NIVXFORGE** | Rows 40 / 59 / N5 / N6 → hide the curve; recorded truthful data gap |
| Navigator (previously approved) | Implement Cisco navigator incl. − collapse, + expand, click-the-collapsed-ribbon-to-expand, circles sized relative to events/day, hover count+time, click-to-focus, red compromise dots, blue search-result dots. REMOVE custom trajectory Zoom In / Zoom Out | Rows 35, 36, 37, 42, 43, 49, 50, 62, 140 + matrix N1–N11 |

Sequence fixed by the owner: **DT2-3a** AMP presentation correction → **DT2-3b**
process/file vertical-axis relationship parity → **DT2-3c** IOC / compromise
visual parity (yellow highlighting, separate compromise event, blue halo,
indicator description, tactics/techniques in Event Details, red compromise
navigator dots). Custom Detection previous/next is removed from the parity
presentation and is NOT an approximation of the blue-halo behaviour. No IOC may
be fabricated to demonstrate the UI.

## REV 3 — SCREENSHOT EVIDENCE RULE (ADOPTED)

Evidence priority for Phase 1 is now:
1. Owner-supplied Cisco AMP / Secure Endpoint Device Trajectory screenshots
   (PRIMARY VISUAL REFERENCE)
2. Official / public Cisco documentation and screenshots
3. Cisco videos / demos
4. Other legitimate public Cisco material

New classification rules:
- Clearly visible in an owner-supplied Cisco screenshot but not described in
  prose ⇒ `PUBLICLY_OBSERVED / SCREENSHOT_VERIFIED`, **not**
  `REFERENCE_BEHAVIOR_NOT_VERIFIED`.
- Screenshot establishes appearance but not behaviour ⇒
  `APPEARANCE = SCREENSHOT_VERIFIED`, `BEHAVIOR = REFERENCE_BEHAVIOR_NOT_VERIFIED`.
  The behaviour is not to be invented.
- A NivXForge control is not preserved merely because an engine supports it.
- A Cisco-visible control is not removed merely because prose does not mention it.

Consequence: the 60 `REFERENCE_BEHAVIOR_NOT_VERIFIED` rows must be **re-tested
against the owner's Cisco screenshots** before any of them is hidden. Region
comparison A–Q (page header, computer context, filter+search, 30-day navigator,
24-hour navigator, navigator controls, graph, process rows, file rows,
lifelines, parent/child geometry, event glyphs, IOC presentation, selected
event, right-side details, toolbar, empty/loading states) is required, with
MATCH / PARTIAL_MATCH / MISMATCH / REQUIRED_CORRECTION per difference.

## REV 3 — BLOCKER: CISCO REFERENCE SCREENSHOTS NOT IDENTIFIABLE

The job's asset store holds **1,660 artifacts**, overwhelmingly NivXForge
captures. Filenames are timestamps or opaque hashes, so the Cisco Device
Trajectory references cannot be identified by name. Eight of the most
Cisco-looking candidates were inspected directly; **none is AMP Device
Trajectory**:

| ARTIFACT | ACTUALLY IS |
|---|---|
| `fmt441do_duSb_B-XV6M…jpeg` | Cisco **XDR** incident overview (kill chain) |
| `dxfplui3_4GuAlKLiUygTkhJ…jpeg` | **Palo Alto Cortex XDR** incidents |
| `7ip8gyu0_CtcSzq_Qfuyoeww…webp` | **Microsoft 365 Defender** incident "Attack story" |
| `0d17btr1_XiGo5LOd2Z0afUmR…jpeg` | **SentinelOne** Graph Explorer (Powered by Mandiant) |
| `j025v9q3_Ry9FvcC7fmdnkVso…webp` | Cisco **XDR** Integrations page |
| `cwaheub6_FSVBZ5fvq9FQMbT9…jpeg` | **Elastic Security** integration setup |
| `44ry9gqu_image-1 (17).jpeg` | **NivXray XDR** incident page (our own) |
| `vtjm0bqj_keU8FeVRayY9dEtl…jpeg` | **Microsoft Defender** onboarding |

Per the STRICT RULE and the new screenshot-evidence rule, DT2-3a **must not**
begin: applying 60 hide-decisions against documentation alone is exactly what
the owner has now overridden, and guessing which artifacts are the Cisco
reference risks cloning the wrong product's UI (the store demonstrably contains
Cortex XDR, Defender and SentinelOne screens).

**REQUIRED FROM OWNER:** identify the Cisco AMP / Secure Endpoint **Device
Trajectory** screenshots — by artifact URL, exact filename, or by re-attaching
them. Once identified, the region-by-region A–Q comparison runs first, the 60
NOT_VERIFIED rows are re-tested against them, and then the single approved
DT2-3a correction pass proceeds.

CODE_CHANGED: **NO** · UI_CHANGED: **NO** · DATA_CHANGED: **NO** ·
NOTHING HIDDEN · NOTHING DELETED · NO PHASE-2 FLAG.

---

# REV 4 — SCREENSHOT REFERENCE SET ESTABLISHED (CISCO OFFICIAL FIGURES)

## CISCO_REFERENCE_1..4 — STATUS

| REF | OWNER-SUPPLIED URL | RESULT |
|---|---|---|
| CISCO_REFERENCE_1 (full page) | `ciscomngsvsprod.service-now.com/sys_attachment.do?sys_id=63084ec2…31a5` | **REFERENCE ARTIFACT NOT ACCESSIBLE** — HTTP 200 but redirected to `auth_redirect.do` → `id.cisco.com` SAML SSO. No image bytes. |
| CISCO_REFERENCE_2 (navigator) | `…sys_id=f7084ec2…31e4` | **REFERENCE ARTIFACT NOT ACCESSIBLE** — same Cisco SSO redirect |
| CISCO_REFERENCE_3 (relationship / IOC) | `…sys_id=6b084ec2…31a9` | **REFERENCE ARTIFACT NOT ACCESSIBLE** — same Cisco SSO redirect |
| CISCO_REFERENCE_4 (event details) | `…sys_id=27084ec2…31ac` | **REFERENCE ARTIFACT NOT ACCESSIBLE** — same Cisco SSO redirect |

Owner-authorised fallback applied: **the Cisco guide's own embedded figures.**
Rendered directly out of the official Secure Endpoint User Guide PDF (740 pages,
4.9 MB, fetched from `docs.amp.cisco.com`) and stored for the record:

| FILE | SOURCE | SHOWS |
|---|---|---|
| `cisco_ref/CISCO_DT_FULL_PAGE_p402.png` (1543×851) | User Guide p.402 embedded figure | **The complete Device Trajectory page** — header, search+filters, navigator, trajectory graph, right-side Activity list |
| `cisco_ref/CISCO_DT_NAVIGATOR_p403.png` (1483×215) | p.403 embedded figure | Navigator strip / line graph above the dates |
| `cisco_ref/CISCO_DT_DEVICE_DETAILS_p404.png` (1145×854) | p.404 embedded figure | **"Show details" device drawer** + device action bar |
| `cisco_ref/CISCO_DT_IOC_TEXT_p405.png` | p.405 render | "Trajectory Indications of Compromise" section |

These are Cisco-published screenshots of the Cisco Secure Endpoint console. No
Cisco XDR, Cortex XDR, Defender, SentinelOne, Elastic or NivXForge image was
used as parity evidence.

## A_Q_VISUAL_COMPARISON (against `CISCO_DT_FULL_PAGE_p402.png`)

| REGION | CISCO_SCREENSHOT | CURRENT_NIVXFORGE | VERDICT | REQUIRED_CORRECTION |
|---|---|---|---|---|
| **A** Page header | Device name in large bold (`Demo_Upatre`) + `Show details` + `Actions ⌄`; right: `Inbox status: Requires attention ⌄`, **share icon button**, **expand/fullscreen icon button** | "Device Trajectory" text heading; XDR incidents chip; Light/Dark; "Use Legacy Device Trajectory"; fullscreen icon | **MISMATCH** | Header title = the DEVICE NAME, not "Device Trajectory". Add Inbox status + share. Remove XDR chip and legacy link. **Fullscreen icon is now SCREENSHOT_VERIFIED → KEEP** |
| **B** Computer context | No separate computer card; `Show details` opens a right-side drawer titled with the device name: Device details / Connector / Antivirus / **Compromise events ⚠103**, footer `Device Trajectory | Events` + `Scan` `Move to group` `More ⌄` | Computer card row + drawer with our own fields | **PARTIAL_MATCH** | Drop the card, keep the drawer; drawer fields become OS, Processor ID, Local IPs, Public IP, Last active, Group, Policy, Host Firewall, Flag, Connector, Antivirus, Compromise events. Actions = Scan / Move to group / More |
| **C** Filter + search bar | **Search box on the LEFT** (full width, magnifier inside, placeholder exactly `Search Device Trajectory`), **`Filters ⌄` on the RIGHT**. Nothing else — no counts, no zoom, no presets | Filters on the left, search on the right, then 5 icon buttons and an observations counter | **MISMATCH** | Swap order, strip every extra control |
| **D** 30-day navigator | Thin **blue line graph** across the top; grid of day cells; day numbers under cells; month name under the 1st of the month (`Jun`, `Jul`); **red dots inside day cells, size varying**; selected day cell filled blue with bold blue numeral | Sparkline with gradient fill + per-day dots; bar inside each cell; red strip at top of cell; month labels at the two ends | **MISMATCH** | Red dots in-cell (sized), no bars, no red strip, month label positioned at the month boundary, selected-day fill+bold numeral |
| **E** 24-hour navigator | Full-width **light-blue filled band**, hour labels `0:00 … 24`, date label under `0:00`, a white in-band window region, red dot for compromise. **No triangle handles visible** | Hour cells + hatching + window band + triangle handles + dashed cursor + HH:MM text + "window …UTC" line | **MISMATCH** | Adopt the filled-band presentation; handles become `APPEARANCE = REFERENCE_BEHAVIOR_NOT_VERIFIED`; remove hatching, dashed cursor and readouts |
| **F** Navigator controls | A **`⌄` chevron at the left of the ribbon** (this version) — with the guide's `-`/`+` collapse wording (C12 p.171) | `▼ / ▶` chevron in the filter bar | **PARTIAL_MATCH** | Move the control to the left of the ribbon; implement collapse per C12 (`-` / `+` / click-the-ribbon) |
| **G** Trajectory graph | Left gutter header `Timeline`; date columns `Jul 25` / `Jul 26`; **rotated vertical time ticks** (`23:57`,`00:00`,`00:07`,`00:20`,`01:00`…); vertical grid lines per tick | Horizontal ISO `HH:MM:SSZ` tick labels above the plot | **PARTIAL_MATCH** | `Timeline` gutter label, date columns, rotated local-style ticks (our AmpCanvas already rotates — the relationship canvas does not) |
| **H** Process rows | Right-aligned labels in the gutter with a **file-type tag** (`wsymqyv90.exe [PE]`, `iexplore.exe [PE]`); malicious label carries a **pink/red highlight**; **group section headers** `System` and `Files & Network` | Left-aligned truncated label + `pid N · GUID/no GUID`; `[rowTag]`; `[System]` section only in EVENT LANES | **PARTIAL_MATCH** | Right-align, keep a Cisco-style `[PE]` type tag (**`[rowTag]` is now SCREENSHOT_VERIFIED in principle → CHANGE not REMOVE**), pink highlight for malicious, section headers in the parity graph. Remove pid/GUID from the label |
| **I** File rows | Files and processes share the gutter under `Files & Network` | Processes only | **MISMATCH** | **DT2-3b** |
| **J** Lifelines | Thin **green** horizontal line; small **square glyphs** strung along it; short dashed continuation after the last event | Green/white lifeline, dashed when no exit evidence, start dot + end tick | **PARTIAL_MATCH** | Green solid + square event glyphs; remove start dot/end tick; dashes only as the trailing continuation |
| **K** Parent/child geometry | Not exercised in this figure (single lineage) | Orthogonal connector + arrowhead | **NOT OBSERVED IN REFERENCE** | `APPEARANCE = REFERENCE_BEHAVIOR_NOT_VERIFIED`; arrowheads stay CHANGE pending a richer Cisco figure |
| **L** Event glyphs | Small outlined **squares** for ordinary events; **red circular icons** for malicious/quarantine; **yellow/orange ⚠ triangle** in the Activity rows | `▲ ■ ◆ ●` by family, red ring | **MISMATCH** | Adopt squares + red malicious icon + ⚠ triangle; park the family glyph set |
| **M** IOC presentation | Not exercised (p.405 text documents yellow highlight + compromise event + blue halo) | Absent | **MISSING** | **DT2-3c** |
| **N** Selected event | Not exercised in this figure | Row band + accent bar | **NOT OBSERVED IN REFERENCE** | Behaviour is DOCUMENTED (C3); appearance unverified — do not invent |
| **O** Right-side details | Header `Activity` (no count). Rows: optional **⚠**, process name, glyph, target (`8.8.8.8:443`, `wsymqyv90.exe`). **No timestamp column.** Vertical scrollbar with ▲/▼ | `Activity` + count; actor / glyph / target / **HH:MM:SS** | **PARTIAL_MATCH** | Remove the count and the time column; add the ⚠ prefix |
| **P** Toolbar | **There is no trajectory toolbar at all** | Full dt2 navbar + mode tabs + basis rail | **MISMATCH** | Remove entirely (rows 60–68, 96–105) |
| **Q** Empty / loading | Not exercised | Five epistemic texts | **NOT OBSERVED IN REFERENCE** | Ruling #2: one neutral line |

Regions: **MISMATCH 7 · PARTIAL_MATCH 6 · MISSING 1 · NOT OBSERVED 3 · MATCH 0.**
**NivXForge Device Trajectory is not yet an AMP clone in any single region.**

## 60_ROW_RETEST_RESULT (screenshot rule applied)

| STATUS | COUNT | ROWS |
|---|---|---|
| **RECLASSIFIED to SCREENSHOT_VERIFIED → no longer proposed for removal** | **3** | **#5** fullscreen/expand icon (visible top-right) → KEEP · **#93** row type tag `[rowTag]` (Cisco shows `[PE]`) → CHANGE · **#20** — *not* reclassified (see below) |
| **RECLASSIFIED — appearance verified, form wrong** | **2** | **#35** navigator collapse chevron: appearance SCREENSHOT_VERIFIED, behaviour DOCUMENTED (C12) → CHANGE · **#53** navigator triangle handles: **NOT visible in the Cisco figure** → stays REMOVE, downgraded from PUBLICLY_OBSERVED |
| **STILL REFERENCE_BEHAVIOR_NOT_VERIFIED (confirmed absent from the Cisco page)** | **55** | zoom in/out (#36,#37,#62), earlier/later (#38), fit-day (#39), Event ◀▶ (#60), Detection ◀▶ (#61), window label (#63), activity-volume (#64), window state (#65), selection banner (#66), mode tabs (#67), mode caption (#68), whole basis rail (#96–#105), matched/total (#34), per-type counts (#20), presets (#27), legend (#28), clear-all (#29), hatching (#51), dashed cursor (#54), event cursor (#55), day label (#56), window line (#57), day→hour polyline (#46), MITRE-adjacent removals now superseded, observables (#116), details pivots (#119), ◇ placeholders (#121), all handoff/projection/locating banners (#123–#130), epistemic chip (#12), Device IID (#13), Identity Confidence (#14), Activity Rows (#15), XDR chip (#2), legacy link (#4), wheel navigation (#89), lifeline dots/ticks (#74,#75), pid/GUID labels (#79,#80), internal ids (#81), empty-state prose (#95) |
| **EXCLUDED FROM SCORE per ruling #4** | **1** | #3 theme toggle |

**ROWS_RECLASSIFIED: 5** (#5, #35, #53, #93 + #9 compromise-events count relocated
to the drawer). **ROWS_STILL_NOT_VERIFIED: 55.** Nothing was hidden — this is
the retest only.

REV 4 totals: 140 audited · **KEEP 34** · **CHANGE 30** · **REMOVE 55** ·
**MISSING 20** · EXCLUDED 1 · NOT_VERIFIED 55.

## DT2_3A EXECUTION STATUS

**NOT STARTED. NO CODE, UI OR DATA CHANGE IN REV 4.**
`git status` shows only this document, the four reference images and PRD.md.

Reason: the retest materially **re-scoped** DT2-3a. The Cisco figure proves the
page header, the filter/search order, the whole navigator presentation, the row
gutter, the glyph vocabulary and the right-pane columns are all different from
what REV 1–3 assumed, and it removed 5 planned deletions while adding new
required changes. Executing a 140-row pass across 8 components on the old
assumptions would have produced the wrong clone. The corrected plan is above and
is ready to execute as a single pass on the next instruction.

Acceptance endpoint for that pass is fixed: **WS-W1-1789575060 /
`dev_0e10780f2c86`**, real evidence window, no fabricated telemetry; anything
the corpus cannot exercise will be reported as **NOT OBSERVED IN ACCEPTANCE
CORPUS**.

---

# DT2-3a — APPROVED CORRECTION PASS · EXECUTED

CODE_CHANGED: **YES** · UI_CHANGED: **YES** · DATA_CHANGED: **NO**
Engines, resolvers, projections, evidence rules and tenant authority: **untouched.**

## FILES_CHANGED (8)

| FILE | CHANGE |
|---|---|
| `AmpFilterBar.jsx` | rewritten — search LEFT with the magnifier inside, `Filters ⌄` RIGHT, Enter-to-submit, nothing else in the row |
| `AmpNavigator.jsx` | rewritten — 30-day ribbon with in-cell sized red compromise dots, plain filled 24-hour band, `−`/`+` collapse, click-the-ribbon-to-expand |
| `RelationshipCanvas.jsx` | rewritten — `Timeline` gutter, date columns, rotated ticks, `Files & Network` section, right-aligned labels with `[PE]`, green solid lifelines, square event glyphs; basis rail removed from the presentation |
| `AmpComputerHeader.jsx` | rewritten — device-name title + `Show details` + `Actions`, Cisco-shaped drawer (Device details / Connector / Antivirus / Compromise events + footer actions) |
| `AmpActivityPanel.jsx` | edited — no count, no timestamp column, ⚠ prefix, neutral empty state |
| `AmpEventDetails.jsx` | edited — product pivots and the provenance/identity block removed; `Copy SHA-256` added; indicator/tactics box retained |
| `EdrDeviceTrajectoryPage.jsx` | edited — device-name header + share + expand; toolbar, mode tabs, basis rail, handoff/projection/request banners, tenant prose and the deep-link control moved behind `PARKED_NIVXFORGE_UI` |
| `dt2/__tests__/graphModel.test.js` | 7 presentation assertions retargeted to the engine or inverted into parity guards, + 3 new DT2-3a tests |

## PARITY_ROWS_APPLIED

KEEP_ROWS_PRESERVED **34** · CHANGE_ROWS_IMPLEMENTED **24** ·
REMOVE_ROWS_HIDDEN **55** · MISSING_ROWS_IMPLEMENTED **3** (#6 Share > Copy URL,
#91 + #120 Copy SHA-256) · MISSING_DEFERRED_DT2_3B **5** (#70 files on the
vertical axis, #92 System/connector section, #86 + #87 return-to-selection
arrows, #113 + #114 full Cisco detail field sets) · MISSING_DEFERRED_DT2_3C
**4** (#58 red-dot → Compromise Events, #137 yellow IOC highlighting, #138 the
compromise event, #139 the blue halo) · CHANGE_DEFERRED **6** (filter
categories #22–#26, search grammar #32 + #33, #17 drawer click-to-focus, #140
blue search dots, #59 cloud-query line = data gap, #134 retention statement).

Reclassification during implementation: **#10 `Show details` → KEEP.** The
Cisco figure shows it as an explicit button next to the device name, so the
REV 1 proposal to move the trigger onto the device name was wrong.

## RESULTS

| RETURN FIELD | RESULT |
|---|---|
| HEADER_RESULT | Title is now the device name (`WS-W1-1789575060`, 19px bold) + `Show details` + `Actions ⌄`; right: theme (out of scope), share, expand. "Device Trajectory" heading, XDR chip and legacy link gone |
| SEARCH_FILTER_RESULT | Search left (`Search Device Trajectory`, magnifier inside, Enter submits — verified 15 → 3 rows on `certutil`, 16 lanes restored on clear), `Filters ⌄` right. Zoom/step/fit buttons, matched counter, presets, legend, clear-all, count badge and per-type counts all gone |
| NAVIGATOR_RESULT | 30 day cells with month labels, sized red compromise dot on Jun 1, selected day filled + bold; plain filled 24-hour band with sized circles, hour labels `0:00…23`, `JUN 1`; sparkline, hatching, dashed cursor, day-count line and window readout gone. `−` collapses, `+` **and the ribbon** expand (both verified) |
| TRIANGLE_HANDLES_RESULT | Removed from the presentation. `moveRange` still drives band sliding; `resizeRangeStart/End` remain in `dt2/` untouched |
| TRAJECTORY_TOOLBAR_RESULT | Not rendered. `navBarParked` still compiles behind the flag with stepping, zoom ladder, density buckets and window state intact |
| PROCESS_LIFELINE_RESULT | Solid green lifeline; unterminated spans get a short trailing dash and never an invented cap. Start dots and end ticks gone |
| ROW_GUTTER_RESULT | Right-aligned names with the `[PE]` tag (13 of 16 rows), `Files & Network` section header, `Timeline` gutter label, date column `Jun 1`. `pid`, GUID markers, `[rowTag]` and `proc_…` identifiers gone |
| ACTIVITY_PANE_RESULT | `Activity` header with no count; rows are ⚠ / actor / glyph / target with no timestamp column; 15 real rows; `◇` placeholders gone |
| EVENT_SELECTION_RESULT | Selecting a row opens Event Details in place; back returns to the list. Pivot buttons absent, indicator/tactics box present, `Copy SHA-256` available |
| NIVXFORGE_ENGINES_PRESERVED | TrajectoryEngine, RelationshipEngine, graph projection, viewport/range engines, coverage, prefetch, request coordinator, focus resolver, handoff diagnostics, causality state, provenance, internal identity — all intact; only presentation changed |

## FOCUSED_TESTS

`yarn test` → **118 passed / 118 (4 files)**, up from 115 (7 were failing after
the correction because they asserted the old presentation). The 7 were
retargeted to the engine (`parentOf`, `childrenOf`, `whyOf`, `neighbourStep`)
or inverted into parity guards (`CANVAS` must NOT contain `CAUSALITY_UNKNOWN`,
`NO PARENT EDGE IN EVIDENCE`, `WHY THIS EDGE`, `IDENTITY DOWNGRADED`, `pid {`,
`no GUID`, wheel handlers). Three new tests assert the Cisco gutter
(`textAnchor="end"`, `[PE]`, `Files & Network`, `Timeline`) and that a row is
styled malicious only on a real verdict.

Live acceptance on **WS-W1-1789575060 / `dev_0e10780f2c86`** (customer
`default`, 15 recorded events, real evidence only): 16 lanes, 15 activity rows,
1 compromise event, 1 compromise day dot, 2 hour-band bins, 0 page errors.
One runtime defect was found and fixed during acceptance (`Prop` crashed on an
explicit `null` because `typeof null === "object"`).

## TRUTHFUL_DATA_GAPS

1. **CISCO FEATURE DATA SOURCE NOT AVAILABLE IN NIVXFORGE** — endpoint
   cloud-query volume per day (C3 p.403). The line graph above the dates is
   omitted; no substitute metric is shown under Cisco's meaning.
2. Cisco disposition **clean** — NivXForge records no CLEAN verdict, so the
   option is not offered. SUSPICIOUS is kept as its own value and never mapped.
3. **Inbox status** (p.402 figure) — no triage/inbox state exists; omitted
   rather than fabricated.
4. **Processor ID** and **Flag** (p.404 drawer) — not collected; omitted.
5. Operating system, Local IPs, Public IP, Group, Policy, Host Firewall,
   Connector version, Sensor state, Definitions → render **"Not collected"**
   for this endpoint; Antivirus carries a "Not collected" chip.
6. 3 of 16 rows have no sensor-reported image and render **"Unknown process"**
   rather than the internal `proc_…` identifier.
7. Blue search-result dots (#140) need per-day matched counts the projection
   does not yet return — deferred, not approximated.

## NOT OBSERVED IN ACCEPTANCE CORPUS

- No evidenced parent/child edge in this window → **no stem is drawn** (all 16
  lanes are roots). The stem geometry is implemented and gated on `edgeFor`.
- No terminated process span → the terminated cap could not be exercised.
- No IOC/compromise-event object, no connector/System events, no non-PE
  artefact type tag.

## A_Q_AFTER_MATRIX

| REGION | BEFORE | AFTER | VERDICT | REMAINING DIFFERENCE |
|---|---|---|---|---|
| A header | "Device Trajectory" + XDR chip + legacy link | device name + Show details + Actions + share + expand | **MATCH** | Inbox status omitted (gap 3) |
| B computer context | card + our own fields | Cisco drawer, device-name title, 4 groups, footer actions | **MATCH** | Processor ID / Flag not collected |
| C filter + search | Filters left, search right, 5 icon buttons, counter | search left, Filters right, nothing else | **MATCH** | Filter categories + search grammar deferred |
| D 30-day navigator | sparkline + bars + red strip | day cells + sized red dots + month labels + selected fill | **PARTIAL** | cloud-query line omitted (gap 1); blue search dots deferred |
| E 24-hour navigator | hatching, handles, cursors, readouts | plain filled band, sized circles, hour labels, date | **MATCH** | — |
| F navigator controls | ▼/▶ chevron in the filter bar | `−` / `+` at the ribbon, ribbon click expands | **MATCH** | — |
| G graph | ISO ticks above the plot | Timeline gutter, date column, rotated ticks | **MATCH** | — |
| H process rows | left-aligned + pid + GUID + rowTag | right-aligned + `[PE]`, malicious highlight ready | **MATCH** | 3 rows read "Unknown process" |
| I file rows | none | none | **MISMATCH** | **DT2-3b** |
| J lifelines | dashed spans, start dots, end ticks | solid green + trailing dash only | **MATCH** | terminated cap not exercised |
| K parent/child geometry | arrowheads | plain stems, evidence-gated | **PARTIAL** | no edge in the corpus to display |
| L event glyphs | ▲ ■ ◆ ● by family | outlined squares, red circle for malicious | **MATCH** | Cisco's exact icon set is richer |
| M IOC presentation | absent | absent | **MISMATCH** | **DT2-3c** |
| N selected event | row band + accent | unchanged | **PARTIAL** | Cisco's selected-icon appearance not observable in the reference |
| O right-side details | count + time column + pivots + observables | Activity, ⚠/actor/glyph/target, in-place details | **MATCH** | full Cisco field sets deferred |
| P toolbar | full dt2 navbar + tabs + basis rail | none | **MATCH** | — |
| Q empty / loading | five epistemic texts | "No activity to display." / "Loading…" | **MATCH** | — |

Regions: **MATCH 12 · PARTIAL 3 · MISMATCH 2** (was MATCH 0 · PARTIAL 6 ·
MISMATCH 7 · MISSING 1).

## REMAINING_VISUAL_DIFFERENCES

1. ~~The graph SVG does not fill its pane.~~ **RESOLVED** — the relationship
   canvas now measures its own container (ResizeObserver); the SVG renders
   1291 px wide at 1920×800 and meets the Activity pane, verified live.
2. Files are not yet vertical-axis rows (**DT2-3b**).
3. No IOC yellow highlighting, compromise event or blue halo (**DT2-3c**).
4. The 30-day ribbon carries no per-day activity indication at all, because
   Cisco conveys it through the cloud-query line we cannot produce. Owner may
   wish to revisit this under ruling #8.
5. Filter categories (System / Flags / File Type), the "one per category" rule,
   `Apply Filters`, and the documented search grammar are not yet implemented.

## DT2_3A_VERDICT

**AMP-parity presentation correction complete and live on real evidence; NOT
yet full AMP parity.** 12 of 17 regions now match the Cisco reference, 2 remain
mismatched by design (DT2-3b, DT2-3c) and 5 visual differences are recorded
above. No engine was weakened, no evidence rule relaxed, no telemetry deleted,
no IOC or relationship fabricated, and tenant authority is untouched.

Post-verification: the graph-width difference was closed in the same pass
(canvas self-measurement), re-verified live at 1291 px with 0 page errors and
118/118 tests green.

**STOPPED for owner visual review. DT2-3b and DT2-3c not started. No
deployment.**
