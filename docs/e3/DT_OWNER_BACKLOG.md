# DT owner backlog: status per item (persisted so a handoff cannot lose it)

Updated 2026-10-02. Statuses: OWNER-VERIFIED / DONE / NOT INCLUDED (reason). Tests are under `nivxray-xdr/tools/e3ui/` and `backend/tests/edr_trajectory/`.

## Current pass
| # | Item | Status | Evidence |
|---|---|---|---|
| N1 | Day popover pins on click (Esc, outside click and link close it; focus trap) | **OWNER-VERIFIED** | nav_test.py |
| N2 | Time links and red dots navigate: select the day, move the hour bracket onto the dot (selected ring), use a ±30 min window, centre the grid and highlight the marker and row, open Activity Details, close the popover, one history entry (Back restores), spinner while fetching, never silent | **OWNER-VERIFIED** | nav_test.py (38/38: every link; dot time == event time to the minute; grid selected marker == event id; Back) |
| N3 | 24h time bar parity with the day bar (hover preview, click pin, activity dots, cursors, click-to-zoom, red-dot jump) | DONE | nav_test.py |
| S1 | Search: magnifier, clear (×) while typing, "N results", prev/next, empty state inside the grid ("No events match '<q>'…", Clear, widen to 30 days) | DONE | actions_search_test.py |
| X1 | Actions menu with AMP parity: pivots (Events, Process Tree, Campaign Story, Live Query, View Changes) marked with ›. Mutating actions (Take Forensic Snapshot, Start/Stop Isolation, Scan, Diagnose Sensor, Move to Group) only ever create APPROVAL_REQUESTED | DONE | actions_search_test.py; backend APPROVAL_ACTIONS |
| X2 | Isolation chip next to the hostname (sensor state, or "approval requested"; never shown as isolated without evidence) | DONE | actions_search_test.py |
| X3 | Details drawer: UTC times, "Sensor" (not "Connector"), related compromise events as links | DONE | actions_search_test.py |
| X4 | Product / Version in the narrative | DONE (renders "not reported by sensor" until the sensor collects it, an E1 data gap) | actions_search_test.py |

## A. Past tense
| Item | Status |
|---|---|
| One shared past-tense label map (Executed, Created, Moved, Deleted, Scanned, Quarantined…) | DONE (`amp/labels.js`) |
| "Quarantine Failed — <reason | reason not reported by sensor>" + Reason row | DONE |
| "Not Quarantined — <reason>" | DONE |
| Unit test that bans present-tense labels | DONE (`labels.test.mjs`) |

## B. AMP detection details
| Item | Status |
|---|---|
| Header: timestamp on the left, severity badge on the right, small muted past-tense label | DONE |
| Narrative: "Detected … as <red name>." / "Moved by … executing as …" / outcome only from enforcement evidence / "Process disposition X." | DONE |
| Own signature / hash-reputation hit = MALICIOUS red hexagon with provenance; behavioral, ML, IOC and MITRE never Malicious | DONE (`disposition.py`, `test_signature_disposition.py`) |
| Search view: matched row in red + its actor row, hourly ticks + event columns, hatched after the last column | DONE |
| Activity row: ▲, bold actor, hexagon glyph, target | DONE |
| Hamburger rail control; › chevrons on items with sub-pages | DONE |

## C. MITRE
| Item | Status |
|---|---|
| `docs/e3/DT_MITRE_ATTRIBUTION_INVENTORY.md`; reuse the E1 mapper via an adapter | DONE |
| One official STIX catalogue (Enterprise v19.2), compact + version stamp, revoked/deprecated, same-version test | DONE |
| Same "MITRE | ATT&CK" box and ◇ wording; Rule-mapped / Heuristic / Intel-derived label | DONE |
| ATT&CK badge on markers, tactic filter group, search by T-ID or name | DONE |
| Device ATT&CK strip | DONE |
| HeatMap pivots both ways (minimal HeatMap change in its own commit, flag VITE_E3_ATTACK_PIVOT) | DONE (182a780a) |
| ATT&CK Navigator layer export | DONE |
| MITRE terms-of-use attribution | DONE |
| Regression test: old vs new identical attributions | DONE (data-level parity test + DOM compare in mitre_test.py) |

## D. IOC / ATT&CK strip at scale
| Item | Status |
|---|---|
| Group by detection: ×count, affected rows, first → last, formatted times | DONE |
| Severity pills that filter | DONE |
| Top 5 + "Show all", ~220px max height, virtualized, quick filter, collapsible | DONE |
| "1 of N ‹ ›" stepper | DONE |
| ATT&CK columns top 5 + "+N more"; matrix toggle | DONE |
| high_detection_volume: 1,000 detections < 100 ms | DONE (mitre_test.py) |

## E. Persistence
| Item | Status |
|---|---|
| Owner requests appended to `DT_AMP_REFERENCE_SPEC.md`; this backlog | DONE |

NOT INCLUDED: none in the A–E scope. Out of scope (E1-owned): see "Known E1 items" in `E1_PRODUCTION_SYNC_BRIEF.md` §i.
