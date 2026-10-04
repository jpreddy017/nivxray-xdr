# M2 Visual / Interaction Self-Review Checklist (vs /app/memory/DT_AMP_REFERENCE_SPEC.md)

Status key: DONE / PARTIAL / MISSING. Screenshots (2000×1300) are in `/app/.e3ui-harness/shots_m2/`. Automated checks: `m2_interaction_test.py` (51/51 pass, `results.json`).

## PAGE
| Spec line | Status | Evidence / note |
|---|---|---|
| Hostname title ~34px bold, outlined-blue "Show details", filled-blue "Actions ▾" | DONE | 01_full_page; Show details popover = OS/sensor/device/policy |
| "Inbox status: … ▾" mapped to our status; Share + Fullscreen square buttons | PARTIAL | Mapped from NivXForge detections on the device. The XDR incident inbox isn't reachable in preview. Share copies the deep link |
| Rounded #24272c container on #1a1c20 page | DONE | theme.js CSS vars |
| Full-width rounded search with clear (x), result count, (i) icon; blue "Filters ▾" | DONE | 07_search |
| NivXForge sidebar restyled dark, icon + label, ~360px | DONE | Scoped CSS, only while V3 is mounted |

## NAVIGATOR
| Spec line | Status | Note |
|---|---|---|
| Slate block #2e3a4c, collapsible ∨ chevron | DONE | v3-nav-collapse |
| Thin blue 30-day sparkline | DONE | v3-sparkline |
| 30 day cells, day numbers, month label under first day of month, selected day highlighted | DONE | 02 |
| Blue activity dots / larger red compromise dots | DONE | |
| Day tooltip: date, "● Compromise events", "1  05:07" blue link → jumps + opens details | DONE | 05_activity_details_detection (tooltip visible, jump tested) |
| 24h strip: hour ticks, date under 0:00, draggable bracket, red detection marker | DONE | Drag a new range or move the bracket; click = 1h |
| Future time hatched | DONE | |
| No-data time hatched | PARTIAL | Only future time is hatched. Per-hour no-data needs an hourly density read that doesn't exist yet |
| Spinner overlay; requests cancellable; last selection wins; stale responses never overwrite | DONE | AbortController + request id guard |

## GRID
| Spec line | Status | Note |
|---|---|---|
| Labels ~260px right-aligned ~14px; grid; Activity ~400px | DONE | |
| "Timeline" header, day headers + vertical dividers, rotated HH:MM ~12px | DONE | |
| Event-compressed X; idle time collapses; sparse hourly ticks fill gaps | DONE | Gap ≥1h inserts one italic tick column with a dashed divider |
| Diagonal hatch after last evidence / now | DONE | v3-future-hatch |
| Own horizontal scrollbar; header scrolls in sync; sticky section headers | DONE | Single scroll box + sticky header and section |
| Section bands #0f1012, bold white right-aligned | DONE | |
| Row = file/executable identity "name [TYPE]"; truncated hash when no name | DONE | PE/ELF/MachO/Script/GZ/ZIP/MSI/CAB/OOXML/OLE2/PDF/TXT/Unknown |
| Per-instance lifeline segments; row expands to instances | DONE | ▸N toggles sub-rows per process instance |
| Light-grey lifeline; connector actor→target with small arrow + marker; dotted leads | DONE | |
| Causal: solid proven / dashed correlated / "?" unresolved | DONE | Linux FILE/NET rows show "?" (actor NOT_OBSERVED) |
| Grid lines thin #3a3d42 | DONE | |

## MARKERS
| Spec line | Status | Note |
|---|---|---|
| Shape = disposition (circle/hexagon only with evidence; square otherwise) | DONE | No assessment evidence in the data, so every marker is a square (correct by rule) |
| Inner symbols + ^ → ▷ ○ ⇌ lightning ↺ × USB | DONE | Glyphs drawn. The sensor only emits create/execute/network/dns/registry |
| ▷ with red hexagon badge = execute blocked | MISSING | No blocked-execute telemetry; glyph not drawn yet |
| Flags: warning triangle, command-line glyph | DONE | |
| Flags: audit-only eye | MISSING | Not collected (filter disabled) |
| Hover tooltip + actor/target pair highlight | DONE | |
| Selection: bold label, lifeline glow band, marker glow ring | DONE | 04 |

## ACTIVITY PANEL
| Spec line | Status | Note |
|---|---|---|
| "Activity" header, ~45px rows, [amber triangle] bold actor, glyph, target | DONE | 03 |
| Time-ordered, own scrollbar, two-way sync | DONE | Virtualized |
| Swap to ACTIVITY DETAILS; "‹" back keeps scroll + highlighted row | DONE | The list stays mounted while hidden |
| UTC timestamp, dashed underline, hover = local time | DONE | |
| Severity badge | DONE | |
| Execute narrative sentences | DONE | 04 |
| Detection narrative incl. "No quarantine/response evidence recorded." + "Process disposition Unknown." | DONE | 05 |
| Interactive tokens (dotted, full on hover, click/right-click menu), copyable hash chips, accent "Unknown", severity-coloured detection name, never "Malicious" without evidence | DONE | |
| Collapsible "Evidence & provenance" incl. observed vs ingested, lateness, "What we cannot tell you" | DONE | Ingest time is shown for the Windows preview device; imported rows say "not collected" |
| "↩ Return to activity" when the selection is off-screen | DONE | |

## SEARCH
| Spec line | Status |
|---|---|
| ?q= in URL, shareable | DONE |
| Only matching rows + linked actor rows; matched label red; Activity filtered; clear restores | DONE |
| SHA-256, filename, process, cmdline, IP, domain, user; next/prev | DONE |

## FILTERS
| Spec line | Status | Note |
|---|---|---|
| Dark scrollable panel, blue square checkboxes, bullet indent, Cancel link + blue "Apply filters"; apply-only-on-Apply; in URL; "X of Y" | DONE | 06 |
| All types master + every listed group/item; not-produced types disabled "not collected" | DONE | |

## RIGHT-CLICK MENU
| Spec line | Status |
|---|---|
| Copy hash, Copy path, Search trajectory, Isolate lineage, Open File Trajectory (not yet built), File Analysis (not yet built) | DONE (08a) |
| Approval-only actions + confirm dialog → "Approval requested — not executed." | DONE (08b) |

## INTERACTION
| Spec line | Status | Note |
|---|---|---|
| Wheel zoom, +/-, drag-pan, horizontal scroll, day click, draggable range, Last 24h / Now / prev-next / Fit / Reset | DONE | Wheel zoom works over the time header, or with Ctrl/⌘/Alt over the body (a plain wheel scrolls the body) |
| Expand/collapse lineage, isolate lineage + restore | DONE | 09 |
| Deep links resolved through history | DONE | newest / ~30-day / late-arrived / nonexistent |
| Back/forward restores state | DONE | URL is the state (t0, t1, event, q, f, iso) |
| Viewport rendering; dense clusters grouped when zoomed out | DONE | Row + column virtualization; markers group with counts below 10px per column |

## PALETTE / TYPE / ASSETS
| Spec line | Status | Note |
|---|---|---|
| Accent #6ea0ff, red #e5534b, amber Medium | DONE | |
| Inter / system sans | DONE | |
| Section + column headers ~18px semibold; Activity rows ~15px; title ~34px | PARTIAL | "Timeline" and "Activity" are 18px; section band text is 15px so it fits a 26px row |
| Dark default; Light toggle keeps working | DONE | 12_light_theme |
| Own glyphs; no Cisco logos/names/fonts | DONE | |

## Performance matrix (`perf_matrix.json`, client-side fixture rows through the same model + render path)
| events | first marker ms | model ms | rows | DOM markers | scroll frame median / p95 ms | select→details ms | heap MB |
|---|---|---|---|---|---|---|---|
| 100 | 594 | 2 | 98 | 77 | 33.3 / 33.4 | 80 | 13 |
| 1,000 | 368 | 6 | 922 | 77 | 33.3 / 33.5 | 76 | 21 |
| 5,000 | 393 | 20 | 3,906 | 77 | 33.3 / 33.5 | 78 | 18 |
| 10,000 | 403 | 41 | 6,867 | 77 | 33.3 / 33.5 | 75 | 19 |
| 50,000 | 559 | 168 | 19,720 | 77 | 33.4 / 33.5 | 76 | 60 |
Scroll frame time is measured over two `requestAnimationFrame`s, so 33.3 ms means no dropped frames at 60 Hz.
