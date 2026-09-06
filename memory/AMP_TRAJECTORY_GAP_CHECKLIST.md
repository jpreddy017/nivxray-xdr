# AMP Device Trajectory · 100 % clone · GAP CHECKLIST (baseline study)

Owner instruction (2026-06): clone the **observable Cisco AMP / Secure
Endpoint Device Trajectory experience 100 %** first. No redesign, no
"AMP-inspired", no NivXRay enhancements, no UX decisions taken by me.
The owner reviews the clone, then specifies NivXRay changes.

Sources studied: Cisco Secure Endpoint / AMP for Endpoints User Guide
(Device Trajectory chapter), Cisco "Identify the detection engine"
(Detected By, Activity Details, Event Details pane), Secure Firewall
management-center file/malware trajectory docs (icon aggregation,
truncated-path dotted line), Cisco Secure Endpoint help (filters,
timeframes, right-click launch, red = malicious).

Target surface: **new page only** — `/xdr/edr/device-trajectory`.
`/edr/trajectory` stays untouched (P0-F.7 pivots + 4 test iterations
depend on it).

Status vocabulary: **PRESENT** (already reproduced) · **PARTIAL** ·
**MISSING** (must be built) · **UNVERIFIABLE** (cannot confirm the AMP
behaviour from public documentation — must be flagged to the owner, never
guessed).

---

## 1 · Screen / layout structure
| # | AMP observable | Status in the new page |
|---|---|---|
| 1.1 | Computer header: hostname, group, OS, connector version, definitions, policy, internal/external IP | **MISSING** |
| 1.2 | Filters row across the top (event type, timeframe, artifact) | **MISSING** |
| 1.3 | Legend of event icons / dispositions | **MISSING** |
| 1.4 | Trajectory workspace as the dominant region | PRESENT |
| 1.5 | Right-hand **Event Details** pane | **MISSING** (details render below, not right) |
| 1.6 | **Activity Details** pane with **Detected By** at its bottom | PARTIAL (details exist; no Detected By) |
| 1.7 | Fullscreen toggle preserving endpoint/selection/viewport/zoom | **MISSING** |
| 1.8 | Trajectory control cluster (zoom slider, fit, fullscreen) | PARTIAL (zoom ± / fit buttons; no slider) |

## 2 · Timeline / axis
| 2.1 | Horizontal time axis with adaptive tick labels + date breaks | **MISSING** (no ruler on the new page) |
| 2.2 | "Now" / latest-activity marker | **MISSING** |
| 2.3 | Timeframe presets (1 / 7 / 14 / 30 days) | **MISSING** |
| 2.4 | Zoom via slider, wheel and controls, focal point preserved | PARTIAL (buttons only, centre-anchored) |

## 3 · Activity representation
| 3.1 | One row per process/file/network entity | PRESENT |
| 3.2 | **Process lifeline bars** spanning start→end, not just dots | **MISSING** on the new page |
| 3.3 | Parent/child connectors between lifelines | **MISSING** on the new page |
| 3.4 | Event **icons** carrying disposition + action (aggregated glyphs) | **MISSING** (plain coloured dots) |
| 3.5 | Red treatment for malicious/high-risk events | **MISSING** on the new page |
| 3.6 | Dotted line where a path/lineage is truncated | **MISSING** |
| 3.7 | Row labels with executable/file/network identity + counts | PRESENT |
| 3.8 | Hover tooltip on an event | **MISSING** |

## 4 · Navigation
| 4.1 | Drag/pan horizontally through time | PARTIAL — **NOT PROVEN** (see open defect) |
| 4.2 | Drag/pan vertically through activity | PRESENT (proven: lanes 0→14) |
| 4.3 | Horizontal scrollbar over the full retained period | PARTIAL — effect **NOT PROVEN** |
| 4.4 | Vertical scrollbar over the full activity axis | PRESENT (proven: → lanes 300–324) |
| 4.5 | Continuous movement with on-demand loading, no viewport jump | PARTIAL (windowing proven; **deep lanes render empty — OPEN DEFECT**) |
| 4.6 | Navigator: 30-day band → select day | **MISSING on the new page** (exists on the old one) |
| 4.7 | Navigator: 24-hour band → select time → trajectory centres | **MISSING on the new page** (exists on the old one) |
| 4.8 | Activity sparkline with peaks + red marks | **MISSING on the new page** (exists on the old one) |

## 5 · Selection & details workflow
| 5.1 | Click an event → select + bring into view | PARTIAL (selects; does not reposition) |
| 5.2 | Selected event visually distinguished | PRESENT |
| 5.3 | Activity Details for the selected event | PRESENT |
| 5.4 | **Detected By** (which engine detected it) | **MISSING** |
| 5.5 | Event Details pane for an event arrived at from the Events page | **MISSING** |
| 5.6 | Right-click / context menu (launch trajectory for a computer, open computer management, pivot on an artifact) | **MISSING on the new page** (exists on the old one) |
| 5.7 | Deep-link to a specific event and land on it | **MISSING** |

## 6 · Cannot be confirmed from public documentation
Flag to the owner rather than invent:
- exact pixel metrics (row height, icon size, colour hex values);
- exact zoom step ratios and slider granularity;
- exact icon artwork (Cisco assets are proprietary — equivalents must be
  drawn, and that difference must be reported, not hidden);
- exact retained-period default (AMP tenant/policy dependent).

## 7 · Underneath (unchanged, per instruction)
`edr_raw_events → canonical evidence → trajectory projection → UI`.
No second telemetry SSOT, no second detection engine, no second evidence
engine. `GET /api/edr/endpoints/{id}/trajectory` (Stage-1, 24/24 proven)
is the data path; the clone consumes it.

## 8 · Build order for the next session
1. Open defect: deep lane slices render empty (blocks 4.5).
2. Layout shell: computer header · filters row · legend · right-hand
   details pane · fullscreen (1.1–1.8).
3. Time axis + timeframe presets + zoom slider (2.1–2.4).
4. Lifelines, connectors, disposition icons, red treatment, truncation
   dotted line, tooltips (3.2–3.8).
5. Navigator (30-day + 24-hour + sparkline) on the new page (4.6–4.8).
6. Selection workflow: bring-into-view, Detected By, Event Details pane,
   context menu, deep link (5.1–5.7).
7. Re-prove §20 A–T, and report every remaining difference in §6 terms.

**Nothing in §2–§6 marked MISSING has been implemented yet. The clone is
NOT complete and must not be reported as complete.**
