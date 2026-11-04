# E2E-UX0 · 14-SURFACE REFERENCE CATALOGUE

Companion to `E2E_UX0_BLUEPRINT.md`. Governs the whole console, not one page.
Rule: **one primary reference per surface**; a secondary reference may
contribute a single interaction only where it is demonstrably better and does
not fragment the product language.

**Source honesty.** Rows sourced from official current product documentation
are marked `DOC`. Rows sourced from an owner-supplied screenshot are marked
`OWNER-SCREENSHOT` with the visible product build. Where the product version or
capture date is not determinable from the material, it is written `unknown` —
it is never guessed. No reference below is a mockup presented as a vendor
console.

| # | NivXRay surface | Primary reference | Exact reference screen | Source | Date/version | Secondary (justified) |
|---|---|---|---|---|---|---|
| 1 | Global shell / navigation | **Cisco XDR** | left rail Control Center · Incidents · Investigate · Intelligence · Automate · Assets · Client Management · Administration + top utility ribbon | `docs.xdr.security.cisco.com` + OWNER-SCREENSHOT | current docs 2026-06; screenshot build unknown | — |
| 2 | Incidents queue | **Cortex XDR** | `Incidents · Found 2,843 results` compact left queue with Sort, per-row score/assignment/status/ID/title/device/user/updated | OWNER-SCREENSHOT (Cortex XDR, "Advanced view") | build unknown | Cisco XDR incident status model (New/Open/Closed) |
| 3 | Incident workspace | **Cortex XDR** | split view: persistent queue + incident detail, tabs Overview · Timeline · Alerts & Insights · Key Assets & Artifacts · Executions, ATT&CK tactic strip, lifecycle rail, 4-panel row | OWNER-SCREENSHOT | build unknown | Cisco XDR tab vocabulary for NivX-only tabs (Evidence · Worklog · Report) |
| 4 | Attack Story | **Microsoft Defender XDR** | Attack story 3-pane: alert list ‖ incident graph (Layout, Group similar nodes) ‖ incident details rail | DOC `learn.microsoft.com/defender-xdr/investigate-incidents` + OWNER-SCREENSHOT | docs current 2026-06 | Cortex causality chain (CGO on the left) for process ancestry only |
| 5 | Process / Activity graph | **Cortex XDR** | Executions / Causality view: causality instance chain + Forensics Highlights + All Events table | DOC `cortex-docs.paloaltonetworks.com` (3.x causality-view) | 3.x docs | SentinelOne Graph Explorer toolbar-left control stack (OWNER-SCREENSHOT) |
| 6 | Entity 360 | **Microsoft Defender XDR** | asset side pane → full entity page (risk, active alerts, MFA state, remediation actions) | DOC `learn.microsoft.com` investigate-incidents / assets tab | current | SentinelOne right-drawer tabs Overview · Indicators · Mitigation · Notes · History · Raw Data (OWNER-SCREENSHOT) |
| 7 | Endpoint investigation | **Cortex XDR** | endpoint/agent detail + Forensics Highlights (process, network, file, registry, syscalls) | DOC cortex-docs | 3.x/5.x | — |
| 8 | Hunting | **Microsoft Defender XDR** | Advanced hunting: query editor + schema tree + results grid + column pivot | DOC `learn.microsoft.com` advanced hunting | current | Elastic Security searchable/filterable event table + Timeline workspace |
| 9 | Assets | **Cisco XDR** | Assets inventory table with disposition/type filters and drawer detail | DOC `docs.xdr.security.cisco.com` | current | — |
| 10 | Intelligence | **Cisco XDR** | Intelligence app: observable verdict + pivot menu | DOC cisco incident-detection / relations-graph | current | CrowdStrike Falcon Enrichments rail (report cards with Dismiss / Add to graph) (OWNER-SCREENSHOT) |
| 11 | Response | **Cortex XDR** + **Defender** | action centre / pending-approval list with per-action lifecycle | DOC both | current | — |
| 12 | Data Sources / Integrations | **Cisco XDR** | integrations catalogue + per-source health | DOC cisco | current | — |
| 13 | Collector / onboarding | **Elastic Security** | agent/integration onboarding: choose → configure → verify → ready | DOC `elastic.co` Fleet/integrations | current | Cortex agent installation flow |
| 14 | Command Intelligence | **NivXRay original** (evidence-first) | no vendor equivalent — Assessment · Executive Summary · Decode Status · Execution Chain · Recovered Payload · Behaviors · Indicators & Intelligence · ATT&CK · Native/LOLBAS · Impact · Evidence & Provenance · Technical Details | own | — | SentinelOne right-drawer section rhythm for panel density only |

## Per-surface decision detail (structure · interaction · NivX truth)

| # | Structural pattern to reproduce | Interaction to reproduce | NivX capability that must survive | Required backend truth | Missing backend truth today | ADOPT/ADAPT/REJECT | Wave |
|---|---|---|---|---|---|---|---|
| 1 | one permanent left rail + top utility ribbon; no second permanent rail | rail group expand, active highlight, tenant pill | permission-adapted rail via `/api/xdr/rbac/me/effective` | effective permissions (exists) | — | ADOPT | **1** |
| 2 | compact queue rows: checkbox · severity · score · assignee · status · ID+title · device/user chips · "Updated x ago" | row select drives right pane; sort; filters; selected row visually distinct | tenant scoping, verdict grammar, SLA | incidents list API (exists) | incident *score* is not computed → render `NOT AVAILABLE` | ADAPT | **1** |
| 3 | header row (severity▾ · ★ · ID · name · score · assignee▾ · status▾ · ⋮), italic incident sentence, stat clusters (alerts ring · hosts · users) + "Open for N days", tab row, ATT&CK strip, lifecycle rail, 4 equal panels | tab switch without losing queue; Show More → flyout; entity click → flyout | NivX 10 tabs (Overview · Attack Story · Timeline · Evidence · Entities · Detections · MITRE · Response · Activity · Report) — **Cortex's 5 tabs must not delete ours** | incident detail, detections, entities, activity (exist) | "Open for N days" derivable; alert-severity ring needs per-severity counts | ADAPT | **1** |
| 4 | 3-pane: pinned alert list ‖ graph ‖ details rail | play-through timeline, node zoom, group similar nodes, node → rail update | epistemic bands OBSERVED/SUPPORTED/INFERRED/POSSIBLE/UNKNOWN on every edge | causal edges with evidence refs | edge provenance incomplete → render edges only where cited | ADAPT | 2 |
| 5 | chain + Forensics Highlights + All Events table | node select → highlights + events filter | provenance per node | process ancestry (partial) | full syscall/registry projections | ADAPT | 2 |
| 6 | entity header + fact grid + tabbed drawer | inline pivot → flyout → full page | risk basis must be citable | entity 360 API | risk score authority | ADAPT | 2 |
| 7 | endpoint detail + activity projections | drill from asset row | device trajectory already exists | trajectory API (shadow flag) | — | ADAPT | 3 |
| 8 | query editor + schema + results grid | run, pivot column → filter, save query | saved hunts | search API | schema browser | ADAPT | 3 |
| 9 | dense inventory table + drawer | filter by type/disposition | asset inventory is real | assets API (exists) | — | ADOPT | 3 |
| 10 | observable verdict + pivot menu | pivot → investigate / block / enrich | OSINT is an evidence contributor, never the verdict | `osint.py` (exists, unwired) | provider keys per tenant | ADAPT | 4 |
| 11 | action list with lifecycle column | approve / dispatch / verify | **ACCEPTED ≠ EXECUTED ≠ CONTAINED ≠ VERIFIED** | response API + approvals (exist) | verification evidence | ADOPT | 4 |
| 12 | catalogue + per-source health | connect → verify | `HEALTHY · EVIDENCE INCOMPLETE` must remain possible | data-sources API (exists) | per-stream counters, computed latency | ADOPT | 4 |
| 13 | linear wizard choose→configure→verify→ready | stepper, copy-install, verify poll | CONNECTED only on real telemetry | collector API (exists) | — | ADOPT | 4 |
| 14 | 12-section evidence-first composition | decode status → drill to unresolved | Analysis Completeness ≠ Confidence | R-4/R-5 contracts | canonical propagation (R-7) | REJECT vendor pattern; build own | **gated on Lane B** |

## Rejected patterns (with reason)
| Pattern | Product | Why rejected |
|---|---|---|
| AI narrative verdict panel ("Decisive True Positive / Likely False Positive") | Cisco XDR AI analysis view | we will not ship a confident narrative we cannot cite per claim |
| Per-tenant / per-analyst custom incident layouts | Cortex XSIAM 2.3 / XSOAR | layout customisation before a good default multiplies the rejected problem |
| Dark-only default | SOC-craft writing | Cisco ships Light default; both themes are first-class here |
| "Avoid tabs, single scrollable view" | OpenSOAR design notes | valid at *alert* scope (inside a flyout), wrong at *incident* scope |
| Low-contrast grey-on-dark metadata | several vendors | legibility overrides screenshot matching (UX0-R3 / §28) |
| Reducing the workspace to Cortex's 5 visible tabs | Cortex | would delete 5 NivX investigation capabilities to gain visual similarity |

## Program rule
Catalogue broadly in parallel; **implement a surface only once its primary
reference and its NivX capability/data mapping are locked** (rows above).
Fidelity does not drop as scope grows — scope is divided into waves, quality is
not.
