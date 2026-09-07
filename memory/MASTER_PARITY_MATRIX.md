# MASTER PARITY MATRIX — MATRIX 1
## NivXRay XDR ⇄ Cisco XDR · NivXForge EDR ⇄ Cisco Secure Endpoint/AMP

**Phase: AUDIT ONLY. No UI was changed.** Companion to
`/app/memory/MASTER_OWNERSHIP_AUDIT.md` (Matrix 2 + Matrix 3 + orphan
worklist). Written under `/app/memory/MASTER_GATE.md`.

Parity gate, verbatim from the gate: *100 % **observable** parity — layout,
IA, navigation, typography/lettering, spacing, terminology, controls,
charts, states, interaction. "Looks close" is not acceptance: capture →
compare → record deviation → fix → repeat. Independent implementation; no
Cisco code or assets.*

**Nothing in this document declares parity.** Where a reference capture does
not exist, the row is `REFERENCE_CAPTURE_REQUIRED` and is not guessed.

---

## 0 · WHAT THIS PASS ADDS OVER Y0

`/app/memory/Y0_CISCO_XDR_REFERENCE_INTAKE.md` froze the baseline from **7**
owner-supplied Cisco XDR captures (R1–R7) with 33 gap rows. Y1/Y2/Y3.1 then
shipped. This pass **re-verified every Y0 row against the running build**
with an authenticated session, and adds the **NivXForge EDR ⇄ Cisco Secure
Endpoint** side, which Y0 did not cover.

Runtime evidence used: authenticated screenshot of `/xdr/incidents` (XDR
shell + rail + queue), authenticated screenshots of `/edr`,
`/edr/detections`, `/edr/process-tree` (EDR shell + rail + pages), the React
route table (44 routes), and `XdrShell.jsx` / `NivXForgeConsole.jsx` rail
definitions.

### Reference coverage

| Product | Reference | Captures held | Surfaces still unseen |
|---|---|---|---|
| NivXRay XDR | **Cisco XDR** | **7** — R1 Investigate · R2 Incident/Response tab · R3 Assets→Devices · R4 Investigation results (graph+timeline) · R5 Incident Overview · R6 Incidents list + preview drawer + MITRE popover · R7 Control Center tile grid | Detection findings tab · Evidence tab · Worklog tab · Report tab · Intelligence · Automate · Client Management · Administration · **expanded ribbon / Casebook** · **observable pivot menu** · standalone Global Search results |
| NivXForge EDR | **Cisco Secure Endpoint / AMP** | **1 behavioural baseline** — Device Trajectory, conformed in P0-F.13.1 and re-proven in P0-F.13.5 + Detection Attribution (`/app/memory/AMP_TRAJECTORY_CONFORMANCE.md`) | **Computers list · Detections list · Events · File Trajectory · Vulnerabilities · Outbreak Control (lists/allow/block) · Endpoint groups/policies · Search · Reports · Accounts · Device Control · the AMP global shell (top nav, not a left rail)** |

**Honest consequence, stated first:** the EDR product's own shell cannot be
claimed at parity — the reference for it uses a **top navigation bar**, and
the entire NivXForge console other than Device Trajectory is
`REFERENCE_CAPTURE_REQUIRED`.

---

## 1 · NivXRay XDR ⇄ CISCO XDR — Y0 ROWS RE-VERIFIED AGAINST THE RUNNING BUILD

Status changes are marked **↑ CLOSED** or **↔ unchanged** against Y0.

### 1.1 · Shell / IA / navigation

| # | Reference | Verified in the running build (2026-06, authenticated) | Status |
|---|---|---|---|
| V-1 | Left rail: **8 flat primaries**, chevron children, no group headers | **8 primaries confirmed live**: `Control Center · Incidents · Investigate · Intelligence · Automate · Assets · Client Management · Administration`, active row = left accent bar + tint | **↑ CLOSED** `REAL_RUNTIME_VERIFIED` |
| V-2 | Reference nav vocabulary | matches exactly, live | **↑ CLOSED** `REAL_RUNTIME_VERIFIED` |
| V-14 | Expanded children as indented sub-lists under the 8 parents | confirmed live (`Incidents` → `My Queue · SLA / Aging · Response`, the latter two `disabled`) | **↑ CLOSED** `REAL_RUNTIME_VERIFIED` |
| V-3 | **Light default**; dark only for the investigation canvas | the console still boots **DARK**; a theme toggle exists (`DARK` pill in the topbar). Two-way theme parity is not delivered | **↔** `NOT_IMPLEMENTED` |
| V-4 | Topbar: help `?` · bell **with `99+` count badge** · user block **name over org** | live: search field · `?` · theme toggle · `ALL CUSTOMERS` over `admin@nivxray.com`. **No notification bell.** The reference has **no** topbar search field on these captures; ours does | **↔** `IMPLEMENTED_NOT_RUNTIME_VERIFIED` (bell missing; two additive deviations) |
| V-5 | **Bottom-left ribbon pill** with badge, on every screen | absent | **↔** `NOT_IMPLEMENTED` (Y3.2) |
| N-1 | `← Incidents` / `← Investigate` back links | breadcrumbs present (`NivXRay XDR › Incidents`), no back link | **↔** `NOT_IMPLEMENTED` |
| N-4 | `Client Management` as a first-class MSSP node | now a rail primary, but it targets `/xdr/admin/users-roles` — an **administration** destination, not a client-management surface | **partially** `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| N-5 | Ribbon reachable from every screen | absent | **↔** `NOT_IMPLEMENTED` |
| I-1 | Rail collapse via hamburger; children expand in place | collapse exists; EDR pages no longer render the XDR rail at all (correct after Y1 separation) | **↔** `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |

### 1.2 · Incidents list (R6)

| # | Reference | Verified live at `/xdr/incidents` | Status |
|---|---|---|---|
| V-15 | **Four** count tiles above the table (`1,504 Incidents · 8 New · 221 Open · 1,454 …`) | **eight** tiles live (`CRITICAL 17 · HIGH 31 · UNASSIGNED 275 · MY QUEUE 0 · SLA RISK 0 · ON HOLD 0 · NEW 65 · UPDATED 65`) plus a `276 ALL / — SELECTED` header pair and three analytic cards (Incident distribution · Aging & SLA · Workload) that the reference does not have | `NOT_IMPLEMENTED` — count-tile **band exists**, composition and cardinality differ |
| V-16 | **Removable** active-filter chips with `×` | a `Filters` toggle exists; the live state reads *"No filters — showing all incidents in the selected time window."* No removable chips observed | `NOT_IMPLEMENTED` |
| V-17 | Columns `☐ · Priority (coloured numeric badge) · Name · Source · Created (relative) · Assignee` | live columns: `☐ · NUMBER · PRIORITY · SEVERITY · INCIDENT · VERDICT · CUSTOMER · DETECTION SOURCE · EVIDENCE · MITRE · SLA · OWNER` — **12 columns vs 6**; priority renders `P 1`/`P 3` badges, not a numeric score; `Created (relative)` absent | `NOT_IMPLEMENTED` (was `IMPLEMENTED_NOT_RUNTIME_VERIFIED` in Y0 — **downgraded on runtime evidence**) |
| V-18 | **Right preview drawer** on row select, with priority-score breakdown + `View Incident Detail` | row selection navigates; no drawer | `NOT_IMPLEMENTED` (Y3.3) |
| V-19 | **MITRE ATT&CK popover** over the list | MITRE is a column (`T1059.001 · T1218.011`) and a separate page | `NOT_IMPLEMENTED` |
| I-10 | Row select → drawer, **no navigation** | navigation only | `NOT_IMPLEMENTED` |
| I-11 | Chip `×` removes one filter; `Filters` toggles the panel | partial | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| I-5 | Column sort `⇅` · `⚙` column chooser · `Rows per page` · numbered pager | live: `Filters · Saved Views · Customize · Last 7 days · Comfort · Export · Refresh · COLUMN SEARCH` + state tabs (`All 276 · New 269 · In Progress 7 · On Hold 0 · Resolved 0 · Closed 0`). Rich, but **not the reference control set**; no `Rows per page`/numbered pager observed | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| S-4 | `N matching results` on every table | the tab counters carry the numbers; the reference's literal `N matching results` string is not used on this surface | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| S-7 | Priority as a **numeric score with a published additive breakdown** (incl. asset-value contribution) | priority is `P1…P5`, verdict is separate; no additive breakdown surfaced. Owner decision **C** stands: the breakdown must state *"Asset Value Contribution: Not Available"* rather than invent one | `NOT_IMPLEMENTED` + `BLOCKED` (asset value has no source) |

### 1.3 · Control Center (R7)

| # | Reference | Verified live | Status |
|---|---|---|---|
| V-20 | Multi-tab, **customisable**, source-attributed, time-ranged **4-column draggable tile grid** | rail `Control Center` → `/xdr/mss-dashboard`, a fixed layout. **`XdrDashboardPage` (the tile page consuming `/api/xdr/dashboard/tiles`, reachable with real data) is imported in `App.jsx` and never mounted on a route** — see F-7 in the ownership audit | `NOT_IMPLEMENTED` + **ORPHAN starting point exists** (Y3.4) |
| V-21 | Tile source attribution names **other vendors** (Secure Client, Secure Firewall, CrowdStrike…) | single endpoint telemetry domain | `BLOCKED · REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED` |
| I-12 | `Customize` enters tile drag/edit mode; per-tile `⋯`; per-tile time range | absent (a `Customize` button exists on the **incidents queue**, not the dashboard) | `NOT_IMPLEMENTED` |
| I-13 | Dashboard tab switching per customer/product context | single dashboard | `NOT_IMPLEMENTED` |

### 1.4 · Incident workspace (R2 · R5)

| # | Reference | Verified live | Status |
|---|---|---|---|
| V-6 | Header: numeric severity pill · status dropdown · MITRE tactic strip · `N Linked Incident` · assignee · `AI-generated` tag | header exists; element-level conformance not measured this pass | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| V-7 | **Exactly six** tabs `Overview · Detection · Response · Evidence · Worklog · Report` | the record still carries **12** tabs (incl. `Notes`, `Related`) | `NOT_IMPLEMENTED` |
| V-8 | Overview: three cards `N Assets · N Observables · N Indicators`, each `View all` + `TOP ACTIVE` + per-entity event counts + chevron pivot | not present in this shape | `NOT_IMPLEMENTED` |
| V-12 | Graph legend `Malicious · Suspicious · Common · Unknown · Clean · Asset` | ours adds `DETECTED_RULE_MATCHED`, has no `Common`/`Clean`. **Owner decision A stands: the honest vocabulary is kept; no `Clean` verdict will be fabricated for parity** | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` — permanent, accepted deviation |
| I-2 | Graph toolbar: zoom ± · collapse · undo · pan · layout · filter · hide | the XDR graph does not have this control set (the AMP canvas has its own) | `NOT_IMPLEMENTED` |
| I-3 | `Show/Hide timeline` toggling a quarterly stacked-disposition axis | absent on the XDR graph | `NOT_IMPLEMENTED` |
| I-7 | Response tab: phase rail `Identification · Containment · Eradication · Recovery`, per-action `Execute`, live state | **new evidence**: the response surfaces exist but the **engine that would execute them is not deployed** (`apps/nivxray-xdr-response`, F-5), and `/xdr/respond/*` runs on browser-local stores | `NOT_IMPLEMENTED` (was `IMPLEMENTED_NOT_RUNTIME_VERIFIED` — **downgraded**; an `Execute` control must not be shown operational while the executor is unwired) |
| I-9 | `Full screen` graph | AMP trajectory has it; the XDR graph does not | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| S-2 | Live action states `✓ Complete` / `● Running` | response verification states exist with different rendering; grading lives in `edr_plane/response.py::proof_of()` and is deliberately stricter than the reference (`EXECUTED` is a claim, never completion) | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` — accepted deviation |
| N-2 | `N Linked Incident` from an incident | linked incidents exist **EDR→XDR** only (`/api/edr/endpoints/{id}/linked-incidents`); the XDR record's `Related` tab has no API (`M-2`) | `NOT_IMPLEMENTED` |

### 1.5 · Investigate (R1) and investigation results (R4)

| # | Reference | Verified live | Status |
|---|---|---|---|
| V-11 | `Investigate` H1 · tabs `Investigation \| Detection findings` · **New Investigation** paste box · `0 / 2,000` counter · disabled primary · `Saved Investigations` table with `23 matching results` and `—` for empty description | `/xdr/investigations` exists with a different composition; no paste-to-investigate surface | `NOT_IMPLEMENTED` |
| S-1 | Primary action disabled until input is valid | n/a | `NOT_IMPLEMENTED` |
| S-3 | `Investigation complete` chip + severity counters (1 critical / 2 warning) | absent | `NOT_IMPLEMENTED` |
| I-4 | Pie/donut **legend checkboxes filter the table** | absent | `NOT_IMPLEMENTED` |
| — | R4 canvas: `Full screen` · `31 Nodes` badge · grouped nodes with counts (`Hostnames 9`, `IP Addresses 13`, `Endpoints 8`) · bottom quarterly timeline with stacked disposition bars | not present in this shape | `NOT_IMPLEMENTED` |

### 1.6 · Assets → Devices (R3)

| # | Reference | Verified live | Status |
|---|---|---|---|
| V-9 | Three summary cards — Source-health donut `81%` · `723 Devices` with Types/Status pies whose **legends are checkbox filters** · Operating Systems count grid | `/xdr/endpoints` has no summary band | `NOT_IMPLEMENTED` |
| V-10 | Columns `Device name (link + chevron pivot) · Vulnerabilities ⇅ · Cisco Security Risk Score · OS (icon+label) · Sources · Last active · Type · Managed ⓘ · ⚙` | different column set; **`Vulnerabilities`, risk score, `Managed`, multi-vendor `Sources` have no collector in this build** | `NOT_IMPLEMENTED` (layout) + `BLOCKED` (content) |
| I-8 | `Download CSV` · `Edit Labels` · `Rules` | absent; labels/rules have no backend | `NOT_IMPLEMENTED` + `BLOCKED` |
| I-6 | Entity chevron opens the **pivot menu** | `ArtifactContextMenu` was extended in Y3.1 and the pivot builder (`xdr/lib/pivots.js`) is shared by both products, but it is not on these rows and the menu's **visual** parity was never measured | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` (behaviour) + **`REFERENCE_CAPTURE_REQUIRED` (visual)** |
| N-3 | Entity → pivot → source product | proven for detection → EDR trajectory and for incident → EDR (`FLOW 3`) | `REAL_RUNTIME_VERIFIED` (those paths only) |

### 1.7 · Conventions and states

| # | Reference | Verified live | Status |
|---|---|---|---|
| V-13 | Empty cell renders `—` | mixed: the queue uses `–` for SLA, `◇ NO EVIDENCE` for evidence, `? UNKNOWN` for severity/owner. **Deliberate** — the honest vocabulary is preferred over a bare dash where absence has a reason | `NOT_IMPLEMENTED` as literal parity · accepted deviation where a reason exists |
| S-5 | `AI-generated` provenance tag on narrative text | narratives carry provenance differently | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| S-6 | Loading / error conventions | not in any capture | `REFERENCE_CAPTURE_REQUIRED` |

### 1.8 · XDR surfaces with no reference capture — not guessed

`Detection findings` tab · `Evidence` tab · `Worklog` tab · `Report` tab ·
`Intelligence` section · `Automate` section · `Client Management` section ·
`Administration` section · **expanded ribbon / Casebook** · **observable
pivot menu (visual)** · standalone Global Search results.

**All `REFERENCE_CAPTURE_REQUIRED`.** Y3.1 shipped the pivot menu's
*behaviour* only; its visual parity remains uncertified, exactly as the gate
records.

---

## 2 · NivXForge EDR ⇄ CISCO SECURE ENDPOINT / AMP

### 2.1 · The one conformed surface

| Surface | Reference basis | Verified | Status |
|---|---|---|---|
| **Device Trajectory (AMP canvas)** | AMP Device Trajectory, conformed in P0-F.13.1, re-proven P0-F.13.5 (25/25) + Detection Attribution (12/12) | horizontal + vertical drag pan · NAVIGATE bar (zoom ±, step ±50 %, fit-in-view, fit-all, jump first/last, live span readout) · **wheel scrolls, never zooms** (Ctrl/Cmd only) · 1 s ribbon floor · lane virtualisation (24 of 491 rows in the DOM) · out-of-window evidence counted, never silent · zoom anchors on the nearest **observed** instant · Activity Details with full provenance + `Detection` section | **`END_TO_END_VALIDATED`** for the trajectory; the *rest* of the console is not |

### 2.2 · EDR shell

| # | Reference (Cisco Secure Endpoint) | Verified live at `/edr` | Status |
|---|---|---|---|
| E-1 | Secure Endpoint uses a **top navigation bar** (`Dashboard · Analysis · Outbreak Control · Management · Accounts · Search`), not a left rail | NivXForge renders an **11-item left rail** (`Overview · Detections · Device Trajectory · Process Tree · Campaign Story · Files · Network · Threat Hunting · Forensics · Live Query · Response`) | `REFERENCE_CAPTURE_REQUIRED` — the IA shape is a **known structural divergence**, not yet measurable without a capture |
| E-2 | Product identity on every screen | live: `NIVXFORGE EDR · ENDPOINT DETECTION & RESPONSE`, own topbar, customer pill, `Investigate in NivXRay XDR` pivot, own theme control, `data-product="NIVXFORGE_EDR"` | `REAL_RUNTIME_VERIFIED` |
| E-3 | Own login | `/edr/login` renders NivXForge branding | `REAL_RUNTIME_VERIFIED` |
| E-4 | Session expiry keeps product identity | **defect**: an unauthenticated deep link to `/edr/*` renders the **NivXRay XDR** login | `NOT_IMPLEMENTED` |
| E-5 | Landing page = Secure Endpoint **Dashboard** (inbox/overview with real counts) | `/edr` is a card landing page. Its `DEVICE · CUSTOMER · USER` read `Not provided` without a pivot, `AGENT STATUS` reads `Reserved · later slice`, `RISK` reads `—`, and **four of five surface cards are hardcoded `available: false`** although Detections and Process Tree are routed and implemented (F-2) | `NOT_IMPLEMENTED` + **ORPHAN (stale flags)** |

### 2.3 · EDR surfaces, per-page truth (verified live, authenticated)

| Surface | Route | Live result | Reference | Status |
|---|---|---|---|---|
| Detections | `/edr/detections` | renders; on `dev_42e8c6dc74b9` shows *"0 DETECTIONS · 0 EVENTS EVALUATED — NO RULE FIRED"*, while the same endpoint returns **10 detections / 971 events evaluated** under its `ep_` identity (F-1) | AMP `Events`/`Detections` list | **ORPHAN (mis-wired)** + `REFERENCE_CAPTURE_REQUIRED` |
| Process Tree | `/edr/process-tree` | renders *"NO MATCHING EVIDENCE"* on the `device_iid`, **54 nodes / 49 observed / 5 ghost roots** on the `ep_` identity (F-1) | AMP process ancestry | **ORPHAN (mis-wired)** + `REFERENCE_CAPTURE_REQUIRED` |
| Campaign Story | `/edr/campaign-story` | 30 KB real projection, 30/30 proof | no AMP equivalent — a NivXRay-original surface | `END_TO_END_VALIDATED`, parity **not applicable** |
| Files | `/edr/files` | reserved stub; `/api/edr/file-trajectory` exists but `artefacts.file[].sha256`/name are unpopulated (`G-4`) | AMP **File Trajectory** | `BLOCKED` (data) |
| Network | `/edr/network` | reserved stub | AMP device/network events | `BLOCKED` — no endpoint network/DNS collection |
| Response | `/edr/response` | reserved stub, while the `REAL_ENDPOINT_VALIDATED` response-evidence surface lives at `/xdr/admin/edr-response` with 41 KB of real records (F-3) | AMP endpoint isolation + actions | **ORPHAN + ownership misplacement** |
| Threat Hunting | `/edr/hunting` | reserved stub | AMP **Search** | `NOT_IMPLEMENTED` |
| Forensics | `/edr/forensics` | reserved stub | AMP forensic snapshot | `NOT_IMPLEMENTED` |
| Live Query | `/edr/live-query` | reserved stub | Orbital / live query | `NOT_IMPLEMENTED` |
| **Computers / Endpoint inventory** | **absent from the EDR product** | the endpoint inventory lives at **`/xdr/endpoints`** | AMP **Computers** — a core Secure Endpoint surface | **ownership conflict with D-4** — Computers is EDR-owned per the product lock, but is only present in XDR |
| Fleet File Trajectory | `/xdr/intelligence/files/:key` | an **EDR capability hosted in the XDR product** | AMP File Trajectory (fleet) | ownership question + `BLOCKED` on data |
| EDR administration | `/xdr/admin/{edr-enrollment,edr-response,edr-capability-truth}` | three working EDR admin surfaces inside the **XDR** console | AMP `Management`/`Accounts` | ownership misplacement |

### 2.4 · EDR surfaces with no reference capture — not guessed

AMP global shell/top nav · **Computers** list · **Detections/Events** list ·
**File Trajectory** · **Vulnerabilities** · **Outbreak Control**
(simple/advanced custom detections, allow/block lists) · endpoint
**groups/policies** · **Search** · **Reports** · **Accounts** · **Device
Control**.

**All `REFERENCE_CAPTURE_REQUIRED`.**

---

## 3 · PARITY SCORECARD (counts only — no parity is claimed)

| Product | Rows re-verified | `REAL_RUNTIME_VERIFIED` / `END_TO_END_VALIDATED` | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` | `NOT_IMPLEMENTED` | `BLOCKED` | `REFERENCE_CAPTURE_REQUIRED` |
|---|---|---|---|---|---|---|
| NivXRay XDR ⇄ Cisco XDR | 38 | 5 | 9 | 20 | 4 | 11 surfaces |
| NivXForge EDR ⇄ Secure Endpoint | 17 | 4 | 0 | 5 | 3 | 12 surfaces + the shell IA |

### Rows that CLOSED since Y0
`V-1` · `V-2` · `V-14` (the 8-primary rail with indented children, verified
live) and `N-3` for the two proven pivot paths.

### Rows DOWNGRADED on runtime evidence in this pass
| Row | Y0 | Now | Why |
|---|---|---|---|
| `V-17` | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` | `NOT_IMPLEMENTED` | 12 live columns vs the reference's 6; priority is a band, not a numeric score |
| `I-7` | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` | `NOT_IMPLEMENTED` | the response executor is not deployed; an `Execute` control must not read as operational |

### Permanent, owner-accepted deviations (must not be "fixed" into parity)
1. **Disposition vocabulary** — `DETECTED_RULE_MATCHED` is kept; `Clean` /
   `Common` will not be fabricated (owner decision **A**).
2. **Response grading** — `EXECUTED` is a sensor claim, never completion;
   only probe-backed `VERIFIED` is green. Stricter than the reference.
3. **Named absences** — `◇ NO EVIDENCE` / `? UNKNOWN` / `∅` are preferred
   over a bare `—` wherever absence has a reason.
4. **Priority breakdown** must state *"Asset Value Contribution: Not
   Available"* (owner decision **C**).

---

## 4 · WHAT PARITY WORK IS BLOCKED ON WHAT

| Blocker | Blocks |
|---|---|
| **Reference captures** (11 XDR surfaces + 12 EDR surfaces + the AMP shell) | Y3.1 pivot-menu visual sign-off · incident tabs 4–6 · Intelligence/Automate/Client Management/Administration · the whole EDR console beyond Device Trajectory |
| **`REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED`** (`G-16 / FLOW-5`) | `V-21` tile source attribution · multi-vendor `Sources` column · multi-source correlation. *A real syslog/CEF-LEEF collector is running with 35 delivered envelopes (see F-4) but the console sees none of it — nothing is claimed until that is wired and proven* |
| **No asset-value source** | `S-7` priority-score breakdown |
| **No vulnerability / risk-score / managed-status collector** | `V-10` Devices columns (content) |
| **`apps/nivxray-xdr-response` not deployed** | `I-7` Response phase rail with a working `Execute` |
| **Orphan wiring (F-1 · F-2 · F-3)** | any honest EDR parity claim — three EDR surfaces currently render as empty or reserved while their evidence exists |

---

## 5 · STOP

Matrix 1 is delivered. **No UI was changed and no parity is declared.**
Awaiting approval of the orphan-engine wiring worklist in
`/app/memory/MASTER_OWNERSHIP_AUDIT.md` before any implementation begins.
