# NivXRay XDR — Cisco-XDR-Inspired Unified Platform Consolidation
## REQUIRED OUTPUT BEFORE CODING · Deliverables A–H
### Status: ASSESSMENT ONLY · NO CODE WRITTEN · STOPPED FOR OWNER APPROVAL
### Date: 2026-06 · Author: E1 · Layer: TARGET_SPEC (§0 findings are CURRENT_REALITY)

---

## 0. WHAT I VERIFIED BEFORE WRITING THIS — AND WHERE THE DIRECTIVE'S PREMISE IS OUT OF DATE

The directive is accepted in full. Four of its factual premises, however, describe the
**base NivXRay app** (`/app/frontend`), not the **deployed standalone XDR bundle**
(`/app/apps/nivxray-xdr`). I am disclosing this before the plan, because if I had
"fixed" the stated premise I would have rewritten code that is already correct and
left the real leaks in place.

### 0.1 Premise check — measured, not asserted

| Directive premise | Measured reality in `/app/apps/nivxray-xdr` | Verdict |
|---|---|---|
| Sidebar items carry `external: true` (`/investigations`, `/threat-intel`, `/analyze`) | `SIDEBAR` has **53 items · 0 with `external: true`** | **NOT TRUE TODAY** |
| `App.jsx` has only `/xdr`, `/xdr/incidents`, `/xdr/endpoints`, `/edr/*` | `App.jsx` registers **60 routes** | **NOT TRUE TODAY** |
| `/xdr/investigations`, `/xdr/threat-intel`, `/xdr/mitre`, `/xdr/kb`, `/xdr/admin`, `/xdr/platform` do not exist | All exist: `/xdr/investigations`, `/xdr/investigations/:caseId`, `/xdr/intelligence/mitre`, `/xdr/kb`, `/xdr/admin/:section`, `/xdr/admin/platform-health` | **NOT TRUE TODAY** |
| The pages must be migrated from the old app | `XdrInvestigationWorkspacePage` (1,103 lines) + `EvidenceFirstInvestigationWorkspace` (2,128) + `XdrEvidenceExplorerPage` (443) + `XdrMitreHeatmap` (808) + `XdrKbPage` (222) + `XdrSearchPage` (230) are **already native** | **ALREADY DONE** |
| Every visible sidebar target must be an in-XDR route | Automated check of all 53 items against the 60 routes: **0 unrouted targets** | **ALREADY TRUE** |

Measurement commands are reproducible: item/route parse of `xdr/XdrShell.jsx` +
`App.jsx`; `grep -rn "external: true" src/`; live OpenAPI read (785 `/api` paths).

### 0.2 The launcher behaviour the directive is right about — it just lives elsewhere

There **are** real cross-product escapes. They are not in the rail; they are in the
**pivot menus and the backend's own deep links**. This is the F-1 lesson repeating in a
new class: *the defect is per call-site, not global.*

**LEAK-1 · `xdr/components/Pivot.jsx` — 13 `external: true` targets, all dead.**
`window.open()` to `/analyze`, `/threat-intel?q=…`, `/documents?q=…`, `/heatmap`,
`/analyst?case=…&tab=verdict`, `/analyst?tab=iue`. **None of those paths exist in this
bundle**, so `<Route path="*">` bounces the new tab to `HOME_PATH`. The analyst clicks
"Hash Intelligence" and gets a second tab of the incident queue. This is precisely the
dead control the shell's own comment already condemned when "Analyst Workspace" was
removed — reintroduced through the pivot menu.

**LEAK-2 · the backend hands the UI a cross-product URL.**
`backend/routers/incidents.py::_link_with_context("/threat-intel", …)` is returned as
`evidence_pointers[ioc].deep_link`, and `components/incidents/tabs/OverviewTab.jsx:82`
and `InvestigationTab.jsx:127` do `window.open(deep_link)`. Same dead tab, but authored
**server-side**, so no amount of frontend rail work fixes it. (The EDR pointer at the
same site is legitimate — `/edr` is a real route — and its label was corrected to
"NivXRay EDR" in the one permitted change.)

**LEAK-3 · dead code that will re-enable the class.**
`XdrShell.jsx:403` still defines `openExternal()` and `:630` still renders an
`item.external` branch. No item uses it. Leaving a loaded gun in the rail renderer is
how `external: true` comes back in the next slice.

**LEAK-4 · legitimate, keep as-is.** `components/WorkspaceLaunch.jsx` is a top-bar,
config-gated hand-off to a genuinely separate deployment; with no
`REACT_APP_WORKSPACE_URL` it renders `NOT CONFIGURED` and does nothing. Under directive
§0.8 this is the correct pattern, not a violation.

### 0.3 THE BIGGEST FINDING — WE ARE LYING IN THE OPPOSITE DIRECTION

The four Intelligence rail rows (`ti`, `ioc`, `command`, `malware`) are
`disabled: true`, titled *"arrives in Round P1.0"*, and `XdrReservedPage` renders
**hardcoded `value: 0`** metrics under the sentence *"No intelligence sources are
configured for this tenant."* — over a footnote that claims *"No metric on this page is
fabricated. Every '0' is an authoritative zero from the backing service."*

Live, authenticated, today, on the same backend the console already talks to:

| Probe | Result |
|---|---|
| `GET /api/threat-intel/stats` | **104,975** indicators — ip 58,241 · url 31,796 · domain 3,231 · sha256 2,170 · md5 1,082 · sha1 748 |
| `GET /api/threat-intel/sources` | 8 sources, `configured: true`, real `last_sync` / `last_status` / `last_error` (incl. an honest `HTTP 429` on AbuseIPDB) |
| `GET /api/ioc/health` | **9 providers `state: live`** — VirusTotal · AbuseIPDB · URLScan · Hybrid Analysis · MalwareBazaar · ThreatFox · URLhaus … |
| `GET /api/kb/stats` | **334** KB entries, severity + verdict + top-15 ATT&CK breakdown |
| `GET /api/mitre/heatmap` | **290** heuristics · **125** techniques · 13 tactics |
| `GET /api/xdr/search/capabilities` | 7 searchable entity types + named `NOT_SEARCHABLE_NO_INDEX` reasons |

So the hardcoded zero is **itself the fabrication**, and the footnote makes it a
documented false claim. Under directive §9/§10 this is a **P0 honesty defect**, and it
inverts the delivery plan: Intelligence is not a build, it is a **WIRE**. The backend is
real and populated; the console is the part that is lying.

### 0.4 Reference correction — the directive's target IA is not Cisco's

Verified today against `docs.xdr.security.cisco.com/Content/navigation.htm`
(retrieved 2026-06) and `docs.xdr.security.cisco.com/Content/Incidents/detections.htm`,
`…/Investigate/investigate.htm`, `…/Investigate/activities.htm`,
`developer.cisco.com/docs/cisco-xdr/`.

**Cisco XDR's actual left navigation is 8 primaries:**
`Control Center` · `Incidents` (with **Detections** as a submenu) · `Investigate` (with
**Activities** as a submenu) · `Intelligence` (Judgments · Indicators · Events · Feeds)
· `Automate` · `Assets` · `Client Management` · `Administration` — plus the persistent
**Ribbon** (casebook, observable search, notifications, incidents) and a top-right
Help / Notifications / User-Profile cluster with **Auto/Light/Dark**.

The directive's §2 tree proposes **11 top-level groups** including `FORENSICS`,
`EXPOSURE` and `DATA` as peers. Those are **not Cisco XDR primaries**: forensics/live
query is Secure Endpoint + Orbital territory (and in our product, EDR territory);
exposure/attack-paths has no Cisco XDR primary at all; data/collector health sits under
Administration. Adopting the 11-group tree while calling it "Cisco parity" would mean
**three top-level promises we cannot keep** (Forensics has 5 children, 5 of which are
`BLOCKED_ENVIRONMENT` or unimplemented; Exposure has 4 of 5 unimplemented). That is the
same rail-shaped-promise conflict already recorded in `03_DESIGN/NAVIGATION_SPEC.md`.

**Recommendation (owner decision O-1 below): adopt Cisco's 8 primaries**, put Detections
under Incidents and Activities under Investigate, keep Exposure/Forensics/Telemetry as
**children** (Exposure under Assets, Forensics as an EDR-owned pivot, Telemetry under
Administration). This is closer to the reference *and* honest about coverage.

Two further Cisco facts worth locking, both now confirmed:
- **Priority is a score with published bands** (≥800 red · 600–799 orange · 400–599
  yellow · ≤399 blue) and **Risk** is 0–100 with Critical/High/Medium/Low bands. Our
  queue renders priority as a *band* with no score (audit row `V-17`). Parity here is
  achievable and cheap.
- **Dispositions** are `clean · malicious · suspicious · unknown`; Cisco notes
  `unknown` appears only in ribbon/pivot menus. Owner ruling Y0-A already decided we
  keep our honest vocabulary and do **not** fabricate `Clean`. Unchanged.

### 0.5 Cross-reference: Defender XDR and Cortex XDR (for capability coverage only)

- **Defender XDR**: `Incidents & alerts` · `Hunting` (Advanced hunting, Guided/KQL
  modes) · `Actions and submissions` (Action Center) · `Assets` (Devices, Users,
  Mailboxes, Apps) · `Identities` · workload sections. Two ideas worth adopting: the
  **Action Center as a first-class cross-incident response surface** (our `response`
  rail row is `disabled`, marked "Phase 8"), and **Go hunt from any entity page**.
- **Cortex XDR**: `Incident Response → Incidents / Alerts`, right-click into
  **Causality view** (CI chain + forensics highlights + all-events table) with
  remediate-in-place, `Investigation & Response → Query Builder (XQL)`, Action Center.
  Idea worth adopting: **remediation actions offered directly inside the causality/
  process-tree view**, not only from a separate Response page. Our
  `ProcessTreePanel`/`AttackGraphTab` already draw the chain; the actions are missing.
  XQL-style free query is explicitly **out of scope** (no data lake; `sdl` is disabled).

---

## A. CISCO XDR → NIVXRAY PARITY MATRIX

Columns: Cisco capability · Cisco workflow role · NivXRay equivalent · existing source
component/service · target `/xdr` route · backend API · status · gap · action.

Status vocabulary (no completion percentages, per owner rule):
`NATIVE_WIRED` (renders real API data in XDR today) ·
`NATIVE_HONEST_EMPTY` (native, correct, no data) ·
`BACKEND_REAL_UI_DISABLED` (**the wire-not-build class**) ·
`LEAKS_EXTERNAL` (control escapes the product) ·
`RESERVED_HONEST` (visible, states why not available) ·
`NOT_IMPLEMENTED` · `BLOCKED_ENVIRONMENT` · `EDR_OWNED`.

### A.1 Control Center / Dashboard
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Control Center | Aggregate posture, tile grid, ATT&CK coverage | MSS Dashboard | `XdrMssDashboardPage`, `XdrDashboardPage` | `/xdr/mss-dashboard` | `/api/xdr/*`, `/api/platform/metrics` | NATIVE_WIRED | `/xdr` and `/xdr/dashboard` both redirect to Incidents; no tile framework (`V-20`); dashboards not shareable (`D-9`) | ADAPT |

### A.2 Incidents (Cisco: Incidents ▸ Detections)
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 2 | Incidents list | Risk-prioritised queue | Incident Queue | `XdrIncidentsPage` + `incidents/*` | `/xdr/incidents` | `GET /api/incidents` | NATIVE_WIRED | Priority is a band, no **score** or Cisco bands (`V-17`) | ADAPT |
| 3 | Incident drawer | Preview without leaving list | `IncidentPreviewDrawer` | present | same | same | NATIVE_WIRED | verify against reference (`V-18`) | ADAPT |
| 4 | Incident detail | Case management surface | Incident Record + 14 tabs | `XdrIncidentDetailPage`, `record/tabs/*` | `/xdr/incidents/:id` | `/api/incidents/{id}` | NATIVE_WIRED | Evidence/Overview tabs `window.open` dead links (LEAK-2) | ADAPT |
| 5 | Worklog (notes + auto-response history) | Attributed append-only record | `workspace_cases.incident_state_history[]` | `TimelineTab`, `NotesTab` | `/xdr/incidents/:id` | `PATCH /api/incidents/{id}/state` | NATIVE_WIRED | M-1b notes on non-closure transitions; M-1c standalone note **HELD** by owner | REUSE |
| 6 | Detections (OCSF 1.0, filter, JSON export) | Individual findings | Detection Engineering | `XdrDetectionsPage` | `/xdr/detections` | `edr_raw_events.derivations[]`, `/api/xdr/*` | NATIVE_WIRED | Positioned as engineering, not an analyst **Detections** surface under Incidents; no JSON export; no OCSF field naming | ADAPT |
| 7 | Recommend actions | Pipeline stage | Recommendations tab | `RecommendationsTab`, `XdrRecommendationsPanel` | `/xdr/incidents/:id` | `/api/decode/mitigations/evidence_driven` | NATIVE_WIRED | — | REUSE |

### A.3 Investigate (Cisco: Investigate ▸ Activities)
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 8 | Investigate (observable → enrichment → relations graph + timeline) | Intel-driven investigation entry | Investigation Workspace | `XdrInvestigationWorkspacePage`, `EvidenceFirstInvestigationWorkspace` (2,128 ln) | `/xdr/investigations`, `/…/:caseId` | `/api/investigation/{case_id}/*`, `/api/investigations` | NATIVE_WIRED | **No paste-an-observable entry point.** Cisco's Investigate starts from an IOC, ours starts from a case | BUILD (thin entry, reuse `/api/ioc/enrich`) |
| 9 | Relations graph | Entity relationship canvas | Evidence graph / attack graph | `AttackGraphTab`, `AttackChainPanel` | `/xdr/incidents/:id` | `/api/correlations/*` | NATIVE_WIRED | Cross-case rollup absent (rail row disabled) | ADAPT |
| 10 | Timeline | Chronology | `TimelineTab`, trajectory canvases | present | `/xdr/incidents/:id` | `/api/timeline/*` | NATIVE_WIRED | — | REUSE |
| 11 | Activities (OCSF 1.4 telemetry, filters-first) | Telemetry surface | Evidence Explorer + Telemetry Studio | `XdrEvidenceExplorerPage` (443), `admin/telemetry-studio` | `/xdr/evidence-explorer`, `/xdr/admin/telemetry-studio` | `v2_shadow_observations`, `/api/telemetry/*` | NATIVE_WIRED | Not named/placed as **Activities** under Investigate; Cisco's filters-drawer-first pattern absent | ADAPT |
| 12 | Casebook (ribbon) | Analyst scratchpad across pages | — | none | — | — | NOT_IMPLEMENTED | Deliberately withheld at Y3.2 | RESERVE |
| 13 | Ribbon | Persistent observable search + casebook + notifications | — | none (`V-5` open) | — | — | NOT_IMPLEMENTED | Global search exists in top bar; ribbon does not | RESERVE |

### A.4 Intelligence — **the wire-not-build block**
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 14 | Intelligence ▸ Indicators | Stored indicator search | Threat Intelligence | **base** `ThreatIntelPage` (285 ln); XDR row `disabled` | `/xdr/intelligence/threat` | `/api/threat-intel/*` (19 routes) · **104,975 indicators · 8 sources** | **BACKEND_REAL_UI_DISABLED** | Console says "no sources configured" while 8 are configured and syncing | **WIRE (P0 honesty)** |
| 15 | Intelligence ▸ Feeds | Feed health/sync | TI sources + RSS crawl | `ThreatIntelAdminPanel` (base) | `/xdr/intelligence/threat` | `/api/threat-intel/sources`, `/feeds/status`, `/rss/*` | BACKEND_REAL_UI_DISABLED | real `last_error: HTTP 429` never surfaced to an operator | WIRE |
| 16 | Enrich API / observable disposition | Enrichment on demand | IOC enrichment | `EnrichmentAdminPanel` (base) | `/xdr/intelligence/iocs` | `/api/ioc/enrich`, `/enrich/one`, `/api/enrichment/*`, `/api/osint/lookup` · **9 live providers** | BACKEND_REAL_UI_DISABLED | rail row disabled + hardcoded zeros | **WIRE (P0 honesty)** |
| 17 | Intelligence ▸ Judgments | First-class analyst judgement (`D-4`) | Verdicts + corrections | `/api/corrections/*`, `/api/verdict/stage2/*` | — | present | NOT_IMPLEMENTED as *judgement* | Ownership ambiguity `A-3`; must NOT become a third disposition engine | ADAPT (later PR) |
| 18 | Intelligence ▸ Events | Intel events | — | — | — | — | NOT_IMPLEMENTED | — | RESERVE |
| 19 | (Cisco has no peer) Command Intelligence | NivXRay differentiator | Command analyzer + decode fabric | **base** `CommandAnalyzerPage` (611 ln) | `/xdr/intelligence/command` | `/api/analyze/command`, `/api/decode/*` (17), `/api/die/*` (21) | BACKEND_REAL_UI_DISABLED + LEAKS_EXTERNAL (Pivot → `/analyze`) | rail row disabled; pivot opens a dead tab | **WIRE** |
| 20 | (Cisco: file reputation via modules) Malware Intelligence | Artifact analysis | Documents / artifact analysis | **base** `DocumentsPage` (315 ln) | `/xdr/intelligence/malware` | `/api/documents/*`, `/api/files/*`, `/api/die/analyze` | BACKEND_REAL_UI_DISABLED + LEAKS_EXTERNAL (Pivot → `/documents`) | upload path needs chunked upload + object storage decision | WIRE (read-only first) |
| 21 | ATT&CK coverage visualisation | Technique coverage | MITRE heatmap | `XdrMitreHeatmap` (808 ln) **native** | `/xdr/intelligence/mitre` | `/api/mitre/heatmap` · **290/125/13** | NATIVE_WIRED | Pivot `rule → /heatmap` still opens a dead external tab | REUSE + fix pivot |
| 22 | (Cisco: Help/Docs) Knowledge Base | Runbooks/SOPs | KB | `XdrKbPage` (222) **native** | `/xdr/kb` | `/api/kb/*` · **334 entries** | NATIVE_WIRED | Rail label vs `/xdr/intelligence/kb` duplication | REUSE |

### A.5 Assets
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 23 | Assets (unified device+user inventory) | Asset context for prioritisation | Endpoints inventory | `XdrEndpointsPage`, `XdrEntity360Page` | `/xdr/endpoints`, `/:device` | `/api/edr/*`, `v2_shadow_observations` | NATIVE_WIRED | 1 domain only; **2** real endpoints; LINUX only | REUSE |
| 24 | Device value (user-defined, feeds priority) `D-1` | Prioritisation input | — | — | — | — | **NOT_IMPLEMENTED** (not blocked) | Cisco's asset value is *user-defined*, so this is buildable; priority must keep saying "Asset Value: Not Available" until then | BUILD (later PR) |
| 25 | Users / Identities | Identity context | Honest not-implemented page | `XdrNotImplementedPage` | `/xdr/assets/identity` | none | RESERVED_HONEST | no identity source ingested | RESERVE |
| 26 | Device Trajectory (Secure Endpoint) | Endpoint-centric timeline | AMP trajectory canvas | `EdrDeviceTrajectoryPage`, `XdrDeviceTrajectoryPage` | `/xdr/endpoints/:device/trajectory` · `/edr/device-trajectory` | `/api/edr/device-trajectory` | NATIVE_WIRED / EDR_OWNED | `/xdr/edr/device-trajectory` permanent redirect must stay (`D-2`) | REUSE |
| 27 | Network assets / attack paths | Exposure graph | Honest not-implemented | `XdrNotImplementedPage` | `/xdr/assets/network`, `/attack-paths` | none | RESERVED_HONEST | needs identity + network + exposure graphs | RESERVE |
| 28 | (no Cisco peer) Vulnerability Exposure | CVE/KEV/EPSS correlation | Exposure page | `XdrExposurePage` | `/xdr/exposure` | `/api/xdr/*` | NATIVE_WIRED | should be a **child of Assets**, not a top-level peer | ADAPT |

### A.6 Response
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 29 | Response API (act on observables) | Distributed response | Response boundary → engine → EDR | `backend /api/xdr/respond/*`, `apps/nivxray-xdr-response` (:8056), `edr_plane/response.py` | `/xdr/respond/*` | `/api/xdr/respond/*`, `/api/edr/response/actions` | NATIVE_WIRED (orchestration) | **2 real adapters vs 16 stubs**; isolation `BLOCKED_ENVIRONMENT` (no `CAP_NET_ADMIN`) | REUSE — **never reimplement** |
| 30 | Approvals | Destructive-action gate | Approvals queue | `XdrApprovalsPage` | `/xdr/respond/approvals` | `/api/xdr/respond/*` | NATIVE_WIRED | — | REUSE |
| 31 | Action Center (Defender/Cortex) | Cross-incident response surface | rail row `response` **disabled** ("Phase 8") | `EdrResponsePage` (EDR side) | — | `/api/response/*`, `/api/xdr/respond/*` | NOT_IMPLEMENTED (XDR side) | data exists (31 commands, 5 verified) but XDR has no cross-incident view | BUILD (thin projection) |
| 32 | Remediate from causality view (Cortex) | Act where you look | process tree has no actions | `ProcessTreePanel`, `AttackGraphTab` | `/xdr/incidents/:id` | `/api/xdr/respond/*` | NOT_IMPLEMENTED | analyst must leave the tree to act | ADAPT (later PR) |

### A.7 Automate
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 33 | Automate ▸ Workflows | No/low-code workflow engine | Playbooks + designer | `XdrPlaybooksPage`, `XdrPlaybookDesignerPage` | `/xdr/respond/playbooks` | `/api/xdr/*` | NATIVE_WIRED | browser-local stores in places (`F-5` legacy) | ADAPT |
| 34 | Automation rules (5 types, incl. **Approval**) `D-12` | WHEN → THEN | Automation rules | `XdrAutomationRulesPage`, `…RuleEditorPage` | `/xdr/respond/automation-rules` | `/api/xdr/*` | NATIVE_WIRED | rule-type parity unaudited | ADAPT |
| 35 | Workflow runs | Execution history | — | `VisualExecutionStudio` | — | engine sqlite SSOT | NOT_IMPLEMENTED as a rail surface | RESERVE |

### A.8 Administration / Data
| # | Cisco | Role | NivXRay | Component | Route | API | Status | Gap | Action |
|---|---|---|---|---|---|---|---|---|---|
| 36 | Integrations (API-key-linked sources) | Source registry | Integrations | `IntegrationsBody` | `/xdr/admin/integrations` | `/api/admin/*` (76) | NATIVE_WIRED | — | REUSE |
| 37 | Devices / API clients / users | Tenancy + access | Users/Roles, API/Webhooks, Secrets | `UsersRolesBody`, `WebhooksBody`, `ApiKeysBody`, `SecretsBody` | `/xdr/admin/*` | `/api/xdr/rbac/*`, `/api/xdr/api-keys` | NATIVE_WIRED | RBAC fail-closed already shipped | REUSE |
| 38 | (Cisco: under Administration) Collectors / Data sources / Telemetry health | Ingest operations | 14 native admin surfaces | `CollectorsBody`, `DataSourcesBody`, `adminMeta.js` | `/xdr/admin/:section` | `/api/xdr/collectors`, `/api/telemetry/*` | NATIVE_WIRED | **F-4 collector split-brain** (two runtimes, two state stores, third registry) still open | ADAPT |
| 39 | Client Management (AnyConnect+Secure Endpoint) | Agent lifecycle | EDR enrolment | `EdrEnrollmentBody`, `/xdr/admin/agents` | `/xdr/admin/agents` | `/api/edr/*` | NATIVE_WIRED | EDR-owned; XDR keeps an entry point only (`D-8`) | REUSE |
| 40 | Platform health | Is the platform itself up? | Platform Health | `PlatformOverviewBody` | `/xdr/admin/platform-health` | `/api/platform/*` | NATIVE_WIRED | — | REUSE |

**Matrix roll-up (counts, not percentages):** `NATIVE_WIRED` 24 · `BACKEND_REAL_UI_DISABLED` **6** ·
`RESERVED_HONEST` 3 · `NOT_IMPLEMENTED` 8 · `BLOCKED_ENVIRONMENT` 1 (isolation execution) ·
`EDR_OWNED` 2. Actions: `REUSE` 13 · `ADAPT` 14 · `WIRE` 6 · `BUILD` 4 · `RESERVE` 5.
**Nothing in this matrix requires a new engine.**

---

## B. CURRENT → TARGET ROUTE MAP

### B.1 Rail (target = Cisco's 8 primaries; owner decision O-1)

```
NivXRay XDR
├── Control Center            /xdr/mss-dashboard        (ADAPT · today /xdr redirects to incidents)
├── Incidents                 /xdr/incidents
│   ├── My Queue              /xdr/incidents?mine=1
│   └── Detections            /xdr/detections           (RENAME from "Detection Engineering")
├── Investigate               /xdr/investigations
│   ├── Observable            /xdr/investigate           ← NEW thin entry (Cisco's real front door)
│   ├── Evidence Explorer     /xdr/evidence-explorer
│   ├── Activities            /xdr/activities            ← NEW alias of the telemetry surface
│   └── Global Search         /xdr/search
├── Intelligence              /xdr/intelligence
│   ├── Threat Intelligence   /xdr/intelligence/threat    WIRE
│   ├── IOC Intelligence      /xdr/intelligence/iocs      WIRE
│   ├── Command Intelligence  /xdr/intelligence/command   WIRE
│   ├── Malware Intelligence  /xdr/intelligence/malware   WIRE
│   ├── MITRE ATT&CK          /xdr/intelligence/mitre     (native today)
│   └── Knowledge Base        /xdr/kb                     (native today)
├── Automate                  /xdr/respond/playbooks · /automation-rules · /approvals
├── Assets                    /xdr/endpoints
│   ├── Entity 360            /xdr/endpoints/:device
│   ├── Trajectory            /xdr/endpoints/:device/trajectory
│   ├── Identity / Network    /xdr/assets/identity · /network        RESERVED_HONEST
│   ├── Exposure              /xdr/exposure               (demoted from top level)
│   └── Attack Paths/Critical /xdr/assets/attack-paths · /critical   RESERVED_HONEST
├── Client Management         /xdr/admin/agents           (entry point only; EDR owns it)
└── Administration            /xdr/admin/:section  (14 native sections)
    ├── Detect                /xdr/rule-studio · /xdr/admin/detection-registry · /correlation-rules
    ├── Data                  /xdr/admin/collectors · /data-sources · /parsers · /normalization
    ├── Telemetry             /xdr/admin/telemetry-studio · /telemetry-health
    └── System                /xdr/admin/platform-health · /xdr/docs
```

### B.2 Route deltas — additions only, **zero removals**

| Current | Target | Change |
|---|---|---|
| `/xdr/intelligence/threat` → `XdrReservedPage` | → `XdrThreatIntelPage` | REPLACE component, route unchanged |
| `/xdr/intelligence/iocs` → `XdrReservedPage` | → `XdrIocIntelPage` | REPLACE component |
| `/xdr/intelligence/command` → `XdrReservedPage` | → `XdrCommandIntelPage` | REPLACE component |
| `/xdr/intelligence/malware` → `XdrReservedPage` | → `XdrMalwareIntelPage` | REPLACE component |
| — | `/xdr/investigate` | ADD (observable entry) |
| — | `/xdr/activities` | ADD (Activities surface) |
| — | `/xdr/response` | ADD (Action Center projection) |
| `/xdr/intelligence/kb` and `/xdr/kb` | keep both | one canonical + one permanent alias |
| `/xdr/edr/device-trajectory` | keep | **permanent** context-preserving redirect (`D-2`) |
| all 60 existing routes | keep | no route is deleted in this program |

### B.3 Cross-product boundary (unchanged, and the only permitted exceptions)

| Destination | Mechanism | Verdict |
|---|---|---|
| `edr.nivxforge.com/edr/*` | `productOrigins.productHref("edr", …)`, context in query string | ALLOWED — different product |
| `workspace.nivxmachines.com` | `WorkspaceLaunch`, config-gated, `NOT_CONFIGURED` otherwise | ALLOWED — different deployment |
| `nivxray.nivxforge.com` | **API origin only** | never a navigation target |
| `/analyze`, `/threat-intel`, `/documents`, `/heatmap`, `/analyst` | today `window.open` | **FORBIDDEN — these are the leaks** |

---

## C. COMPONENT DEPENDENCY CLOSURE

Traced with import graphs, not filenames. Result: **the closure is small, and the two
biggest "migrations" in the directive should not happen at all.**

### C.1 Base-app pages proposed for migration

| Source (base app) | Lines | Import closure | Verdict |
|---|---|---|---|
| `pages/ThreatIntelPage.jsx` | 285 | `@/components/Header`, `@/components/PageHeader`, `@/lib/api`, `@/lib/auth`, lucide | **PORT LOGIC, NOT FILE.** Drop `Header`/`PageHeader` (XdrShell + `AdminHero` own chrome). `@/lib/api` + `@/lib/auth` already exist in the XDR bundle. Net new deps: **0** |
| `pages/CommandAnalyzerPage.jsx` | 611 | + `@/components/ShellcodeView` | PORT LOGIC. One extra component to bring or stub |
| `pages/DocumentsPage.jsx` | 315 | as above, plus upload | PORT READ PATH ONLY. Upload needs the chunked-upload + object-storage decision first |
| `pages/KnowledgeBasePage.jsx` | 611 | as above | **DO NOT MIGRATE** — `XdrKbPage` is already native on `/api/kb/*` |
| `pages/MitreHeatmapPage.jsx` | 295 | as above | **DO NOT MIGRATE** — `XdrMitreHeatmap` (808 ln) is already native and richer |
| `pages/AdminPage.jsx` | 426 | **7 sub-panels** (`TrainingNotesCard`, `ConfusionMatrixCard`, `TaxiiAdminPanel`, `RegressionDashboard`, `EnrichmentAdminPanel`, `ThreatIntelAdminPanel`, `DocsFeedbackPanel`) | **DO NOT MIGRATE THE PAGE.** 14 native admin sections already exist. Harvest **only** `ThreatIntelAdminPanel` + `EnrichmentAdminPanel` as the config half of PR-XDR-2 |
| `pages/PlatformHealthPage.jsx` | 377 | as above | DO NOT MIGRATE — `PlatformOverviewBody` is native |
| `v2/pages/InvestigationWorkspace.jsx` | 621 | `../theme`, `../flags`, `./SelectionContext`, `Header`, lazy tabs | **DO NOT MIGRATE.** `XdrInvestigationWorkspacePage` (1,103) + `EvidenceFirstInvestigationWorkspace` (2,128) + `WorkspaceSelectionContext` (124) are the native equivalents. Migrating would create a **second investigation surface** — directive §21 violation |
| `v2/pages/CaseWorkspaceShell.jsx` | 63 | `Header`, `flags` | DO NOT MIGRATE — it is a 63-line shell; XdrShell is ours |
| `v2/pages/EvidenceGraphTab.jsx` | 699 | `../theme`, `./SelectionContext` | **HARVEST ALGORITHMS ONLY** if `AttackGraphTab` proves insufficient. Do not import `v2/theme` (a second design token system) |
| `v2/pages/GlobalSearch.jsx` | 283 | `../theme`, `./SelectionContext` | DO NOT MIGRATE — `XdrSearchPage` (230) + `/api/xdr/search` are native |

### C.2 Closure rules (binding on every PR)

1. **Never import `@/components/Header` or `PageHeader` into the XDR bundle** — the shell
   owns chrome; two headers is the merged-product failure returning.
2. **Never import `v2/theme.js`** (42 ln) — the XDR bundle has `nx-tokens.css` /
   `nx-theme.css` / `nx-epistemic.css`. A second token system is a second design
   authority (already an open reconciliation risk).
3. `@/lib/api` + `@/lib/auth` in the XDR bundle are the **only** API/auth clients.
4. `SelectionContext` → use the native `WorkspaceSelectionContext`.
5. Anything migrated must render **inside `XdrShell`** and be wrapped in `Protected`.
6. Absolute cross-app URLs must resolve through `productOrigins`, never be literals.

### C.3 Backend closure — nothing to build

All six WIRE items already have live, authenticated APIs (785 `/api` paths total):
`/api/threat-intel/*` (19) · `/api/ioc/*` (3) · `/api/enrichment/*` (4) ·
`/api/osint/lookup` · `/api/analyze/*` (8) · `/api/decode/*` (17) · `/api/die/*` (21) ·
`/api/documents/*` (8) · `/api/files/*` (6) · `/api/kb/*` (6) · `/api/mitre/*` (5).
**No new backend router is required for PR-XDR-1..3.**

---

## D. P0 IMPLEMENTATION PLAN

Ordering principle: **remove the lie first, then close the escape, then add surface.**
Every PR builds, tests and deploys independently.

### PR-XDR-0 · Kill the launcher class (smallest, highest leverage)
1. `Pivot.jsx`: delete all 13 `external: true` targets. Re-point to in-XDR routes where
   one exists (`hash|ip|domain|url` → `/xdr/intelligence/iocs?q=&type=`; `process` →
   `/xdr/intelligence/command`; `file` → `/xdr/intelligence/malware`; `rule` →
   `/xdr/intelligence/mitre`; `engine` → `/xdr/investigations/:case`). Where no
   destination exists, render a **named absence with a reason** (the Y3.1 pattern) —
   never a dead tab.
2. `XdrShell.jsx`: delete `openExternal()` and the `item.external` render branch; delete
   the now-false header comment about opening capabilities in a new tab.
3. `backend/routers/incidents.py`: change the IOC pointer's `deep_link` from
   `/threat-intel?…` to `/xdr/intelligence/iocs?…`. **Backend change, deliberate**, since
   the leak is authored server-side. (Requires `test_incidents_projection` update.)
4. `OverviewTab.jsx` / `InvestigationTab.jsx`: `window.open(deep_link)` →
   `navigate(deep_link)` for same-origin `/xdr/*` targets; keep `window.open` **only**
   for `productOrigins`-resolved cross-product URLs.
5. Guard test: **no `window.open` with a non-`/xdr`, non-`/edr`, non-`productOrigins`
   target may exist in the bundle** (AST scan, allow-list with written reasons — the
   P0-2C Layer-1 pattern).

**Acceptance:** every pivot either navigates in-product or states why it cannot; zero
new tabs to non-existent paths; `git grep "external: true" src/` → 0.

### PR-XDR-1 · Rail truth + IA lock (owner decision O-1 required first)
Restructure `SIDEBAR` to the 8 Cisco primaries; Detections under Incidents; Activities
and Global Search under Investigate; Exposure under Assets. Add `/xdr/activities` and
`/xdr/investigate`. `/xdr` lands on **Control Center** or stays on Incidents — **owner
decision O-2**. No capability is removed; only grouping and labels change.

### PR-XDR-2 · Intelligence honesty (P0 — the actual defect)
Replace `XdrReservedPage` for `threat` and `iocs` with native surfaces reading
`/api/threat-intel/stats|sources|iocs|feeds/status` and
`/api/ioc/enrich|health` + `/api/enrichment/*` + `/api/osint/lookup`. Real counts, real
`last_sync`, real `last_error` (surface the `HTTP 429`), real provider states. Harvest
`ThreatIntelAdminPanel` + `EnrichmentAdminPanel` logic for the config half.
**Delete the hardcoded zeros and the false footnote.** Where a metric genuinely has no
API, the page must say `NO_API_FOR_THIS_METRIC`, not `0`.

### PR-XDR-3 · Command + Malware intelligence
`/xdr/intelligence/command` on `/api/analyze/command` + `/api/decode/*` + `/api/die/*`
(port `CommandAnalyzerPage` logic, drop its chrome). `/xdr/intelligence/malware`
**read-only first** on `/api/documents` + `/api/files` + `/api/die/analyze`; upload
deferred until the chunked-upload/object-storage decision (**owner decision O-3**).

### PR-XDR-4 · Detections + Activities as analyst surfaces
Reposition `XdrDetectionsPage` as Cisco-style **Detections** under Incidents (filters,
JSON export, detection → activity/evidence/asset/incident links). Introduce
`/xdr/activities` as the filters-drawer-first telemetry surface over
`v2_shadow_observations`, honest about **LINUX-only, 2 endpoints, last delivery
2026-09-06T15:46Z** (P0-3 is the root cause and must be named on the page).

### PR-XDR-5 · Response / Action Center
`/xdr/response` as a **projection** of the existing lifecycle
(`response_lifecycle.facts{}`), never a new store. Must render the seven distinct states
and never let `dispatched` read as containment. Cortex-style remediate-from-tree is a
follow-on, not this PR.

### PR-XDR-6 · Automate + Administration consolidation
Automation rule-type parity audit (`D-12`, incl. Approval as a rule type); F-4 collector
split-brain reconciliation (**must not** be solved by pointing the console at `:8055`).

### PR-XDR-7 · Assets / Exposure / asset value
`Assets` grouping; `device value` as a user-defined prioritisation input (`D-1`) so the
priority breakdown can stop saying "Asset Value: Not Available".

**Explicitly NOT in this program:** XQL-style data-lake query (`sdl` disabled), casebook
/ ribbon (`RESERVE`), real endpoint isolation execution (`BLOCKED_ENVIRONMENT`),
production collector enrollment and the auth/dedupe production deploy (**frozen**).

---

## E. FILES TO CHANGE (by PR)

**PR-XDR-0** — `src/xdr/components/Pivot.jsx` · `src/xdr/XdrShell.jsx` (delete external
branch) · `src/components/incidents/tabs/OverviewTab.jsx` ·
`src/components/incidents/tabs/InvestigationTab.jsx` · `backend/routers/incidents.py`
(IOC deep_link) · `backend/tests/canonical/incidents/test_incidents_projection.py` ·
NEW `tests/adoption/test_no_external_product_navigation.mjs`.

**PR-XDR-1** — `src/xdr/XdrShell.jsx` (`SIDEBAR` only) · `src/App.jsx` (2 added routes) ·
NEW `tests/adoption/test_rail_ia_lock.mjs`.

**PR-XDR-2** — NEW `src/xdr/pages/XdrThreatIntelPage.jsx`,
`src/xdr/pages/XdrIocIntelPage.jsx`, `src/xdr/intel/threatIntelApi.js` ·
`src/App.jsx` (2 swaps) · `src/xdr/pages/XdrReservedPage.jsx` (remove `threat`, `iocs`).

**PR-XDR-3** — NEW `XdrCommandIntelPage.jsx`, `XdrMalwareIntelPage.jsx` (+ optional
`ShellcodeView` port) · `src/App.jsx` · `XdrReservedPage.jsx` (remove `command`,
`malware`).

**PR-XDR-4** — `XdrDetectionsPage.jsx` · NEW `XdrActivitiesPage.jsx` · `src/App.jsx`.
**PR-XDR-5** — NEW `XdrResponseCenterPage.jsx` · `src/App.jsx`.
**PR-XDR-6/7** — admin bodies, `adminMeta.js`, assets grouping (scoped at approval time).

---

## F. FILES EXPLICITLY NOT TO CHANGE

**Frozen — owner instruction:**
`backend/routers/xdr_rbac.py` · `backend/routers/xdr_ingest.py` ·
`backend/services/ingest_idempotency.py` · `backend/deps.py` (`seed_admin`) ·
any Vercel/DNS config · any production DB or collector enrollment path ·
`frontend/.env`, `backend/.env` (`REACT_APP_BACKEND_URL`, `MONGO_URL`, `DB_NAME`).

**Do not touch — load-bearing or authoritative:**
`apps/nivxray-xdr-response/**` (response SSOT; 2 real adapters + 16 declared stubs) ·
`backend/edr_plane/**` · `backend/services/edr/endpoint_query.py` (the ONE alias
resolver; a second resolver is the F-1 class returning) · `backend/nivxforge/**` ·
`backend/engine/**` · `l1_evidence`, `l2_investigation`, `workspace`, `reasoning`
(LEGACY but imported) · the 39 adopted "legacy" routes (`F-8`).

**Do not migrate (see §C.1):** `frontend/src/v2/pages/InvestigationWorkspace.jsx` ·
`CaseWorkspaceShell.jsx` · `GlobalSearch.jsx` · `pages/KnowledgeBasePage.jsx` ·
`pages/MitreHeatmapPage.jsx` · `pages/AdminPage.jsx` · `pages/PlatformHealthPage.jsx` ·
`frontend/src/components/Header.jsx` / `PageHeader.jsx` · `frontend/src/v2/theme.js`.

**Do not delete:** `/xdr/edr/device-trajectory` redirect · `WorkspaceLaunch.jsx` ·
`XdrNotImplementedPage` / remaining `XdrReservedPage` capabilities ·
`productOrigins.js` · `productScope.js` · `ProductScopeGuard.jsx`.

---

## G. RISKS

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R-1 | **Second investigation surface** created by migrating `v2/InvestigationWorkspace` | High if the directive is followed literally | Product-splitting; §21 violation | §C.1 forbids it; native workspace is the SSOT |
| R-2 | **Second design token system** via `v2/theme.js` | Medium | Two design authorities (already an open risk) | §C.2 rule 2; import guard in the PR-XDR-0 AST scan |
| R-3 | Wiring Intelligence exposes **tenant-unscoped** intel reads | Medium | Cross-tenant disclosure — the exact defect found inside `identity_refs()` | Every new page must call through `resolve_tenant_scope()`; add cross-tenant gates to the PR test like the 18 in P0-2C |
| R-4 | Rail restructure breaks `data-testid` selectors and existing tests | High | Test churn misread as regression | Keys are the testid basis — **preserve every `key`**, change only grouping/labels |
| R-5 | Real TI counts (104,975) make the console look "full" while **telemetry is blind** since 2026-09-06 | High | Analyst misreads platform health | Activities/Detections pages must name the freshness gap (`TelemetryFreshness` exists — reuse it) |
| R-6 | Malware page's upload path drags in file storage | Medium | Scope explosion, base64-in-Mongo anti-pattern | Read-only first; upload gated on owner decision O-3 (object storage) |
| R-7 | Backend `deep_link` change breaks another consumer | Low | Dead link elsewhere | `grep` all `deep_link` consumers before the change; the projection test pins the shape |
| R-8 | Priority-score parity invents a score we cannot compute | Medium | Fabricated prioritisation | Cisco's formula needs **asset value**, which we do not have; render the score only from Detection Risk and state the missing component (existing ruling) |
| R-9 | `test_p0_f4_endpoint_process_tree.py` trio + `test_row_projection_shape` still red | Certain | Green-suite ambiguity | Pre-existing and separately classified; **never baseline-reset**, never absorbed into a parity PR |
| R-10 | Vercel `yarn.lock` / root-deployment recurrence | Medium | Deploy failure | `refuse-root-deployment.sh` + `--frozen-lockfile` already in place; verify per PR |

---

## H. ACCEPTANCE TEST PLAN

### H.1 Automated navigation contract (new, `tests/adoption/`)
For **all 60+ routes**, headless: origin stays on the XDR host · `XdrShell` mounted ·
`Protected` enforced · active nav key correct · F5 (SPA fallback) works · API calls go to
the configured API origin. Enumeration is **pinned** (a guard matching nothing is worse
than none — P0-2C Layer-3).

### H.2 Anti-leak gate (the P0 gate)
`window.open` allow-list: only `productOrigins`-resolved cross-product URLs and
`WORKSPACE_URL`. Zero `external: true` in `src/`. **No `/analyze`, `/threat-intel`,
`/documents`, `/heatmap`, `/analyst` literal in any built chunk.** Backend gate: no
`evidence_pointers[].deep_link` may target a path outside `/xdr/*` or `/edr/*`.

### H.3 Intelligence honesty gate (PR-XDR-2/3)
Rendered TI indicator total **equals** `/api/threat-intel/stats.total` (asserted
non-zero, so it cannot pass vacuously) · source count equals the API's `configured`
count · `last_error` surfaced verbatim · provider states equal `/api/ioc/health` · **no
hardcoded numeric literal** in the new pages (AST scan) · a metric with no API renders
`NO_API_FOR_THIS_METRIC`, never `0`.

### H.4 Tenant isolation
`analyst@nivx-live.com` vs `analyst@default.com` vs admin on every new surface;
cross-tenant `?customer=` denied; no hostname / `endpoint_id` leakage in the DOM;
out-of-scope records 404 identically to non-existent ones (existence never disclosed).

### H.5 Auth
Login against the configured API · `/auth/me` · unauthenticated `/xdr/*` →
`/login?returnTo=` · **no token in any URL**, no cross-origin token passing.

### H.6 Regression (must stay at or above baseline; **no baseline reset**)
`X1–X3/Y2 22/22` · `P0-F.13.5 25/25` · Detection Attribution `12/12` ·
`P0-W authorization 25/25` · `P0-2C alias invariant 10/10` ·
`p0_2c_alias_site_sweep 52/52` · response engine `27` ·
`backend/tests/edr` **340 passed / 3 failed** (the known `test_p0_f4` trio) ·
`test_incidents_projection` 19 passed / **1 known pre-existing failure**
(`test_row_projection_shape`, verified failing on a clean tree) ·
`docs_reconcile --gate` **0 violations** · frozen install + production build pass.

### H.7 Evidence-integrity gate (the NivXRay differentiator)
Every new surface must show, per analytical claim: `source`, `field`,
`observed_value`, `evidence_ref`, `timestamp`, `entity_ref`, `provenance`. An enrichment
with no cited provider response renders `PROVENANCE_MISSING`, never a verdict.

---

## OWNER DECISIONS REQUIRED BEFORE PR-XDR-1

- **O-1 · Information architecture.** (a) Cisco's **8 primaries** — my recommendation,
  reference-accurate and honest about coverage; or (b) the directive's **11-group tree**
  as written, accepting three top-level groups that are mostly unimplemented.
- **O-2 · Landing route.** `/xdr` → **Control Center** (Cisco behaviour) or stay on
  **Incidents** (the current owner-locked "primary analyst work surface").
- **O-3 · Malware Intelligence upload.** Read-only first (recommended), or include
  upload now — which requires the object-storage decision.
- **O-4 · Backend `deep_link` change.** Approve the one backend edit in PR-XDR-0
  (`/threat-intel` → `/xdr/intelligence/iocs`). Without it the launcher behaviour cannot
  be closed from the frontend.
- **O-5 · Judgements (`D-4` / `A-3`).** Adopt `/api/corrections/*` or
  `/api/verdict/stage2/*` as the judgement surface — explicitly **not** a third
  disposition engine. Defer or schedule?

## STOP

No source file has been modified for this program. The only change in the working tree
is the single owner-permitted string in `backend/routers/incidents.py:644`
(`"NivXForge EDR"` → `"NivXRay EDR"`), verified live and with the pre-existing test
failure proven pre-existing by `git stash`. Freeze holds: no production deploy of
API-key auth or ingest dedupe, no collector enrollment, no telemetry seeding, no
DNS/Vercel change, no production DB change.

Awaiting approval of O-1…O-5 and of the PR sequence.
