# INVESTIGATE → INDIVIDUAL INCIDENT · CONSOLIDATION INVENTORY
**READ-ONLY.** No route, workspace, backend contract, collection or document
was modified, redirected, renamed or deleted while producing this report.
Every claim below is from repository code, live API responses on the preview
deployment, or the operational database. Matching tab names were never
accepted as parity.

Date: 2026-06-21 · Method: source inspection + live authenticated probes as
`admin@nivxray.com` (cross-tenant), `analyst@nivx-live.com` (tenant-scoped)
and anonymous.

---

## 1 · ROUTE REALITY (this is not what either page's docstring claims)

| Route | What it renders today | Evidence |
|---|---|---|
| `/xdr/incidents/:id` | `XdrIncidentDetailPage` — 8 primary views (Overview · Story · Timeline · Evidence · Detections · Pivots · Response · Activity) + `report` as an action view | `App.jsx:247`, `XdrIncidentDetailPage.jsx:93-104` |
| `/xdr/investigations` | `XdrInvestigationsListPage` — "Investigate" landing | `App.jsx:249` |
| `/xdr/investigations/:caseId` | **Already a redirect** into `/xdr/incidents/:caseId?tab=…` (`story·process→story`, `trajectory→timeline`, `graph→entities`, `evidence→evidence`, `verdict·security_state→overview`, `attack→mitre`) | `App.jsx:158-176, 253` |
| `/xdr/investigations/:caseId/_engine` | `XdrInvestigationWorkspacePage` — the 8-tab causal engine page, "retained for rollback and engineering inspection", **not a rail destination** | `App.jsx:255-257` |

**Contradiction found.** The list page's own comment says it opens each row in
the unified workspace, but the live handler is
`navigate('/xdr/investigations/<caseId>/_engine?tab=story')`
(`XdrInvestigationsListPage.jsx:123-124`). So the "rollback-only" engine page
**is** the live destination of the Investigate landing.

**Dead code found.** The entire `src/xdr/investigation/` folder is unmounted:
`EvidenceFirstInvestigationWorkspace.jsx` (2 128 lines), `AttackChainPanel`,
`ProcessTreePanel`, `ScenarioIntelligencePanel`, `XdrCompletenessPanel`,
`InvestigationReportShell`, `WorkspaceSelectionContext`, `completeness.js` —
nothing outside the folder imports any of them (repo-wide grep). The incident
page's "Analysis completeness" is a backend field
(`XdrIncidentDetailPage.jsx:299-302`), not that module. `ScenarioIntelligencePanel`
is the only consumer of `POST /api/xdr/investigation/{id}/scenario-match`
(`routers/xdr_scenarios.py:98`), so that backend capability currently has **no
reachable UI**.

---

## 2 · THERE ARE THREE DIFFERENT "INVESTIGATION" DOMAIN OBJECTS

| Object | Key | Store (live counts) | API | Auth | Relationship to an Incident |
|---|---|---|---|---|---|
| **A · XDR incident investigation** (autonomous investigator + IUE) | `incident_id` → `investigation_id` (`inv_…`) | `workspace_cases{doc_type:"xdr_incident"}` **941** | `GET /api/incidents/{id}/investigation`, `/understanding` | optional user, **no tenant scope** (see §6) | **Analytical child of an Incident.** Cannot exist without one |
| **B · v2 case engine** (IKG · verdicts · trajectory · artifacts) | `case_id` (`case_golden_*`) | `v2_cases` **37**, driven by `v2_shadow_observations` **176 170** | `/api/v2/cases`, `/api/v2/cases/{id}/investigation·trajectory/device·artifacts`, `/api/v2/security-state/{id}` | `require_admin` (**not** tenant RBAC) | **Separate domain object.** Live: `/api/v2/cases` returns **37 cases and ZERO `inc_` ids** |
| **C · L1/L2 analyst workspace case** (sample/bundle forensics) | `case_id` (`case-…`) | `investigation_cases` **104** | `POST/GET/DELETE /api/investigation[/{case_id}]` + `/workspace`, `/state/transition`, `/summary`, `/story`, `/iocs`, `/capabilities`, `/threat`, `/detections`, `/hunting` | `get_current_user`, **owner-email scoped** | **Separate domain object**, evidence-bundle driven, own §8.1 state machine |
| (D · timeline investigations) | `iid = sha256(input)[:16]` | `investigations` **629**, `investigation_events` **1 100** | `/api/investigations*` | owner-email scoped | NivXMachines Workspace product, not XDR console |

So the answer to "is Investigation a separate domain object?" is
**a mixture, and the XDR console currently mixes A and B on one route**:

- The object the Investigate landing lists is **B**.
- The object the incident workspace investigates is **A**.
- `case_id` ↔ `incident_id` **do not map**: live probe
  `GET /api/incidents/case_golden_cobalt_strike_36fae8f5` → **404**
  (also for `case_golden_clean_workstation_6b3c52ef`). The engine page's own
  fallback (`/api/incidents/:caseId` when the v2 read fails) only works when
  the id happens to be an incident.
- Consequence today: the Investigate landing lists **37 golden-fixture engine
  cases** (the `/api/incidents` fallback never runs, because the v2 list is
  non-empty for an admin) and none of them is an incident.

---

## 3 · CAPABILITY GAP MATRIX · INVESTIGATION → INCIDENT

`Duplicate/Unique` = is the capability already present in the incident page.
`Migration Required` = work needed to reach the owner's target where the
Individual Incident is the complete workspace.

| Capability | Incident Current | Investigation Current | Backend Authority / API | Data Identity | Duplicate / Unique | Gap | Migration Required |
|---|---|---|---|---|---|---|---|
| Attack Story | **Native** `AttackStoryTab` (tab `story`) + engine panel "How it unfolded" | Engine tab `story` incl. **Sequential Attack Milestones**, **Causal Anchor Entities**, **Containment Recommendations** | Incident: `GET /api/incidents/{id}/attack-story`. Engine: `GET /api/v2/cases/{id}/investigation` | incident_id vs case_id | DUPLICATE (two renderings) | Engine sub-blocks are mounted in the incident page only inside the collapsed `EngineDepth` panel, and only for admins (§6) | Expose the three engine sub-blocks as first-class story sections once the API is tenant-scoped |
| Timeline | **Native** `TimelineTab` | not a tab (trajectory is) | `GET /api/incidents/{id}/attack-story` | incident_id | UNIQUE to incident | none | none |
| Evidence | **Native** `EvidenceTab` + `IncidentProvenance` | Engine tab `evidence` = **case artifacts** | Incident: incident record. Engine: `GET /api/v2/cases/{id}/artifacts` (live: `count: 0` for incidents) | incident_id / case_id | COMPLEMENTARY | Artifact list is case-engine data; for incidents it is empty in this build | Keep as engine depth; do not promote an empty capability |
| Entities / Evidence Graph (IKG) | **Native** `EntitiesGraphTab` (Graph\|Table lens in Story) + engine panel `graph` | Engine tab `graph` = **Investigation Knowledge Graph** node/edge inventory | Incident: `GET /api/incidents/{id}/attack-graph`. Engine: v2 investigation payload `ikg` | incident_id / case_id | DUPLICATE | IKG counts only in the collapsed engine panel | Merge IKG counts into the existing entity lens header |
| Detections | **Native** `TechnicalTab` + ATT&CK drill-down | not present | `GET /api/incidents/{id}/summary` | incident_id | UNIQUE to incident | none | none |
| Device Trajectory | Engine panel under Timeline | Engine tab `trajectory` (lane view + `traj_view` switch) | `GET /api/v2/cases/{id}/trajectory/device` (admin-only), plus native `/api/edr/device-trajectory` page | case_id | DUPLICATE of the EDR page | admin-only API; `?traj_view=` control not exposed in the incident page | Reuse as-is; add the lane/view switch if analysts ask |
| Process Ancestry | Engine panel under Story | Engine tab `process` | `GET /api/edr/process-tree?incident_id=` (tenant-scoped router, but **403 for the tenant analyst** in probe) | incident_id | DUPLICATE | authorization (§6) | none in UI |
| Security State (causal FSM) | Engine panel under Overview | Engine tab `security_state` | `GET /api/v2/security-state/{id}?tenant_id=` — **403 `TENANT_REQUIRED`** without an explicit tenant | case_id + tenant | DUPLICATE | the embedded panel must supply `tenant_id`; it reads `activeTenant()` and otherwise reports absence | Verify the embedded path passes a tenant; no new contract |
| Verdict / derivation | **Native** Overview (`verdict_stage2`, derivation chain, contributing signals) + engine panel `verdict` | Engine tab `verdict` (v3.1b engine header, bands, profiles `soc_balanced/aggressive/conservative`) | Incident: incident record. Engine: v2 investigation (`VERDICT_ENGINE_V3` flag = `shadow` ⇒ observable) | incident_id / case_id | DUPLICATE, **two different engines** | the **profile selector** (3 profiles) and negative explainability `"why isn't this X?"` (`/investigation/explain/{pattern}`) exist ONLY on the engine page | Decide whether v3 profiles become an incident-level control; today the shadow engine must not outrank the incident verdict |
| MITRE ATT&CK | **Native** `MitreTab` as a drill-down under Detections | Engine tab `attack` | Incident: `/summary`. Engine: v2 payload | both | DUPLICATE | none material | none |
| Knowledge Graph | engine panel `graph` | engine tab `graph` | v2 investigation `ikg` | case_id | DUPLICATE | see Entities | merge |
| Causal Anchors | inside engine `story` panel | engine tab `story` | v2 investigation | case_id | DUPLICATE | collapsed + admin-only | promote after §6 |
| Sequential Attack Milestones | inside engine `story` panel | engine tab `story` | v2 investigation | case_id | DUPLICATE | collapsed + admin-only | promote after §6 |
| Containment Recommendations | inside engine `story` panel; incident has its own `RecommendationsTab` + response plane | engine tab `story` ("Minimal Effective Containment") | v2 investigation vs `/api/xdr/respond/*` | case_id vs incident_id | **CONFLICTING AUTHORITIES** | two different containment answers | Keep the response plane authoritative; render engine containment as engine detail only |
| Reports | **Native** `ReportTab`, deep-linkable `?tab=report` | none | `GET /api/incidents/{id}/report` (+ `/pdf`, block writes) | incident_id | UNIQUE to incident | **no auth at all on this router (§6)** | security fix only |
| Case / investigation state | incident lifecycle (`new→in_progress→on_hold→resolved→closed`) | engine page shows none; object **C** has its own state machine | `PATCH /api/incidents/{id}/state` vs `POST /api/investigation/{id}/state/transition` | incident_id vs case_id | DISTINCT MODELS | none for incidents | none |
| Evidence provenance | **Native** `IncidentProvenance` + Task 3A telemetry origin | engine page shows pipeline stages implicitly | `/api/incidents/{id}` + `/pivots` | incident_id | UNIQUE to incident | none | none |
| Investigation-specific APIs/services | — | `/api/v2/cases/*`, `/api/v2/security-state/*`, `/api/investigation/*`, `/api/xdr/investigation/{id}/scenario-match` | as listed | case_id | RETAIN AS BACKEND SERVICE | `scenario-match` has no reachable UI | keep services; no second UI |

### Reverse matrix · what the Individual Incident has that Investigation does not
| Capability | Backend authority | In engine page? |
|---|---|---|
| Incident lifecycle + transition guard | `PATCH /api/incidents/{id}/state` | no |
| Priority (P1–P5 bands) · Severity | `/api/incidents/{id}` derivation | no |
| Assignment / ownership | `PATCH /api/incidents/{id}/assignee` | no |
| Risk · Confidence · **Analysis completeness** (three separate facts) | `/api/incidents/{id}` | partial (bands only) |
| Detections that contributed (weights, label effect) | `/api/incidents/{id}/summary` | no |
| Response plane (6 distinct facts, authorization-gated) | `/api/xdr/respond/*`, `/api/edr/response/actions` | no |
| Activity · worklog · findings ledger · analyst overlays | `/api/incidents/{id}/investigation`, `/intelligence/overlays` | no |
| **Investigation Pivots** (Task 3A: telemetry origin · IOC verification · native consoles) | `GET /api/incidents/{id}/pivots` | no |
| Telemetry-source provenance | `/pivots` + `IncidentProvenance` | no |
| Notes · Closure · Report | `/api/incidents/{id}/report`, case doc | no (report absent) |
| Domain views (`/xdr/incidents/:id/domain/:key`) | `/api/incidents/{id}` | no |

**Net:** the engine page carries **no unique analyst capability** — only a
different *rendering* of eight engine outputs, plus three genuinely
engine-only controls: the **verdict profile selector**, **negative
explainability**, and the **trajectory view switch**. Everything else it shows
is already mounted in the incident workspace as `EngineDepth` panels
(`capabilities=["verdict","security_state"] · ["story","process"] · ["graph"] ·
["trajectory"] · ["evidence"] · ["attack"]` = all 8 engine tabs).

---

## 4 · CAN A LEGITIMATE INVESTIGATION EXIST WITH NO INCIDENT?

Proven from code and contracts, not assumed:

- **Backend: YES, two ways.** Object **C** (`POST /api/investigation` with an
  evidence bundle, owner-scoped, 104 live cases, own state machine) and object
  **B** (`POST /api/v2/cases`, `require_admin`, 37 live cases, none an
  incident) both exist and both are incident-free by construction.
- **XDR console: NO.** Repo-wide grep of `apps/nivxray-xdr/src` finds **no call
  site** for `POST /api/investigation`, `POST /api/v2/cases` or
  `POST /api/cases/save`. There is no "create investigation", no
  "promote selection to case" and no hunt→case action anywhere in the XDR
  frontend.
- **Hunt → selected evidence → analyst-created investigation: NOT PROVEN.**
  `XdrHuntingPage` pivots to authoritative records only; it creates nothing.
  The only "save/correlate/start investigation" UI in the repository is the
  **NivXMachines Workspace** app (`/app/frontend`), a separate product with
  its own host, against objects **C/D**.
- **Standalone forensic / evidence-only case: BACKEND-ONLY.** Object **C** can
  hold one (sample + bundle + workspace state), but the XDR console has no
  route that renders it. `/xdr/investigations` does not list `investigation_cases`
  at all — it lists `v2_cases`.

**Therefore:** non-incident investigation is a **real backend domain** and a
**non-existent console workflow**. Retiring the standalone XDR Investigate UI
removes no user-reachable non-incident capability today.

---

## 5 · SMALLEST SAFE SEQUENCE TO THE TARGET
Target: `Incidents Queue → Quick Inspection → Individual Incident Full
Investigation Workspace`.

1. **S1 · Security first (blocking, see §6).** Scope the six anonymous /
   unscoped incident sub-routes. Nothing else should move while an incident
   sub-resource is readable without a session, because consolidation will make
   those routes the *only* investigation authority.
2. **S2 · Fix the Investigate landing's destination + data authority.** One
   change each: open rows in `/xdr/incidents/:id` (the redirect already
   exists), and list the **incident registry** as the primary authority with
   `/api/v2/cases` demoted to an engineering view. Today the landing shows 37
   ids that are not incidents and opens the "rollback-only" page.
3. **S3 · Tenant-scope the engine read path** (`/api/v2/cases/*` is
   `require_admin`, so every embedded engine panel is blank-or-error for a
   tenant analyst). Until then, the incident workspace's engine depth is an
   admin-only capability and must say so rather than looking empty.
4. **S4 · Promote the three engine-only story blocks** (Milestones · Causal
   Anchors · IKG counts) from the collapsed panel into the Story/Entities
   sections, keeping the raw engine panel under progressive disclosure.
5. **S5 · Decide the two conflicting authorities**: engine "Minimal Effective
   Containment" vs the response plane; v3 verdict profiles vs the incident
   verdict. Recommendation: response plane and incident verdict stay
   authoritative; the engine's answers render as engine detail with their
   engine + profile named.
6. **S6 · Only then** retire the standalone engine route to
   `/_engine` engineering-only status (it already is) and delete the unmounted
   `src/xdr/investigation/` folder after confirming `scenario-match` either
   gets a home in the incident page or is registered as unreachable.
7. **S7 · Non-incident investigations**: keep objects **C/D** as backend
   services. If the owner wants them in the XDR console, the minimal UI is
   **one list + one read-only case view** under a clearly separate route
   (e.g. `/xdr/cases`), NOT a second incident workspace — plus a single
   "create from selected evidence" action wherever the analyst selects
   evidence. Nothing in the current console needs it.

### Classification
- **REUSED AS-IS**: Device Trajectory · Process Ancestry · Security State ·
  Evidence/artifacts (already mounted as `EngineDepth`).
- **MOVED / EXPOSED IN INCIDENT**: Sequential Attack Milestones · Causal
  Anchor Entities · IKG node/edge counts · (optionally) trajectory view
  switch.
- **MERGED**: engine `graph` into the existing Entities lens; engine
  `verdict` header into Overview's verdict block (engine + profile named).
- **RETAINED AS BACKEND SERVICE**: `/api/v2/cases/*`, `/api/v2/security-state/*`,
  `/api/investigation/*` (object C), `scenario-match`, IUE
  `/understanding`.
- **LEGACY / REMOVABLE AFTER PARITY**: `XdrInvestigationWorkspacePage` as a
  *destination* (keep as the embedded capability provider), the unmounted
  `src/xdr/investigation/` folder (7 files, ~2.6 kLOC), the
  `/xdr/investigations` landing once the queue is the single entry.
- **MUST REMAIN SEPARATE**: object **C** (bundle/sample forensic cases) and
  object **D** (Workspace command timelines) — different identity, different
  ownership model, no incident.

---

## 6 · P0 SECURITY FINDINGS DISCOVERED DURING THE INVENTORY (no fix applied)

All verified live on preview. These are **incident sub-resources**, i.e. the
exact surfaces consolidation will depend on.

| Route | Auth | Tenancy | Live probe |
|---|---|---|---|
| `GET /api/incidents/{id}/investigation` (`autonomous_investigator.py:50`) | optional | **none** (`_col.find_one({"id": id})`) | **anonymous 200**; `nivx-live` analyst reads a `default` incident: state, 32 state-history rows, 172 activity rows, 12 executions, 13 findings |
| `GET /api/incidents/{id}/investigation/executions` (`:116`) | optional | none | same class |
| `GET /api/incidents/{id}/investigation/findings` (`:130`) | optional | none | **anonymous 200**, 13 findings |
| `GET /api/incidents/{id}/attack-story` (`attack_story.py:25`) | optional | none | **anonymous 200** |
| `GET /api/incidents/{id}/attack-graph` (`attack_graph.py:21`) | optional | none | **anonymous 200** |
| `GET /api/incidents/{id}/report` + `/report/pdf` (`report.py:13,22`) | **no dependency at all** | none | **anonymous 200** |
| `POST/PATCH/DELETE /api/incidents/{id}/report/blocks*` (`report.py:50,86,106,117`) | **no dependency at all** | none | code-verified: unauthenticated write, `author_email` taken from the request body (not probed — it would mutate data) |

For contrast, the routes that were fixed in P0-W behave correctly:
`/api/incidents/{id}` → 404 cross-tenant, `/understanding` → 404,
`/summary`, `/intelligence/overlays`, `/pivots` → 403 anonymous.
Same defect class as P0-W; these six routers were simply never included.
The one-line shape of the fix already exists in the codebase
(`incidents.py::_authorized_incident`).

**Recommendation:** authorise S1 as a separate small task before any
consolidation work. I have changed nothing.

---

## 7 · EXPLICITLY NOT DONE
No implementation, no deletion, no redirect, no rename, no migration, no
backend contract change, no data change. Task 3A remains closed and untouched.
Event Explorer, Hunting, enrichment and console-route administration were not
started.
