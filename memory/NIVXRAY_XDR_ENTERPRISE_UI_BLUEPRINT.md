# NIVXRAY XDR ENTERPRISE UI BLUEPRINT

Read-only inventory + blueprint. **No UI code was written or changed.** W1
CLOSED/FROZEN 6/6. W2-1 not started. 2026-09-18.
Owner lock: *enterprise UI/UX parity is a product requirement* — capability and
interaction-quality parity with Cisco XDR, Cortex XDR/XSIAM, Defender XDR,
Falcon, Elastic Security/Fleet, Sophos Central; **never** pixel copying.
Standing directive applies (`ENGINEERING_DIRECTIVE_RESEARCH_FIRST.md`).

---

## 1 · INVENTORY (measured, not estimated)

`apps/nivxray-xdr/src` · **239** JS/JSX files · **~60,029** lines of JSX ·
**62** routes · **168** distinct `/api/...` paths referenced by the SPA.

Largest surfaces: `EvidenceFirstInvestigationWorkspace.jsx` 2128 ·
`AttackGraphTab.jsx` 1643 · `XdrInvestigationWorkspacePage.jsx` 1115 ·
`XdrFleetFileTrajectoryPage.jsx` 1063 · `AttackChainPanel.jsx` 944 ·
`EdrDeviceTrajectoryPage.jsx` 937 · `XdrIncidentsPage.jsx` 911 ·
`UsersRolesBody.jsx` 842 · `XdrMitreHeatmap.jsx` 811 · `MitreTab.jsx` 746.

### 1.1 Finding A — **three parallel component systems** (the root cause of inconsistency)
| system | contents | verdict |
|---|---|---|
| `xdr/nx/` | `NxPageShell`, `NxSurface`, `NxChip`, `NxEmpty`, `NxLink`, `NxHeroHeader`, `NxProvenance`, `NxDonut`, `NxHBar`, `NxAreaSpark`, `NxDensity`, `nx-tokens.css`, `nx-theme.css`, `nx-page.css`, `nx-epistemic.css` | **this is the real design system — promote it to the single one** |
| `xdr/design/` | `tokens.css` (**1082 lines**, a second token set), `*V2` components, `CortexOnboardingWizard.jsx`, `_WizardLegacyBridge.jsx`, `glyphs.jsx`, `Provenance.jsx`, `Entity.jsx` | **CONSOLIDATE into `nx/`**; two token files is why "the same concept looks different on different pages" |
| `xdr/components/` + `components/incidents/` | 26 + 4 files, **two** incident component trees | **CONSOLIDATE**; `components/incidents/tabs/OverviewTab.jsx` duplicates `xdr/pages/incidents/record/tabs/` |

`styles/globals.css` is **21 lines** — there is effectively no global
foundation; 1,082 lines of tokens sit in a feature folder. Also:
`CortexOnboardingWizard` / `_WizardLegacyBridge` are **vendor-named
components** — rename (`NxOnboardingWizard`) on contact; we do not carry a
competitor's name in our component tree.

### 1.2 Finding B — we have reproduced the exact fragmentation Cortex is
**publicly trying to escape.** Telemetry onboarding is spread across **eight**
surfaces today:
`admin/DataSourcesBody` · `admin/CollectorsBody` · `admin/IntegrationsBody` ·
`admin/IngestRoutingBody` · `admin/ParsersBody` · `admin/NormalizationBody` ·
`/xdr/admin/data-sources-native` · `/xdr/admin/telemetry-health` — and the last
one is filed under **Investigate**, not Administration. This is the single
highest-value consolidation in the product.

### 1.3 Finding C — engineering terminology in customer-facing navigation
27 admin sections (`adminMeta.js`), including `IngestRoutingBody`,
`NormalizationBody`, `ParsersBody`, `EnginesBody`, `EngineRoleAdminBody`,
`CapabilityHubBody`, `EdrCapabilityTruthBody`, `GoldenPipelineTrace`,
`ClosedLoopPanel`, `CorpusBody`. These are implementation names. An analyst
does not know what a "corpus", an "engine role" or a "golden pipeline trace"
is. Rename to operator language; keep the engineering view behind *Details*.

### 1.4 Finding D — duplicate destinations for one job
* dashboards: `/xdr/dashboard` · `/xdr/control-center` · `/xdr/mss-dashboard`
* rule authoring: `/xdr/rule-studio` · `/xdr/detect/studio`
* knowledge base: `/kb` · `/xdr/kb` · `/xdr/intelligence/kb`
* trajectory: `/edr/trajectory` · `/edr/device-trajectory` ·
  `/xdr/edr/device-trajectory` · `/xdr/endpoints/:device/trajectory`
* investigation: `XdrInvestigationWorkspacePage` (1115) **and**
  `EvidenceFirstInvestigationWorkspace` (2128)

### 1.5 Finding E — honest-state discipline already exists (keep it)
`XdrEntity360Page` renders actions as `state: "unavailable"` with an explicit
`reason` (e.g. `NO_RESPONSE_DRIVER`); 5 sidebar items are `disabled: true`
with `title: "arrives in Phase N"`; `XdrReservedPage` backs reserved routes;
`NxEmpty` / `NxProvenance` exist. **This is the asset the redesign must not
lose** — it is already closer to "Verdict, cited" than any benchmark console.
Twenty files match `placeholder|TODO|mock`; each must be audited in its slice
(a keyword match is not proof of fake data, and I did not verify them
individually — stated as a limit, not a conclusion).

---

## 2 · ROUTE CLASSIFICATION (proposal — 62 routes)

`KEEP` · `RESTYLE` (design system only) · `REFACTOR` (structure + IA) ·
`CONSOLIDATE` (merge/redirect) · `REBUILD` · `DEFER`

| area | routes | verdict |
|---|---|---|
| shell | `/`, `/xdr`, `/login`, `*` | **REFACTOR** — single shell, global search, tenant switcher, help, user |
| command centre | `/xdr/control-center`, `/xdr/dashboard`, `/xdr/mss-dashboard` | **CONSOLIDATE → 1** (lens switch, not 3 routes) |
| incidents | `/xdr/incidents`, `/:id`, `/:id/domain/:domainKey` | **REFACTOR** — enterprise table standard + flyout; `XdrIncidentsPage` 911 lines splits |
| investigation | `/xdr/investigations`, `/:caseId`, `/xdr/evidence-explorer`, `/xdr/evidence/:executionId`, `/xdr/search` | **REFACTOR + CONSOLIDATE** the two workspaces; **preserve** Summary/Story/Timeline/Evidence/Analysis/ATT&CK/IOC/trajectory/response/worklog/exports |
| intelligence | `/xdr/intelligence/{threat,iocs,command,malware,mitre,kb}`, `/xdr/intelligence/files/:key`, `/xdr/kb`, `/kb`, `/xdr/docs`, `/docs` | **RESTYLE + CONSOLIDATE** the 3 KB routes into 1 |
| detect / automate | `/xdr/detections`, `/:id`, `/xdr/rule-studio`, `/xdr/detect/studio`, `/xdr/detect/tuning/:ruleId`, `/xdr/respond/{playbooks,playbooks/:id,automation-rules,automation-rules/:id,approvals}` | **CONSOLIDATE** studio duplication; **RESTYLE** the rest |
| assets | `/xdr/endpoints`, `/:device`, `/:device/trajectory`, `/xdr/assets/{identity,network,attack-paths,critical}`, `/xdr/exposure`, `/xdr/cve` | **REFACTOR** into the entity model; identity/network stay **honest-empty** until a source exists |
| activity | `/xdr/activities` | **RESTYLE** |
| administration | `/xdr/admin`, `/xdr/admin/:section` (27 sections) | **REBUILD IA** — operator language, and telemetry onboarding leaves Admin for **Data Sources** |
| **Data Sources (new)** | `/xdr/data-sources{,/sources,/add,/collectors,/integrations,/coverage,/health,/verify}` | **REBUILD** — absorbs the 8 fragmented surfaces (Finding B) |
| EDR routes in the XDR SPA | `/edr/*` (12 routes), `/xdr/edr/device-trajectory` | **DEFER + CONSOLIDATE** — NivXForge is a separate product surface; XDR links to it, does not host it |
| reserved | 5 `disabled` rail items | **KEEP** as honest "not yet" |

---

## 3 · TARGET ARCHITECTURE

### 3.1 Shell (one SPA, one rail)
```
┌────────────────────────────────────────────────────────────────┐
│ NivXRay XDR    ⌘K Global Search      Tenant ▾  Help  User ▾   │
├───────────────┬────────────────────────────────────────────────┤
│ Control Centre│  page header · breadcrumb · actions            │
│ Incidents     │  ┌──────────────────────────────────────────┐  │
│ Investigate   │  │ workspace (table / entity / workspace)   │  │
│ Intelligence  │  └──────────────────────────────────────────┘  │
│ Automate      │                          ▸ contextual flyout   │
│ Assets        │                                                │
│ Data Sources  │                                                │
│ ──────────    │                                                │
│ Administration│                                                │
└───────────────┴────────────────────────────────────────────────┘
```
Rules: one permanent rail; **no second permanent nav column**; depth via
contextual tabs → flyouts → full entity page; `Data Sources` is promoted out of
Administration (Finding B); tenant switcher is shell-level, never per page.

### 3.2 Design system first — single source
Promote `xdr/nx/` to **the** system; fold `xdr/design/tokens.css` into
`nx-tokens.css`; migrate `*V2` components in; delete the second incident tree.
Required primitives before any screen work: app shell · rail · page header ·
breadcrumbs · type scale · spacing scale · **DataTable** · card/surface · tabs ·
status chip · badge · filter bar · search · command palette · dropdown/menu ·
form controls · dialog · **drawer/flyout (layered)** · entity link · timeline ·
graph · evidence panel · raw-event/code viewer · tooltip · toast · **empty ·
loading/skeleton · error · degraded** · light + dark. One concept, one
component, everywhere.

### 3.3 DataTable standard (single component, all operational pages)
search · multi-filter · sort · configurable + resizable columns · pagination ·
bulk select + bulk actions · saved views · severity/status chips · timestamp
with timezone basis · refresh · export where appropriate · row quick actions ·
drill-down to flyout · full keyboard access · dense-but-scannable.

### 3.4 Layered flyouts (preserve investigation context)
`Incident → endpoint flyout → process context → hash/IOC context`, each with an
explicit "open full entity page". Our own component; pattern validated by
Elastic's documented layered details flyouts.

### 3.5 Entities as first-class
`Device · User · Process · File · Hash · IP · Domain · URL · Detection ·
Incident · Evidence`, each with `Overview | Activity/Timeline | Detections |
Evidence | Relationships | Response` as applicable. `XdrEntity360Page` is the
seed — its `unavailable + reason` discipline becomes the platform rule.

### 3.6 Data Sources (operational questions first)
`Overview · Sources · Add Data Source · Collectors · Integrations · Coverage ·
Health · Verify`. Answers, in order: what is connected · is it healthy · when
did telemetry last arrive · how much · **is evidence complete** · what needs
attention. Engineering lifecycle (routing, parsers, normalization) moves under
**Details**, not top-level nav.
`Add Data Source` = catalog (`All | Connected | Available` × Endpoint ·
Network · Identity · Cloud · Email · SaaS · Threat Intel · Custom) → guided
wizard → **Verify**.

### 3.7 Verify Ingestion — the screen the benchmarks do not have
`acquisition → durability → transport → parsing → normalization → canonical
evidence → detection readiness`, each row bound to an authoritative field, each
able to read `PENDING | PASS | REFUSED | GAP | UNKNOWN`. Per `W2_CONTRACTS_FROZEN.md`
C-4/C-10: a confirmed collection gap renders **`HEALTHY · EVIDENCE INCOMPLETE`**,
never plain `Healthy`.

---

## 4 · BACKEND CONTRACTS THE UI REQUIRES (BUILD — do not wire until real)
per-stream counters · collection latency P50/P95/P99 · dedupe observability API
(`xdr_ingest_dedupe` has **no** read endpoint today) · COLLECTION_GAP records ·
rule-to-channel bindings · **measured** `parser_ok`/`normalized_ok` ·
collector queue/drop metrics. Until each exists the UI shows a truthful
unavailable state. **No fabricated number, chart, status, count, timestamp,
severity, verdict or response result may reach a production screen.**

## 5 · W2 SEPARATION (hard)
UI work must not destabilise W2-1. The UI may consume W2 contracts only once
authoritative, and **must not visually claim PowerShell / Security /
multi-channel capability before W2 proves it**.

## 6 · SLICE 1 (proposed, after blueprint approval)
1. Design-system consolidation (single tokens, single incident tree, rename
   vendor-named components) — no route changes.
2. Global shell + rail + global search + tenant switcher.
3. `Data Sources` end-to-end: Overview → Sources → Add → Collectors →
   Verify, absorbing the 8 fragmented surfaces.
Nothing else. Incidents, Investigation, Assets, Automate and Administration
follow slice by slice on the same system.

## 7 · ACCEPTANCE STANDARD (per slice)
BEFORE screenshots · REFERENCE public benchmark screenshot + the specific
interaction principle taken from it · AFTER screenshots at matching states,
including empty/loading/error/degraded and light/dark. Compare information
density · hierarchy · workflow steps · discoverability · interaction
consistency · table capability · navigation depth · **analyst click count** ·
state handling. Parity is not declared on appearance: every visible datum must
name its backend source.

## 8 · LIMITS OF THIS BLUEPRINT
Read-only static inventory. Route list is from `path="…"` declarations (62,
including 12 `/edr/*` and the catch-all). The `placeholder|TODO|mock` match set
(20 files) is a **to-audit list**, not a verdict. Classifications are proposals
for owner approval; no file has been moved, renamed, restyled or deleted.
