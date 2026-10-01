# NivXRay · Analyst Workspace · Architecture Blueprint

**Status**: DRAFT v1.1 — ARB conditional approval received; 9 amendments applied
**Implementation authorization**: NOT GRANTED (pending PR-0 sign-off)
**Companion document**: `WORKSPACE_USER_JOURNEY.md` (required before code)
**Version**: 1.1 (amended per ARB review)
**Date**: 2026-08-04

---

## Amendment Log (v1.0 → v1.1)

| # | ARB Requirement | Where Addressed |
|---|---|---|
| A1 | Justify every §5 decision (purpose · usage · overlap · migration · risk) | §5 rewritten with 5-column rationale table |
| A2 | Investigation-first §8 layout (not dashboard-first) | §8 fully reworked |
| A3 | Investigation State model | New §8.1 |
| A4 | Explicit Workspace Modes (Quick Triage · Investigation · Deep Analysis) | New §8.2 |
| A5 | Strengthened persistence requirements | New §8.3 |
| A6 | Evidence Navigation (every object clickable to source) | New §8.4 |
| A7 | `/api/investigation/:case_id/workspace` state endpoint | §10 amended |
| A8 | PR-0 Architecture Validation before any code | §13 amended |
| A9 | `WORKSPACE_USER_JOURNEY.md` companion required before implementation | See separate file |

---

## §1-2 · Purpose & Scope · ✅ ARB Approved (unchanged)

Define the architecture, principles, personas, feature inventory, and success criteria for NivXRay's Analyst Workspace (Layer 4) so all future product engineering has a single governing reference. Out of scope: any L0 change, any test-file change, any per-workflow blueprint (Reports, Detections, Integrations get their own).

## §3 · Design Principles · ✅ (v1.0 list retained · ARB approved)

P1 Investigation First · P2 Evidence First · P3 Progressive Disclosure · P4 Context Preservation · P5 Single Investigation Workspace · P6 Zero Duplicate Pages · P7 Zero Duplicate Workflows · P8 Analyst Efficiency over Visual Effects · P9 Everything Explainable · P10 Deterministic Investigation First.

## §4 · Analyst Personas · ✅ (retained with mode-mapping clarification)

**Persona A · Tier-1 Analyst (Triage)** — 50-500 alerts/shift · ≤ 3 clicks · verdict, risk, top 3 IOCs, top 3 actions. Enters Workspace in **Quick Triage Mode** (see §8.2).

**Persona B · Tier-2/3 Analyst (Deep Investigation)** — 1-5 investigations/day · full evidence graph · exportable report. Enters Workspace in **Investigation Mode** or **Deep Analysis Mode** (see §8.2).

Both personas use the **same Workspace**. Different modes, not different pages.

---

## §5 · Workspace Feature Inventory · Amendment A1

Every existing page classified with full ARB-required rationale.

**Legend**: Purpose = what the page currently does · Usage = observed analyst use · Overlap = which pages it duplicates · Migration = where it goes · Risk = what breaks if we get this wrong.

### Investigation Surfaces (5 pages → 1 canonical Workspace)

| Page | Purpose | Usage | Overlap | Migration | Risk |
|---|---|---|---|---|---|
| **AnalystWorkspacePage** | Full investigation view with evidence, MITRE, Cert | Presumed primary analyst surface | Overlaps with WorkspacePage (~70%), AutoInvestigate (~60%), CommandAnalyzer (~50%), AnalystRC5 (~80%) | **KEEP as canonical `/investigate` shell** | Low — this is already the closest to target |
| **AnalystRC5Page** | RC5-era iteration of Analyst Workspace | Legacy iteration | 80% overlap with AnalystWorkspacePage | **MERGE** — port any unique RC5 evidence panels into canonical Workspace as cards, then remove page | Medium — must audit RC5 for evidence surfaces not present in AnalystWorkspacePage before removing |
| **AutoInvestigatePage** | Paste-and-analyze single command | High — natural entry point | 60% overlap (same evidence output, different input) | **MERGE** as "Auto-Investigate" **input mode** at top of Workspace | Low — input surface only, no evidence data loss |
| **CommandAnalyzerPage** | Command-line specific analyzer | Similar to AutoInvestigate | Overlaps with AutoInvestigate + AnalystWorkspace | **MERGE** as "Command Analyzer" **input tab** at top of Workspace | Low — unified input surface |
| **WorkspacePage** | Original workspace predecessor | Legacy — presumed superseded | 70% overlap with AnalystWorkspacePage | **REMOVE** with 30-day redirect to `/investigate` + banner | Medium — must audit for unique panels; anything unique becomes an issue |

### Executive & Discovery Surfaces (3 pages → repurposed)

| Page | Purpose | Usage | Overlap | Migration | Risk |
|---|---|---|---|---|---|
| **DashboardPage** | Org KPI landing | SOC-manager-level | No overlap with Investigation | **MODIFY** into **Executive Dashboard** (`/dashboard`) — expand with KPI Panel from Coverage Dashboard | Low |
| **MitreHeatmapPage** | Cross-corpus MITRE view | SOC-manager + investigation drill | Overlap with per-investigation MITRE data | **MODIFY** — one implementation, two entry points: MITRE card inside `/investigate` + heatmap in `/dashboard` | Low |
| **ThreatIntelPage** | External IOC intel feed | Analyst + SOC-manager | Overlap with per-investigation IOC surface | **MODIFY** — IOC card inside `/investigate` reuses feed data; standalone feed page at `/threat-intel` retained | Low |

### Content & Knowledge Surfaces (3 pages → 1)

| Page | Purpose | Usage | Overlap | Migration | Risk |
|---|---|---|---|---|---|
| **DocsPage** | Public documentation | External + internal | Overlaps with KnowledgeBase + Documents | **KEEP as canonical `/docs`** | Low |
| **KnowledgeBasePage** | Internal KB articles | Analyst reference | ~60% overlap with Docs | **MERGE** into `/docs` under a "Knowledge Base" section | Low — content additive |
| **DocumentsPage** | Uploaded docs surface | Presumed low usage | Likely overlaps with DocsPage | **AUDIT then REMOVE if duplicate** — decision deferred until content audit | Medium — audit required |

### Lab / Engineering Surfaces (7 pages → `/lab` container)

| Page | Purpose | Usage | Overlap | Migration | Risk |
|---|---|---|---|---|---|
| **LabPage** | Advanced analyst / engineer surface | Engineer-facing | Distinct from analyst flow | **KEEP under `/lab`** (container page for advanced tooling) | Low |
| **BatchTestPage** | Batch corpus test runs | Engineering QA | None (analyst-side) | **MOVE under `/lab/batch-test`** | Low |
| **BenchmarkPage** | Perf benchmark harness | Engineering QA | None | **MOVE under `/lab/benchmark`** | Low |
| **MultiLayerBatteryPage** | Layered decode stress runs | Engineering QA | None | **MOVE under `/lab/battery`** | Low |
| **SampleLibraryPage** | Corpus sample browser | Both analyst-adjacent + engineering | Data reused in "Related Samples" card | **MODIFY** — corpus browser lives at `/lab/corpus`; "related samples" reuses same data as a card in `/investigate` | Low |
| **SemanticMappingInspectorPage** | Semantic map debugger | Engineering | None (analyst-side) | **MOVE under `/lab/semantic`** | Low |
| **LearnerPage** | Model training UI | Engineering | Overlap with ModelStudio + TrainingInbox | **MOVE under `/lab/models`** | Medium — three overlapping model surfaces need internal audit; deferred to post-consolidation model-surface blueprint |
| **ModelStudioPage** | Model management UI | Engineering | Overlap with Learner | **MOVE under `/lab/models`** | Medium (same) |
| **TrainingInboxPage** | Training feedback queue | Engineering | Overlap with Learner | **MOVE under `/lab/models`** | Medium (same) |

### Admin & Auth (3 pages → 2 top-level routes)

| Page | Purpose | Usage | Overlap | Migration | Risk |
|---|---|---|---|---|---|
| **AdminPage** | Admin operations | Admin-only | None | **KEEP at `/admin`** | Low |
| **CorrectionsAdminPage** | Analyst-correction review | Admin | Related to Admin | **KEEP under `/admin/corrections`** | Low |
| **LoginPage** | Auth | All | None | **KEEP at `/login`** | Low |

### Standalone Modules (2 pages → 1 route)

| Page | Purpose | Usage | Overlap | Migration | Risk |
|---|---|---|---|---|---|
| **ThreatModelPage** | Threat modeling workflow | Distinct workflow | None | **KEEP at `/threat-model`** — decision deferred to separate blueprint | Low |

### Post-Consolidation Route Map

```
/investigate       Investigation Workspace (Persona A + B, all modes)
/dashboard         Executive Dashboard (org KPIs · MITRE heatmap)
/threat-intel      Standalone threat-intel feed
/threat-model      Threat Modeling module
/docs              Documentation + Knowledge Base
/lab               Advanced engineer surface (batch, benchmark, battery, corpus, semantic, models)
/admin             Admin + Corrections
/login             Auth
```

**Result**: 24 pages → **8 top-level routes** (revised from 7 to keep `/threat-intel` as a standalone feed distinct from the per-investigation IOC card, since ARB required more precise separation).

---

## §6 · Success Definition · ✅ (v1.0 metrics retained · ARB approved with amendments)

All v1.0 metrics stand. **New metrics added per ARB Amendment A5**:

| Metric | Target |
|---|---|
| Workspace state restoration on return (scroll + cards + evidence + filters + timeline) | 100% |
| Mode switching (Quick Triage ↔ Investigation ↔ Deep Analysis) within same case | 0 page reloads · 0 data refetches |
| Every visible IOC / capability / MITRE / transformation clickable to source evidence | 100% |
| Investigation state transitions (New → … → Reported) captured deterministically | 100% |

---

## §7 · Layered Architecture · ✅ ARB Approved (unchanged)

L4 Analyst Workspace ← L3 Presentation Services ← L2 Investigation Services ← L1 Evidence Services ← L0 Deterministic Platform (FROZEN). Every layer reads downward only.

---

## §8 · Investigation Workspace Layout · Amendment A2

**Reframe**: the Investigation itself is the centerpiece — not a summary dashboard. Summary is one *lens* on the investigation; Evidence, Timeline, Story, Analysis, and Exports are peer lenses.

### New Layout · Investigation-First

```
┌──────────────────────────────────────────────────────────────────────────┐
│  NivXRay ·  Case #CS-2026-08-04-0001                                      │
│  Mode:  [ Quick Triage | Investigation | Deep Analysis ]      State: ●   │
│         (Active mode highlighted; state pill: New → Collecting → …)      │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                       ▼   THE INVESTIGATION   ▼                          │
│                                                                          │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │  Input:  [ paste command / drop file / upload alert ]            │   │
│   │                                          [ Investigate → ]        │   │
│   └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│   [ Summary ]  [ Story ]  [ Timeline ]  [ Evidence ]  [ Analysis ]      │
│   [ Exports ]                                                            │
│   ─────────────────────────────────────────────────────────────────      │
│                                                                          │
│   (Active lens renders here · progressive disclosure inside each lens)   │
│                                                                          │
│   Every element is clickable → drills into Evidence lens with source     │
│   highlighted (Amendment A6).                                            │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  Persist: scroll · open lens · selected evidence · filters · timeline    │
│  position — restored on return (Amendment A5).                           │
└──────────────────────────────────────────────────────────────────────────┘
```

**Six top-level Lenses (not "cards"):**

1. **Summary** — Executive verdict, risk, top 3 IOCs, top 3 actions (Tier-1 satisfied here)
2. **Story** — Ordered Attack Story derived from evidence graph
3. **Timeline** — Chronological transformation + evidence timeline
4. **Evidence** — The investigation's source-of-truth: Certificate + human_trace + IOC + MITRE + Capability all cross-linked
5. **Analysis** — Detection Rules + Hunting Queries + Threat Assessment (Tier-2/3)
6. **Exports** — PDF / DOCX / STIX / Sigma / KQL / IOCs

**Default lens** varies by Mode (see §8.2). Every lens can drill into Evidence (§8.4).

---

### §8.1 · Investigation State Model · Amendment A3

Every case carries an explicit state. Deterministically transitioned; never derived from UI.

```
New → Collecting → Correlating → Reviewing → Completed → Reported
                                       ↓
                                   Reopened → Correlating (re-enters loop)
```

| State | Meaning | Enters When | Exits When |
|---|---|---|---|
| **New** | Case created, no input yet | Case ID minted | Input submitted |
| **Collecting** | Input received, engine running | Investigate clicked | Convergence Certificate emitted |
| **Correlating** | L2 Investigation Services deriving | Certificate emitted | All L2 services returned |
| **Reviewing** | Analyst is actively working | Analyst opens Workspace | Analyst marks Completed |
| **Completed** | Investigation finalized | Analyst confirms | Report exported |
| **Reported** | Report generated + exported | Export triggered | Reopen action |
| **Reopened** | Case reopened for further work | Reopen action | Re-enters Correlating |

State is stored, resumable, and displayed as a persistent pill on the Workspace header.

---

### §8.2 · Workspace Modes · Amendment A4

Three modes. **Same Workspace. Same evidence. Different depth.** Modes never create separate pages.

| Mode | Default Lens | Progressive Disclosure Cap | Persona |
|---|---|---|---|
| **Quick Triage** | Summary | Story teaser only; other lenses collapsed | Tier-1 |
| **Investigation** | Summary + Story + Timeline visible; Evidence & Analysis on-demand | Full evidence reachable in ≤ 1 click | Tier-1 → Tier-2 transition |
| **Deep Analysis** | Evidence lens open by default with human_trace expanded; all lenses accessible | No caps — every layer navigable | Tier-2/3 |

Mode is chosen at case entry (via alert-source hint or analyst preference) and can be switched at any time **without a page reload or data refetch**.

---

### §8.3 · Workspace Persistence Requirements · Amendment A5

Persistence contract for every Workspace instance:

- Scroll position of the active lens
- Which lens is open
- Which evidence element is currently selected / highlighted
- Any filters applied (e.g. show-only-decoded-layers, hide-noise, MITRE filter)
- Timeline slider position (for time-scrubbed evidence review)
- Mode (Quick Triage / Investigation / Deep Analysis)
- Investigation state (from §8.1)

All persisted server-side as **Workspace State** (see §10 endpoint). Restored on any return to the same `case_id`. Deterministic — two returns produce byte-identical restored state.

---

### §8.4 · Evidence Navigation Contract · Amendment A6

Every clickable object in the Workspace must resolve to a source in the deterministic evidence chain. This is non-negotiable — it's how the Convergence Certificate becomes a **live, navigable investigation surface**.

| Clicked Object | Drills Into | Ultimate Source |
|---|---|---|
| IOC (URL/IP/hash) | Evidence lens · highlighted IOC panel | Convergence output substring · L0 canonical output |
| Capability tag | Evidence lens · capability provenance panel | Sample metadata + transformation registry |
| MITRE technique | Evidence lens · MITRE panel | Capability tag → MITRE mapping (registry) |
| Transformation name (in Story/Timeline) | Certificate lens · transformation row highlighted | Convergence Certificate iteration record |
| Iteration in timeline | Certificate lens · iteration expanded | Convergence Certificate iterations[n] |
| Detection rule | Analysis lens · rule with evidence-anchor list | Rule generator inputs (evidence + registry) |
| Hunting query | Analysis lens · query with evidence-anchor list | Query generator inputs (evidence + registry) |
| Executive Summary bullet | Story lens · originating story event | Story event → evidence anchor |

**Rule**: no dead ends. Every UI element is either evidence itself or one click away from evidence.

---

## §9 · Card / Lens Inventory · ✅ (renamed cards → lenses; content retained)

Six top-level lenses (Summary · Story · Timeline · Evidence · Analysis · Exports). Sub-panels inside each lens are drawn from L2 Investigation Services. No panel modifies evidence.

---

## §10 · Data Contract · Amendment A7

Existing endpoints from v1.0 retained. **New endpoint added**:

- `GET  /api/investigation/:case_id/workspace` — returns Workspace State (§8.3): mode, current lens, scroll, selected evidence, filters, timeline position, investigation state (§8.1)
- `PUT  /api/investigation/:case_id/workspace` — persists Workspace State (idempotent · analyst client emits on lens/mode/filter change)
- `POST /api/investigation/:case_id/state/transition` — moves case through §8.1 state machine (New → Collecting → …); transitions are validated server-side and audit-logged

All L1 endpoints remain deterministic, idempotent, cache-friendly. State transitions are audit-logged with actor + timestamp for compliance.

---

## §11 · Risks & Non-Goals · ✅ ARB Approved (unchanged)

R1 hidden dependencies · R2 muscle memory · R3 disclosure hiding critical evidence. Non-goals: no AI copilot, no multi-user collaboration, no theming.

---

## §12 · Approval Gate · ✅ Retained · updated checklist

Implementation MUST NOT begin until:

- [ ] All 9 amendments (A1-A9) reviewed and confirmed by ARB
- [ ] Companion `WORKSPACE_USER_JOURNEY.md` reviewed and approved
- [ ] PR-0 (§13) confirms blueprint + journey + evidence-navigation contract + persistence contract + state machine

---

## §13 · Post-Approval Plan · Amendment A8

**PR-0 · Architecture Validation (no code)**
- Blueprint v1.1 approved by ARB
- `WORKSPACE_USER_JOURNEY.md` approved by ARB
- Feature Inventory (§5) decisions signed off
- Evidence Navigation Contract (§8.4) signed off
- Persistence Contract (§8.3) signed off
- State Machine (§8.1) signed off
- Data Contract (§10) signed off

**Only after PR-0 sign-off**:

1. **PR-1** · L2 Investigation Services scaffolding (backend only, no UI)
2. **PR-2** · L1 read APIs (`/api/investigation/*` including workspace-state endpoints)
3. **PR-3** · L4 `/investigate` shell + State Model + Mode selector (empty lenses)
4. **PR-4** · Summary + Story lenses
5. **PR-5** · Timeline + Evidence lenses (Evidence Navigation Contract goes live here)
6. **PR-6** · Analysis + Exports lenses
7. **PR-7** · Page consolidations & route redirects per §5
8. **PR-8** · Persistence server-side + client-side wiring (§8.3)

Each PR: all 438+ tests pass · M8 corpus byte-identical · R1 corpus byte-identical · zero L0 changes.

---

**End of Blueprint v1.1 · Awaiting ARB Re-Review**
