# NivXRay · Analyst Workspace · Architecture Blueprint

**Status**: DRAFT — pending review and approval
**Author**: Emergent (this document is a design proposal, NOT an implementation)
**Owner review required before**: any code, any file changes, any UI work
**Version**: 1.0 (proposal)
**Date**: 2026-08-04

> **NOTE**: This blueprint is a **reviewable document**. Implementation MUST NOT begin until this blueprint has been reviewed and approved by the project owner. This document becomes the governing reference for all future Workspace implementation.

---

## 1. Purpose

Define, in one place, the architecture, principles, personas, feature inventory, and success criteria for NivXRay's Analyst Workspace (Layer 4 in the Commercialization Architecture) so that all future product engineering has a single governing reference and cannot drift.

## 2. Scope

**In scope**
- The single unified Investigation Workspace surface analysts interact with
- The reads from the frozen L0 Deterministic Platform via L1 Evidence Services
- The composition of L2 Investigation Services outputs into L3 Presentation Cards
- Consolidation and rationalization of the 24 currently-existing pages into a coherent Workspace

**Out of scope for this blueprint**
- Any change to L0 (Convergence Engine, Transformation Registry, Certificate model, Corpus, Fingerprints)
- Any change to test files that currently guard L0
- Detection-rule generation logic, executive report content, integration adapters — those are separate P0 blueprints authored after this one is approved

---

## 3. Governing Design Principles (Permanent)

These principles govern **every** future Workspace decision. Any proposal that violates one of them requires explicit override with rationale.

| # | Principle | What it Means in Practice |
|---|---|---|
| P1 | **Investigation First** | Every screen answers a question an analyst is asking, not a data structure the backend has. |
| P2 | **Evidence First** | Every claim on screen is anchored to a piece of evidence with a click-through to the source. |
| P3 | **Progressive Disclosure** | Executive summary loads first. Details reveal on demand. Analyst never faces an empty wall of JSON. |
| P4 | **Context Preservation** | Drilling into a detail never loses the analyst's current investigation position. Back never blanks the workspace. |
| P5 | **Single Investigation Workspace** | One URL, one screen, one investigation. All cards live inside it. No sibling pages that do variations of the same thing. |
| P6 | **Zero Duplicate Pages** | If two pages do overlapping work, they merge or one is removed. Not both are kept. |
| P7 | **Zero Duplicate Workflows** | If two workflows lead to the same evidence, one is chosen as canonical. |
| P8 | **Analyst Efficiency over Visual Effects** | Motion, gradients, and animations must serve comprehension. No decoration for its own sake. |
| P9 | **Everything Explainable** | Every verdict, score, rule, and IOC exposes "why" via the Convergence Certificate + provenance chain. Nothing is a black box. |
| P10 | **Deterministic Investigation First** | AI or heuristics may narrate, never mutate. Every reproducible investigation must yield byte-identical results across runs. |

---

## 4. Analyst Personas

The Workspace serves **two personas simultaneously without duplication**.

### Persona A · Tier-1 Analyst (Triage)
- **Alert volume**: 50-500 alerts per shift
- **Decision speed**: seconds to a few minutes per alert
- **Primary need**: verdict, risk level, top 3 IOCs, top 3 recommended actions
- **Interaction budget**: ≤ 3 clicks from alert URL to actionable answer
- **What they must see first**: Executive Summary card, Verdict, Risk, "What do I do next?"

### Persona B · Tier-2/3 Analyst (Deep Investigation)
- **Alert volume**: 1-5 investigations per day, each 30 min - 4 hours
- **Decision speed**: deliberate; needs to be defensible
- **Primary need**: full evidence graph, timeline, transformation chain, capability matrix, correlation with other cases, exportable report
- **Interaction budget**: any depth of detail must be reachable without opening a new page
- **What they must see on demand**: Convergence Certificate, human_trace, per-transformation provenance, MITRE mapping, capability tags, related samples

### Design Consequence
- Tier-1 needs the summary; Tier-2/3 needs the depth. Both are served in the **same Workspace** through Progressive Disclosure (P3), not through separate pages.

---

## 5. Workspace Feature Inventory · Consolidation Plan

Every currently existing page is classified below. **Nothing is silently duplicated.**

| # | Existing Page | Decision | Merges Into | Reason |
|---|---|---|---|---|
| 1 | `AnalystWorkspacePage.jsx` | **KEEP as canonical base** | Investigation Workspace | Closest to target architecture. Becomes the single Workspace shell. |
| 2 | `AnalystRC5Page.jsx` | **MERGE** | Investigation Workspace | RC5-era iteration of the same idea. Best pieces absorbed as cards. |
| 3 | `AutoInvestigatePage.jsx` | **MERGE** | Investigation Workspace | Same intent (analyze payload). Becomes the "Auto-Investigate" default input mode. |
| 4 | `WorkspacePage.jsx` | **REMOVE (redirect)** | Investigation Workspace | Overlapping predecessor. Route redirects to new canonical Workspace. |
| 5 | `CommandAnalyzerPage.jsx` | **MERGE** | Investigation Workspace | Same intent. Absorbed as the "Command Analyzer" input tab. |
| 6 | `LabPage.jsx` | **KEEP (separate)** | Lab (developer surface) | Different persona — engineer/analyst power tools. Kept but explicitly labeled "Lab / Advanced," not shown in the analyst nav. |
| 7 | `DashboardPage.jsx` | **MODIFY** | Executive Dashboard | Repurpose as org-level Executive Dashboard (KPI Panel expanded). Not a per-investigation surface. |
| 8 | `MitreHeatmapPage.jsx` | **MODIFY** | MITRE Card inside Workspace + standalone Heatmap in Executive Dashboard | Data reused in two places, one implementation, two entry points. |
| 9 | `ThreatIntelPage.jsx` | **MODIFY** | IOC Intelligence card inside Workspace + standalone Feed page | Per-investigation view lives in Workspace; feed view is standalone. |
| 10 | `ThreatModelPage.jsx` | **KEEP (separate)** | Threat Modeling module | Different workflow, defer decision to later blueprint. |
| 11 | `BatchTestPage.jsx` | **KEEP (Lab)** | Lab / QA | Engineering utility. Not analyst-facing. Move under Lab. |
| 12 | `BenchmarkPage.jsx` | **KEEP (Lab)** | Lab / QA | Same as above. |
| 13 | `MultiLayerBatteryPage.jsx` | **KEEP (Lab)** | Lab / QA | Same as above. |
| 14 | `SampleLibraryPage.jsx` | **MODIFY** | Corpus Explorer (Lab) + Related-Samples card | Data reused in Workspace ("similar samples") + browseable corpus in Lab. |
| 15 | `KnowledgeBasePage.jsx` | **MERGE** | Documentation surface | Absorbed into the single Docs surface. |
| 16 | `DocsPage.jsx` | **KEEP as canonical Docs** | Docs | Public / external documentation surface. Kept. |
| 17 | `DocumentsPage.jsx` | **REMOVE (unless justified)** | — | Overlapping with Docs; audit content and remove if duplicate. |
| 18 | `LearnerPage.jsx` | **KEEP (Lab)** | Lab / Model surface | Model-training UI. Not analyst-facing. |
| 19 | `TrainingInboxPage.jsx` | **KEEP (Lab)** | Lab / Model surface | Same. |
| 20 | `ModelStudioPage.jsx` | **KEEP (Lab)** | Lab / Model surface | Same. |
| 21 | `SemanticMappingInspectorPage.jsx` | **KEEP (Lab)** | Lab / Model surface | Same. |
| 22 | `CorrectionsAdminPage.jsx` | **KEEP (Admin)** | Admin | Admin surface, not analyst. |
| 23 | `AdminPage.jsx` | **KEEP (Admin)** | Admin | Same. |
| 24 | `LoginPage.jsx` | **KEEP** | Auth | Auth surface. |

### Post-Consolidation Page Tree

```
/investigate                        Investigation Workspace (single surface)
/dashboard                          Executive Dashboard (org-level KPIs)
/threat-model                       Threat Modeling module
/docs                               Documentation
/lab                                Lab / Advanced (Batch, Benchmark, Corpus,
                                    Models, Semantic, Battery)
/admin                              Admin (Corrections, Ops)
/login                              Auth
```

**24 pages → 7 top-level routes. Zero duplicates. Every analyst workflow starts at `/investigate`.**

---

## 6. Success Definition · What "World-Class" Means

The Workspace succeeds when it hits the following measurable criteria:

| Metric | Target | Rationale |
|---|---|---|
| Max clicks from alert URL to verdict + risk | **≤ 2** | Tier-1 speed |
| Max navigation depth for any evidence element | **≤ 3 levels** | Prevents drilling loss (P4) |
| Time to first meaningful paint | **≤ 1.5 s** | Analyst attention window |
| Time to full investigation payload | **≤ 5 s** for a 10-iteration convergence | Depth analysts expect |
| Context-switch cost (leave & return) | **0** — state must persist across navigation | P4 |
| Duplicate workflows | **0** | P6 / P7 |
| Report generation clicks (PDF / STIX) | **≤ 1** | Executive report is a first-class output |
| Every visible claim links to evidence | **100%** | P2 / P9 |
| Verdict reproducibility across two runs | **byte-identical** | P10 |
| WCAG accessibility level | **AA** | Enterprise procurement |

---

## 7. Layered Architecture (Restated)

```
L4 · Analyst Workspace              [this blueprint's scope]
    ↑ reads
L3 · Presentation Services (Cards)  [this blueprint's scope]
    ↑ reads
L2 · Investigation Services         [read-only derivations of L1 evidence]
    ↑ reads
L1 · Evidence Services              [read APIs over L0 output]
    ↑ reads
L0 · Deterministic Platform         [FROZEN — no changes]
```

**Contract**: L4 never calls L0 directly. L3 never mutates L2. L2 never mutates L1. L1 never mutates L0.

---

## 8. Investigation Workspace Layout (proposed)

Single URL: `/investigate` (with optional `?case_id=…`).

```
┌────────────────────────────────────────────────────────────────────────┐
│  NivXRay  ·  Investigation Workspace                                   │
│  Input:  [ paste command line / drop file ]         [ Investigate → ]  │
├─────────────────────────┬──────────────────────────────────────────────┤
│                         │                                              │
│   EXECUTIVE SUMMARY     │  ATTACK STORY                                │
│   • Verdict             │  1 · PowerShell launched                     │
│   • Risk (Critical)     │  2 · Downloaded from c2.evil.local           │
│   • Confidence          │  3 · Decoded Base64 payload                  │
│   • Top 3 IOCs          │  4 · Contacted C2 · likely staging …         │
│   • Recommended Actions │                                              │
│                         │                                              │
├─────────────────────────┴──────────────────────────────────────────────┤
│                                                                        │
│   [ Timeline ]  [ MITRE ]  [ IOCs ]  [ Capabilities ]                  │
│   [ Detection Rules ]  [ Hunting Queries ]  [ Certificate ]  [ Raw ]   │
│                                                                        │
│   (Active card content renders below with progressive disclosure)      │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│  Export:  [ PDF ]  [ DOCX ]  [ STIX ]  [ Sigma ]  [ KQL ]  [ IOCs ]    │
└────────────────────────────────────────────────────────────────────────┘
```

**Notes**
- Executive Summary + Attack Story are **always visible** (Tier-1 satisfied in ≤ 2 clicks).
- All other cards are **tabbed** below the fold (Tier-2/3 progressive disclosure).
- Export bar is persistent; single-click generates deterministic reports.
- Raw Decode is the **last** tab — matching modern EDR UX (P1: Investigation First).

---

## 9. Card Inventory · L3 Presentation Services

| Card | Reads from | Persona Primary | State |
|---|---|---|---|
| Executive Summary | `executive_summary.py` | Tier-1 | New |
| Attack Story | `attack_story.py` | Both | New |
| Investigation Timeline | `timeline_builder.py` | Both | New |
| MITRE Navigator | `capability_explorer.py` (MITRE facet) | Both | Reuse existing MITRE data |
| IOC Intelligence | `ioc_intelligence.py` | Both | New (data exists, no UI) |
| Capability Matrix | `capability_explorer.py` | Tier-2/3 | New |
| Detection Rules | `detection_rules.py` | Tier-2/3 | New (P0 #3 blueprint) |
| Hunting Queries | `hunting_queries.py` | Tier-2/3 | New (P0 #3 blueprint) |
| Convergence Certificate Viewer | L1 direct | Tier-2/3 | New wrapper around existing `/api/decode/certificate` |
| Raw Decode / Human Trace | L1 direct | Tier-2/3 | New wrapper |

**Every card is a read-only projection.** No card writes to L0/L1.

---

## 10. Data Contract · Evidence Service Reads (L1)

Every Workspace card consumes a stable read API. Proposed L1 surface:

- `GET /api/investigation/:case_id` — bundle (Convergence output + all derived L2 artifacts) in a single call
- `GET /api/investigation/:case_id/certificate` — raw Convergence Certificate
- `GET /api/investigation/:case_id/story` — Attack Story only
- `GET /api/investigation/:case_id/iocs` — IOC intelligence only
- `GET /api/investigation/:case_id/capabilities` — capability projection
- `GET /api/investigation/:case_id/mitre` — MITRE mapping
- `GET /api/investigation/:case_id/detections` — Sigma/KQL/Splunk (from P0 #3 work)
- `GET /api/investigation/:case_id/report.pdf` — Executive Report (from P0 #2 work)
- `GET /api/investigation/:case_id/stix` — STIX 2.1 bundle

All endpoints return deterministic outputs. Idempotent. Cache-friendly.

---

## 11. Risks & Explicit Non-Goals

**Risks**
- R1 · Consolidating 24 pages will surface hidden dependencies. Mitigation: feature inventory (§5) already lists every page and its disposition. Each removal is a separate reviewable PR.
- R2 · Analyst muscle memory. Mitigation: 30-day redirect from old routes to `/investigate` with a banner: *"You've been redirected — this is now your Investigation Workspace."*
- R3 · Progressive disclosure may hide critical evidence from Tier-1 by mistake. Mitigation: Executive Summary card exposes top 3 IOCs + top 3 recommendations by default; nothing critical is behind a tab.

**Explicit Non-Goals for this blueprint**
- No AI/LLM copilot in v1.0 (deferred to a separate blueprint after L4 is stable)
- No multi-user collaboration in v1.0 (single-analyst view first)
- No customization/theming in v1.0 (one canonical UI)

---

## 12. Approval Gate

Implementation **MUST NOT** begin until the project owner has explicitly approved this blueprint.

**Blueprint review checklist** (project owner to confirm):
- [ ] Design principles (§3) are correct and permanent
- [ ] Personas (§4) match the intended market
- [ ] Feature inventory decisions (§5) are all correct — no duplicates missed, no useful surface removed
- [ ] Success metrics (§6) are the right ones to be measured against
- [ ] Layered architecture (§7) matches the frozen L0 contract
- [ ] Workspace layout (§8) is the right analyst experience
- [ ] Card inventory (§9) covers everything analysts need in v1.0
- [ ] Data contract (§10) is stable enough for future P0 items (Reports, Detections, Integrations) to build on
- [ ] Risks (§11) are acceptable

Once approved, this document becomes the governing reference. All future L4 work is measured against it. Deviations require an amendment to this blueprint, not a code shortcut.

---

## 13. What Happens Next

**Pending owner approval, in this order:**

1. Owner reviews §3-§11 and approves or requests amendments.
2. Once approved, this blueprint version is locked and stored at `/app/memory/ANALYST_WORKSPACE_BLUEPRINT.md`.
3. Implementation proceeds in tightly scoped, reviewable PRs:
   - PR-1: L2 Investigation Services scaffolding (backend only, no UI)
   - PR-2: L1 read API (`/api/investigation/*`)
   - PR-3: L4 shell (`/investigate` route, layout skeleton)
   - PR-4: Executive Summary + Attack Story cards
   - PR-5: MITRE + IOC + Capability cards
   - PR-6: Certificate + Raw Decode cards
   - PR-7: Page consolidations & route redirects (per §5 inventory)
   - PR-8: Export bar wiring (defers actual PDF/STIX to P0 #2 blueprint)

Each PR carries: passing 438+ existing tests, byte-identical M8 corpus, byte-identical R1 corpus, no L0 changes.

---

**End of blueprint · awaiting owner review**
