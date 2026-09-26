# NivXRay → NivXRay XDR · Capability-Gap Audit

**Status:** 2026-02-10 · evidence-backed inspection of `/app/backend` and `/app/frontend`
**Scope:** All 10 audit areas requested by the owner directive
**Result classifications:** ADOPT · CONSUME · ADAPT · EXTEND · REBUILD · NEW · NOT_PRESENT

The audit is deliberately terse — every row cites the concrete backend
path so the anti-hallucination CI gate can verify the claim.  Zero
speculation, zero invented capabilities.

---

## §1 · End-to-End Investigation Workspace (UX)

Base NivXRay ships **~30 native workspace pages** in `/app/frontend/src/pages/`:

| Base page | Purpose | XDR status |
| --- | --- | --- |
| `AnalystWorkspacePage.jsx`         | Central workspace surface | **ADAPT** — XDR ships `XdrIncidentDetailPage` + `EvidenceFirstInvestigationWorkspace`; UX depth partial |
| `EvidenceExplorerPage.jsx`         | Evidence datalake browser | **NOT_PRESENT in XDR** — needs adapter |
| `InvestigationDetailPage.jsx`      | Investigation SSOT view | **CONSUMED** (`/api/incidents/:id/summary`) |
| `InvestigationSessionPage.jsx`     | Multi-input session workspace | **NOT_PRESENT in XDR** |
| `IEDDETracePage.jsx`               | Live IEDDE stage trace | **CONNECTED (this session)** — `XdrIeddeStagePanel` |
| `CommandAnalyzerPage.jsx`          | Command intelligence surface | **NOT_PRESENT in XDR** — Slice 14 backlog |
| `DeviceTrajectoryPage.jsx`         | 3-pane trajectory canvas | **CONNECTED** — Slice 6 native XDR canvas |
| `MitreHeatmapPage.jsx`             | MITRE heatmap | **CONNECTED** (`/xdr/intelligence/mitre`) |
| `BatchTestPage.jsx`, `BenchmarkPage.jsx`, `MultiLayerBatteryPage.jsx` | Analyst regression harnesses | **NOT_PRESENT in XDR** — see §§ 3-4 |
| `CorrectionsAdminPage.jsx`         | Analyst correction lifecycle | **NOT_PRESENT in XDR** — needed for tuning §§ 4-6 |
| `HistoryPage.jsx`                  | Investigation history | **NOT_PRESENT in XDR** |
| `SampleLibraryPage.jsx`, `LabPage.jsx` | Sample + corpus workbench | **NOT_PRESENT in XDR** — see § 2 |
| `AutoInvestigatePage.jsx`          | Auto-investigation | **NOT_PRESENT in XDR** |
| `ComparePage.jsx`                  | Investigation diff | **NOT_PRESENT in XDR** |

### XDR workspace pieces that DO exist today (verified)
- Investigation Canvas (SVG · semantic edges · minimap · clusters)
- Evidence-First Workspace container (node types, inspector, pivot menu)
- Synchronized Timeline (Canvas ↔ Timeline ↔ Attack Story ↔ Inspector ↔ MITRE)
- Verdict Panel (Stage-2 consumer)
- Investigation Report Panel (`/api/incidents/:id/summary` consumer)
- DIE / IEDDE / IUE / UAIE panels (this session)
- Recommendations Panel (this session — deterministic, evidence-driven)
- Response Drawer + Approvals Queue + Evidence Ref page
- MITRE Heatmap (native)
- Detection Rules catalog + Sigma authoring
- Playbooks Designer + Automation Rules
- Admin › Engines (this session — data-driven inventory)

### Gap classification (Workspace)
| Item | Classification | Notes |
| --- | --- | --- |
| Evidence Explorer               | **NEW (XDR)**  | Consume `/api/analyze`, `/api/incidents`, IKG |
| Command Intelligence native page| **ADAPT**       | Slice 14 backlog · consume DIE + `/api/analyze` |
| Global search across incidents  | **NEW (XDR)**  | Existing base has cross-index; not surfaced in XDR |
| Case notes + attachments        | **NEW (XDR)**  | Slice 15 backlog |
| Related incidents / campaigns   | **CONSUME**    | Base `/api/correlations/find-related` |
| Selection sync across ALL panels| **EXTEND**     | Canvas + Timeline + Inspector are synced today; DIE/IEDDE/IUE/UAIE panels are NOT yet in the sync bus |
| Continuous investigation loop   | **NEW (XDR)**  | Requires an event bus; today panels are independent |

### Recommendation
Ship a **`WorkspaceSelectionContext`** provider that every panel subscribes to.
When any panel selects an entity (process / IOC / rule / technique) the
context emits `{ kind, ref, source }`; every other panel refetches or
filters based on it.  DIE / IEDDE / IUE / UAIE panels currently
receive `incident` only — extend to receive `selection`.  This is the
one architectural change that turns "collection of panels" into "one
investigation operating system".

---

## §2 · NivXRay Corpus + Golden-Corpus Architecture

Base ships **six** golden-corpus modules under `engine/`:

| File | Purpose |
| --- | --- |
| `engine/golden_corpus.py`                       | Primary corpus (fingerprints + expected results) |
| `engine/golden_corpus_categories.py`            | Category taxonomy |
| `engine/golden_corpus_expansion.py`             | Expansion / new sample onboarding |
| `engine/golden_corpus_expansion_r2.py`          | Second expansion generation |
| `engine/golden_corpus_obfuscation_family.py`    | Obfuscation-family samples |
| `engine/golden_corpus_taxonomy.py`              | Taxonomy definitions |

Plus a physical corpus directory: `/app/backend/corpus/manifest.json`
+ `reports/` + `vendor/` (vendor evidence samples).

### Base API surface (verified)
- `POST /api/corpus/validate/json`
- `GET  /api/corpus/validate/example`
- `POST /api/regression/run`
- `GET  /api/regression/{latest,history,gate}`
- `GET  /api/regression/corpus/entries`, `POST /api/regression/corpus/entries`
- `POST /api/batch/test/json`, `GET /api/batch/history{,/{id}}`, `POST /api/batch/evaluate/nxgec`
- `POST /api/batch/test/mine`, `POST /api/batch/test/mine/preview`

### Classification (Corpus)
| Capability | Classification | Notes |
| --- | --- | --- |
| Base golden corpus                          | **ADOPT / CONSUME** | Via `/api/regression/*` + `/api/corpus/validate` |
| Vendor evidence samples                     | **ADOPT / CONSUME** | Via `/api/batch/evaluate/nxgec` |
| Regression gate                             | **ADOPT / CONSUME** | `/api/regression/gate` — go/no-go for rule promotion |
| Investigation-scenario corpus (§3 concept)  | **NEW (XDR)**       | Base corpus is per-input; scenario-level corpus is XDR-specific |
| Negative / contradictory-evidence corpus    | **EXTEND**          | Base has some; need `benign/ambiguous/false_positive/incomplete/conflicting` categories added |
| Corpus-driven recommendation tests          | **NEW (XDR)**       | No base equivalent — this is what the tuning workbenches need |
| Playbook regression corpus                  | **NEW (XDR)**       | XDR owns the Response Engine + playbooks |

### Recommendation
1. Build an XDR **`corpus/scenarios/*.json`** directory containing
   full investigation scenarios (raw evidence → expected entities →
   expected rule matches → expected verdict → expected recommendations
   → expected playbook → expected response outcome).
2. Every XDR release runs the scenarios against:
   (a) base `/api/regression/run` for engine-side truth,
   (b) local `computeRecommendations()` for XDR-side truth,
   (c) Response Engine simulator for playbook truth.
3. Gate on **all three** — if either side regresses, the build fails.
4. Ship scenarios in the **required categories**: benign · suspicious ·
   ambiguous · malicious · false-positive · incomplete-evidence ·
   conflicting-evidence · unknown.
5. Explicit **NOT_PRESENT** in base: an "investigation-scenario"
   schema.  This is XDR-owned. Do not reinvent the sample-level
   golden corpus.

---

## §3 · Corpus Replay + Regression

Base API is complete:
- `/api/regression/run`, `/api/regression/gate`, `/api/regression/history`
- `/api/batch/test/json` with mine-preview + mine-write.

### Classification
| Capability | Classification |
| --- | --- |
| Historical event replay for a rule change   | **CONSUME** (`/api/batch/test/json` + `/api/regression/run`) |
| Golden-corpus regression before rule promotion | **CONSUME** (`/api/regression/gate`) |
| Scenario-level replay (rule + verdict + recommendation + playbook) | **NEW (XDR)** — orchestrates the three consumers |
| Impact preview UI (before/after)            | **NEW (XDR)** — reads results of the above |
| Version diff visualisation                  | **NEW (XDR)** |

### Recommendation
An **`XdrReplayEngine.js`** shared library that composes:
1. `RegressionConsumer.run({ rule_id, changes })`
2. `BatchTestConsumer.test({ scope, rule_id, changes })`
3. `computeRecommendations(scenario)` locally
4. `simulatePlaybook(playbook_id, scenario)` on the Response Engine
And returns `{ before, after, delta }` for the tuning workbenches.

---

## §4 · Detection Rule Tuning

Existing base primitives:
- `POST /api/regression/corpus/entries` — add TP/FP entries
- `POST /api/regression/run` — evidence-backed replay
- `GET  /api/regression/gate` — go/no-go
- `POST /api/corrections` + approve/reject/rollback — analyst correction lifecycle
- `POST /api/batch/test/json` — batch replay

Existing XDR primitives (this repo):
- `src/xdr/detect/sigmaEngine.js` — deterministic Sigma evaluator
- `src/xdr/detect/detectionRuleStore.js` — lifecycle + version history
- `/xdr/detections`, `/xdr/detections/:id` — catalog + editor

### Classification
| Capability | Classification | Notes |
| --- | --- | --- |
| Rule editor (Sigma YAML)                | **CONNECTED** | `/xdr/detections/:id` |
| Rule lifecycle + version history        | **CONNECTED** | `detectionRuleStore.js` |
| Rule metrics (matches / TP / FP / precision) | **CONSUME**   | `/api/regression/latest` + corrections analytics |
| Rule replay against last 24h / 7d / incident | **CONSUME** | `/api/batch/test/json` |
| Rule replay against golden corpus       | **CONSUME**   | `/api/regression/run` |
| Impact preview (matches before/after)   | **NEW (XDR)** | Compose regression + batch results |
| Rollback                                | **CONSUME**   | `/api/corrections/{id}/rollback` |
| Rule tuning workbench UI                | **NEW (XDR)** | Not yet built |

### Recommendation
Ship `/xdr/detect/tuning/:ruleId` — Rule Tuning Workbench that reads
all four base surfaces and shows **INSUFFICIENT TELEMETRY FOR METRIC**
when base returns no data.  Never fabricate percentages.

---

## §5 · Playbook Tuning

Existing XDR primitives:
- `playbookStore.js` — lifecycle + versions
- `simulatePlaybook(payload)` — Response Engine dry-run
- Response Engine execution store (SQLite) — real executions

### Classification
| Capability | Classification | Notes |
| --- | --- | --- |
| Playbook designer                       | **CONNECTED** | `/xdr/respond/playbooks/:id` |
| Playbook lifecycle + versions           | **CONNECTED** | `playbookStore.js` |
| Playbook simulation                     | **CONNECTED** | `/api/respond/simulate-playbook` |
| Execution metrics (success / failure / rejection) | **CONSUME** | Response Engine `GET /api/respond/executions?playbook_id=` — **NOT_PRESENT in engine today** → EXTEND |
| Impact preview                          | **NEW (XDR)** | Compare simulator trace v1 vs v2 |
| Approval-reject metrics                 | **CONSUME**   | Response Engine already tracks approvals |
| Target-resolution failure metrics       | **EXTEND**    | Engine records `unresolved_target 422` but doesn't aggregate |
| Playbook regression corpus              | **NEW (XDR)** | See § 2 recommendation |
| Playbook tuning workbench UI            | **NEW (XDR)** | Not yet built |

### Recommendation
Add `GET /api/respond/executions/analytics?playbook_id=` to the
Response Engine.  Then ship `/xdr/respond/tuning/:playbookId`.  Every
metric derived from real execution rows.

---

## §6 · Recommendation Tuning

Existing base primitive:
- `POST /api/decode/mitigations/evidence_driven` — authoritative
  recommender (schema v2)
- `POST /api/mitigations/compare` — diff two mitigation sets

Existing XDR primitive (this session):
- `src/xdr/intel/recommendationEngine.js` — deterministic composer
- `src/xdr/intel/XdrRecommendationsPanel.jsx` — Investigation panel

### Classification
| Capability | Classification | Notes |
| --- | --- | --- |
| Base evidence-driven recommender        | **CONSUMED** | This session |
| XDR deterministic composer              | **NEW (XDR)** | Ships now |
| Explainability (why? / supporting[])    | **CONNECTED** | Every rec carries `supporting[]` + `risk_modifiers[]` |
| Already-executed suppression            | **CONNECTED** | Composer subtracts executed playbook actions |
| Priority modifiers (production / destructive) | **EXTEND** | Composer supports `risk_modifiers[]` — asset metadata needed |
| Recommendation tuning workbench         | **NEW (XDR)** | Not yet built |
| A/B compare two recommendation configs  | **CONSUME**   | Base `/api/mitigations/compare` |

### Recommendation
Ship `/xdr/investigate/tuning/recommendations` — explains every
active recommendation, allows suppression rules (tenant-scoped), and
runs A/B compares against the scenario corpus.

---

## §7 · Negative / Contradictory Evidence Handling

Existing base primitives:
- `engine/detectors/explainability.py` — negative explainability
- `engine/explain_export.py` — negative explanations export
- `POST /api/verdict/stage2/compute` — returns
  `negative_explanations[]`

### Classification
| Capability | Classification |
| --- | --- |
| Negative explainability engine            | **CONSUMED** — Verdict panel renders `negative_explanations[]` |
| "Why NOT worse" surface                   | **CONNECTED** — Verdict Panel |
| Contradictory-evidence handling in composer | **CONNECTED** — Composer never fabricates when data is missing; renders honest banners |
| Contradictory-evidence scenario corpus    | **NEW (XDR)** — see § 2 |

---

## §8 · Rule → Verdict → Recommendation → Playbook Relationship

### Classification
| Relationship | Base implementation | XDR |
| --- | --- | --- |
| Rule → Technique (MITRE)         | `RULE_TO_TECHNIQUE` in `mitreTactics.js` + base MITRE mapper | **CONNECTED** |
| Rule → Verdict weight            | `/api/verdict/stage2/compute` `evidence[].weight` | **CONSUMED** |
| Verdict → Recommendation         | `/api/decode/mitigations/evidence_driven` | **CONSUMED** |
| Rule → Recommendation            | XDR composer templates | **CONNECTED** (this session) |
| Recommendation → Playbook        | XDR composer + Response Engine `playbookStore` | **CONNECTED** (this session) |
| Playbook → Response → Evidence   | Response Engine `xdr_response_evidence` triple | **CONNECTED** |
| Response → Updated investigation | `/api/xdr/incidents/{id}/response-executions` | **CONNECTED** |

### Recommendation
Build **`RuleRecPlaybookRelationshipGraph`** — a small SVG or table
showing this exact chain for a selected incident.  Every edge is
data-backed (rule id → technique → weight → recommendation → playbook →
execution).  No fabrication.

---

## §9 · Investigation → Response → Response-Evidence feedback loop

Fully **CONNECTED** today:
- `POST /api/xdr/response-evidence` writes evidence_ref + audit_ref + timeline_ref
- `GET  /api/xdr/incidents/{id}/response-executions` reads them back
- Recommendation composer consumes executions to subtract completed actions

### Classification
| Capability | Classification |
| --- | --- |
| Response evidence sink                | **CONNECTED** |
| Response-executions read-back         | **CONNECTED** |
| Investigation recomputes after response | **CONNECTED** (Recommendations Panel `recalc()` on refresh) |
| Continuous recompute on new evidence  | **EXTEND** — needs WebSocket / polling; today it's on manual refresh |

---

## §10 · Analyst Interaction / Pivot Workflows

Existing XDR primitives:
- `Pivot.jsx` — Slice 1 contextual pivots
- Right-click Analyst Pivot Menu on canvas
- Deep-links to Evidence Ref, MITRE, IOC, Process Tree, Trajectory

### Classification
| Capability | Classification | Notes |
| --- | --- | --- |
| Canvas right-click pivot menu           | **CONNECTED** |
| Entity Inspector pivot chips            | **CONNECTED** |
| Cross-panel selection sync (Canvas ↔ Timeline ↔ Attack Story ↔ Inspector ↔ MITRE) | **CONNECTED** |
| DIE / IEDDE / IUE / UAIE panels in the sync bus | **EXTEND** — currently receive `incident` only |
| Recommendation → clickable pivot on the recommendation itself | **NEW (XDR)** — each rec has an `action`; clicking it should route |
| Global search across incidents / hosts / IOCs | **NEW (XDR)** |
| Related incidents / campaigns pivot     | **CONSUME** (`/api/correlations/find-related`) — not yet wired |

---

## Priority-ranked backlog (from this audit)

### P0 · Turn the panels into one operating system
1. **`WorkspaceSelectionContext`** — one selection bus every panel subscribes to.
2. **Continuous recompute** — Recommendations Panel polls incidents endpoint every 30s + on selection change.
3. **Recommendation → action deep-link** — each rec's `action` routes to the right panel (DIE / IEDDE / process-tree / respond drawer).

### P0 · Corpus / Replay / Regression architecture
4. **`corpus/scenarios/*.json`** with all eight categories.
5. **`XdrReplayEngine.js`** composing `/api/regression/run` + `/api/batch/test/json` + local recommender + playbook simulator.
6. **XDR-side regression CI job** — fail on rule/playbook/recommendation regressions.

### P0 · Rule / Playbook / Recommendation tuning
7. **`/xdr/detect/tuning/:ruleId`** workbench — real metrics or `INSUFFICIENT TELEMETRY FOR METRIC`.
8. **`/xdr/respond/tuning/:playbookId`** — needs Response Engine analytics endpoint (`EXTEND`).
9. **`/xdr/investigate/tuning/recommendations`** — explainability + suppression + A/B compare.

### P1 · Missing native workspace pages
10. **`/xdr/investigate/evidence-explorer`** (adapts base `EvidenceExplorerPage`).
11. **`/xdr/investigate/command`** (adapts base `CommandAnalyzerPage`; Slice 14).
12. **`/xdr/investigate/history`** (adapts base `HistoryPage`).
13. **`/xdr/investigate/related`** — `/api/correlations/find-related` consumer.
14. **Global search** — top-nav search across incidents / hosts / IOCs.

### P1 · Feedback loop tightening
15. Response evidence auto-refreshes Recommendation Panel.
16. Rule / Playbook / Recommendation versions ⇄ scenario-corpus replay.

### P2 · Vendor / connectors — DELIBERATELY DEPRIORITISED
17. Phase C CrowdStrike / Defender / SentinelOne / Cisco SEP.
18. Phase D Windows WEF / WinRM / WMI.

---

## Explicit NOT_PRESENT verifications

| Requested / Assumed | Verified? |
| --- | --- |
| VEEE (Vision Evidence Extraction)      | **PRESENT** — `services/veee/evidence_extractor.py` |
| ICE (Investigation Correlation Engine) | **PRESENT** — `services/ice/correlate.py` |
| Investigation-scenario schema in base  | **NOT_PRESENT** — new XDR construct required |
| Base "recommendation tuning" endpoint  | **NOT_PRESENT** — XDR-owned |
| Base "playbook regression" endpoint    | **NOT_PRESENT** — XDR-owned (Response Engine) |

## Boundary invariants (unchanged)

- Base `/app/backend` still authoritative.  XDR consumes.
- One XDR write path: `POST /api/xdr/response-evidence`.
- Every new tuning surface writes to XDR-owned stores (playbookStore,
  detectionRuleStore, scenario corpus) — never mutates base state.
