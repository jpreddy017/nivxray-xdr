# IUE ARCHITECTURE TRACE — TRACK A · READ-ONLY

**Owner directive**: Read-only trace of the IUE / Universal Investigation
Engine architecture across every investigation entry point. **No code
changes, no route fixes, no new pipelines. STOP after the report.**

**Distinction enforced throughout this document**:
- ✅ **IUE-in-code** — an IUE-shaped module exists in the codebase
- ⚠️ **IUE-on-path** — IUE actually drives the request through
  classify → plan → dynamic routing → downstream execution on the
  production execution path

These are **NOT the same thing**. This trace shows they are almost
entirely divorced from each other today.

Date: 2026-08-10
Scope: `backend/routers/{cases,documents,auto_investigate,ops,die,sessions,uil,workspace_investigation}.py`,
`backend/v2/jobs/pipeline.py`, `backend/nivxforge/investigation/`,
`backend/services/die/`, `backend/services/uil/`, `backend/services/ida/`,
`backend/v2/investigation/iu/`, `backend/v2/verdict/`.

---

## 1. Intended canonical architecture (from user directive)

```
ANY INPUT
   │
   ▼
Input Health
   │
   ▼
IUE  ← Universal Investigation Engine (single entry point)
   │
   ▼
Profile / understand input
   │
   ▼
Determine intent
   │
   ▼
Build deterministic processing plan
   │
   ▼
Dynamic routing
   │
   ▼
Artifact extraction / decoding / analyzers
   │
   ▼
Investigation Context Builder
   │
   ▼
Canonical Investigation Object (SSOT)
   │
   ├─────────────┬─────────────┬─────────────┐
   Attack Story  Timeline      Evidence      MITRE
   Verdict       Trajectory    Threat Intel  LOLBAS
   Recommendations             Reports       Analyst View
                                              Executive View
```

Every entry point (paste, DOCX, PDF, image, archive, binary, PCAP,
URL, vendor JSON…) is supposed to converge here.

---

## 2. Executive summary — what the trace actually shows

**IUE exists in the codebase in FOUR parallel implementations.**
**IUE is on the production execution path of ZERO of the four main
investigation entry points.** Every entry point either bypasses IUE
entirely or invokes it as a post-hoc *metadata stamp* on an object that
was built by a different orchestrator.

| Concern | State |
|---|---|
| Is there an IUE-in-code? | ✅ Yes, four of them (see §3) |
| Is IUE on the production execution path? | ❌ No — none of the four are used as the front-door orchestrator |
| Do all entry points converge on a single IUE? | ❌ No — each entry point picks its own pipeline hard-coded at the route |
| Is `InvestigationModel` the canonical SSOT? | ⚠️ Partial — it is one of THREE SSOT-shaped objects (§7) |
| Does the MDR pipeline call IUE? | ❌ No — see §5.4 |
| Does `cases.py` call the MDR pipeline? | ❌ No — see §5.1, §5.2 |
| Does the L1-fixed `documents.py` call IUE? | ❌ No — it jumps straight to the MDR pipeline (§5.3) |

The immediate consequence for the Workspace bug the user observed:
**even if `routers/cases.py` were routed to the MDR pipeline
(the "L1b" fix that was drafted), it would still not go through IUE.
We would just be exchanging one bypass for another.**

---

## 3. IUE-shaped modules in the codebase (`IUE-in-code`)

Four distinct modules named/shaped like "IUE" or "input understanding"
live in parallel. None is authoritative.

### 3.1 `backend/nivxforge/investigation/input_understanding.py`
- Also re-exported as `backend/nivxforge/investigation/universal_investigation_engine.py`
  (module docstring literally says "renamed to Universal Investigation
  Engine (UIE) because it is the sole entry point for every
  investigation").
- 17 input types (`cisco_xdr`, `crowdstrike`, `defender`, …, `powershell`, `base64`, `unknown`).
- Provides a `_ROUTE_BY_TYPE` dict → `"auto-investigate"` or `"decode"`.
- Public API: `understand(text) -> dict`, alias `run_uie(text)`.
- **Called from**: `routers/ops.py`, `routers/auto_investigate.py`,
  `routers/die.py` (see §5), and (indirectly) from `routers/cases.py`
  through `decode_smart`.
- **Actually drives routing?**  **NO.** Every caller stamps the result
  into `cio.metadata["input_understanding"]` *after* the pipeline
  has already run. The `route` field it emits is never read.

### 3.2 `backend/services/die/input_understanding.py` (761 LOC)
- Docstring: *"The IUE is the FIRST thing every Workspace paste passes
  through. It answers WHAT did the analyst give me? and WHAT am I
  going to do with it? Then — and only then — the existing engines
  execute."*
- 21 input types (`powershell_encoded`, `nested_shell_chain`,
  `command_chain`, `pe_file`, `vendor_json`, `vendor_report_text`, …).
- Emits a full **`InputUnderstanding`** object with:
  - `plan: List[PlanStep]` — deterministic processing plan.
  - `_execute_plan()` — actually runs the plan step-by-step.
  - `next_engine`, `engines_selected`, `engines_skipped`, `pipeline_flow`.
  - `ConfidenceMatrix`, `hero_sentence`, `execution_trace`.
- Public API: `understand(text, execute=True) -> InputUnderstanding`.
- **This is the module that most closely matches the user's intended
  IUE — profile + intent + processing plan + dynamic execution.**
- **Called from**:
  - `POST /api/die/understand` (analyst UI panel only)
  - `POST /api/die/investigation-results` (used by Workspace to render
    the "Investigation Results" pane — but only as a *renderer*, not
    as the orchestrator of the main investigation)
  - `POST /api/die/investigation` (SSOT projection)
  - `POST /api/sessions/investigate`, `POST /api/uil/investigate`
    (session/uil adapters — see §5.7, §5.8)
- **Actually drives Workspace Save Case / Reinvestigate / Documents
  Re-Investigate / Auto-Investigate?**  **NO.** None of those four
  routes call this module.

### 3.3 `backend/v2/investigation/iu/` (engine + per-language detectors)
- New v2-namespaced package with individual detectors:
  `powershell_script.py`, `command_line.py`, `bash.py`, `python.py`,
  `vbscript.py`, `javascript.py`, plus `engine.py`.
- Emits `source="input_understanding.<name>"` provenance tags on
  Evidence Graph nodes.
- **Called from**: `v2/investigation/graph/builder.py` — it is used
  to *label evidence nodes*, not to drive routing.
- **Actually the entry-point IUE?**  **NO.** It is a graph-annotator.

### 3.4 `backend/services/uil/` — Universal Input Layer
- `classifier.py`, `mixed.py`, `preprocess.py`.
- Emits `InputKind`, `KIND_LABEL`.
- Public API: `classify()`, `normalize()`, `split_mixed()`.
- **Called from**: `POST /api/uil/classify`, `POST /api/uil/split`,
  `POST /api/uil/investigate` (see §5.8).
- **Actually the entry-point IUE?**  **NO** — it is used only by the
  `/api/uil/*` router; the primary Workspace/AutoInvestigate/Docs
  paths do not go through it.

### 3.5 A fifth partial: `backend/services/die/input_health.py`
- Not an IUE, but the pre-IUE **Input Health** stage from the intended
  diagram is implemented here.
- Only surfaced via `POST /api/die/health-check`. **Not on the primary
  investigation path.**

---

## 4. Downstream investigation pipelines in the codebase

Three parallel "investigation orchestrators" exist. Each was intended
to be the successor to the one before it; none is retired.

### 4.1 `routers/ops.py::decode_smart` (`/api/decode/smart`)
- Historically the primary Workspace decoder.
- Runs: ingress gate → atomic-IOC guard → PS-encoded-command
  short-circuit → deterministic best-decode → CIM composition →
  **CIO composition** → IUE metadata stamp (`nivxforge` IUE,
  §3.1) → verdict engine → OSINT enricher → verdict refresh.
- Does **NOT** produce: `investigation_model`, `investigation_narrative`,
  `investigation_report`, `mdr_investigation`, `verdict_shadow`,
  Attack Story, IKG, Executive Card. Those are MDR-only.

### 4.2 `v2/jobs/pipeline.py::run_investigation_with_progress` (MDR)
- The modern "auto-investigate" pipeline.
- Runs: `_detect_commands` → `_extract_entities` → per-command decode
  (with cache) → archetype pre-decode → `_flatten_mitre` →
  `_merge_iocs` → OSINT → `_investigation_quality` →
  `_mdr_executive_card` → `_build_investigation_model` →
  `_compose_narrative` → `_compose_investigation_report` →
  **verdict_shadow attach** (Wave 1).
- **Never calls any of the four IUE modules.**
- Called from: `routers/auto_investigate.py`, `routers/documents.py`
  (L1 fix), `routers/auto_investigate_jobs.py`.

### 4.3 `services/die/investigation_results.py::render` + Session
- The "SSOT renderer" — used by `/api/die/investigation-results`,
  `/api/die/investigation`, `/api/sessions/investigate`,
  `/api/uil/investigate`.
- **This one DOES call the `services.die` IUE (§3.2)** internally
  (`understand_input` is imported and used to drive the plan +
  `_execute_plan()`).
- Produces a `Canonical` SSOT object (`services/die/canonical.py`)
  — distinct from `v2.investigation.model.InvestigationModel`
  (the MDR SSOT).

### 4.4 `routers/workspace_investigation.py` — L1 Analyst Workspace APIs
- `POST /api/investigation` (create case), `GET /api/investigation/{id}`,
  Attack Story, IOC Intelligence, Threat Assessment, Detection Rules,
  Hunting Queries. Backed by `l2_investigation.services.*`.
- Consumes an **EvidenceBundle** (yet another shape).
- Called by: New L4 Analyst Workspace UI (per blueprint).
- **Does NOT call IUE.** Bundle is expected to arrive pre-built.

---

## 5. Per-entry-point classification (the questions the owner asked)

Every entry point below is classified as one of:
- **`IUE-driven`** — IUE classifies → produces plan → drives routing.
- **`IUE-stamp only`** — IUE runs but only stamps metadata; the plan
  is not consulted; routing is hard-coded at the route.
- **`bypasses IUE`** — IUE is never called on this path.

### 5.1 `POST /api/cases/save` (Workspace Save Case)
- File: `backend/routers/cases.py:44-244`.
- Flow:
  ```
  cases.save_case()
      └─▶ if needs_reinvestigate:
              routers.ops.decode_smart(input)     ← /api/decode/smart pipeline
                  ├─▶ ingress_gate
                  ├─▶ atomic_ioc_guard
                  ├─▶ deterministic_best_decode
                  ├─▶ CIM compose
                  ├─▶ CIO compose
                  │       └─▶ IUE stamp (nivxforge §3.1)     ← IUE runs HERE
                  │             (metadata-only, no plan, no routing)
                  ├─▶ verdict refresh
                  └─▶ OSINT enrich
      └─▶ mongo upsert(workspace_cases)
  ```
- **IUE-on-path? NO** — `nivxforge` IUE runs as a post-hoc metadata
  stamp inside CIO composition. `_ROUTE_BY_TYPE` is not consulted.
- **MDR-on-path? NO** — `run_investigation_with_progress` is never
  called. That is why the saved case has no `investigation_model`,
  no `investigation_narrative`, no `investigation_report`, no Attack
  Chain, no `verdict_shadow`.
- **Classification: `IUE-stamp only` + `bypasses MDR`**.

### 5.2 `POST /api/cases/{case_id}/reinvestigate` (Workspace Reinvestigate)
- File: `backend/routers/cases.py:507-575`.
- Flow: identical to §5.1 — literally calls `decode_smart`.
- **Classification: `IUE-stamp only` + `bypasses MDR`**.

### 5.3 `POST /api/documents/{doc_id}/re-investigate` (L1-fixed 2026-08-10)
- File: `backend/routers/documents.py:408-560`.
- Flow:
  ```
  documents.reinvestigate_document()
      ├─▶ extract text (PDF/DOCX/XLSX/HTML)
      └─▶ v2.jobs.pipeline.run_investigation_with_progress(raw=text)
              ├─▶ _detect_commands
              ├─▶ _extract_entities
              ├─▶ per-command decode
              ├─▶ MDR compose (exec summary, timeline, urls, recs)
              ├─▶ _mdr_executive_card
              ├─▶ _build_investigation_model
              ├─▶ _compose_narrative
              ├─▶ _compose_investigation_report
              └─▶ verdict_shadow attach (Wave 1)
  ```
- **IUE-on-path? NO** — the MDR pipeline never calls IUE. Not the
  `nivxforge` one, not the `services.die` one, not the v2 detectors,
  not `services.uil`. It jumps straight into command detection.
- **Classification: `bypasses IUE`** (produces rich MDR output but
  never asked "what is this input?" first).

### 5.4 `POST /api/v2/auto-investigate` (paste → Auto Investigate)
- File: `backend/routers/auto_investigate.py:645-821`.
- Flow:
  ```
  auto_investigate()
      ├─▶ ingress_gate (vendor JSON normalisation only)
      ├─▶ v2.jobs.pipeline.run_investigation_with_progress()   ← same as §5.3
      ├─▶ CIM compose
      ├─▶ CIO compose
      │       └─▶ IUE stamp (nivxforge §3.1)          ← IUE runs HERE
      │             (metadata-only, no plan, no routing)
      ├─▶ verdict refresh
      ├─▶ OSINT enrich
      └─▶ verdict_shadow attach (Wave 1) — ONE OF TWO shadow attach
          sites (the pipeline itself also attaches in §5.3)
  ```
- **IUE-on-path? NO** — same as §5.1. Metadata stamp only.
- The IUE stamp happens *after* the MDR pipeline has already produced
  the entire investigation. Routing decisions are irrelevant at that
  point.
- **Classification: `IUE-stamp only` (post-hoc)**.

### 5.5 `POST /api/decode/smart` (raw Workspace paste)
- File: `backend/routers/ops.py:636-2435`.
- Same as §5.1 (this is the underlying handler cases.py calls).
- **Classification: `IUE-stamp only`**.

### 5.6 `POST /api/die/understand`, `/api/die/investigation`, `/api/die/investigation-results`
- File: `backend/routers/die.py:53-135`.
- Directly call `services.die.input_understanding.understand()` (§3.2).
- Also produce the `services/die/canonical.Canonical` SSOT via
  `investigation_results.render()`.
- These are the **only routes where IUE is genuinely driving the
  investigation** — classify → plan → execute → SSOT.
- **BUT**: the Workspace only uses them for the analyst-facing
  "Investigation Results" pane and the IUE panel. The Save Case /
  Reinvestigate flow does not route through them.
- **Classification: `IUE-driven`** — but only for these three
  analyst-facing surfaces, not for the main investigation flow.

### 5.7 `POST /api/sessions/investigate`
- File: `backend/routers/sessions.py:104-120`.
- Delegates to `services.die.investigation_results.render()` — so also
  `IUE-driven` via §3.2.
- Not used by the current Workspace UI investigation flow.
- **Classification: `IUE-driven`** (but not on the Workspace path).

### 5.8 `POST /api/uil/investigate`
- File: `backend/routers/uil.py:59-118`.
- Calls `services.uil.classify()` (§3.4) THEN delegates to
  `services.die.investigation_results.render()` → §3.2 IUE.
- **Classification: `IUE-driven` (double: `services.uil` classifier
  gates the input, then `services.die` IUE builds the plan)** —
  but the primary Workspace does not hit this route.

### 5.9 `POST /api/investigation` (L1 Analyst Workspace bundle create)
- File: `backend/routers/workspace_investigation.py:189-215`.
- Accepts a pre-built `bundle` dict; persists via `CaseStore`.
- No IUE, no MDR pipeline. The bundle is expected to already exist.
- **Classification: `bypasses IUE` and `bypasses MDR`** — this is a
  storage router, not an investigation router.

### 5.10 Other investigation-shaped routes (for completeness)
| Route | File | IUE-on-path? | MDR-on-path? |
|---|---|---|---|
| `POST /api/analyze` | `routers/analyze.py` | ❌ | ❌ (uses legacy analysis_core) |
| `POST /api/analyze/async` | `routers/analyze.py` | ❌ | ❌ |
| `POST /api/analyze/stream` | `routers/analyze.py` | ❌ | ❌ |
| `POST /api/decode/chain` | `routers/chain.py` | ❌ | ❌ |
| `POST /api/decode/certificate` | `routers/convergence.py` | ❌ | ❌ |
| `POST /api/documents/{id}/batch-decode` | `routers/documents.py` | ❌ | ❌ (uses `decode_smart` per line) |
| `POST /api/ai/auto-decode` | `routers/ai.py` | ❌ | ❌ |
| `POST /api/ai/auto-investigate` | `routers/ai.py` | ❌ | ❌ |
| `POST /api/iedde/analyze` | `routers/iedde.py` | ❌ | ❌ |
| `POST /api/moe/analyze` | `routers/moe_panel.py` | ❌ | ❌ |
| `POST /api/threat-model/analyze` | `routers/threat_model.py` | ❌ | ❌ |

---

## 6. Where does IUE end and downstream begin?

**Answer: today, IUE never ends because it never begins.** The IUE that
matches the user's diagram (`services.die.input_understanding`, §3.2)
runs its own end-to-end execution inside `render()` — it *is* the whole
pipeline for the `/api/die/*` routes. It has no handoff boundary to a
downstream orchestrator because it never hands off.

For the four IUE modules, the runtime shape today is:

| Module | Runs as | Handoff to downstream? |
|---|---|---|
| `nivxforge` IUE (§3.1) | Metadata stamp | ❌ No handoff — output field `route` is never read |
| `services.die` IUE (§3.2) | Whole-pipeline executor | ❌ Not on Workspace/Docs path |
| v2 detectors (§3.3) | Evidence-graph annotator | ❌ Not orchestration |
| `services.uil` (§3.4) | Route gate for `/api/uil/*` | ➜ delegates to `services.die` IUE inside that route |

**Consequence**: the boundary between "IUE" and "investigation pipeline"
that the user's diagram implies does not exist as a code contract.
Each entry point picks its own pipeline at the router level.

---

## 7. Is `InvestigationModel` the canonical SSOT?

**No — it is one of THREE SSOT-shaped objects in the codebase**:

| Object | File | Produced by | Consumed by |
|---|---|---|---|
| **`InvestigationModel`** | `v2/investigation/model.py` | `_build_investigation_model()` in MDR pipeline (§4.2) | `v2/investigation/narrative.py`, `v2/investigation/report.py`, `v2/verdict/canonical_input.py` (Wave 1) |
| **`Canonical` (SSOT)** | `services/die/canonical.py` | `services/die/investigation_results.render()` (§4.3) | `/api/die/investigation-results`, `/api/die/investigation`, `/api/sessions/investigate`, `/api/uil/investigate`, `WorkspacePage.jsx` (line 1869) |
| **`CIO` (Canonical Investigation Object)** | `nivxforge/investigation/cio.py` | `nivxforge.investigation.build_cio()` in `decode_smart` (§5.5) and `auto_investigate` (§5.4) | `/api/decode/smart`, `/api/v2/auto-investigate`, `v2/verdict/shadow.py::compute_shadow` (Wave 1) |

Plus one more shape appearing only on the L1 Analyst Workspace path
(§5.9):
- **`EvidenceBundle`** (`l2_investigation/schemas.py`) — expected as
  input to `POST /api/investigation`, projected out again via
  `l2_investigation.services.workspace_bundle`.

The Wave 1 shadow (`verdict_shadow`) is attached on **two** paths
(auto_investigate CIO + MDR pipeline InvestigationModel) with different
projection functions (`compute_shadow(cio)` vs
`from_investigation_model(model)`), meaning the shadow itself observes
two different SSOTs.

---

## 8. Where does the Workspace UI actually read the investigation from?

`/app/frontend/src/pages/WorkspacePage.jsx` (~3982 LOC) consumes
**all three SSOTs at once**:

| Line | Endpoint | SSOT shape | Purpose |
|---|---|---|---|
| 1869 | `POST /die/investigation-results` | `Canonical` (§4.3) | Investigation Results pane |
| 680, 1338, 1641, 1942, 3952 | `POST /die/understand` | `InputUnderstanding` (§3.2) | IUE panel + analyst narrative |
| — | `POST /decode/smart` | `CIO` (§5.5) | Verdict, IOCs, MITRE, decode chain |
| — | `POST /v2/auto-investigate` | `CIO` + MDR fields | Auto Investigate flow |
| — | `POST /cases/save` (and reinvestigate) | Persists `CIO`-shaped fields, not `InvestigationModel` | Save Case flow — this is where DOCX loses its Attack Chain |

So the Workspace displays a **merge** of three SSOTs rendered from
three different pipelines, each of which has a different opinion about
what the input is. The Save Case flow only persists the `CIO` slice —
which is why re-opening a saved DOCX case has no Attack Chain, no
Investigation Model, no MDR report.

---

## 9. Downstream consumers — where the CIO / InvestigationModel is actually read

| Consumer | Reads from |
|---|---|
| Attack Story panel (Workspace) | `analyze.chain` (from `services.die.analyze`) — NOT `InvestigationModel` |
| MITRE panels | Three sources: `mdr.mitre` (MDR), `cio.evidence_graph`, `analyze.mitre` (die) |
| Evidence Graph | `cio.evidence_graph` (nivxforge CIO) |
| Verdict card | `cio.verdict` (via `refresh_verdict`); `verdict_shadow.verdict_canonical` for Wave 1 |
| Recommendations | Two sources: `mdr_recommendations` (MDR), `cio.metadata.recommendations` |
| Analyst Summary / Analyst Narrative | Three sources: `investigation_narrative` (MDR), `cio.summary` (nivxforge), `services/die/analyst_narrative` (DIE) |
| Executive Summary / Executive Card | Two sources: `mdr.executive_card` (MDR), `cio.summary` (nivxforge) |
| Trajectory / Timeline | `mdr.mdr_investigation.timeline` |
| Threat Intel | `cio.metadata.osint` + `cio.metadata.ti_hits` |
| LOLBAS | `cio.metadata.lolbas` |
| Reports | Two sources: `investigation_report` (MDR), `services/die/narrative.generate_report` (DIE) |

**Every one of these consumers has ≥1 upstream path that does not go
through IUE.**

---

## 10. Gap analysis — canonical vs. actual

| Intended stage | Codebase reality |
|---|---|
| Input Health | Exists (`services/die/input_health.py`) — reachable only via `/api/die/health-check`. **NOT on the primary investigation path.** |
| IUE (classify + intent + plan) | Exists 4× (§3). The version that most closely matches the intent (§3.2) is **only on the `/api/die/*`, `/api/sessions/*`, `/api/uil/*` paths — none of which are used by the Workspace Save/Reinvestigate flow.** |
| Dynamic routing | Exists in intent (`_ROUTE_BY_TYPE`, `next_engine`, `pipeline_flow`) — **no consumer actually consults these fields to pick a pipeline.** Routing today is hard-coded at each FastAPI route. |
| Artifact extraction / decoding / analyzers | Exists — many. `RC5`, `wrapper_archetypes`, MDR command decode, `deterministic_best_decode`. Each entry point picks its own. |
| Investigation Context Builder | Split across `_build_investigation_model()` (MDR) and `build_cio()` (nivxforge) and `render()` (die). **Three parallel context builders, no single hand-off.** |
| Canonical Investigation Object (SSOT) | Exists 3× (§7) — no unification. |
| Downstream consumers | Each consumer picks one of the three SSOTs. |

---

## 11. Naming inconsistency the user should know about

The codebase uses these terms **interchangeably** while pointing at
different modules:

- **IUE** — Input Understanding Engine
- **UIE** — Universal Investigation Engine (the `nivxforge` rebrand,
  per its own docstring: "Per the 2026-02 operator directive, the
  Input Understanding Engine (IUE) has been renamed to the Universal
  Investigation Engine (UIE) because it is the sole entry point for
  every investigation, not just a classifier.")
- **UIL** — Universal Input Layer (`services/uil/`)
- **UAIE** — mentioned in `services/uaie/`
- **DIE** — Decoder Intelligence Engine (`services/die/`) — but *its*
  IUE module (§3.2) is often described as "the IUE"
- **v2 IU** — v2/investigation/iu/ per-language detectors

Multiple modules literally believe they are "the sole entry point".
None is.

---

## 12. Answers to the specific questions in the directive

> 1. Does `POST /api/cases/save` invoke IUE?

Yes — the `nivxforge` IUE (§3.1) runs as a metadata stamp inside
`decode_smart`. **It does not drive routing.** The MDR pipeline is
not invoked; `InvestigationModel`, Attack Story, Executive Card,
Analyst Narrative, and `verdict_shadow` are not produced.

> 2. Does `POST /api/cases/{id}/reinvestigate` invoke IUE?

Same as above (identical implementation).

> 3. Does `POST /api/documents/{id}/re-investigate` invoke IUE?

**No — it bypasses IUE entirely** and jumps straight to the MDR
pipeline (L1 fix). The MDR pipeline produces rich outputs but never
asks "what is this input?" first.

> 4. Where exactly does IUE end and the downstream investigation pipeline begin?

Nowhere — the boundary does not exist as a code contract (§6).

> 5. Does IUE produce a canonical investigation context/plan that all three paths should consume?

Only `services/die/input_understanding` (§3.2) produces a plan. None
of the three paths in question 1-3 consumes that plan.

> 6. Which path bypasses IUE, and why?

- **Documents Re-Investigate (§5.3)** — bypasses IUE completely; jumps
  to MDR. History: `decode_smart` was the wrong pipeline for DOCX, so
  the L1 fix (2026-08-10) routed DOCX to MDR directly, but IUE was not
  in the L1 fix scope.
- **All L1 Analyst Workspace routes (§5.9)** — bypass everything;
  storage-only.
- **All legacy `analyze.*` and `chain.*` routes (§5.10)** — pre-IUE
  code paths that were never refactored.

The Workspace Save/Reinvestigate paths (§5.1, §5.2) do not "bypass"
IUE in the strict sense — they stamp it — but the stamp has no effect
on routing or downstream data.

> 7. Is `v2.jobs.pipeline.run_investigation_with_progress` itself downstream of IUE, or is it currently acting as a parallel orchestration layer?

**Parallel orchestration layer.** It has no IUE call anywhere in its
729 lines. It is a peer to `decode_smart` and to
`services/die/investigation_results.render()`, not a downstream of
IUE.

> 8. Identify every current entry point that can create/update an investigation case and classify it.

See §5.1–§5.10.

Summary counts:
- `IUE-driven` routes: **3** (`/api/die/understand`,
  `/api/die/investigation`, `/api/die/investigation-results`) plus
  the derived `/api/sessions/investigate` and `/api/uil/investigate`.
- `IUE-stamp only` routes: **3** (`/api/cases/save`,
  `/api/cases/{id}/reinvestigate`, `/api/decode/smart`,
  `/api/v2/auto-investigate` — the last two are the underlying
  handlers; the first two delegate to `decode_smart`).
- `bypasses IUE` routes: **11+** (see §5.10 table plus §5.3 and §5.9).

> 9. Identify whether InvestigationModel is the canonical SSOT produced by IUE/downstream context building, or merely one projection.

**One projection of three.** See §7.

> 10. Identify where Attack Story, MITRE, Evidence, Verdict, Recommendations, Analyst Summary and Executive Summary consume the canonical object.

See §9. Every consumer has ≥1 upstream path that does not go through
IUE, and most read from two or three different SSOTs depending on
which entry point the analyst hit.

---

## 13. Consequence for the Workspace DOCX bug the user just spotted

Fixing `routers/cases.py` to call `run_investigation_with_progress`
(the "L1b" fix the previous prompt drafted) would:

- ✅ Cause `POST /api/cases/save` and `POST /api/cases/{id}/reinvestigate`
  to produce `investigation_model`, `investigation_narrative`,
  `investigation_report`, `mdr_investigation`, `verdict_shadow` — so
  the Attack Chain / Executive Summary / Analyst Summary would appear.
- ❌ **NOT** put those routes through IUE. It would exchange one
  bypass for another (both currently ignore IUE).
- ❌ **NOT** unify the three SSOTs. Save Case would persist yet
  another slice.
- ⚠️ Add a fourth `verdict_shadow` attach site (§7 already lists two),
  which the Wave 1 observation store would see as legitimate new
  traffic — potentially skewing divergence data.

**The user's instinct is right**: the correct architectural move is
not to add a fourth path, but to have every entry point converge on
a single IUE → single canonical investigation → single SSOT →
downstream consumers.

---

## 14. STOP

Per directive: no recommendations for code changes.

Read-only trace ends here. Awaiting owner review before any
implementation step is proposed.
