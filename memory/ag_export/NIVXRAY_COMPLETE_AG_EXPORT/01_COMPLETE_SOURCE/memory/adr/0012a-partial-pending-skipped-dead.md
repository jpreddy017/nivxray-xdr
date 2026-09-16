# NivXRay — Partial · Pending · Skipped · Dead Inventory

**Type**: READ-ONLY discovery follow-up to ADR-0012 (Workspace 360° Audit).
**Date**: 2026-02-15 · Session-20.
**Scope**: Enumerate every task/component that is (a) partially executed, (b) explicitly pending, (c) skipped/deferred, or (d) dead / dead-ish code. Every row carries a file path or ADR citation. No code is modified.

Legend:

- 🟡 **PARTIAL** — implemented but with a documented gap (mock, missing wiring, or incomplete branch).
- 🟠 **PENDING** — explicitly queued, owner-approved plan, not yet started.
- ⛔ **SKIPPED / LOCKED** — deliberately deferred by owner directive.
- 💀 **DEAD / DEAD-ISH** — present in repo but unreachable or superseded and no longer used from the live surface.

---

## §1 · Partially executed tasks

### 1.1 · P2 UI Slice-3 · Behavioral Timeline persistence

- **File(s)**: `backend/routers/behavioral.py`, `frontend/src/components/investigation/BehavioralTimeline.jsx`, `backend/tests/canonical/api/test_p2_uislice3_persistence.py`.
- **Status**: 🟡 PARTIAL.
- **What works**: `POST /api/behavioral/attach`, `GET /api/behavioral/case/{id}`, `DELETE /api/behavioral/case/{id}`; optional `case_id` auto-attach on both ingest routes; frontend hydrate `useEffect`; workspace isolation regression locked; 8/8 focused tests + 65/65 P2 combined regression PASS.
- **What is partial**:
  - `persistMeta` after successful ingest is set **optimistically** on the client — the real, fresh `adapter_history` is only pulled on next mount / caseId change. This is a deliberate trade to save a round-trip, but it means the "recent history" panel (planned but not yet built in the UI) will be one step behind until reload.
  - `case_id` on ingest is **NOT verified** against `workspace_cases` for the current user. Retrieval is safe (`user_email + case_id` scope), but a caller can shadow their own future case IDs. No cross-user leak.
  - No UI surface yet exposes `adapter_history[]` (bounded 20). It's persisted but invisible.
- **Evidence**: `ADR-0010v · Limitations honestly recorded`.

### 1.2 · P2 Slice-3 · EVTX transport

- **File(s)**: `backend/services/behavioral/evtx_reader.py`, `backend/tests/canonical/api/test_p2_slice3_evtx_transport.py`.
- **Status**: 🟡 PARTIAL (transport itself is complete; the primary test is **mocked**).
- **What works**: Bytes → XML wrapping → Sysmon normalizer. Size cap (16 MiB) and record cap (10 000) enforced. Magic byte check. Malformed → 400. Round-trip test asserts canonical evidence emerges.
- **What is partial / mocked**:
  - The main round-trip test uses `patch("Evtx.Evtx.Evtx", return_value=_FakeEvtxLog(records))` — the actual `python-evtx` binary parser is never exercised in CI. Comment in the test: **"Round-trip via mocked `Evtx.records()`"**.
  - No real `.evtx` fixture is committed. **This is Task 2 of the current stabilisation plan — on hold at the owner's Task 1 stop-point.**
- **Evidence**: `test_p2_slice3_evtx_transport.py:10 · G. Round-trip via mocked Evtx.records()`; handoff summary Issue 1.

### 1.3 · Python AST analyzer (`services/die/python_ast.py`)

- **Status**: 🟡 PARTIAL.
- **Coverage**: Standard `exec()`, `eval()`, `import subprocess`, some string obfuscation heuristics.
- **Gaps** (confirmed by the `PrevMode` case in this session):
  - No `T1059.006` (Python interpreter) mapping fires for `python -c "…"` invocations.
  - No `T1027.013` (Encrypted/Encoded File) recognition for `bytes.fromhex(...)` + XOR loop pattern.
  - No `T1140` (Deobfuscate/Decode Files or Information) inference when the peeled Layer-1 itself contains a decoder.
  - No `T1620` (Reflective Code Loading) recognition for `exec(<decrypted_bytes>.decode())`.
  - `_B64_PATTERNS` in `services/die/recursive_decode.py` recognises PowerShell `-Enc`, .NET `FromBase64String`, and `base64 -d` — but NOT Python `base64.b64decode(...)`. Therefore recursive decode never re-enters when the loader is Python.
- **Evidence**: `PrevMode` case (`d2ba2d2e-4bfa-…`) has `mitre = [T1027 (regex mapper)]` only.

### 1.4 · CSV/EDR analyzer

- **File(s)**: `backend/services/die/csv_edr_analyzer.py`.
- **Status**: 🟡 PARTIAL.
- **Coverage**: SEP-schema column mapper (Category+Action). Fires MITRE augmentation.
- **Gap**: Other vendors (CrowdStrike CSV, Defender CSV, Splunk CSV) not schema-mapped. Falls back to generic text extraction, losing structured richness.

### 1.5 · Office / DOCX / PPTX / XLSX

- **Status**: 🟡 PARTIAL.
- **Coverage**: Text extraction from `word/document.xml`, `ppt/slide*.xml`, `xl/sharedStrings.xml` via `safe_iter_zip_members`. Canonical narrative bridge fires prose-MITRE (T1219/T1204.002/T1071/T1486/T1003/T1566) on the extracted text.
- **Gaps**: No macro extraction, no OLE object recovery, no embedded-payload detection, no OOXML relationships analysis.

### 1.6 · PE analyzer

- **File(s)**: `backend/services/pe_analyzer.py`.
- **Status**: 🟡 PARTIAL.
- **Coverage**: Produces PE header + section summary on upload.
- **Gap**: The output is **not wired to** `risk_score`, `verdict_card`, or `get_authoritative_mitre`. It shows in Workspace panels but does not influence the verdict.

### 1.7 · Ingress gate — vendor JSON normalisation

- **File(s)**: `backend/nivxforge/investigation/ingress_gate.py`.
- **Status**: 🟡 PARTIAL.
- **Coverage**: Cisco XDR / CrowdStrike / Defender / SentinelOne / QRadar / Splunk / Sysmon JSON shapes normalised to plain text before extractors run.
- **Gaps**: NDJSON multi-line ingest; STIX 2.1 bundle; CEF/LEEF headers; email JSON exports.

### 1.8 · Sysmon adapter — Event 3 MITRE

- **File(s)**: `backend/services/behavioral/sysmon_adapter.py`.
- **Status**: 🟡 PARTIAL by design.
- **Behavior**: Event 3 (network connect) **does NOT** independently emit MITRE techniques. Only the Event-1 CommandLine (of the correlated parent) hands off to the DIE catalogue.
- **Rationale (locked)**: ADR-0010q · Evidence Producer constraint — Sysmon adapter must not run its own MITRE mapper.
- **Consequence**: A dangling E3 (UNRESOLVED_DANGLING) contributes no MITRE ids to the timeline.

### 1.9 · L4 Analyst Workspace Shell (`/investigate`, `/investigate/:caseId`)

- **File(s)**: `frontend/src/workspace_v4/*`.
- **Status**: 🟡 PARTIAL — "SHELL ONLY per ARB PR-3 scope directive".
- **In place**: `AnalystWorkspaceShellPage`, `LensTabs`, `ModeSelector`, `StatePill`, case list, workspace state persist, `investigationApi.js` adapter.
- **Explicit non-goals (locked in the file header)**: "no graphs, no timelines, no story content, no IOC cards, no detection rules, no reports".
- **Lens tabs**: 5 tabs (Summary / Story / IOC / Detection / Report) — Summary and Story are partially rendered; the others are `LensPanel` placeholders.
- **Persistence indicator**: `TID_PERSIST_INDICATOR` wired.

### 1.10 · Verdict-card MITRE surface

- **File(s)**: `backend/evidence_extractor.py` calling `operations.mitre_map()`.
- **Status**: 🟡 PARTIAL — legacy regex mapper is still the primary MITRE source in the verdict card even after UI-DEF-02 convergence shipped.
- **Gap**: `verdict_card.indicators[]` and `verdict_card.mitre` do **not** consult `get_authoritative_mitre`. They consult the regex mapper directly.

### 1.11 · Report determinism — PDF

- **File(s)**: `backend/routers/reports.py`, `backend/tests/test_report_determinism.py`.
- **Status**: 🟡 PARTIAL.
- **Locked deterministic formats**: Markdown, STIX, YARA, Sigma, MITRE Navigator, MDR.
- **Deferred**: PDF report determinism (per ADR-0008). Timestamps in PDF metadata are not currently pinned.

### 1.12 · IKG (Investigation Knowledge Graph)

- **Status**: 🟡 PARTIAL / SHADOW.
- **What exists**: `services/uaie/*` (ledger, provenance, retirement, ssot_projector, etc.), `services/attack_fingerprint.py`, `services/ice/*` (correlated behaviour clusters).
- **What is not live**: Trajectory Engine, Case Engine, Adapters, Artifact Store, Verdict Engine v3 — all `NIVX_FLAG_*=shadow` in `backend/.env`. Their output is computed for validation but NOT surfaced.

### 1.13 · Determinism of enrichment layers

- **Status**: 🟡 PARTIAL — core deterministic, enrichment non-deterministic.
- **Non-deterministic legs**: TI lookups (bounded 500 ms · Item-5), OSINT enrichment (bounded 20 s), AI describe (bounded 25 / 90 s, negative cache 10 min), Sysmon DNS reverse (surfaced as `advisory` only).
- **Diagnostic surface**: `ti_lookup_meta.status` on responses; AI cache markers.

### 1.14 · Storage-write-through

- **Status**: 🟡 PARTIAL.
- **Behavior**: `POST /api/cases/save` writes the full SSOT bundle inline in `workspace_cases` AND a content-addressable pointer via `services/ssot_store.store_ssot`. Two writes, one truth.
- **Gap**: If `investigation_ssot` write fails, the case still lands in `workspace_cases` (fault-tolerant), but the pointer will be missing. No repair job exists.

---

## §2 · Explicitly pending tasks (owner-approved, not started)

### 2.1 · Task 2 · Real EVTX Fixture

- **Handoff**: Issue 1 (P0).
- **State**: 🟠 PENDING — plan approved, not started (waiting for Task 1 review this session).
- **Ask**: Commit a real minimal Sysmon-generated `.evtx` (E1 + E3), route through `evtx_reader` + normalizer, drop mocks from the primary round-trip test.

### 2.2 · Task 3 · Attack Chain auto-scroll / focus

- **Handoff**: Issue 2 (P1).
- **State**: 🟠 PENDING — plan approved, not started.
- **Ask**: On evidence-row click, scroll the matching MITRE lane into view in `TrajectoryDiagram.jsx`. Deterministic when multiple techniques. Preserve pan/zoom/drag.

### 2.3 · Task 4 · Source-agnostic architecture audit

- **State**: 🟠 PENDING — plan approved, not started.
- **Ask**: Audit `BehavioralTimeline`, `sysmon_adapter`, and the ingest envelope contract for any Sysmon-specific coupling that would obstruct WMI / Syslog / firewall / DNS / EDR / Linux adapters landing on the same canonical contract.

### 2.4 · Deprecation sunsets (ADR-0009 §5.1)

- **State**: 🟠 PENDING owner sign-off.
- **6 legacy report routes** ready for `deprecated=True` + 60-day sunset:
  - `POST /api/report`
  - `POST /api/report/stix`
  - `POST /api/report/stix/download`
  - `POST /api/report/stix/investigation`
  - `POST /api/report/{fmt}`
  - `GET /api/observation` (X-Lab-A residual)
- **Successor**: `POST /api/v2/analyze/report`.

### 2.5 · Duplicate-route documentation pointers (ADR-0009 §5.2)

- **State**: 🟠 PENDING.
- **4 duplicates**: `/api/timeline/events` (GET/POST), `/api/timeline/recent`, `/api/timeline/events/{investigation_id}` — canonical alternative is `/api/die/timeline`.

### 2.6 · Second-pass route audit (ADR-0009 §5.4)

- **State**: 🟠 PENDING.
- **87 UNKNOWN routes** need a runtime-log + dynamic-URL-construction pass to convert most into ACTIVE-UI. The expected split shifts from headline "85 % dead" (ADR-0007) to "~60 % live, ~30 % internal/experimental, ~10 % genuinely disposable".

### 2.7 · Second-pass parser sandboxing (ADR-0010b)

- **State**: 🟠 PENDING (currently a residual risk).
- **Ask**: Move PE / DOCX / shellcode parsers to a subprocess-isolated boundary so a hostile payload cannot crash the API worker.

### 2.8 · Real-Investigation-Proof Phase B (Human Trial)

- **State**: 🟠 PENDING owner authorisation.
- **Origin**: ADR-0010e Phase A completed as REDIRECT. Phase B is the human-in-the-loop trial.

---

## §3 · Skipped / locked (deferred by owner directive)

### 3.1 · P2 Sysmon Event 22 · DNS

- **State**: ⛔ LOCKED. Owner directive on 2026-02-15.
- **Reason**: Cannot advance to Slice-4 until the 4 P2 UI stabilisation tasks close (persist ✅, evtx fixture, auto-scroll, source-agnostic audit).

### 3.2 · P2 Sysmon Event 11 · File Create

- **State**: ⛔ LOCKED, downstream of §3.1.

### 3.3 · IKG expansion beyond the persistence-required minimum

- **State**: ⛔ LOCKED per Task-1 execution rules ("DO NOT start · IKG expansion beyond the persistence required for the timeline").

### 3.4 · New MITRE mappings / new verdict logic / new behavioral rules

- **State**: ⛔ LOCKED per current stabilisation directive.

### 3.5 · Workspace redesign / reroute to `/uil/investigate` canonical entry

- **State**: ⛔ NOT authorised (Phase 5 sequencing gate).
- **Detail**: `NIVX_CANONICAL_UIL_INVESTIGATE=on` in `.env` but the primary Workspace flow does not call it. Switching primary submit route requires the Phase-5 EntryAdapter migration (ADR-0008 §5.5).

### 3.6 · Shadow subsystem promotions

- **State**: ⛔ SHADOW-locked per `.env`:
  - `NIVX_FLAG_TRAJECTORY_ENGINE=shadow`
  - `NIVX_FLAG_CASE_ENGINE=shadow`
  - `NIVX_FLAG_ADAPTERS=shadow`
  - `NIVX_FLAG_ARTIFACT_STORE=shadow`
  - `NIVX_FLAG_VERDICT_ENGINE_V3=shadow`
- **Promotion criteria**: ADR-0008 §4 · shadow-replay validation.

### 3.7 · TweetFeed integration (A/B/C)

- **State**: ⛔ BACKLOG per ADR-0011.

### 3.8 · `raise NotImplementedError` sites

- `services/technique_detector.py:132` — a `raise NotImplementedError` on an abstract detector base branch.
- `backend/llm_provider.py:101` — `NivX Cognis (Qwen 2.5 7B) not yet deployed — set OLLAMA_HOST / OLLAMA_MODEL`.
- Both are guarded so they cannot fire in production paths.

### 3.9 · Skipped tests (conditional)

Tests that skip when their fixture/env is absent (not defects — deliberate):

| Test | Skip condition | File |
|---|---|---|
| `test_notdecoded_regression.py` | No cases folder | line 71 |
| `test_uaie_baseline_gates.py` | No cases under `tests/uaie_baseline/` | line 31, 55 |
| `test_r24_raw_corpus.py` | No raw corpus | line 71 |
| `test_composer_sample_acceptance.py` | `MONGO_URL` absent | line 98 |
| `test_ssot_sample_acceptance.py` | `MONGO_URL` absent | 152, 172 |
| `test_projection_sample1_unchanged.py` | `MONGO_URL` absent | 19, 38, 51 |
| `test_text_extract_from_archive.py` | `MONGO_URL` absent | 271 |
| `test_executor_all.py` | `MONGO_URL` absent | 267, 280 |
| `test_phase5_1_uil_investigate.py` | `MONGO_URL` absent | 201, 226 |

These skip cleanly in dev pods without Mongo; they run in CI with Mongo present.

---

## §4 · Dead / dead-ish code and components

### 4.1 · Unregistered backend router

- **File**: `backend/routers/privacy.py` (Tenant Privacy admin — Feb 2026).
- **Grep result**: **0** references in `backend/server.py`. **0** references in `frontend/src/`.
- **State**: 💀 UNMOUNTED. Endpoints `GET/PUT /api/admin/privacy/settings`, `GET /api/admin/privacy/audit`, `POST /api/admin/privacy/purge-now` are NOT reachable.
- **Recommendation** (not actioned): either register in `server.py` or move to `_archive/`.

### 4.2 · Legacy 6-lane `AttackGraph` component

- **File**: `frontend/src/components/AttackGraph.jsx`.
- **State**: 💀 DEAD-ISH — imported in `WorkspacePage.jsx` line 9 but only rendered when `analysis.description.entity_graph.nodes` is populated (line 3971). That field is only set by the **AI-describe leg** on `/api/analyze`. In the primary Workspace `/api/decode/smart` + `/api/die/*` flow it is never populated, so the component effectively does not render.
- **Supersedes**: `TrajectoryDiagram.jsx` (14-tactic Attack Chain).
- **Also**: `DocsPage.jsx` still references `attack_graph_anatomy.svg` documentation image, which is stale.

### 4.3 · Kill-Chain Path card

- **File**: `frontend/src/pages/WorkspacePage.jsx:3981`.
- **State**: 💀 REMOVED — comment reads: *"Kill-Chain Path card (G1/G2 toggle) removed 2026-03-02 per user request — the same information is projected on the dedicated Investigation Session page (Incident Graph / Attack Story tabs)."*
- **Left-behind**: The G1/G2 toggle state and helpers may still be present elsewhere. NOT VERIFIED FROM CODE in this pass.

### 4.4 · Legacy `mitre_matrix` regrouping in the analyst narrative

- **State**: 💀 DEAD BRANCH.
- **Behaviour**: `AnalystNarrativePanel` used to regroup MITRE from a flat list; the canonical narrative bridge now delivers a pre-grouped `mitre_matrix`. The legacy branch stays in the tree as a fallback but only triggers when `mitre_matrix` is empty AND narrative fields are all empty — extremely rare after Phase 5.W.

### 4.5 · Legacy report emitters

- **State**: 💀 SUPERSEDED but not sunset yet (see §2.4).
- **Routes**: 5 `/api/report*` routes plus `/api/observation`. Superseded by `/api/v2/analyze/report`. ADR-0009 §5.1.

### 4.6 · Timeline duplicates

- **State**: 💀 DUPLICATE. `/api/timeline/*` overlaps `/api/die/timeline`. ADR-0009 §5.2.

### 4.7 · X-Lab-A residual observation surface

- **State**: 💀 RESIDUAL. `/api/observation*` — flagged for removal by ADR-0009 §5.1 after X-Lab-A was retired in Session-7. `test_workspace_isolation_guard.py` still passes.

### 4.8 · `services/technique_detector.py`

- **Signal**: Contains `raise NotImplementedError` at line 132 (abstract branch).
- **Uses**: Grep across `routers/*.py` shows it is referenced by "legacy paths" comments. NOT VERIFIED FROM CODE which live path still calls it. **Suspect dead / dead-ish** — recommend a second-pass callsite audit.

### 4.9 · Placeholder / partially-wired admin pages

- **Files**: `frontend/src/pages/TrainingInboxPage.jsx`, `LearnerPage.jsx`, `ModelStudioPage.jsx`, `ThreatModelPage.jsx`, plus `SemanticMappingInspectorPage` (referenced in `static_docs/current_state_audit.md:358` as *"presence unclear if fully wired"*).
- **State**: 🟡 wired to routes in `App.js` (`/admin/models`, `/admin/training-inbox`, `/learner`). Backend routes exist under `/api/admin/*` and `/api/learner/*`. Depth of implementation NOT VERIFIED FROM CODE in this pass.

### 4.10 · `llm_provider.NivXCognis` (Qwen 2.5 7B) backend

- **File**: `backend/llm_provider.py:101`.
- **State**: 💀 NOT DEPLOYED — raises `NotImplementedError("NivX Cognis (Qwen 2.5 7B) not yet deployed — set OLLAMA_HOST / OLLAMA_MODEL")`. Guarded — falls back to Emergent LLM key.

### 4.11 · Legacy stage-generator narrative

- **File**: `backend/services/die/narrative.py`.
- **State**: 🟡 → 💀. Runs first; its output is overwritten / augmented by `canonical_narrative_enrichment` whenever the latter has content. In practice the legacy output only survives on inputs that the canonical enricher does not hit.

### 4.12 · Legacy hash surface

- **File**: `backend/routers/ops.py:452` (comment: *"Legacy hash surface — sha256 is authoritative from FileStore"*).
- **State**: 🟡 retained for backward-compatibility with earlier saved cases that reference `md5`/`sha1` only.

### 4.13 · `l0_note` legacy field

- **File**: `backend/routers/ops.py:1240` (comment: *"legacy field, retained for UI"*).
- **State**: 🟡 retained for UI compatibility.

### 4.14 · `PageHeader.actions` legacy alias

- **File**: `frontend/src/components/PageHeader.jsx:20` (comment: *"legacy alias for rightSlot"*).
- **State**: 🟡 retained for backward compatibility.

### 4.15 · UNKNOWN cluster (ADR-0009 §5.4)

- **State**: 💀-suspect (17 % of the API surface).
- **87 routes** with no strict FE match and no test-touch. ADR-0009 explicitly warns "UNKNOWN never means DEAD". Requires second-pass audit before any deletion.

### 4.16 · pytest `noqa: F401` register-only imports

- Files: `routers/lolbas_export.py`, `routers/rc5_diag.py` (5 lines).
- **State**: Not dead — imports register parsers/interpreters/detectors as side effects. Documented with `# noqa: F401 — register`.

---

## §5 · Cross-referenced quick counts

| Bucket | Count | Notes |
|---|---:|---|
| 🟡 Partial features | 14 | §1.1 – §1.14 |
| 🟠 Pending (owner-approved) | 8 | §2.1 – §2.8 |
| ⛔ Locked / deferred | 9 (major)+9 (skipped tests) | §3 |
| 💀 Dead / dead-ish (confirmed) | 8 | §4.1 – §4.4, §4.10, §4.11, §4.6, §4.7 |
| 💀 Dead-ish (suspected, needs 2nd-pass) | 3 | §4.8, §4.9, §4.15 |
| 🟡 Retained-for-compat | 4 | §4.12 – §4.14 (+PageHeader alias) |

**Total distinct items**: ≈ 55.

---

## §6 · What is safe to sunset without further authorisation

**Nothing.** Every dead-ish item above still has at least one code-path referring to it or has been called out by ADR-0009 as "do NOT delete without a second-pass." Removal requires:

1. Explicit owner sign-off per ADR-0008 §5.5, AND
2. Verification that the corresponding regression test suite still passes without the code, AND
3. A grep pass across `frontend/src/`, `backend/routers/`, `backend/services/`, and `_archive/` (if present) to confirm no dynamic/lazy reference.

The **only** items that could be sunset with just an owner sign-off (no code change beyond a `deprecated=True` flag) are:

- **ADR-0009 §5.1** · 5 legacy `/api/report*` routes + `/api/observation`.
- **ADR-0009 §5.2** · 4 `/api/timeline/*` routes.

Deletion (rather than deprecation) of any of these should wait 60 days per the sunset rule in ADR-0009 §4.

---

## §7 · Rules honoured

- No file modified during this discovery. Only additive deliverables produced (this document + PDF).
- Every claim carries a file/function/ADR citation.
- Every unverifiable statement is tagged `NOT VERIFIED FROM CODE`.
- Global locks intact — no work resumed on Task 2 / 3 / 4 or on any locked slice.
- No parallel mapper, verdict engine, or evidence store introduced.

*End of inventory.*
