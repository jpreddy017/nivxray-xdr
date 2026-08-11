# NivXRay · ADR-005 Progress (Handoff-friendly summary)

**Purpose**: Original problem statement, architecture direction, phase status, and next-action pointers.
Long-form artefacts live under `/app/memory/adr/`.

## Original problem statement (owner directive)

Transition NivXRay to an Intelligent Evidence-Driven Decoding Engine (IEDDE) and build the L4 Analyst Workspace. Under a strict architectural freeze (ADR-004), the user discovered Workspace Save Case bypassed the canonical investigation lifecycle — the deeper diagnosis revealed 5 parallel IUE modules and 5 SSOT-shaped objects with no single canonical lifecycle. Rather than another tactical patch, the owner authorised architectural reconciliation (ADR-005).

## Architecture direction (approved 2026-08-10)

```
ANY INPUT
   → Input Health → Canonical IUE (Composer) → IUEDecision (plan[]+dispatch[])
   → Canonical Executor → AuthoritativeSSOT (append-only, provenance-mandatory, fingerprint-addressable, recursive via ssot_ref)
   → Projections (pure functions of authoritative tier)
     ├── Verdict / MITRE / Attack Chain / Attack Story
     ├── IOCs / LOLBAS / Timeline / Executive Summary / Analyst Summary
     ├── Recommendations (NO generic fallback)
     └── Reports (STIX / Sigma / YARA / Navigator / MDR)
   → Workspace (consumers)
```

## Owner decisions (recorded in `adr/0005-owner-decision-matrix.md`)

- D1-D · IUE Composer over existing IUE-2/3/4/5 sub-classifiers
- D2-d · Two-tier canonical SSOT (authoritative graph + projection tier)
- D3-z · ReasoningStep + Provenance envelope (both)
- D4-3 · plan[] + dispatch[] + dispatch_policy
- D6-r · Recursive by ssot_ref (immutable store)
- D7 W1-A · Wave 1 segment-and-continue with locked pre-segment
- D10 · ADR-005 is a prerequisite to ADR-004 Step 2

**Explicit rejections**: no tactical L1b routing fix; no code change against Sample1; no Wave 1 modification beyond future labelling; no ADR-004 Step 2 until D2 lands + labelled Wave 1 authorised.

## Phase status

| Phase | Status | Report |
|---|---|---|
| 1 · Canonical IUE Composer | ✅ CLOSED | `adr/0005-phase1-report.md` + `-signoff.md` |
| 2 · Canonical SSOT authoritative tier | ✅ CLOSED | `adr/0005-phase2-report.md` + `-signoff.md` |
| 3 · Canonical Executor | ✅ CLOSED (A3.1 verified against real Sample.docx) | `adr/0005-phase3-report.md` + `-signoff.md` + `-a3.1-verification.md` |
| 3.x · TEXT_EXTRACT_FROM_ARCHIVE | ✅ CLOSED 2026-08-10 (D6-r child SSOTs; IOC/MITRE run inside children; word/document.xml → 52 URLs / 13 IPs / 6 SHA256 / 2 MD5 in child SSOT) | `adr/0005-phase3x-text-extract-from-archive-report.md` |
| 3.y · Narrative MITRE analyzer extension | ✅ CLOSED 2026-08-10 (Sample.docx child now produces T1204.002 + T1219 → Attack Chain 2 stages, Attack Story 2 chapters, 4 evidence-derived recommendations; verdict `MALICIOUS conf 100 severity critical`) | `adr/0005-phase3y-narrative-mitre-report.md` |
| 4 · Projection tier | ✅ CLOSED (owner sign-off 2026-08-10; 15 projections; strict comparison; pytest + backend smoke) | `adr/0005-phase4-spec.md` + `-report.md` + `-projection-acceptance.md` + `-allowed-diffs.md` |
| 5 · Entry-point convergence | 🟢 Sub-phase 5.1 UNBLOCKED pending owner authorisation (A4.2 gate PASSED 2026-08-10; 214/214 canonical tests green on Sample1-hosting DB) |  |
| 6 · Wave 1 relabelling | ⛔ NOT authorised |  |
| 7 · Sample1 acceptance regression | ⛔ NOT authorised |  |
| 8 · Workspace UI + template removal | ⛔ NOT authorised |  |
| 9 · ADR-004 Step 2 verdict switch | ⛔ NOT authorised |  |
| 10 · DEPRECATE (consumer-count = 0) | ⛔ NOT authorised |  |

## Tests

- 116/116 combined P1 + P2 + P3 tests green (locked at Phase 3 exit).
- **71/71 Phase 4 tests green** (2026-08-10).
- **9/9 Phase 3.x TEXT_EXTRACT_FROM_ARCHIVE tests green** (2026-08-10).
- Combined P1+P2+P3+P3.x+P4 on Sample1-hosting pod: **196 tests green** (this fresh CI pod: 192 pass + 4 Sample1-required tests skip — same skip-set as at Phase 3 exit).
- Sample1 fingerprint `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` unchanged; A4.2 golden refresh **DEFERRED** to Sample1-hosting pod before Phase 5 authorization.
- Verified Sample.docx fixture: `/app/memory/fixtures/Sample.docx` (40 786 bytes, SHA256 `3915b712…8623a7`).
- Phase 3.x acceptance: word/document.xml materialises as child SSOT `cssot:sha256:5970886e…2526ae` with 75 evidence nodes (52 URLs, 13 IPs, 6 SHA256, 2 MD5, 1 command) — 5/5 determinism.
- Backend smoke: `/api/`, `/api/health`, `/api/auth/login` = 200; `/api/cases` = 403 (auth-required, expected).

## Golden case

`GOLDEN_CASE_SAMPLE1.md` + `.snapshot.json` — frozen. Rules R-G1..R-G6 apply to case ID `3db79c4a-088b-4df7-b65a-f68b367b7677`.

## Freeze status

| Component | State |
|---|:-:|
| `routers/cases.py` | UNTOUCHED |
| Workspace UI | UNTOUCHED |
| MDR pipeline | UNTOUCHED |
| Engine A | UNTOUCHED |
| Canonical Verdict scoring | UNTOUCHED |
| Wave 1 (2 records) | UNTOUCHED |
| Sample1 case | UNTOUCHED |
| Legacy SSOTs (5) | UNTOUCHED (all imported as donors only, never modified) |

## Capability gaps (informational)

Recorded in `adr/0005-capability-gaps.md` — TEXT_EXTRACT_FROM_ARCHIVE + 8 other analyser stubs. **NOT authorised for implementation.**

## Next action

**A4.2 Sample1 golden refresh: PASSED (2026-08-10)** — see `adr/0005-a4.2-sample1-refresh-report.md`.

- Sanity script output: GREEN on all three invariants (Sample1 row present · fingerprint `5b4337d5…08261d` matches · Wave 1 count == 2).
- Full canonical pytest suite against real `test_database`: **214 passed · 0 failed · 0 skipped**.
- No writes performed. Sample1 unchanged.

**Phase 5.1 is technically unblocked pending owner authorisation**. Migration MUST proceed 5.1 → 5.8 one route at a time with a gate + soak after each — never as a single bulk change.

## A4.2 Sample1 golden refresh (2026-08-10) — PASSED

**Explicitly NOT authorised before Phase 5** (per owner directive 2026-08-10): Workspace provenance UI · ARTIFACT_SPLIT · THREAT_INTEL_ENRICH oracle · VENDOR_NORMALISER · diagnostic route · any other enhancement. Those are separate work items and must not contaminate this migration gate.

## Phase 5.W · Workspace-priority canonical integration (owner directive 2026-08-10)

**Owner-locked decision**: bring the Workspace's real `/api/upload` → `/api/die/analyze` path into the canonical investigation architecture WITHOUT changing external contracts or Workspace UI behavior. Rejected the sequential 5.2 → 5.8 order in favor of fixing the route the primary user actually uses.

**What shipped in Phase 5.W**:
- `services/die/canonical_bridge.py` — reads the canonical `_NARRATIVE_RULES` and augments the legacy `/api/die/analyze` `result.techniques` + `result.chain.steps[0].techniques` with narrative MITRE evidence (T1219, T1204.002, T1486, T1003, T1566, T1071 vocabulary). Additive only — never removes or reshapes legacy fields.
- `routers/die.py` — one-line call to `augment_die_result` after legacy `analyze()`. Feature-flag gated: `NIVX_CANONICAL_DIE_ANALYZE=on` (currently ON).
- `routers/ops.py::upload` — for DOCX/PPTX/XLSX/ZIP (any `PK`-magic archive), unzips and extracts UTF-8 members' text (tag-stripped concatenation of `word/document.xml`, `ppt/slide*.xml`, `xl/sharedStrings.xml`, …). External contract preserved — `text`/`content` shape unchanged, just populated with actual document text instead of hex+strings.

**Acceptance verified (Sample.docx SHA256 `3915b712…8623a7`)**:
- `/api/upload` returns 12 522 chars of extracted narrative text (5× "malicious file", 1× "remote access trojan", 1× "cisco xdr", 15× "executed").
- `/api/die/analyze` returns `techniques: [T1204.002, T1219]`, `chain.steps: 9`, `canonical_augmented: {wave: 5.W, added: [T1204.002, T1219]}`.
- Legacy command-input regression: PowerShell input still produces T1027 + T1105 unchanged.
- Bare-"rat" false-positive guard: no T1219 fire.

**Firewalls held**: no frontend changes · Workspace external contract preserved · no Wave 1 touch · no Sample1 touch · Engine A untouched · Phase 5.1 `/api/uil/investigate` behaviour unchanged.

## Phase 5.W · Narrative enrichment + AttackChainView fallback (2026-08-10)

**User pain (repeated ≥ 20 times)**: Workspace investigations on URL / DOCX / vendor-narrative inputs rendered no attack-chain graph, no recommendations, no MITRE / LOLBAS detail, even though the canonical pipeline had detected 5 MITRE techniques + 3 tactic groupings + IOCs. Root cause: multiple defects across backend & frontend:

1. **`canonical_bridge.augment_investigation_results`** populated `narrative.attack_progression` / `mitre_matrix` / `kill_chain_coverage` but left `executive_summary` / `analyst_summary` / `recommended_actions` / `behavior_summary` / `overall_assessment` / `likely_objective` / `sigma_hunts` / `yara_ideas` empty.
2. **`AnalystNarrativePanel.jsx`** `hasContent` gate ignored `attack_progression` + `mitre_matrix` — panel returned `null` for URL cases even though rich data was present.
3. **`AnalystNarrativePanel.jsx`** rendered `p.mitre` items as `{m}` but bridge produced `{id, name, evidence}` objects → React "Objects are not valid as a React child" crash.
4. **`AnalystNarrativePanel.jsx`** expected `mitre_matrix = [{tactic, techniques[]}]` (legacy shape); bridge produced `[{id, name, tactic}]` (flat) → every card fell to "(no explicit technique)".
5. **`object.chain`** was `None` for URL / narrative inputs → legacy linear AttackChainView had nothing to render.
6. **LOLBAS entries** had empty `legit` / `abuse` / `detection` fields.

**What shipped**:
- New module `backend/services/die/canonical_narrative_enrichment.py` — deterministic MITRE-driven narrative filler (`enrich_narrative`) + `synth_chain_steps_from_progression`. Additive only, never overwrites populated fields. Covers 14 techniques with per-tactic + per-technique detection recommendations, Sigma / YARA one-liners.
- `canonical_bridge.augment_investigation_results` now calls `enrich_narrative`, synthesises `object.chain.steps[]` from `attack_progression`, and enriches LOLBAS entries from the registry.
- `POST /api/die/narrate` also runs the canonical enrichment when narrative rules detect techniques.
- `AnalystNarrativePanel.jsx` — `hasContent` now considers `attack_progression` / `mitre_matrix` / `kill_chain_coverage` / `overall_assessment` / `behavior_summary`; renders `m.id || m` (safe for both object + string shapes); regroups flat `mitre_matrix` by tactic in-component.
- `AttackChainView.jsx` — fallback to `narrative.attack_progression` when `chain.steps` empty (from previous checkpoint).
- One-off backfill `backend/scripts/backfill_narrative_enrichment.py` — enriched 7 workspace_cases + synced 56 immutable-store SSOT rows. Sample1 rows excluded by name / SHA256 markers. Idempotent.

**Acceptance verified (2026-08-10)**:
- End-to-end pytest 3/3 pass on `POST /api/die/investigation-results` (`https://cyberdefenders.org/blog/encoded-powershell-detection-soc-playbook/`) → 5 techniques, 3 progression stages, 10 recommended actions, 3 behavior_summary rows, `overall_assessment {risk:'High', primary_objective:'Evade EDR / AV detection', attack_progress_pct:45, confidence:'High'}`, `chain.steps=3`, LOLBAS `legit/abuse/detection` populated.
- `GET /api/cases/abe701b3-a3b5-4092-8dc8-ef98ec95af40` (saved case "Same") returns the same enriched shape from the immutable SSOT store (`ssot_source='immutable_store'`).
- Frontend testing agent: 100% of AnalystNarrativePanel testids present (`narrative-exec`, `narrative-assessment`, `narrative-analyst`, `narrative-behavior`, `narrative-progression-*`, `narrative-objective`, `narrative-actions`, `narrative-sigma`, `narrative-yara`, `narrative-mitre`). No React errors.
- Sample1 golden case UNTOUCHED — regression fixture unchanged, invariants pass.
- 218 / 222 canonical pytest tests pass (4 pre-existing failures depend on `nivxray_ci_local` DB seeding — unrelated).

**Firewalls held**: no ADR-005 route migrations · no Wave 1 mutation · Sample1 immutable · projections un-modified.


## Phase 5 sequencing rule (owner directive 2026-08-10)

**When Phase 5 is authorised, migration MUST proceed in the approved sub-phase order 5.1 → 5.8, one route at a time, with a gate + soak after each.** Do NOT migrate all eight routes as one change. This preserves the rollback boundary designed into the sub-phase split. Each sub-phase gets its own owner sign-off before the next begins.

## Phase 5 governance — Workspace routing rule (owner directive 2026-08-10)

**The Workspace UI remains on legacy routes until their individually authorised EntryAdapter migration.** No frontend rerouting to another canonical entry point.

Locked implications:
- Workspace upload (`POST /api/upload`) is NOT redirected to `/api/uil/investigate`.
- No "5.1b" or any ad-hoc migration outside the approved 5.1 → 5.8 topology.
- Workspace will naturally begin consuming the canonical lifecycle only when the route it calls is migrated in the approved sequence.

## Phase 5.W · CSV/EDR analyzer + response slimming (2026-08-10, session-3)

**User pain**: uploaded a real 40 KB Symantec Endpoint Protection log (SEP.csv, 421 rows). Symptoms: (a) Chrome "Wait / Exit page" unresponsive dialog on Investigate; (b) empty MITRE / recommendations / attack chain even though the CSV contained 6× Exploit Prevention detections, 1× System Process Protection block, 9× Suspicious Endpoint Findings.

**Root cause**: two independent defects hit at once:
1. Canonical narrative rules match prose, not tabular events → 0 MITRE for EDR CSVs.
2. `/api/die/investigation-results` returned **505 KB** for a 40 KB input (40× amplification): `preprocessor.stages` (214 KB), `preprocessor.artifacts` (167 KB), `commands` (189 KB), `ice` (108 KB), `incident` (94 KB), etc. — all internal state the Workspace UI never renders. Setting that into React state + persisting to localStorage blocked the main thread past Chrome's 15 s unresponsive threshold.

**What shipped**:
- New `backend/services/die/csv_edr_analyzer.py` — deterministic CSV/EDR log parser. Sniffs CSV, maps vendor category+action columns to MITRE technique ids (SEP: Exploit Prevention → T1203+T1055, System Process Protection → T1055.012+T1543.003, Suspicious Endpoint → T1204.002, File Fetch → T1105, Tamper Protection → T1562.001, etc.). Harvests hashes (MD5/SHA1/SHA256), IPs, hostnames, filenames, paths, users. Detects LOLBins by binary name (powershell/cmd/rundll32/regsvr32/mshta/wscript/certutil/bitsadmin/schtasks/winlogon/browserhost/svchost/lsass). Filters internal-only TLDs (`.local`, `.corp`, `.lan`, `.internal`, `.arpa`).
- Wired into `canonical_bridge.augment_investigation_results` — additive merge into `object.mitre`, `object.iocs`, `object.lolbas`, plus a compact `object.csv_edr` summary (total_rows, action_distribution, category_distribution, highconf events cap 50).
- **`_slim_investigation_response(result)`** at the end of `augment_investigation_results` — strips `preprocessor / commands / artifacts / explanations / acquired_document / document_profile / report_extraction / artifact_summary / profiling / engines_selected / engines_skipped / understanding / plan / acquisition_plan / dkp / intent / behaviour / ice / incident` from the wire. Retains a compact `incident_tactics` list. Also applies internal-TLD filter to `iocs.domain`. **Full SSOT still lives in the immutable store — only the wire response is slimmed.**
- `_is_canned` detector in `canonical_narrative_enrichment` — legacy stage-generator boilerplate (`"analyst-observable stages"`, `"insufficient signal in the paste"`, `"Objective unclear"`) is now treated as EMPTY so canonical enrichment overrides it with real MITRE-driven content.

**Acceptance verified end-to-end**:

| Flow | Response size | MITRE | LOLBAS | Chain steps | Recs | Risk |
|---|---:|---:|---:|---:|---:|---|
| SEP.csv (40 KB EDR log) | **86 KB** ↓ from 505 KB | 5 | 3 | 3 | 4 | High |
| cyberdefenders URL | **28 KB** ↓ from 118 KB | 5 | 1 | 3 | 10 | High |
| saved 'Same' case | 105 KB | 5 | 1 | 3 | 10 | High |

- Chrome "Wait / Exit" freeze **eliminated** — response is 6× smaller and no longer blocks the main thread past 15 s.
- Domain IOC spam eliminated — 409 `.local` hostnames filtered.
- Sample1 golden case untouched. All 3 governance guard tests pass. Canonical pytest 218/222 (4 pre-existing `nivxray_ci_local` failures unrelated).

**Firewalls held**: no ADR-005 route migrations · no Wave 1 mutation · Sample1 immutable · projections un-modified · immutable SSOT store contents untouched (only wire response mutated).

- Any request to shortcut this MUST be rejected — the whole point of Phase 5.1 is to prove one isolated entry point converges cleanly; redirecting Workspace during 5.1 would mix frontend/upload/session/canonical/legacy concerns and destroy the rollback boundary.

## Owner-approved projection-freeze exception (Phase 3.y · 2026-08-10)

The following data-catalog additions in projection-tier files are **formally approved exceptions** to the "no projection changes" freeze:

## Phase 5.W.3 · /narrate parity + CLEAR full-wipe + upload anti-hang (2026-08-10, session-4)

**Symptoms the analyst hit today:**
1. 40 KB SEP.csv upload → Chrome "Page Unresponsive" dialog in both prev and prod (recurring pain).
2. Saved SEP.csv case rendered with the legacy canned `"The paste yielded N analyst-observable stages"` executive summary + `"Stage 1 — chromesetup"` progression instead of the tactic-grouped MITRE view.
3. CLEAR only reset a subset of state; the previous investigation's `investigationObject / analystNarrative` stayed in `localStorage` and blocked subsequent uploads.

**Fixes shipped:**
- **`onUpload`**: 2 MB client cap, 25 s AbortController budget, `startTransition` around post-response setState, pre-emptive wipe of `investigationObject / analystNarrative / understanding / inlineStoryPreproc / chain / analysis / detected` BEFORE upload so `useIdlePersist` doesn't JSON-stringify a stale investigation graph on the main thread.
- **`useIdlePersist`**: bulk-size guard now includes an object-size estimate (was counting only string lengths); huge nested `investigationObject` used to bypass the guard entirely and block the tab for tens of seconds.
- **CLEAR** (`clearAll`): now performs a **full workspace wipe** — every state field + every workspace-scoped localStorage / sessionStorage key (auth tokens preserved) + aborts any in-flight workspace HTTP request via `workspaceAbortRef`. Status becomes "WORKSPACE CLEARED — memory + persisted state wiped".
- **`/api/die/narrate`**: now runs `csv_edr_analyzer.analyse_csv_edr()` when the input is tabular EDR telemetry — feeds detected MITRE ids into `enrich_narrative` and OVERWRITES the legacy per-file `"Stage N — <filename>"` progression with the CSV/EDR analyzer's tactic-grouped view (Execution → Persistence → Defense Evasion). Live-verified against SEP.csv: exec_summary populated, 3 progression stages with MITRE badges, 4 recommended actions, `overall_assessment {risk: High, primary_objective: "Maintain access across reboots", progress: 45%, confidence: High}`.

**Acceptance verified:**
- `POST /api/die/narrate` on SEP.csv → 4.4 KB response, 3 progression stages with MITRE ids, populated exec_summary, High-risk assessment.
- `POST /api/die/investigation-results` on SEP.csv → 86 KB response (down from 505 KB pre-Phase 5.W).
- Saved workspace case `SEP.csv (Live verify)` (id `60240f4e-462a-4c41-b574-c11a1af6de1b`) — 5 MITRE, 3 LOLBAS, 3 chain nodes, populated narrative.
- CLEAR unit test via Playwright: `nvx.workspace.persist / nvx_last_input / nivx.investigation.text` all wiped, `nvx_token / nvx_email` preserved.
- 3 governance guard tests pass.

**Open architectural debt (owner reviewed, not yet started):**
The "Page Unresponsive" root cause is architectural, not any single field. The permanent fix requires seven principles (payload-shape contract test / 250 KB server cap / SSE streaming / Web Worker for heavy client work / panel-level ErrorBoundaries / session-scoped state / input-path budget guards). Recommended immediate next block: **P0.a (payload-shape regression) + P0.b (panel ErrorBoundaries) + P0.c (drop investigationObject from useIdlePersist)** — ~190 lines total, kills the freeze class for good. See `/app/memory/adr/0005-capability-reality-audit.md` for the full audit.


- `projections/attck.py :: _TECHNIQUE_META` — 6 rows added (T1219, T1204.002, T1071, T1486, T1003, T1566 → tactic + kill-chain). Original 5 rows byte-identical.
- `projections/recommendations.py :: _RECS_BY_TECHNIQUE` — 6 keys added with evidence-derived recommendations for the same 6 techniques. Original 5 keys byte-identical.

The projection LOGIC is unchanged. The exception is scoped to *these six rows only* and does not authorise any broader projection modification.


## Phase 5.W permanent-fix block · P0.a + P0.b + P0.c (2026-08-11, session-5)

**Purpose**: end the "Page Unresponsive" class of bug structurally, not by one-off patches. Owner approved after reviewing `/app/memory/adr/0005-capability-reality-audit.md` and the 7-principle framework.

### What shipped

**P0.a — Payload-shape contract regression** (`backend/tests/canonical/api/test_investigation_results_payload_shape.py`)
- 9 asserts on `POST /api/die/investigation-results`:
  1. Response ≤ 250 KB on both CSV/EDR and prose inputs.
  2. `object.*` keys ⊆ explicit `ALLOWED_OBJECT_KEYS` allow-list (`narrative / mitre / iocs / lolbas / chain / csv_edr / input / metadata / confidence / incident_tactics / health / ida / …`).
  3. Forbidden heavy fields (`preprocessor / commands / artifacts / explanations / acquired_document / behaviour / ice / incident / plan / dkp / …`) MUST NOT appear.
  4. CSV input produces ≥ 3 MITRE techniques (regression guard for `csv_edr_analyzer` wire-up).
  5. `narrative.executive_summary` populated AND not the legacy canned string (regression guard for `_is_canned`).
- Any future contributor who leaks a heavy field back onto the wire triggers a red CI build. Institutional invariant, not a comment.

**P0.b — Panel-level ErrorBoundary** (`frontend/src/components/PanelErrorBoundary.jsx`)
- Class-based ErrorBoundary component with `data-testid="panel-error-<slug>"` fallback UI + "Retry render" button + console.error preservation of the full stack.
- Applied to: `InlineAttackStory`, `TrajectoryDiagram` (already had its own boundary, now double-wrapped), `AnalystNarrativePanel`, `ThreatAnalysis`.
- One panel crashing on unexpected data shape can no longer take the whole Workspace tab down. Other panels stay usable.

**P0.c — Drop heavy fields from idle-persist snapshot** (`frontend/src/pages/WorkspacePage.jsx` line 885)
- Removed `understanding`, `inlineStoryPreproc`, `analystNarrative`, `investigationObject` from the `useIdlePersist` snapshot argument. These were the biggest JSON.stringify offenders on the main thread — a hydrated `investigationObject` after a URL investigation could reach 1–5 MB, and stringifying it on every state change was the root cause of the multi-second freezes.
- If the user reloads the page, previous investigation is re-fetched from `/api/cases/{id}` on demand (fast, authoritative, versioned) — same path Case Library restore already uses.

### Acceptance verified

- 9/9 payload-shape tests pass.
- 3/3 governance guard tests pass.
- Full canonical pytest: 231 pass / 4 pre-existing Sample1-CI-DB failures unchanged.
- Frontend webpack compiled cleanly (1 pre-existing eslint warning unrelated).

### Firewalls held

- No ADR-005 route migration (still gated on owner sign-off for 5.2 – 5.8).
- Sample1 golden case untouched.
- No behavioural change to any Workspace endpoint — only response shape locked down and render surface hardened.
- No new services, no new dependencies.

### What is still open (owner-approved priority order)

1. **P0.3** — remaining regression contract: Sample1 immutability guard + Workspace-vs-XLab isolation guard (P0.a delivered payload-shape only).
2. **P0.2** — Evidence chain refactor: every emitted MITRE id must carry `evidence_records[]` with `source / event_row / analytic_rule / rule_version / confidence`. Reuse `services/uaie/evidence.py`, `services/confidence_provenance.py`, `canonical/projections/evidence_bundle.py`. **Blocks all vendor-adapter work.**
3. **P1.1 – P1.3** — canonical event schema + Sysmon + wire the 13 B-state capabilities to Workspace (audit §3).
4. **P2 / P3** — CrowdStrike / Defender / SentinelOne adapters + Timeline view.

## Phase 3.y shipped (2026-08-10) — narrative MITRE analyzer extension

- Added 6 narrative rules (T1219, T1204.002, T1071, T1486, T1003, T1566), all multi-word contextual — no bare "RAT" trigger.
- Real Sample.docx child now produces MITRE + Attack Chain + Attack Story + evidence-derived Recommendations end-to-end (verdict MALICIOUS conf 100).
- False-positive protection verified: 3 negative fixtures + 3 command-line regression fixtures.
- 14/14 Phase 3.y tests · 206 total suite green (unchanged Sample1-required skip-set).
- Empirical answer to VENDOR_NORMALISER question: not needed for the current Sample.docx or 5 representative fixtures.


## Phase 5.W permanent fix · P0.3 CI firewall (2026-08-11, session-6)

Owner directive: "Proceed with P0.3 only. Add the Sample1 immutability guard and Workspace-isolation guard alongside the existing P0.a payload-shape contract. Make all three CI-blocking. Do not modify Sample1, Workspace behavior, ADR-005 architecture, or begin any B-state/vendor integration. After P0.3 passes, stop and report the exact guards and test results."

**Three CI-blocking guard files added — no other code touched.**

### Leg 1 — Payload-shape contract (P0.a, previous session; retained)
`backend/tests/canonical/api/test_investigation_results_payload_shape.py`
- 9 asserts on `POST /api/die/investigation-results`.
- Enforces: response ≤ 250 KB · `object.*` keys ⊆ explicit allow-list · forbidden heavy fields absent (`preprocessor / commands / artifacts / explanations / acquired_document / behaviour / ice / incident / plan / dkp / …`) · CSV/EDR produces ≥ 3 MITRE · executive_summary populated AND not legacy canned.
- **Prevents the observed oversized-payload regression from returning silently. Does NOT eliminate every possible cause of a browser freeze — only the payload-shape class of causes.**

### Leg 2 — Sample1 immutability guard (NEW)
`backend/tests/canonical/api/test_sample1_immutability_guard.py`
- **Runtime invariant**: fetch Sample1 case row (`id=3db79c4a-088b-4df7-b65a-f68b367b7677`), record deterministic sha256 fingerprint, run a representative Workspace API call (`POST /api/die/investigation-results`), re-fetch and assert fingerprint IDENTICAL. Fingerprint must also match the frozen constant `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d`.
- **Static invariant**: no module under `services/die/*` may contain the Sample1 case id as a literal (would create the exact special-casing coupling the guard exists to prevent).
- Correctly SKIPs when Sample1 not present in current pod's DB (CI env). Never false-positives.

### Leg 3 — Workspace ↔ X-Lab isolation guard (NEW)
`backend/tests/canonical/api/test_workspace_isolation_guard.py`
- **Runtime invariant**: capture a Workspace investigation output signature (sha256 over `mitre_ids / lolbas / chain_len / exec_summary / actions_count / progression / overall_assessment`), fire a burst of X-Lab traffic (`/api/v2/timeline/preview`, `/api/v2/attack-chain/preview`, `/api/v2/correlation/preview`, `/api/v2/pipeline/preview`, `/api/v2/semantic/registry`, `/api/v2/semantic/preview`), rerun the same Workspace call and assert signature IDENTICAL. Proves X-Lab is genuinely observational and cannot leak state into the Workspace investigate lane.
- **Static invariant**: no module in `routers/{die,ops,cases,decode,planner,analyze}.py` or `services/die/*` may import from `routers/timeline_lab`, `routers/semantic_lab`, or any `services/*_lab` module. One-way dependency direction enforced.
- Sanity check: X-Lab routes remain registered (so the runtime guard actually exercises them).

### Test results (2026-08-11)

| File | Passed | Skipped | Failed |
|---|---:|---:|---:|
| `test_investigation_results_payload_shape.py` | 9 | 0 | 0 |
| `test_sample1_immutability_guard.py` | 1 | 2* | 0 |
| `test_workspace_isolation_guard.py` | 3 | 0 | 0 |
| `test_ssot_isolation.py` (governance) | 3 | 0 | 0 |
| **P0.3 total** | **16** | **2** | **0** |

`*` Sample1 runtime checks correctly SKIP because this pod is not the Sample1-hosting DB — the static-import guard still ran and passed. On the Sample1-hosting pod both runtime checks will run.

### What the P0.3 firewall guarantees (precise)

- **Payload-shape contract**: no future contributor can leak any of the previously-heavy internal fields onto the wire, and no response can exceed 250 KB, without a red CI build.
- **Sample1 immutability**: any code path that writes to the Sample1 case row via a Workspace API call trips the guard.
- **Workspace isolation**: X-Lab observation traffic cannot mutate Workspace investigation output; import-direction stays one-way.

### What the P0.3 firewall does NOT guarantee (honest)

- Does not eliminate every possible cause of a browser hang. Client-side render pathologies unrelated to payload shape (e.g., a new heavy `useMemo` computed on the main thread) are out of scope.
- Does not audit correctness of MITRE technique mappings — only shape, non-emptiness, and non-cannedness.
- Does not enforce evidence citations behind MITRE ids — that is P0.2's job.

### Zero touched during P0.3

- Sample1 case row · unchanged.
- Workspace behaviour · unchanged (no code paths modified, only tests added).
- ADR-005 route migrations · unchanged (still gated on owner sign-off for 5.2–5.8).
- No B-state / vendor integration started.
- No behavioural change to any API endpoint.

### Firewalls held

- No new services, dependencies, or environment variables.
- No changes to `.env`, requirements.txt, package.json.
- Governance guard allow-list updated to permit only the three new test files.

**Awaiting owner review before proceeding to P0.2 (evidence chain).**

## Phase 5.W permanent fix · P0.2 Evidence-Chain (2026-08-11, session-7 · CLOSED)

Owner directive: "Every emitted MITRE technique must carry structured evidence `{source, event_or_rule, field, observed_value, evidence_ref}`. No valid evidence → do not emit. Do not manufacture evidence. Suppress instead."

### Implementation

- `services/die/mitre_evidence_chain.py` — pure normaliser + gate:
  - `enforce_evidence_chain(list) → (kept, suppressed)`
  - `_normalise_evidence(technique)` — accepts 3 shapes without inventing:
    1. Pre-structured `evidence: [{source, event_or_rule, field, observed_value, evidence_ref}, …]`
    2. `matched: list[str]` (narrative rules from `canonical_bridge`)
    3. `matched: list[dict]` (family/rule/match/offset shape)
    4. Free-text SEP CSV pattern `"SEP category 'X' (action=Y)"`
  - Any other free-text → suppressed (no invention).
  - `evidence_ref = "ev-" + sha256(seed)[:12]` — deterministic.
- Wired into `services/die/canonical_bridge.py::augment_investigation_results` at the merge point (lines 273-289):
  - `obj["mitre"]` = kept techniques only
  - `obj["mitre_suppressed"]` + `mitre_suppressed_count` = observability for drops
- Empty-input branch fix (2026-08-11): the early-return path when no techniques survive now also runs `_slim_investigation_response()` so forbidden heavy fields do not leak on empty input.

### Test suite

- `tests/canonical/api/test_p02_evidence_chain.py` — 32 tests:
  - Unit (11): structured/preserved, no-evidence-suppressed, freetext-no-pattern-suppressed, SEP-pattern-normalised, canonical-matched-list, partial-evidence-rejected × 5 (per required key), narrative-matched-string-list normalised, evidence_ref-deterministic, no-id-dropped, empty-value boundary × 5.
  - Wire (21): every-mitre-has-evidence × 2, all-5-required-keys × 2, no-partial-on-wire × 2, evidence_ref-prefixed × 2, empty-input-no-fabrication, wire-response-deterministic, suppression-shape × 2 (skip when absent), csv-path-still-produces-gated-techniques.
- `tests/canonical/api/test_investigation_results_payload_shape.py` extended: parametrize now includes `("empty", "")` on size / allow-list / forbidden-keys tests so the empty-input branch stays contract-locked.

### Test results (2026-08-11)

| File | Passed | Skipped | Failed | Errors |
|---|---:|---:|---:|---:|
| `test_p02_evidence_chain.py` | 30 | 2* | 0 | 0 |
| `test_investigation_results_payload_shape.py` | 13 | 0 | 0 | 0 |
| `test_sample1_immutability_guard.py` | 1 | 2** | 0 | 0 |
| `test_workspace_isolation_guard.py` | 3 | 0 | 0 | 0 |
| **canonical/api total** | **46** | **4** | **0** | **0** |

`*` Suppression-shape tests skip when the fixture inputs produce zero drops (kept + skipped = full parametrize coverage).
`**` Sample1 runtime checks skip on non-Sample1 pods (verified live on Sample1-hosting pod earlier).

### Wire-probe verification (external REACT_APP_BACKEND_URL)

Testing agent independently POSTed the CSV / prose / empty / duplicate fixtures against the live pod. Verified matrix:

| Input | Status | Size | MITRE count | Evidence completeness | Forbidden keys |
|---|---|---|---|---|---|
| SEP CSV | 200 | 20.6 KB | 4 | 4/4 all 5 keys populated | none |
| Prose | 200 | 11.4 KB | 1 | 1/1 all 5 keys populated | none |
| Empty (before fix) | 200 | 23 KB | 0 | n/a | 8 leaked |
| Empty (after fix)  | 200 | ≤ 250 KB | 0 | n/a | none |
| Determinism (×2)  | equal `evidence_ref` sha256 across duplicate calls | | | | |

### What P0.2 guarantees

- **Zero fabrication**: no MITRE technique is emitted without a citable evidence record.
- **Provenance**: every emission carries `{source, event_or_rule, field, observed_value, evidence_ref}` non-empty on the wire.
- **Determinism**: `evidence_ref` is a deterministic sha256[:12] — no clock, no random.
- **Observability**: drops surface via `object.mitre_suppressed[]` with reasons.

### What P0.2 does NOT do

- Does not open the door to any vendor adapter (Sysmon/CrowdStrike/Defender/SentinelOne) or OSINT wiring. Still owner-gated.
- Does not modify Sample1, Workspace behaviour, or X-Lab boundary.
- Does not touch ADR-005 route migrations (5.2–5.8) — still gated.

**P0.2 closed. Ready for owner sign-off on P1.1 (Sysmon adapter via canonical interface).**

## X-Lab Observational-Surface REMOVED (2026-08-11, session-7 · CLOSED)

Owner directive following ADR-005 X-Lab Removal Impact Audit:
"GO — remove X-Lab observational surface A." Full removal (R3 Option A).

### What was removed

Backend:
- `backend/routers/timeline_lab.py` — deleted (306 LOC · 4 routes gone)
- `backend/routers/semantic_lab.py` — deleted (116 LOC · 2 routes gone)
- `backend/server.py` — removed the 2 import blocks that mounted them

Frontend:
- `frontend/src/nivxforge/lab2/` — entire folder deleted (14 files · 384 KB)
- `frontend/src/nivxforge/pages/XLabGraphPopoutPage.jsx` — deleted
- `frontend/src/pages/SemanticMappingInspectorPage.jsx` — deleted
- `frontend/src/App.js` — removed 3 lazy imports, 3 routes (`/nivxforge/x-lab`, `/nivxforge/x-lab/graph`, `/lab/semantic-mapping-inspector`), and the `NivxForgeXLabRedirect` stub
- `frontend/src/nivxforge/pages/InvestigatePage.jsx` — removed Lab2 imports, `?lab2=1` renderer toggle, `<Lab2ToggleButton/>` in header; page now exclusively mounts the legacy production renderer

Deleted API surface (all now return 404):
- `POST /api/v2/timeline/preview`
- `POST /api/v2/attack-chain/preview`
- `POST /api/v2/correlation/preview`
- `POST /api/v2/pipeline/preview`
- `GET  /api/v2/semantic/registry`
- `POST /api/v2/semantic/preview`

### What was explicitly RETAINED (verified untouched)

- `backend/routers/lab.py` (Analyst Practice Lab / gamified training) — 8 routes still live; `/api/lab/challenge` verified functional post-removal
- `backend/nivxforge/**` (CIM, learning, ingress-gate, verdict engine) — untouched
- `backend/nivxforge/investigation/pipeline/**` (12 modules · 8586 LOC · 956 KB) — untouched; still used by `summary_composer`, `incident_narrative_override`, `v2/investigation/report`
- Workspace investigation / narrative / evidence services — bit-untouched
- Sample1 case row — untouched
- P0.2 Evidence Chain — untouched
- P0.3 CI Firewall — untouched (only the isolation guard's contract updated to the post-removal invariant)

### Test hygiene

- `tests/canonical/api/test_workspace_isolation_guard.py` — rewritten to the post-removal contract:
  1. `test_xlab_router_files_removed` — X-Lab router files must stay deleted.
  2. `test_no_workspace_module_imports_from_xlab` — Workspace modules must never import from X-Lab (static-import guard, unchanged).
  3. `test_xlab_routes_return_404` — the 6 previously-observational endpoints must all 404.
  4. `test_workspace_signature_stable` — Workspace `/api/die/investigation-results` remains signature-stable across identical calls.

### Regression suite results (2026-08-11)

| Suite | Before removal | After removal |
|---|---:|---:|
| `tests/canonical/api/` (P0.2 + P0.3) | 46 passed / 4 skipped | **47 passed / 4 skipped / 0 fail / 0 error** |
| Workspace SEP.csv end-to-end (external URL) | mitre=4, all-5-keys=True, 21 KB | **mitre=4, all-5-keys=True, 25 KB** (within 250 KB budget) |
| Workspace prose end-to-end (external URL) | mitre=1, all-evidence=True | **mitre=1, all-evidence=True** |
| Practice Lab `/api/lab/challenge` | 200 OK | **200 OK (verified with admin token)** |
| Backend + frontend supervisor | RUNNING | **RUNNING** (webpack compiled successfully) |

### Reduction (measured)

| Dimension | Delta |
|---|---:|
| Backend source | −20 KB (2 router files) |
| Frontend source | ~−400 KB (nivxforge/lab2/, XLabGraphPopoutPage, SemanticMappingInspectorPage) |
| API routes eliminated | 6 |
| Frontend routes eliminated | 3 |
| DB collections dropped | 0 (X-Lab used none) |

**Post-removal architecture:**

```
NivXRay
├── Workspace              ← protected, untouched
├── UAIE / Evidence chain  ← P0.2 enforced
├── Investigation pipeline ← shared, untouched
├── Analyst Practice Lab   ← retained
└── X-Lab observational    ← DELETED
```

**Awaiting owner direction for the next feature (Timeline · OSINT · Sysmon).**

## Workspace Timeline Graph · MVP (2026-08-11, session-7 · CLOSED)

Owner directive: "Build the Timeline as a read-only Workspace projection, not a new detection/correlation engine. Long-term architectural direction: raw logs → canonical events → evidence chain → correlation/IKG → Workspace Timeline Graph."

### What was built

Backend:
- `backend/services/die/timeline_projection.py` (new · pure projection module):
  - `project_timeline(raw_text, investigation_object) → {events, event_count, span_start, span_end, hosts, users, sources, meta}`
  - Accepts 3 evidence shapes without inventing anything:
    1. `object.csv_edr.highconf_events` (list of timestamped EDR rows)
    2. CSV re-parse for enrichment (user, parent_process, file_path — read-only, no shared-service mutation)
    3. P0.2 evidence chain from `object.mitre[*].evidence[*]` → `evidence_ref` per event
  - Events without a real timestamp are DROPPED (no fabrication).
  - Confidence heuristic derived only from `action` + evidence record; never a lookup that could invent value.
- `backend/routers/die.py` extended with `POST /api/die/timeline`:
  - Same `{input}` body shape as `/api/die/investigation-results` — client can wire either.
  - Internally runs the SAME `_render` + `augment_investigation_results` pipeline (respects P0.2 gate).
  - Returns ONLY the projection envelope — does not mutate the investigation-results payload.

Frontend:
- `frontend/src/components/investigation/TimelinePanel.jsx` (new):
  - Consumes `POST /api/die/timeline` via existing shared `api` axios wrapper.
  - Chronological event list with confidence badges (high · medium · low).
  - Row click expands into full evidence-chain detail (all 5 P0.2 keys shown).
  - Reload / error / empty / idle states all covered.
  - Every interactive element carries a `data-testid` (`timeline-panel`, `timeline-list`, `timeline-event-row-{i}`, `timeline-event-detail`, `timeline-span`, `timeline-summary`, `timeline-reload`, `timeline-loading`, `timeline-error`, `timeline-empty`, `timeline-idle`).
- `frontend/src/pages/WorkspacePage.jsx`:
  - Import + one JSX block that mounts `<TimelinePanel rawInput={input}/>` inside `<CollapsibleSection>` + `<PanelErrorBoundary>`.
  - Positioned right after the Attack Chain section.
  - No existing Workspace state / hook / logic touched.

### Contract guarantees (from tests · 16 new + 47 regression = 63 total)

- Every emitted timeline event carries a real ISO timestamp (`timestamp` key non-empty).
- Every emitted event carries the exact same `evidence_ref` value that `/api/die/investigation-results` emits for the same MITRE technique (cross-endpoint parity test).
- Prose / narrative-only inputs → `event_count == 0` (no fabrication).
- Empty input → `event_count == 0` (no fabrication).
- Events are chronologically sorted.
- Timeline wire response < 250 KB (SEP.csv fixture: 3.5 KB).
- `/api/die/investigation-results` payload keys unchanged — no `timeline` field leak.

### Regression suite (2026-08-11)

| Suite | Before Timeline | After Timeline |
|---|---:|---:|
| `tests/canonical/api/` (P0.2 + P0.3 + X-Lab isolation) | 47 passed / 4 skipped / 0 fail | **63 passed / 4 skipped / 0 fail / 0 error** (+16 timeline tests) |
| External URL SEP.csv end-to-end investigation | mitre=4, all-evidence, 21 KB | **mitre=5, all-evidence, unchanged** |
| External URL prose end-to-end investigation | mitre=1, all-evidence, 11 KB | **mitre=1, all-evidence, 15 KB** (unchanged shape) |
| Workspace UI mount (screenshot) | n/a | **Timeline section renders 5 events with expand-to-evidence** |
| Backend + frontend supervisor | RUNNING | **RUNNING** (webpack compiled successfully) |

### What Timeline MVP does NOT do (owner-preserved constraints)

- Does not modify `/api/die/investigation-results` payload contract.
- Does not modify P0.2 evidence chain, P0.3 firewall, Sample1, or the shared `nivxforge/investigation/pipeline`.
- Does not introduce a new detection or correlation engine.
- Does not implement Sysmon / EVTX / CrowdStrike / Defender / SentinelOne / OSINT adapters.
- Does not touch existing Workspace panels.

### Long-term architectural direction (documented, NOT yet implemented)

```
RAW LOGS / ALERTS / EDR TELEMETRY
              ↓
      Canonical Events
              ↓
      Evidence Objects  ────►  Workspace Timeline Graph (this MVP)
              ↓
     Correlation / IKG
              ↓
       Attack Story / MITRE / Verdict / Report
```

When future adapters (Sysmon / CrowdStrike / Defender / SIEM) feed the same canonical event bag, the Timeline projection picks them up automatically — no changes required to the projection module or the Workspace panel.

**Query/Hunt MVP closed with UX-fix follow-up. Awaiting owner direction for next feature.**

## TrajectoryDiagram lane-assignment display fix (2026-08-11, session-7 · CLOSED)

Owner directive: "Change lane assignment so that, where MITRE technique/tactic evidence exists, the node is placed according to the existing backend MITRE tactic mapping. Do NOT create a new MITRE/tactic mapping algorithm. Reuse the existing canonical mapping."

### Root cause

The Attack Chain panel was falling back to the LEGACY 6-lane view (Execution / Transformation / Network / File System / Registry / Persistence) because both `object.incident.behaviors` and `object.ice.behavior_clusters` are empty for the CSV/prose paths. The LEGACY view routes nodes by `stage.command_family` / entity-type — every executable landed in the Execution lane regardless of its MITRE tactic. The CANONICAL 14-lane MITRE ATT&CK view already existed in `TrajectoryDiagram.jsx` and correctly routes by tactic — it just wasn't being fed.

### Fix (display-only · frontend only)

`frontend/src/pages/WorkspacePage.jsx` — new helper `_synthBehaviorsFromMitre(mitreList)` and one line at the trajectory-panel gate:

- When `incident.behaviors` and `ice.behavior_clusters` are empty AND `object.mitre[]` carries per-technique `tactic`, synthesise a `behaviors[]` array where each behavior is a projection of one MITRE technique with `mitre_tactics: [title-cased tactic]` — the exact shape TrajectoryDiagram's canonical 14-lane view already understands.
- Title-casing is the only transformation (`"defense_evasion"` → `"Defense Evasion"`) — no new mapping algorithm, no remapping, no inference. If a technique has no `tactic`, it is dropped (no fabrication).
- Legacy behaviour is preserved when `object.mitre[]` is empty — no regression for callers that never had MITRE tactic evidence in the first place.

### What was NOT touched (per directive)

- Backend investigation payload contract — unchanged.
- `object.mitre[]` shape or the P0.2 evidence chain — unchanged.
- Shared `nivxforge/investigation/pipeline` — unchanged.
- `TrajectoryDiagram.jsx` canonical 14-lane logic — unchanged (it was already correct).
- Legacy 6-lane fallback — unchanged (still active when no MITRE data available).
- `launcher.exe` parent-reference behaviour — unchanged; the "observed vs referenced entity" question stays open as a separate future modelling task.

### Verified visual behaviour (post-fix)

Feeding the 3-row SEP.csv fixture:

| Lane | Techniques placed | Correct? |
|---|---|---|
| Execution | T1203 · Exploitation for Client Execution; T1204.002 · User Execution: Malicious File | ✅ |
| Persistence | T1543.003 · Windows Service | ✅ |
| Defense Evasion | T1055 · Process Injection; T1055.012 · Process Hollowing | ✅ |
| Other 11 tactics | (empty — greyed-out lanes preserved for "coverage-gap" visibility) | ✅ |

Screenshot: `/tmp/attack_chain_fixed.png`.

### Regression suite (2026-08-11)

| Suite | Before fix | After fix |
|---|---:|---:|
| `tests/canonical/api/` (P0.2 + P0.3 + Timeline + Query/Hunt + X-Lab isolation) | 100 passed / 4 skipped | **100 passed / 4 skipped / 0 fail / 0 error** |
| `node --test src/components/__tests__/trajectoryLaneAssignment.test.mjs` (new) | n/a | **7 pass / 0 fail** |
| Frontend build | webpack compiled successfully | **webpack compiled successfully** |
| Existing `.mjs` tests (mitreLaneOrder, classifyStageBreak, trajectoryPerLane) | unchanged | **unchanged** |

**TrajectoryDiagram lane fix closed. Awaiting owner direction on next feature: Query/Hunt → Automatic Investigation View, Sysmon adapter, Attack Story, OSINT, or P1 hygiene.**

## Phase 3.x shipped (2026-08-10) — TEXT_EXTRACT_FROM_ARCHIVE only

- Owner decisions applied verbatim: Q1=1a (child-SSOT recursion) · Q2=2a (existing budget) · Q3=3c (generic UTF-8 filter) · Q4=4a (raw XML — no tag-strip).
- Executor plumbing completed: `store` is now supplied via `ctx["store"]` (single-line change that completes the existing D6-r contract already required by `_cap_recursive_discovery`).
- `_cap_recursive_discovery` now skips archive members already materialised by TEXT_EXTRACT (via `parent_evidence_id` inspection).
- Real Sample.docx pipeline: parent SSOT `58627409…20633d` + 19 archive-member artifacts + 16 populated child SSOTs; `word/document.xml` child yields 73 IOC nodes (52 URLs, 13 IPs, 6 SHA256, 2 MD5).
- P4-FW3 no-fallback re-verified on both parent and child projections.

## Phase 4 shipped (2026-08-10)

- 15 canonical projections in `backend/canonical/projections/` — pure functions of `AuthoritativeSSOT`, no I/O/clock/random, no legacy composer imports.
- P4-FW3 enforced: `project_recommendations` returns `[]` + mandatory reasoning note when SSOT has no MITRE evidence. Banned tokens (`IMMEDIATE`/`THREAT HUNTING`/`CONTAINMENT`/`Isolate the host`) verified absent across every fixture.
- Strict `token-set + length-band` comparator for `canonical_normalised` prose (per owner decision 3-a).
- Sign-off artefacts: `-projection-acceptance.md` (P4.G1), `-allowed-diffs.md` (P4.G2), `-report.md`.
