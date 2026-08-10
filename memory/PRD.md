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
- Any request to shortcut this MUST be rejected — the whole point of Phase 5.1 is to prove one isolated entry point converges cleanly; redirecting Workspace during 5.1 would mix frontend/upload/session/canonical/legacy concerns and destroy the rollback boundary.

## Owner-approved projection-freeze exception (Phase 3.y · 2026-08-10)

The following data-catalog additions in projection-tier files are **formally approved exceptions** to the "no projection changes" freeze:

- `projections/attck.py :: _TECHNIQUE_META` — 6 rows added (T1219, T1204.002, T1071, T1486, T1003, T1566 → tactic + kill-chain). Original 5 rows byte-identical.
- `projections/recommendations.py :: _RECS_BY_TECHNIQUE` — 6 keys added with evidence-derived recommendations for the same 6 techniques. Original 5 keys byte-identical.

The projection LOGIC is unchanged. The exception is scoped to *these six rows only* and does not authorise any broader projection modification.

## Phase 3.y shipped (2026-08-10) — narrative MITRE analyzer extension

- Added 6 narrative rules (T1219, T1204.002, T1071, T1486, T1003, T1566), all multi-word contextual — no bare "RAT" trigger.
- Real Sample.docx child now produces MITRE + Attack Chain + Attack Story + evidence-derived Recommendations end-to-end (verdict MALICIOUS conf 100).
- False-positive protection verified: 3 negative fixtures + 3 command-line regression fixtures.
- 14/14 Phase 3.y tests · 206 total suite green (unchanged Sample1-required skip-set).
- Empirical answer to VENDOR_NORMALISER question: not needed for the current Sample.docx or 5 representative fixtures.

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
