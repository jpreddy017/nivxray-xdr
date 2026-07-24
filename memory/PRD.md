# NivXRay — Enterprise Attack Investigation Platform

## Vision (2026-02-24)

NivXRay is **NOT** a device trajectory viewer, **NOT** a malware detector,
**NOT** a verdict engine. It is a **deterministic enterprise investigation
platform** that reconstructs attack behaviour, explains why it reached its
conclusions, and helps analysts investigate any cyberattack — from initial
access to impact — using a single unified workspace built on the
**Investigation Knowledge Graph (IKG)**.

Every existing tab and route is preserved. Every new capability is a
projection of the IKG. Nothing calculates its own truth.

## Data flow — single source of truth

```
Telemetry → Normalize → Decode → Execution Graph → Verdict Engine
                                          → Correlation Engine
                                          → Investigation Knowledge Graph
                                                     │
                     ┌──────────────┬─────────────────┼────────────────┬────────┐
                     ▼              ▼                 ▼                ▼        ▼
                  Summary       Trajectory       Process Tree     Attack Story  …
                     ▼              ▼                 ▼                ▼        ▼
                  Verdict         ATT&CK       Evidence Graph          TI     Reports
                                        │
                                        └──── Explainability (global collapsible panel)
```

---

## 2026-02-24 · Phase 1 · IKG + Unified Workspace shell (SHIPPED · backend + UI)

**Zero-regression architectural pivot.** Every existing route
(`/`, `/analyst`, `/v2/trajectory/{id}`, `/v2/irg`, `/v2/compare`,
`/dashboard`, …) stays live. The new workspace is additive.

### Backend

- `v2/investigation/ikg.py` — the Investigation Knowledge Graph with
  13 node types (process/file/registry/network/module/service/task/event/
  technique/tactic/verdict/device/incident) and 14 edge verbs
  (created/modified/deleted/contacted/loaded/installed/spawned/executed_by/
  maps_to/covers/contributes_to/rollup_of/hosted_on/part_of).
- `v2/investigation/builder.py` — composes telemetry → IRG enrichment →
  verdict engine → correlation engine → IKG. Emits an `Investigation`
  object carrying `header`, `ikg`, `verdicts`, `profile`, `engine_version`.
- `v2/routers/investigation.py` — new endpoint
  `GET /api/v2/cases/{case_id}/investigation?profile=<id>`.
- Wired into `server.py`. All 820 RC5 tests + 35 verdict tests unchanged.

**Live smoke on `case_dfir_bumblebee_akira_2026`:**
- IKG: 131 nodes / 209 edges
- Node types: incident 1 · device 1 · process 21 · file 5 · network 1 ·
  event 53 · technique 21 · verdict 28
- Edge types: part_of · hosted_on · executed_by · spawned · maps_to ·
  modified · contacted · deleted · contributes_to · rollup_of
- Header: severity=critical · device_score=87 · incident_score=87 · conf=100%

### Frontend

- `v2/pages/InvestigationWorkspace.jsx` — the workspace shell.
  * Persistent header (Case · Severity · Device Risk · Incident Risk ·
    Confidence · Verdict · Events · Processes · Chains · Profile picker
    · engine chip).
  * URL-driven tab router (`?tab=<view>`) — shareable deep links.
  * Tab strip: Summary · Device Trajectory · Process Tree · Attack Story ·
    Evidence Graph · Verdict · ATT&CK · Threat Intelligence · Reports
    (7 of them marked `·soon` for Phase 2-5; Trajectory active).
  * Trajectory tab embeds the existing `DeviceTrajectoryV2` canvas with
    ZERO refactor.
  * Global collapsible **Explainability panel** — deterministic
    "Why is this <band>?" reasoning built from the IKG (top-3 evidence
    signals + correlation bonuses + progressions + tactic coverage).
  * Footer strip with IKG version, profile, and legacy-trajectory link
    (proves nothing was removed).
- `App.js` — new route `/v2/case/:caseId`. All existing routes untouched.

**Tests:**
- `tests/test_investigation_ikg.py` — 10/10 green (edge dedup · type
  validation · builder end-to-end · determinism · spawn edges · verdict
  hierarchy · profile flow-through · engine version).

**All previous verdict / correlation suites still 35/35 green.**

---

## 2026-02-24 · Verdict Engine v3.1b — FROZEN

Rated 9.6/10 by the operator. No further engine changes except bug
fixes. See git log for full v3 → v3.1 → v3.1b history:
- v3   — Deterministic per-event scoring, 7 families, 7-band output.
- v3.1 — Multi-event correlation (Event → Process → Chain → Device → Incident).
- v3.1b — Office LOLBin parents · Attack progression matcher · 6 Adaptive
          weight profiles · Score-escalation ladder · ATT&CK coverage
          wheel · Legacy-vs-modern verdict comparison UI.

---

## Backlog · Prioritised roadmap (adjusted per operator direction)

### Phase 2 — Storytelling + Explainability activation
- **Attack Story tab** — deterministic sentence generator that traverses
  the IKG's parent→child + rollup chains. Every sentence links to its
  IKG evidence node. No LLM.
- **ATT&CK tab** — dedicated Coverage Wheel + technique list + tactic
  list + kill-chain diagram + Navigator JSON + STIX 2.1 export.
  (Move the wheel out of the Verdict/Correlation panel per operator's
  "one responsibility per tab" rule.)
- **Explainability panel** upgrade — support "Why isn't this
  ransomware?" style *negative* questions by scanning the IKG for the
  absence of impact-family signals.

### Phase 3 — Graph views
- **Evidence Graph tab** — Konva causality graph over the IKG's
  spawned/created/modified/contacted edges. NOT chronological.
- **Process Tree tab** — parent→child projection of the IKG's `spawned`
  edges, with per-node verdict badges.

### Phase 4 — Executive views
- **Summary tab** — Executive dashboard (severity, device/incident risk,
  confidence, timeline sparkline, recommendations).
- **Verdict tab** — dedicated hierarchical verdict view with the
  escalation ladder and evidence breakdown lifted out of the drawer.

### Phase 5 — Enrichment + Reports
- **Threat Intelligence tab** — enrichment-only overlay on the IKG.
  Never influences the deterministic verdict.
- **Reports tab** — one-click export (Executive Summary → Attack Story
  → Evidence Graph → ATT&CK Summary → IOC Summary → Timeline → Verdict
  Explanation → Recommendations → Appendix), reading from the same IKG.
- Refactor the existing PDF/MD/STIX builders to consume `Investigation`
  instead of raw frames.

### Constraint
Every phase MUST preserve every existing route and workflow.

---

## Architecture Snapshot

- Backend: `/app/backend/`
  - `engine/` — RC5, IMMUTABLE.
  - `v2/`
    - `investigation/` — ikg.py · builder.py (**Phase 1 SSOT**).
    - `verdict/` — engine.py · correlation.py · signals.py · weights.py
      · profiles.py · progressions.py (**FROZEN v3.1b**).
    - `shadow/irg.py` — canonical relationship enricher.
    - `report/` — MD / PDF / STIX / signed bundle builders.
    - `routers/` — cases · parse · trajectory · ancestry · report · irg ·
      verdicts · **investigation** (new).

- Frontend: `/app/frontend/src/`
  - `pages/` — WorkspacePage (analyzer) · AnalystWorkspacePage · … (all preserved).
  - `v2/pages/`
    - `InvestigationWorkspace.jsx` — Phase 1 shell.
    - `DeviceTrajectoryV2.jsx` — embedded as Trajectory tab.
    - `IRGWorkspace.jsx` · `CompareWorkspace.jsx` · `ProcessAncestry.jsx` · `CaseWorkspaceShell.jsx` — all preserved.
  - `v2/theme.js` — glassy navy-black + emerald tokens.
  - `v2/flags.js` — client-side flag reader.

## Key APIs

- `GET /api/v2/cases/{id}/investigation?profile=<id>` — **the unified investigation**.
- `GET /api/v2/cases/{id}/verdicts` — per-event verdicts (v3).
- `GET /api/v2/cases/{id}/verdicts/aggregate?profile=<id>` — v3.1 multi-layer.
- `GET /api/v2/verdict/profiles` — list Adaptive Weight Profiles.
- (Legacy trajectory + IRG + ancestry + report endpoints all preserved.)

## Feature Flags (backend/.env)

- `NIVX_FLAG_TRAJECTORY_ENGINE=shadow`
- `NIVX_FLAG_CASE_ENGINE=shadow`
- `NIVX_FLAG_ADAPTERS=shadow`
- `NIVX_FLAG_VERDICT_ENGINE_V3=shadow` — gates both the aggregate endpoint
  AND the entire Investigation Workspace.

---

## 2026-02-24 · Verdict Engine v3.1b (SHIPPED · backend + UI)

Rated 9.6/10 by the operator. Ships the six items approved in this
review round, closing the "engine feature" chapter before we pivot to
Investigation Workspace polish.

**Backend additions:**
- `v2/verdict/signals.py` — extended `SUSPICIOUS_PARENT` to cover
  Office/Browser parents spawning **any** of rundll32, regsvr32, certutil,
  msiexec, wmic, bitsadmin, installutil, regasm, regsvcs, hh, csc, msbuild
  (in addition to the existing SHELL_LIKE set). Direct implementation of
  the analyst training on Parent-Child Process Relationships.
- `v2/verdict/profiles.py` — six Adaptive Weight Profiles:
  `soc_balanced` (default) · `threat_hunting` · `dfir` · `high_security` ·
  `cloud_workload` · `ot_ics`. Each profile is a shallow overlay on top of
  the base WEIGHTS / FAMILY_CAPS + a `bonus_multiplier` and `band_shift`.
  No engine logic changes — only tuning constants.
- `v2/verdict/progressions.py` — deterministic Attack Progression matcher.
  Generic kill-chain graphs (NOT campaign signatures):
  * `KC_INITIAL_ACCESS_KILL`      Office → LOLBIN → Download → Persistence
                                  → Evasion → Credential → Impact
  * `KC_DOWNLOAD_EXECUTE`         Shell → Download → Persistence → Evasion
  * `KC_CREDENTIAL_TO_LATERAL`    Shell → Credential → Evasion → Network
  * `KC_PS_RUNKEY_BEACON`         Office → PS → Encoded → Web → RunKey → Beacon
  * `KC_RANSOM_PROGRESSION`       Exec → Persist → Evade → BackupDestroy →
                                  MassEncrypt → RansomNote
  Partial (≥ 5/N) = +8, Full (≥ 7/N or all) = +14. Scaled by profile.
- `v2/verdict/correlation.py` — every AggregateVerdict now carries:
  * `progressions[]` — matched kill-chains
  * `tactic_coverage{tactic → {count, techniques, level}}` — for the wheel
  * `score_escalation[]` — the "why did this score change?" ladder,
    showing each delta (base → correlation bonus → progression bonus →
    corroboration cap → profile band-shift) with reason strings.
  Profile parameters (weights, family caps, bonus multiplier, band shift)
  thread through every layer. Same input + same profile = same output.
- `v2/routers/verdicts.py`:
  * `GET /api/v2/verdict/profiles` — list all profiles
  * `GET /api/v2/cases/{id}/verdicts/aggregate?profile=<id>` — profile-aware
    aggregate. Router prefix changed from `/v2/cases` to `/v2` to host the
    new profiles endpoint alongside case-scoped ones.

**Frontend additions (`v2/pages/CorrelationPanel.jsx` rewritten):**
- **Profile selector** dropdown wired to `/verdict/profiles`.
- **Legacy vs v3.1 side-by-side comparison** (malicious-events count vs
  deterministic score).
- **Score-escalation ladder** rendering every delta step from base score
  → final, with reason strings and running totals.
- **ATT&CK tactic coverage wheel** — one horizontal bar per tactic
  (Execution, Persistence, Defense Evasion, …) coloured by coverage
  level (1/2/3), showing technique counts and technique lists on hover.
- **Attack progression badges** — one card per matched kill-chain with
  matched stages and effective weight.
- **Layer drill-down** — Incident / Device / Chain(s) / Process(es) with
  ring score, band pill, confidence, correlation bonuses, and evidence.

**Live smoke (real seeded case `case_dfir_bumblebee_akira_2026`):**
| Profile          | Device Score | Δ vs SOC |
|------------------|--------------|----------|
| soc_balanced     | 87           | 0        |
| dfir             | 98           | +11      |
| cloud_workload   | 92           | +5       |
| ot_ics           | 100 (band-shifted) | +13 |

Escalation ladder visible in the drawer:
`base 81 → +12 TACTIC_COVERAGE_5 → 93 → +6 MULTI_PROCESS_CORROBORATION →
99 → +4 CROSS_LANE_ATTACK → 100`

**Tests: 35/35 green.**
- `test_verdict_v3.py`             — 9/9 (per-event engine)
- `test_verdict_v3_correlation.py` — 12/12 (multi-layer aggregation)
- `test_verdict_v3_1b.py`          — 14/14 (Office LOLBins · progressions ·
  profiles · escalation · tactic coverage · determinism)

**RC5:** UNTOUCHED. All 820 backend tests remain green.

---

## 2026-02-24 · Verdict Engine v3.1 · Multi-event Correlation (SHIPPED)

Layered aggregation Event → Process → Chain → Device → Incident on top of
the IRG attack graph. Signals de-duplicated per layer, family caps
enforced, correlation bonuses only fire when independent evidence
corroborates. See git log for full detail.

## 2026-02-24 · Verdict Engine v3 · Deterministic Behavioural Scoring (SHIPPED)

Per-event 7-family behavioural scorer. Endpoint
`GET /api/v2/cases/{id}/verdicts`. Feature-flagged on
`NIVX_FLAG_VERDICT_ENGINE_V3=shadow`.

---

## Prior deliveries (condensed — full history in git log)

- Full Interactive Device Trajectory workspace.
- Multi-Case Compare workspace with postMessage sync-scrub.
- IRG Workspace tab (canonical graph view).
- Process Ancestry wired to canonical IRG schema.
- Report generator P2 (JSON / MD / PDF / STIX 2.1 / signed evidence bundle).
- Artifact store with content-addressed IIDs.
- Glassy navy-black + emerald green corporate theme.

---

## Backlog · Prioritised

### FROZEN — engine complete for now
User verdict: "consider freezing the verdict engine and shifting focus
to the Investigation Workspace." Any further scoring refinements go to
the top of the backlog only after the workspace pivots below ship.

### P0 — Investigation Workspace (primary analyst UI)
- **Attack Story generation** — auto-generated narrative from the same
  deterministic evidence chain the correlation engine already surfaces.
- **Evidence Graph visualisation** — replace the flat evidence list with
  a causality graph rendered on the existing Konva engine.
- **Timeline enhancements** — richer swimlane annotations, drag-select
  export, cross-case pin views.

### P1 — Reporting & Case Exports
- Add v3.1 correlation summary + ATT&CK coverage wheel + progression
  breakdown into the PDF / Markdown report builders.
- Signed evidence bundles should carry the aggregate `.correlation.json`
  alongside per-event verdicts.

### P2 — Future scoring refinements (only after workspace ships)
- Temporal-order kill-chain detection (currently unordered stage matching).
- IRG Graph clumping fix (nodes overlapping in tight ms windows).
- `InvestigationCanvas.jsx` refactor (~1000+ lines).

---

## Architecture Snapshot

- Backend: `/app/backend/`
  - `engine/` — legacy RC5, IMMUTABLE.
  - `v2/` — additive namespace. Flag-gated.
    - `v2/routers/` — cases, parse, trajectory, ancestry, report, irg,
      verdicts (now `/v2` prefix hosting both case-scoped + profile endpoints).
    - `v2/verdict/` — engine.py · correlation.py · signals.py · weights.py ·
      profiles.py · progressions.py.
    - `v2/shadow/irg.py` — canonical relationship enricher.
    - `v2/report/` — MD / PDF / STIX / signed bundle builders.
    - `v2/artifact_store/` — deterministic content-addressed artefacts.

- Frontend: `/app/frontend/src/v2/`
  - `canvas_engine/InvestigationCanvas.jsx` — Konva rendering + viewport.
  - `pages/DeviceTrajectoryV2.jsx` — main workspace.
  - `pages/CorrelationPanel.jsx` — v3.1b UI with profile selector,
    verdict comparison, escalation ladder, ATT&CK wheel, progressions.
  - `pages/IRGWorkspace.jsx`, `pages/CompareWorkspace.jsx`.
  - `theme.js` — glassy navy-black + emerald tokens.
  - `flags.js` — client-side flag reader.

## Key APIs

- `GET /api/v2/cases/{id}/trajectory/device` — frame list.
- `GET /api/v2/cases/{id}/ancestry` — process tree.
- `GET /api/v2/cases/{id}/irg` — canonical relationship graph.
- `GET /api/v2/cases/{id}/verdicts` — per-event v3 verdicts.
- `GET /api/v2/cases/{id}/verdicts/aggregate?profile=<id>` — v3.1 multi-layer.
- `GET /api/v2/verdict/profiles` — list Adaptive Weight Profiles.
- `GET /api/v2/report/{id}` (+ `.md`, `.pdf`, `.stix.json`, `.bundle.zip`).

## Feature Flags (backend/.env)

- `NIVX_FLAG_TRAJECTORY_ENGINE=shadow`
- `NIVX_FLAG_CASE_ENGINE=shadow`
- `NIVX_FLAG_ADAPTERS=shadow`
- `NIVX_FLAG_VERDICT_ENGINE_V3=shadow`

---

## 2026-02-24 · Verdict Engine v3.1 · Multi-event Correlation (SHIPPED · backend + UI)

**Motivation:** v3 scored events in isolation. Analysts investigate
attacks, not events. This phase adds a deterministic multi-layer
aggregation engine on top of v3 so the same evidence rolls up through
`Event → Process → Chain → Device → Incident` — using the IRG attack
graph (parent/child, entity iid, root iid) as the correlation
substrate, not timestamps.

**Design rules honoured (all locked by tests):**
- Do NOT sum event scores. Signals are de-duplicated per layer.
- Family caps still apply at every layer (evasion ≤ 25, execution ≤ 40, …).
- Correlation bonuses only fire when independent evidence corroborates:
  * `MULTI_FAMILY_{3,4,5}` — distinct signal families
  * `TACTIC_COVERAGE_{3,5}` — distinct MITRE tactic bases
  * `MULTI_PROCESS_CORROBORATION` — ≥2 processes contribute signals
  * `CROSS_LANE_ATTACK` — attack spans ≥3 lanes
  * `IMPACT_CHAIN` — execution + persistence + impact all present
  * `CREDENTIAL_TO_LATERAL` — credential + evasion + network all present
- Every aggregate carries: `score`, `band`, `confidence`, `explanation`,
  `evidence_breakdown`, `contributing_events[]`, `contributing_processes[]`,
  `signals[]`, `families[]`, `mitre_tactics[]`, `correlation_bonuses[]`,
  `children[]`.
- Zero LLM, zero binary-name reputation, zero external TI.
- Deterministic — same input frames → byte-identical output.

**Shipped (backend):**
- `v2/verdict/correlation.py` — layered aggregation engine.
- `v2/verdict/weights.py` — extended with correlation bonus tiers +
  confidence formula weights.
- `v2/verdict/__init__.py` — exports `correlate`, `CorrelationReport`,
  `AggregateVerdict`.
- `v2/routers/verdicts.py` — new endpoint
  `GET /api/v2/cases/{case_id}/verdicts/aggregate` (flag-gated on
  `NIVX_FLAG_VERDICT_ENGINE_V3=shadow`).
- `tests/test_verdict_v3_correlation.py` — 12/12 tests green
  (dedup, chain aggregate, impact-chain bonus, family cap, determinism,
  confidence scaling, sorted outputs, corroboration ceiling).

**Shipped (frontend):**
- `frontend/src/v2/pages/CorrelationPanel.jsx` — layered visualisation
  (score ring, band pill, confidence, correlation bonuses, top-N
  evidence, MITRE / family / process / event counts).
- Wired into `DeviceDetailsDrawer` in `DeviceTrajectoryV2` as a new
  section `Correlation · v3.1` (only rendered when the flag is
  observable — legacy verdict path remains default).
- Frontend flag registry (`v2/flags.js`) gained `VERDICT_ENGINE_V3`.
- `frontend/.env` — added `REACT_APP_NIVX_FLAG_VERDICT_ENGINE_V3=shadow`
  (also fixed a broken concatenation in the .env that had merged two
  variables on one line).

**Live smoke on real seeded case** (`case_dfir_bumblebee_akira_2026`,
26 shadow observations, DFIR Bumblebee → AdaptixC2 → Akira chain):
- Incident/Device: **score 87 · CRITICAL · confidence 100 %**
- 21 processes tracked, 8 chains identified (`adgnsy.exe` 81,
  `rundll32.exe` 77, etc.)
- Correlation bonuses fired: `TACTIC_COVERAGE_5` (+12),
  `MULTI_PROCESS_CORROBORATION` (+6), `CROSS_LANE_ATTACK` (+4)
- Zero regressions on the existing 9 v3 event-level tests.

**RC5:** UNTOUCHED. All 820 backend tests remain green.

---

## 2026-02-24 · Verdict Engine v3 · Deterministic Behavioural Scoring (SHIPPED)

Per-event 7-family behavioural scorer with corroboration cap,
family caps, decay signals (`SIGNED_MICROSOFT_BINARY`,
`EXPECTED_PARENT_CHILD`, `NO_MITRE_TAGS`) — no name blocklists,
no LLM. Endpoint `GET /api/v2/cases/{id}/verdicts` and tests in
`test_verdict_v3.py` (9/9 green). Feature-flagged on
`NIVX_FLAG_VERDICT_ENGINE_V3=shadow`.

Design doc: `/app/memory/design/VERDICT_ENGINE_V3.md`.

---

## Prior deliveries (condensed — full history in git log & CHANGELOG)

- Full Interactive Device Trajectory workspace (two-box layout, Time
  Compass, viewport sync, sticky regions, playback, bookmarks).
- Multi-Case Compare workspace with postMessage sync-scrub.
- IRG Workspace tab (canonical graph view).
- Process Ancestry wired to canonical IRG schema.
- Report generator P2 (JSON / MD / PDF / STIX 2.1 / signed evidence bundle
  with HMAC-SHA256 chain-of-custody).
- Artifact store with content-addressed IIDs.
- Glassy navy-black + emerald green corporate theme.

---

## Backlog · Prioritised

### P0 (unblocks the next analyst uplift)
- **Extend `SUSPICIOUS_PARENT` to Office → rundll32 / regsvr32 / certutil**
  — currently only covers `Office → SHELL_LIKE`. Attackers use these
  LOLBins from Office too. 4-line detector patch + 2 tests.

### P1 (Verdict Engine v3.2 roadmap)
- **Temporal correlation** — bonus for known attack progressions
  (Office → PowerShell → certutil → C2 · Bumblebee → AdaptixC2 → Akira).
- **Attack story integration** — feed the deterministic evidence chain
  into an auto-generated timeline narrative.

### P2 (Verdict Engine v3.3 roadmap)
- **Risk vs Confidence separation** — expose them as distinct axes in
  the UI (already computed separately in v3.1, just needs visualisation).
- **Adaptive weight profiles** — SOC Balanced / High Security / DFIR
  presets that adjust weights without changing logic.
- **Verdict comparison UI** — legacy verdict vs Verdict v3.1 side-by-side.

### P3 (Longer horizon)
- **Explainability Graph** — replace flat evidence list with a causality
  graph rendered on the existing Konva engine.
- **Evidence categories** in the drawer (Execution / Persistence /
  Network / Impact groupings — already present in `families` field).
- **IRG Graph clumping fix** — spread overlapping nodes when many events
  land in a tight ms window.
- **`InvestigationCanvas.jsx` refactor** — file is ~1000+ lines; extract
  child Konva components once interaction is frozen.

---

## Architecture Snapshot

- Backend: `/app/backend/`
  - `engine/` — legacy RC5, IMMUTABLE.
  - `v2/` — additive namespace. Flag-gated.
    - `v2/routers/` — cases, parse, trajectory, ancestry, report, irg, verdicts.
    - `v2/verdict/` — engine.py (per-event), correlation.py (v3.1), signals.py, weights.py.
    - `v2/shadow/irg.py` — canonical relationship enricher.
    - `v2/report/` — MD / PDF / STIX / signed bundle builders.
    - `v2/artifact_store/` — deterministic content-addressed artefacts.

- Frontend: `/app/frontend/src/v2/`
  - `canvas_engine/InvestigationCanvas.jsx` — Konva rendering + viewport.
  - `pages/DeviceTrajectoryV2.jsx` — main workspace.
  - `pages/CorrelationPanel.jsx` — v3.1 UI (added this session).
  - `pages/IRGWorkspace.jsx`, `pages/CompareWorkspace.jsx`.
  - `theme.js` — glassy navy-black + emerald tokens.
  - `flags.js` — client-side flag reader.

## Key APIs

- `GET /api/v2/cases/{id}/trajectory/device` — frame list.
- `GET /api/v2/cases/{id}/ancestry` — process tree.
- `GET /api/v2/cases/{id}/irg` — canonical relationship graph.
- `GET /api/v2/cases/{id}/verdicts` — per-event v3 verdicts.
- `GET /api/v2/cases/{id}/verdicts/aggregate` — v3.1 multi-layer.
- `GET /api/v2/report/{id}` (+ `.md`, `.pdf`, `.stix.json`, `.bundle.zip`).

## Feature Flags (backend/.env)

- `NIVX_FLAG_TRAJECTORY_ENGINE=shadow`
- `NIVX_FLAG_CASE_ENGINE=shadow`
- `NIVX_FLAG_ADAPTERS=shadow`
- `NIVX_FLAG_VERDICT_ENGINE_V3=shadow`
