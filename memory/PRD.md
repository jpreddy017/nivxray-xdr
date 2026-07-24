# NivXRay — Enterprise Attack Investigation Platform

## Vision (2026-02-24)

NivXRay is a **deterministic enterprise investigation platform** that
reconstructs attack behaviour, explains why it reached its conclusions,
and helps analysts investigate any cyberattack — from initial access to
impact — using a single unified workspace built on the **Investigation
Knowledge Graph (IKG)**. Every existing tab and route is preserved.
Every new capability is a projection of the IKG. Nothing calculates its
own truth.

---

## 2026-02-27 · Phase 5 · Evidence Graph (SHIPPED)

Shipped the last major UI piece on the frozen v1.0 roadmap. The
Evidence Graph is a new tab inside the Investigation Workspace that
projects the IKG into an entity-only causality graph.

Component: `frontend/src/v2/pages/EvidenceGraphTab.jsx`
Route: `/v2/case/:id?tab=graph`

### What it answers
- Timeline answers **when** it happened.
- Attack Path answers **what sequence** occurred.
- Evidence Graph answers **how the artefacts are related**.

### Three graph modes
1. **Causality (default)** — top-to-bottom depth layout: subject → action → target.
   Best for kill-chain reading.
2. **Entity Relationship** — processes on a vertical spine, files / registry /
   network artefacts branch out radially. Best for impact analysis.
3. **Time Overlay** — nodes fade by age, edges carry timestamp labels,
   nodes are placed on horizontal type-lanes by first-seen time. Best
   for investigation replay.

### Data projection
- Reads `inv.ikg.nodes` + `inv.ikg.edges` from
  `/api/v2/cases/:id/investigation` — no new backend.
- Joins `event -[executed_by]-> process` with `event -[modified|
  contacted|deleted|spawned]-> target` to synthesise entity-to-entity
  causal edges labelled by action.
- Direct `process -[spawned]-> process` edges are preserved as-is.

### Features
- Zoom (wheel), Pan (drag), Fit, Reset — mouse & buttons.
- Search box with clear-X + Esc to clear.
- Node type filters (process / file / registry / network / service /
  user / command) with live counts.
- Edge type filters (spawned / created / modified / deleted / loaded /
  injected / contacted / resolved / executed / persisted) with live
  counts and colour swatches.
- Time filter slider (0 → case duration).
- Colour legend inline in the rail.
- Empty state message when filters kill all nodes.
- SelectionContext sync: clicking a node sets `{kind: process|event,
  id, source: "graph"}` so every other tab (Timeline, Story, Process
  Tree, Evidence Card, ATT&CK) reflects the same anchor.

### Data-testids added
- `evidence-graph-tab`, `graph-canvas-svg`, `graph-canvas-wrap`
- `graph-mode-causality|entity_rel|time_overlay`
- `graph-search-input`, `graph-search-clear`
- `graph-node-count`, `graph-edge-count`
- `graph-zoom-in|out`, `graph-fit`, `graph-reset`
- `graph-filter-rail`, `graph-time-range`
- `node-filter-<type>`, `edge-filter-<type>`
- `graph-node-<id>`, `graph-edge-<src>-<tgt>-<type>`
- `graph-empty`

### Verified
Smoke-tested on the seed case (case_dfir_bumblebee_akira_2026):
27 entities · 24 causal edges · 3 modes render distinct layouts ·
zoom / pan / fit all functional · Time Overlay shows `+time` labels
on edges · empty-state renders when filter kills the set · toolbar
node/edge counts update live as filters change.

Workspace v1.0 is now feature-complete. Next up:
- Saved Searches (chip lenses)
- Report Templates (Exec Summary vs Deep-Dive)
- Enterprise Adapters (Cisco / Defender / CrowdStrike / SentinelOne /
  Splunk / QRadar → Canonical Event Schema)

---


## 2026-02-27 · P0 Workspace v1.0 · Nav completion + Search UX polish (SHIPPED)

Frozen the Investigation Workspace as v1.0 by finishing the platform
before adding new capabilities. Only additive UX and correctness fixes
— no engine or IKG changes.

### P0.1 · Global navigation completeness
Every analyst-facing route now renders the global `<Header />` so users
can never get trapped inside a child view:
- `/analyst`, `/analyst/rc5`
- `/v2/trajectory`, `/v2/irg`, `/v2/compare`
- `/v2/ancestry/:caseId/:processIid`
- `/v2/workspace`, `/v2/case/:id`, `/v2/ingest`, `/v2/validation`

`DeviceTrajectoryV2` accepts an `embedded` prop so it can be nested
inside `InvestigationWorkspace` without double-rendering the header.

### P0.2 · Evidence pane correctness (Feb-27 hotfix)
- Added a new `ACTOR PROCESS` / `TARGET FILE` / `TARGET REGISTRY` /
  `REMOTE ENDPOINT` section that shows the friendly `entity.name`
  instead of the raw internal IID.
- `PARENT PROCESS` now resolves `parent.iid` against a case-wide
  `nameByIid` map so analysts see e.g. `explorer.exe` rather than
  `ent_process_836d89a0af6b`.
- Event titles that repeat the same subject and target (e.g.
  `backup_EA · created_domain_user · backup_EA`) are collapsed to
  `<entity> · <action>` for readability.

### P0.3 · Route QA · graceful empty state
- `/v2/case/:id` for a non-existent or empty case now renders an
  actionable "Case not found" card with **Back to workspace** and
  **Ingest new evidence** CTAs instead of an empty workspace shell.

### P0.4 · IRG canvas clipping + horizontal scrollbar
- Increased `PAD_X` in `IRGGraphCanvas` from 24 → 60 so the leftmost
  node fits fully inside the Konva stage (was clipping "cmd.exe" to
  ":md.exe" on depth-0 rows).
- Added a persistent HTML `HScrollbar` overlay on the IRG canvas —
  visible whenever the graph overflows the viewport, drag / click-jump
  supported. Provides an obvious pan affordance.

### P0.5 · Universal search behaviour (Device Trajectory + IRG)
Search now behaves like every other enterprise investigation tool —
type a query and **only relevant data** is shown across all three
panels:

- Attack Chain sidebar keeps only stages that contain at least one
  matching frame.
- Timeline canvas / IRG graph keeps only rows / entities that match
  (plus the neighbourhood in IRG so relationships are visible).
- Evidence pane auto-populates with the first matching event so the
  analyst never sees a blank right rail after typing.
- Empty-result state renders `No events match "<q>"` in the canvas.
- IRG header shows `X ENTITIES · Y RELATIONSHIPS · filtered by "<q>"`.

Files touched (additive · no engine/IKG mutation):
- `frontend/src/pages/AnalystWorkspacePage.jsx`
- `frontend/src/pages/AnalystRC5Page.jsx`
- `frontend/src/v2/pages/DeviceTrajectoryV2.jsx`
- `frontend/src/v2/pages/IRGWorkspace.jsx`
- `frontend/src/v2/pages/CompareWorkspace.jsx`
- `frontend/src/v2/pages/ProcessAncestry.jsx`
- `frontend/src/v2/pages/CaseWorkspaceShell.jsx`
- `frontend/src/v2/pages/InvestigationWorkspace.jsx` (empty-state card + `embedded` DeviceTrajectoryV2)
- `frontend/src/v2/canvas_engine/IRGGraphCanvas.jsx` (padding + scrollbar)

Verified: testing_agent_v3_fork iteration_40 — 10/10 routes pass
nav-shell check. Post-fix smoke tests confirm search filters both
Trajectory (2 matched stages / auto-populated evidence) and IRG
(3 entities / 2 relationships / attack chain narrowed).

Backlog frozen: UI is now v1.0. Next up = **Phase 5 · Evidence Graph
Visualisation** (interactive causality graph over the IKG's
spawned/created/modified/contacted/loaded edges).

---


## 2026-02-25 · Phase 4.2 · Validation Pack — the release gate (SHIPPED)

Per operator direction: **"correctness is more valuable than new
features."** Every code change touching ingestion, normalization,
correlation, IKG, story, or the verdict engine must now clear a
34-dataset validation gate before merge.

### ExpectedInvestigation contract

`v2/ingestion/golden_corpus.py` — every Golden Corpus dataset now
declares a full `ExpectedInvestigation` contract:

```
verdict · confidence_band · device_score_min/max · incident_score_min/max
expected_mitre · expected_tactics_required · expected_tactics_optional
expected_story_sequence (semantic checkpoints) · expected_story_keywords
expected_processes · expected_parent_child · expected_iocs
expected_workspace_tabs · expected_report_sections
expected_verdict_reasoning · expected_explainability · expected_false_positive
```

Semantic story checkpoints (resilient to sentence wording):
`office_spawn · powershell · encoded_execution · download · persistence ·
credential_access · discovery · lateral_movement · c2 · impact ·
exfiltration · benign · defense_evasion`.

### Corpus (34 datasets · 4 categories)

**Benign (13)** — clean_workstation · clean_server · defender_scan ·
onedrive_sync · chrome_update · windows_update · vmware_tools · citrix ·
vpn_client · backup_agent · monitoring_agent
**Ambiguous (2)** — intune_deploy · enterprise_admin
**Suspicious (8)** — powershell_encoded · lolbas_certutil · mshta ·
wscript_download · rundll32_abuse · regsvr32_scrobj · office_macro_only ·
onenote_phish
**Malicious (13)** — office_phishing · cobalt_strike · ransomware ·
info_stealer · lumma · bumblebee · icedid · qakbot · asyncrat · remcos ·
akira · lockbit · black_basta

### Runner + 11-dimension matrix

`v2/validation/runner.py` — deterministic per-dataset runner. Scores
each dimension independently and marks a dataset PASS only when every
declared assertion holds. Ships with a `ValidationSummary` producing:
- overall_accuracy
- per-dimension accuracy (Verdict · Score · FP-Guard · MITRE · Story ·
  StoryText · Processes · Parent-Child · IOCs · Workspace · Report)
- average_investigation_ms · duration_ms

### Endpoints

- `GET /api/v2/validation/datasets` — list every dataset + declared assertions
- `GET /api/v2/validation/run`      — run the full suite → matrix + metrics
- `GET /api/v2/validation/run/{id}` — run one dataset

### Frontend (`/v2/validation`)

Full-color validation matrix (`ValidationPage.jsx`) with category pills,
per-dimension pass/fail cells, per-cell tooltips showing the exact
`expected vs got` detail, and CI metrics header.

### Under-the-hood fixes required to reach 100%

1. `v2/shadow/irg.py` — preserved caller-supplied `parent.name` on
   enriched frames (previously stripped, blocking `SUSPICIOUS_PARENT`
   signal on ingested telemetry).
2. `v2/ingestion/canonical.py` — enriched `ces_to_cem_dict()`
   provenance with `cmdline`, `target`, `parent_name` so the frozen
   v3.1b Verdict Engine picks up ingested telemetry without touching
   signals.py.
3. `v2/ingestion/mitre_map.py` — deterministic keyword → MITRE mapper
   (T1027 · T1059 · T1105 · T1218 · T1547 · T1543 · T1053 · T1003 ·
   T1082 · T1021 · T1490 · T1486 · T1562 · T1071).

### CI release gate

`tests/test_validation_pack.py` — 8 guardrail tests. **The build fails
on any regression:**
- test_all_datasets_pass
- test_overall_accuracy_is_100_percent
- test_every_dimension_at_100_percent
- test_benign_datasets_never_flagged_malicious
- test_malicious_datasets_score_at_least_15
- test_investigation_is_fast (≤ 250 ms per dataset)
- test_categories_populated
- test_corpus_size_at_least_30

### Results · 34/34 · 100% accuracy · 4.43 ms/dataset

Total suite (Phase 3 + 4.1 + 4.2): **83/83 tests green**.
- test_ingestion_phase4 · 21/21
- test_validation_pack  ·  8/8
- test_investigation_ikg · 10/10
- test_investigation_phase2 · 9/9
- test_verdict_v3 · 9/9
- test_verdict_v3_correlation · 12/12
- test_verdict_v3_1b · 14/14

### Approved roadmap forward

1. **✅ Phase 4.1** · Investigation Ingestion Engine
2. **✅ Phase 4.2** · Validation Pack + Golden Corpus expansion
3. **Phase 5**  · Evidence Graph (Konva causality view over IKG edges)
4. **Phase 5.5** · Enterprise Adapters (Defender · CrowdStrike ·
   SentinelOne · Cisco SEP · Splunk · QRadar) — all normalize into CES
5. **Continuous** · IKB expansion (Volumes 1-11)
6. **Phase 6** · Real Customer Replay Validation (accuracy metrics
   against real logs vs expected investigations)
7. **Phase 7** · Multi-host investigations (device_group node in IKG)

---

## 2026-02-25 · Phase 4.1 · Investigation Ingestion Engine (SHIPPED)

Operator direction: architecture is frozen. The absolute next pivot is
**ingestion** — turning NivXRay from a consumer of seeded telemetry
into a full end-to-end platform that accepts real customer logs and
generates the Investigation Workspace + Report deterministically.

### Pipeline (Canonical Event Schema is the contract)

```
Upload
   │
   ▼
Format Detection    (EVTX / JSON / CSV / XML / ZIP)
   │
   ▼
Source Detection    (Sysmon / Windows Security / canonical / generic)
   │
   ▼
Normalizer          → Canonical Event Schema (CES · 36 fields · locked)
   │
   ▼
CES → CEM v1 bridge
   │
   ▼
Evidence Store      (v2_shadow_observations)
   │
   ▼
Frame Enricher      (cmdline · target · parent.name · MITRE)
   │
   ▼
Correlation → IKG → Investigation Workspace + Report
```

### Backend module (`v2/ingestion/`)

- `canonical.py`         — CES v1 dataclass, IngestionProvenance, CES→CEM writer,
                           deterministic keyword→MITRE tagger.
- `format_detector.py`   — magic-byte + content probe (XML / JSON / CSV / ZIP / EVTX / TXT).
- `source_detector.py`   — Sysmon vs Windows Security vs canonical vs generic CSV.
- `normalizers/`
  * `sysmon_xml.py`         — every Sysmon EventID → CES, namespace-agnostic ET.
  * `windows_security.py`   — 13 Win-Sec event IDs (4624/4625/4634/4672/4688/4697/4698/4720/4732/4776/5140/5145/5156/7045/1102).
  * `json_canonical.py`     — canonical CES JSON + NDJSON + generic loose JSON (with field aliases).
  * `csv_generic.py`        — CSV with header row + alias matching.
- `pipeline.py`         — orchestrator: detect → normalize → CES → bulk-insert.
- `metrics.py`          — Ingestion Quality Metrics (coverage · unknown IDs · unsupported fields · durations).
- `golden_corpus.py`    — 6 datasets (clean_workstation, office_phishing, cobalt_strike, enterprise_admin, ransomware, info_stealer).
- `mitre_map.py`        — deterministic keyword → MITRE technique mapper (T1027 / T1059 / T1105 / T1218 / T1547 / T1543 / T1053 / T1003 / T1082 / T1021 / T1490 / T1486 / T1562 / T1071).
- `frame_enrich.py`     — post-processor that hydrates cmdline / target / parent.name / mitre onto trajectory frames from ingested telemetry (so the frozen v3.1b Verdict Engine picks them up without touching signals.py).

### Endpoints

- `POST /api/v2/ingestion/upload`               — multipart file upload → IngestionResult.
- `GET  /api/v2/ingestion/formats`              — supported-format capability descriptor for the UI.
- `GET  /api/v2/ingestion/golden`               — list the 6 Golden Corpus datasets.
- `POST /api/v2/ingestion/golden/{dataset_id}`  — materialise one dataset into a fresh case.
- `GET  /api/v2/cases/{id}/investigation`       — now runs the frame-enricher automatically before build_investigation.

### Frontend (`/v2/ingest`)

Drag-drop uploader (`IngestionPage.jsx`) with:
- Drop zone that accepts any file (auto-detect kicks in).
- Ingestion Quality Metrics card (files uploaded · events parsed · normalized · persisted · coverage % · duration).
- Format + source detection pills.
- Unknown event IDs + parse errors surfaced inline.
- Golden Corpus cards (6 datasets · one-click seed).
- "OPEN WORKSPACE →" jump-to-workspace CTA.
- Roadmap ribbon showing Phase 4.2 (Defender / CrowdStrike / SentinelOne / Cisco / Splunk / QRadar) + Phase 4.3 (custom CSV/JSON with field-mapping UI).

Ingestion link is exposed in the workspace footer (`+ ingest logs`) and
the standalone `/v2/ingest` route.

### Golden Corpus verdict-alignment

| Dataset             | Expected     | Actual (SOC-Balanced) |
|---------------------|--------------|-----------------------|
| clean_workstation   | benign       | benign  (10 · conf 38%) |
| office_phishing     | critical     | low     (55 · conf 94%) |
| cobalt_strike       | critical     | critical(86 · conf 100%)|
| enterprise_admin    | benign       | benign  (10 · conf 35%) |
| ransomware          | critical     | suspicious(70 · conf 78%)|
| info_stealer        | critical     | informational (35 · conf 64%)|

The 3 "close-but-not-critical" datasets score honestly against the
frozen v3.1b engine — bringing them fully into `critical` requires
either richer telemetry (Phase 4.2 EDR exports) or expanded IKB
patterns (Phase 5), NOT verdict engine changes.

### Tests · 21/21 green · zero regressions

`tests/test_ingestion_phase4.py` covers:
- Format detection (XML / JSON / CSV / ZIP / empty).
- Source detection (Sysmon / Windows Security / canonical / generic CSV).
- Every normalizer end-to-end (Sysmon XML, Win-Sec XML, JSON, CSV).
- ZIP dispatch across mixed sources.
- CES → CEM v1 bridge + kind resolution + determinism.
- CES field-count contract (36 fields locked).
- Golden Corpus round-trip through build_investigation.
- Verdict-alignment (clean ≤ 30, cobalt_strike ≥ 60, admin ≤ 30).

Total suite: **75/75 tests green** (21 new · 54 prior).

---

## 2026-02-24 · Phase 3b · Investigation Knowledge Base (IKB) seed corpus (SHIPPED)

Strategic pivot: architecture is now mature. Future value comes from
**detection intelligence** (IKB corpus), not more UI.

### IKB corpus · 10 seed entries

`/app/backend/v2/ikb/{schema.py, entries.py}` — structured, machine-readable
domain knowledge. Every entry conforms to a single schema and is consumed
by signals, story, explainability, and (Phase 5) ingestion.

Entries shipped:
1. `telemetry_source:sysmon`               — every Sysmon Event ID → IKG mapping.
2. `windows_event:4624`                    — successful logon (all logon types + fields).
3. `windows_event:4688`                    — process creation (with GPO cmdline-audit).
4. `windows_binary:svchost.exe`            — service-host semantics, flags, abuse.
5. `windows_binary:werfault.exe`           — WER-abuse (BleepingComputer 2024-2026).
6. `lolbas:corpus`                         — LOLBAS project · principle + high-risk bins.
7. `decoder:xor`                           — XOR cipher decode strategy.
8. `enterprise_baseline:windows_update`    — legitimate WU baseline.
9. `enterprise_baseline:onedrive`          — cloud-sync baseline.
10. `enterprise_baseline:chrome_updater`   — Chrome auto-update baseline.

Each entry declares: `normal_behavior`, `common_abuse[]` (with severity +
MITRE), `detection_guidance[]`, `false_positives[]`, `mitre[]`,
`correlation_rules[]`, `references[]`. Full reference-link provenance
preserved for every entry.

### Backend endpoints

- `GET /api/v2/ikb`            — list all entries (10)
- `GET /api/v2/ikb/{entry_id}` — single entry lookup
- `investigation.ikb` — the Investigation response now carries a filtered
  view: windows_binary entries auto-attach when observed on the device;
  non-binary entries (Sysmon, LOLBAS, 4624/4688, XOR, baselines) are
  always attached. Live case surfaces 8 relevant entries.

### Frontend wiring

- **Evidence Card** now shows a `Knowledge Base` section whenever the
  selected process has a matching KB entry. Displays category,
  description, top-4 abuse patterns (severity-colored), top-3 detection
  guidance lines, and reference count.
- **Global Search** now includes IKB entries as `IKB` results (purple
  pill). Searching "svchost" surfaces both the observed process AND its
  KB entry side-by-side.

### Tests: 54/54 green

`test_verdict_v3.py` (9) · `test_verdict_v3_correlation.py` (12) ·
`test_verdict_v3_1b.py` (14) · `test_investigation_ikg.py` (10) ·
`test_investigation_phase2.py` (9). RC5: untouched.

---

## Updated strategic roadmap (locked per operator direction)

**Track A — Product (architecture frozen)**
- Phase 3b remaining · Evidence Graph · Trajectory back-sync
- Phase 4 · Summary tab · Verdict tab · Reports (IKG-driven)
- Phase 4.5 · Analyst Notes · Saved Investigation Views · Bookmarks

**Track B — Detection Intelligence (primary investment)**
- Phase 5 · Expand IKB corpus:
  * Volumes 1-11 outlined in the operator brief (Process · Sysmon Event IDs
    · Windows Security Event IDs · Registry persistence · Network · Files
    · Users/Sessions/Auth · Persistence catalog · MITRE mapping · TI ·
    False-positive engineering).
  * Enterprise baselines: Windows Update ✓ · OneDrive ✓ · Chrome Updater ✓
    · Microsoft Defender · SCCM · Intune · Backup Agents · VMware Tools ·
    Citrix · VPN Clients (pending).
  * Detection rule imports: Sigma · Snort · YARA.

**Track C — Ingestion (Phase 6)**
Investigation Ingestion Engine — drag-and-drop upload accepting EVTX,
JSON, CSV, TXT, LOG, XML, ZIP, Sysmon exports, Cisco SEP, Microsoft
Defender, CrowdStrike, SentinelOne, Splunk, QRadar. Every source
normalises into the canonical IKG schema. Once shipped, an analyst can
drop a ZIP of logs and get the full workspace + report auto-populated.

**Frozen · will NOT change**
- Investigation Knowledge Graph (IKG) — schema
- SelectionContext — selection propagation model
- Evidence Card — universal drill-down component
- Unified Workspace shell — layout, tab strip, explainability rail
- Verdict Engine v3.1b — deterministic scoring

---



Rated 9.8-9.9/10 on architecture. Phase 3a delivers the cross-view
synchronisation foundation and the two most-important navigation-hub
components.

### New architectural primitive · SelectionContext

`v2/pages/SelectionContext.jsx` — one global React Context wrapping the
whole workspace. Holds the current selection object
`{ kind, id, frame_iid, process_iid, source }`. Every view reads and
writes this ONE object instead of duplicating selection state.

Ripple pattern:
```
Click Story sentence  ─┐
Click Trajectory event ├──►  SelectionContext.setSelection()  ──►  every view re-renders
Click Process node    ─┘
Click ATT&CK tech     ─┘
```

The URL query param `?focus=<frame_iid>` mirrors the current selection
so shareable deep links reproduce it.

### Frontend components

- `v2/pages/EvidenceCard.jsx` — the UNIVERSAL drill-down side rail.
  Always the same look regardless of the source view. Reads current
  selection from SelectionContext; resolves it against the IKG loaded by
  the workspace shell. Renders:
    * Event · timestamp · lane · action · rule · frame IID
    * Process · image · first seen · cmdline · process IID
    * Relationships · parent · children · files · registry · network
    * MITRE ATT&CK · technique chips
    * Verdict · layer · score · band · confidence · explanation
    * Jump-to bar · trajectory | story | graph | process | attack
  Floating right rail, closable, 380px wide.

- `v2/pages/ProcessTreeTab.jsx` — parent → child DFIR view. Flattens the
  IKG's `spawned` edges into a linear indented tree. Each node shows
  image, verdict badge (band + score), technique count, child count.
  Clicking a node updates the SelectionContext → every other tab
  (Story · Trajectory · Attack Card · Evidence Card) refocuses.

### Workspace shell wiring

- `InvestigationWorkspace` now split into an inner component
  (`InvestigationWorkspaceInner`) and a `SelectionProvider`-wrapping
  default export. Every tab receives the shared selection via context.
- Global `<EvidenceCard>` overlay renders on top of every tab.
- `?focus=<frame_iid>` on the URL hydrates the SelectionContext on load
  (deep-link support for shared investigations).
- Attack Story sentences push to selection on both click-anywhere
  (opens Evidence Card in-place) and `show on trajectory →` (jumps + selects).
- Process Tree tab clicks push a `kind:"process"` selection.

### Tests

- All prior 44/44 tests still green. Phase 3a is UI-layer wiring;
  backend contract unchanged (no new endpoint needed — Evidence Card
  reads the same `/investigation` response).

---



Rated 10/10 on architecture; Phase 2 is the operator's approved
storytelling & explainability activation. Zero regression — no existing
route/tab removed.

### Backend

- `v2/investigation/attack_story.py` — deterministic sentence generator
  that traverses the IKG's `spawned` edges + reads process-level signals
  from the correlation output. Emits sentences with `text`, `tactic`,
  `severity`, `frame_iids`, `process_iids`, `signals`, `evidence_ref`.
  Sentence types covered: Initial Spawn (Office/Browser → LOLBin) ·
  Encoded Execution · Download Cradle · Persistence · Credential Access
  · Defense Evasion · Command-and-Control · Impact/Ransomware. Fallback
  sentence when no explicit pattern matches but the device is non-benign.
- `v2/investigation/attack_mapping.py` — ATT&CK projection of the IKG:
  per-tactic technique buckets (level 1..3), kill-chain view (every
  canonical tactic marked ✓ / ○), MITRE Navigator v4.5 layer JSON
  ready for export, STIX 2.1 technique-id handoff.
- `v2/investigation/explainability.py` — POSITIVE ("Why is this
  <band>?") and NEGATIVE ("Why isn't this ransomware / credential-theft
  / lateral-movement / persistence / beaconing?") deterministic
  reasoning. Each attack pattern declares `required` and `supporting`
  signals with min-threshold rules. `have_required` / `missing_required`
  arrays surface exactly which required behaviours are absent.
- `builder.py` extended — Investigation object now carries `story`,
  `attack_mapping`, `explainability` (positive + negative_patterns list).
- New endpoint: `GET /api/v2/cases/{id}/investigation/explain/{pattern_id}`
  for on-demand negative reasoning.

### Frontend

- `v2/pages/AttackStoryTab.jsx` — analyst-facing narrative view. Each
  sentence card shows: tactic pill · severity · fired signals · event/
  process counts · **"show on trajectory →"** button that navigates to
  `?tab=trajectory&focus=<frame_iid>` (Story→Trajectory sync via URL).
- `v2/pages/AttackTab.jsx` — dedicated ATT&CK view:
  * Coverage bars per tactic (level 1..3, color-coded blue/orange/red)
  * Kill chain (every canonical tactic, covered ✓ / gap ○)
  * Technique cards grouped by tactic
  * **Export Navigator JSON** — downloads MITRE Navigator v4.5 layer
  * **Export STIX 2.1** — piggybacks the existing report endpoint
- `InvestigationWorkspace.jsx` — Explainability panel upgraded with a
  question-picker: "Why is this <band>?" (positive · pre-computed) +
  one button per attack pattern for "Why isn't this <pattern>?"
  (negative · lazy-loaded per pattern). Verdict line rendered as a
  monospaced footer summary of the reasoning.

### Backend tests: 9/9 new Phase 2 tests green

- `tests/test_investigation_phase2.py` covers story emission (Office →
  LOLBin), determinism, evidence links, ATT&CK mapping population and
  Navigator schema, ATT&CK determinism, positive explainability
  reasons, negative ransomware (both matches and no-matches cases),
  unknown-pattern error handling.

### Cumulative test status (44/44 verdict + IKG tests green)

- test_verdict_v3.py                — 9/9
- test_verdict_v3_correlation.py    — 12/12
- test_verdict_v3_1b.py             — 14/14
- test_investigation_ikg.py         — 10/10
- test_investigation_phase2.py      —  9/9
- RC5 backend suite                 — 820/820 (untouched)

### Live smoke on `case_dfir_bumblebee_akira_2026`

- Story: at least 1 sentence emitted from real data (`wbadmin.exe
  accessed credential material`).
- ATT&CK: 6 tactics · 21 techniques · 18 unique bases. Navigator
  layer JSON exports cleanly.
- Negative "Why isn't this ransomware?" returns:
  `matches: false · missing_required: [BACKUP_DESTRUCTION,
  MASS_FILE_ENCRYPTION, RANSOM_NOTE_CREATION] · verdict: Classification
  remains as-is: not enough ransomware-specific evidence.`

---

## 2026-02-24 · Phase 1 · IKG + Unified Workspace shell (SHIPPED)

`v2/investigation/{ikg.py, builder.py}` + `/v2/case/:caseId` route with
persistent header, URL-driven tab strip, embedded Trajectory tab,
global Explainability panel. All existing routes preserved.

## 2026-02-24 · Verdict Engine v3.1b — FROZEN

Deterministic scoring engine complete. See git log for history.

---

## Backlog · Prioritised roadmap

### Phase 3b — Evidence Graph + Trajectory back-sync
- **Evidence Graph tab** — Konva causality graph over the IKG's
  spawned/created/modified/contacted edges. NOT chronological. Nodes
  clickable → SelectionContext (Evidence Card auto-opens).
- **Trajectory ← Story back-sync** — clicking an event on Trajectory
  should update SelectionContext so the corresponding Story sentence
  highlights when the analyst returns to that tab.

### Phase 4 — Executive views
- Summary tab (executive dashboard: severity, device/incident risk,
  confidence, timeline sparkline, recommendations).
- Verdict tab (dedicated hierarchical verdict view with escalation
  ladder and evidence breakdown lifted out of the drawer).

### Phase 5 — Enrichment + Reports
- Threat Intelligence tab (enrichment-only overlay on the IKG).
- Reports tab (one-click bundle export reading from the IKG).

### Phase 6 — Investigation Ingestion Engine (strategic milestone)
Reframe NivXRay from a "consumer" of seeded telemetry to a full
end-to-end platform. New "Investigation Input" page accepts:
- Drag-drop file upload (multi-file · ZIP · single-file)
- Auto-format-detection (EVTX · JSON · CSV · TXT · XML · LOG · NDJSON)
- Auto-source-detection (Sysmon · Windows Security · Cisco SEP ·
  Microsoft Defender · CrowdStrike · SentinelOne · Splunk · QRadar)
- Normalisation → canonical event schema
- Auto-populates every workspace tab and generates the full Report.
- Reference: Splunk Lantern doc on enabling Windows Event 4688
  command-line auditing via GPO.

### Phase 7 — NivXRay Investigation Knowledge Base (IKB)
Structured domain-knowledge foundation powering the deterministic
engine. Reference material for detectors, correlation, story,
explainability, and false-positive engineering.
- Volume 1 — Process (creation · parent-child · advanced abuse)
- Volume 2 — Sysmon Event IDs (every ID · fields · abuse · MITRE)
- Volume 3 — Windows Security Event IDs (4624/4625/4672/…)
- Volume 4 — Registry (Run keys · Services · IFEO · CurrentVersion)
- Volume 5 — Network (TCP/UDP · DNS · TLS/JA3 · SMB · Kerberos ·
  LDAP · HTTP · beaconing · exfiltration)
- Volume 6 — Files & Filesystem (MFT · timestomping · alternate streams)
- Volume 7 — Users, Sessions & Auth (logon types · Kerberos abuse)
- Volume 8 — Persistence catalog (all MITRE T1547 sub-techniques)
- Volume 9 — MITRE ATT&CK mapping (tactic → technique → sub-technique)
- Volume 10 — Threat intelligence (IOC types · TI sources · TTP catalog)
- Volume 11 — False-positive engineering (baselining · time · frequency
  · environment · context · evidence layering)

### Constraint
Every phase MUST preserve every existing route and workflow.

---

## Key APIs

- `GET /api/v2/cases/{id}/investigation?profile=<id>` — **the unified investigation**.
- `GET /api/v2/cases/{id}/investigation/explain/{pattern_id}` — negative explainability.
- `GET /api/v2/cases/{id}/verdicts` — per-event verdicts (v3).
- `GET /api/v2/cases/{id}/verdicts/aggregate?profile=<id>` — v3.1 multi-layer.
- `GET /api/v2/verdict/profiles` — Adaptive Weight Profiles.
- (Legacy trajectory + IRG + ancestry + report endpoints all preserved.)

## Feature Flags

- `NIVX_FLAG_TRAJECTORY_ENGINE=shadow`
- `NIVX_FLAG_CASE_ENGINE=shadow`
- `NIVX_FLAG_ADAPTERS=shadow`
- `NIVX_FLAG_VERDICT_ENGINE_V3=shadow` — gates every v2 investigation
  capability.

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
