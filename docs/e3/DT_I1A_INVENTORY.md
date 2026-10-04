# DT-I1A: Device Trajectory Investigation Inventory and Status Matrix

- **Baseline:** `feature/e3-edr-engines` @ `cd5b4e1b` (directive commit `a33ea1ad`).
- **Scope:** read-only inventory. This milestone changes no behaviour.
- **Method:** source inspection of this clone only. No screenshots have arrived yet (owner decision 4), so the visual review of directive §28 is **PENDING**.
- **Classification:** EXISTS_AND_PROVEN, EXISTS_PARTIAL, EXISTS_NOT_WIRED, MISSING, DUPLICATED, DEFERRED.
  - "PROVEN" here means proven by code plus existing tests in this repo. It never means real-telemetry validation.

## 0. Critical findings (they drive DT-I1C)

| # | Finding | Location | Directive conflict | Status |
|---|---|---|---|---|
| F1 | `verdictOf(f)` returns `"benign"` when a frame has no MITRE tags. "No ATT&CK" is rendered as BENIGN with green styling. | `frontend/src/v2/pages/DeviceTrajectoryV2.jsx:32-42` | §2.8 (no ATT&CK ≠ benign), §15.3 | **FIX in DT-I1C** |
| F2 | `verdictOf` promotes MITRE-tagged frames **without any rule/detection** to `"malicious"` via a technique regex (T1003, T1027, T1055, …). The result is red and a "compromise band" with no detection attribution. | same | §13 FIX (red requires supported threat attribution), §44 | **FIX in DT-I1C** |
| F3 | MITRE chips are always red (`T.redT/T.red`), whether or not any engine attributed them. | `EvidencePane`, ~L1520-1539 | §13 FIX | **FIX in DT-I1C** |
| F4 | The "Block SHA" and "Allow-list" buttons have **no handler and no backend wiring**. They imply response capability that does not exist. | `EvidencePane` ACTIONS, ~L1568-1581 | §16, owner update ("never show capability the backend can't provide") | **FIX in DT-I1C**: render as NOT_WIRED and disabled. Copy IID is kept. |
| F5 | The ancestry edges have a *heuristic depth-based fallback* when IRG `entity.iid`/`parent.iid` are absent. | `DeviceTrajectoryV2.jsx` ~L325-360 | §2.5, §5 (no inferred links presented as fact) | **DT-I1D**: label as CORRELATED/UNKNOWN |
| F6 | The strings the owner references, "No detection engine claimed this observation" and "Absence of detection is not evidence of clean", **do not exist anywhere in this branch** (frontend or backend). The deployed console the screenshots come from may be built from a different ref. | grep over the repo | §28 | **OWNER CONFIRMATION NEEDED** (non-blocking). DT-I1C adds both statements truthfully. |
| F7 | The IOC consensus uses a `clean` verdict. Pending and error results are weighted 0, so they give `unknown`, which is good. But `clean` ≠ the directive's BENIGN with provenance, and NO_DATA / UNAVAILABLE / RATE_LIMITED are not distinct states. | `services/ioc_intelligence/consensus.py`, `schema.py` | §9 | DT-I1E: map them behind a view contract; providers unchanged |
| F8 | `pages/DeviceTrajectoryPage.jsx` (legacy) and `v2/pages/DeviceTrajectory.jsx` are retained beside the routed `v2/pages/DeviceTrajectoryV2.jsx`. | `App.js:51,71,204-205` | none | DUPLICATED (legacy, unrouted). Not touched |

## 1. Device Trajectory surface

| Item | Implementation | Status | Notes |
|---|---|---|---|
| Routed DT page | `v2/pages/DeviceTrajectoryV2.jsx` (`/v2/trajectory/:caseId`) | EXISTS_PARTIAL | Contains the case bar, time compass, attack-chain sidebar (MITRE stages), canvas, evidence pane, status bar, filters popover and device drawer |
| Data API | `GET /api/v2/cases/{case_id}/trajectory/device?limit≤5000` (`backend/v2/routers/trajectory.py`) | EXISTS_PARTIAL | Built from shadow observations (`build_from_observations`), with IRG enrichment and evidence-bridge annotation (`BRIDGED / REFERENCED_RECORD_ABSENT / LEGACY_UNBRIDGED`). Case-scoped authz is `engine_case_read`. The limit is bounded but there is no cursor pagination |
| Frame contract | `v2/trajectory/schema.py::TrajectoryFrame` | EXISTS_AND_PROVEN | Fields: frame_iid, ts, lane, action, label, device/process/parent/file/registry/network/user `EntityRef`, mitre, labels, evidence_ids, canonical_evidence_id, provenance |
| Verdict aggregate | `GET /api/v2/cases/{id}/verdicts/aggregate` (`v2/routers/verdicts.py`, `CorrelationPanel.jsx`) | EXISTS_PARTIAL | Profile-based aggregate. It is not a per-event Assessment with supporting/contradicting evidence |
| Activity Details (per event) | `EvidencePane` | EXISTS_PARTIAL | Shows the verdict badge, command line, SHA, actor, parent, MITRE, remote IP, detection rule and actions. It has no sections for causal state, behavior, ML, TI result, supporting/contradicting/missing evidence, retro history, response state or provenance |
| Endpoint header / summary row | `CaseBar` and `DeviceDetailsDrawer` | EXISTS_PARTIAL | Case-centric. Health, isolation and sensor state are not bound to the backend proof states |
| Search / filters | `FiltersPopover` (verdict/kind groups) | EXISTS_PARTIAL | The client-side "verdict" filter inherits F1/F2 |
| JS test runner | `craco test` (jest) is declared in `frontend/package.json`, but `node_modules` is **not installed** in the clone | EXISTS_NOT_WIRED | Pure view-model JS is tested with Node's built-in `node:test` (no install). React render tests are **DEFERRED** until an approved isolated install |

## 2. Engines and evidence

| Capability | Implementation | Status | Notes |
|---|---|---|---|
| Behavioral / sequence engine | `backend/edr_behavior` (E3) | EXISTS_AND_PROVEN (synthetic) / EXISTS_NOT_WIRED | Gives MATCH / NO_MATCH / INSUFFICIENT_EVIDENCE, evidence_refs and deterministic IDs. Not fed by the live pipeline |
| ML signals | `backend/edr_ml` (E3) | EXISTS_AND_PROVEN (synthetic) / EXISTS_NOT_WIRED | Starter models are **TESTING**. ML alone never creates a detection |
| Deterministic rules (E1) | `detection_content/*`; `rule_id` appears on frames | EXISTS_PARTIAL | The frame carries `rule_id` / `provenance.rule_id` and `confidence`. There is no EngineResult contract |
| TI broker | `services/ioc_intelligence` (engine, consensus, cache, health; providers malwarebazaar, threatfox, urlhaus, urlscan, hybrid_analysis, talos, dshield, VT, AbuseIPDB). Also `threat_intel_enrich/`, `routers/enrichment.py`, `routers/threat_intel_enrich.py`, `feeds.py` | EXISTS_PARTIAL + DUPLICATED | There are at least two enrichment paths, and the state vocabulary is not normalised (F7). The DT shows only outbound VirusTotal / AbuseIPDB **links**, not TI results |
| MITRE | `frame.mitre` (from observations), `tacticOf()` client mapping | EXISTS_PARTIAL | Tags carry no attribution source (engine / rule / evidence). The red styling is unconditional (F2, F3) |
| Process identity | M1 `process_iid`; IRG `entity.iid` / `parent.iid` / `root.iid`; `services/entity_resolution.py`; `docs` `PROCESS_IDENTITY_CAUSALITY_DESIGN` | EXISTS_PARTIAL | The UI has a heuristic edge fallback (F5). Edges have no relationship state (PROVEN_CAUSAL / SUPPORTED / CORRELATED / UNKNOWN) |
| Provenance | `frame.provenance`, evidence bridge state, `canonical_evidence_id` | EXISTS_PARTIAL | Bridge state is computed server-side (good) but is **not rendered** in the EvidencePane |
| Response state | `edr_plane/response.py` (`REQUESTED → AUTHORIZED → DISPATCHED → EXECUTED → VERIFIED`, plus `FAILED / VERIFICATION_FAILED / CAPABILITY_UNAVAILABLE / REFUSED`) and `PROOF_STATES`. Routes are in `routers/edr_response.py` | EXISTS_AND_PROVEN (E1, protected) | This is a truthful proof-state vocabulary already, and the EXECUTED wording reads "SENSOR_CLAIM_ONLY_NOT_VERIFIED". The DT does **not** display it. DT-I1H must consume it read-only |
| Assessment engine (§11) | none | MISSING | |
| Hypothesis engine (§12) | none | MISSING | |
| Retrospective replay (§10) | E3 `edr_behavior/replay.py` (rule replay only) | EXISTS_PARTIAL | Covers RULE_CHANGE only. There is no INTEL / MODEL / REPUTATION / ANALYST trigger and no append-only assessment history |
| Analyst disposition (§14) | Analyst notes (`FloatingAddNoteButton`, `AnalystNarrativePanel`) | EXISTS_PARTIAL | No controlled disposition vocabulary, and no separation from machine assessment |
| Canonical authority | `v2_shadow_observations` (CEM) vs `xdr_canonical_evidence` (DSM) | DEFERRED (owner decision) | E3 stays store-independent (§2.7) |

## 3. Plan consequences
1. **DT-I1B:** a store-independent `backend/edr_investigation/` view-model package covering every §15 section, with explicit `NOT_WIRED` / `UNAVAILABLE` / `UNKNOWN` states and contract tests.
2. **DT-I1C:** fix F1–F4 in `DeviceTrajectoryV2.jsx` and add namespaced Activity Details sections driven by a pure JS view model that mirrors the contract.
3. **DT-I1D:** relationship-state labelling for the ancestry edges (F5).
4. **DT-I1E:** TI view-contract mapping (F7).
5. **DT-I1F – J:** as in the directive §26.
