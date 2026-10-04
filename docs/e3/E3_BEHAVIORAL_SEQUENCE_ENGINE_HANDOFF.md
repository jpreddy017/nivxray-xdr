# NivXForge E3: Behavioral + Sequence Detection Engine (Handoff)

- **Status:** IMPLEMENTED AND UNIT-TESTED on a local branch. **Not merged, not pushed, not deployed, not wired into E1.**

| Item | Value |
|---|---|
| Repo clone | `/app/memory/nivxray-xdr` (jpreddy017/nivxray-xdr) |
| Branch | `feature/e3-edr-engines` (local only; no remote changes, no push) |
| Base SHA | `1800aeea8af699786b93961621cf1fca97382b95` (`feature/rc2-alignment`) |
| Final SHA | see `git -C /app/memory/nivxray-xdr rev-parse feature/e3-edr-engines` (also in the final report) |
| Package | `backend/edr_behavior/` (new) |
| Tests | `backend/tests/edr_behavior/` (new) |
| Research note | `docs/e3/E3_BEHAVIORAL_SEQUENCE_RESEARCH_NOTE.md` |

## 1. What was built
A deterministic, evidence-bound behavioral/sequence detection engine. It works as follows:

1. It consumes normalized `EvidenceRecord`s through an **EvidenceProvider** abstraction. It is **not** coupled to `v2_shadow_observations` or `xdr_canonical_evidence`, because that authority decision is still pending.
2. It evaluates versioned, JSON-defined `SequenceRule`s (ordered and optional stages, negative stages, thresholds, relationship constraints, exclusions, confidence adjustments) inside bounded per-(tenant, endpoint) windows.
3. It produces `Detection`s with deterministic IDs, evidence refs, raw refs, canonical event ids, process identities, MITRE techniques, a deterministic explanation and full provenance.
4. It persists detections idempotently: merge-on-overlap with optimistic concurrency.
5. It supports retrospective replay through the **same** code path (`MODE_RETRO`), with checkpoints.
6. It exposes observability counters, including per-rule INSUFFICIENT_EVIDENCE counts.

## 2. Files added (no existing file modified)

| File | Purpose |
|---|---|
| `backend/edr_behavior/__init__.py` | ENGINE_ID, ENGINE_VERSION `e3-seq-1.0.0`, CONTRACT_VERSION `e3.behavior.v1` |
| `contracts.py` | EvidenceRef (generation-free `stable_key`), ProcessRef, EvidenceRecord, StageMatch, EvaluationResult, Detection, MLSignal (boundary), Enrichment (boundary), outcome/status constants |
| `predicates.py` | Safe three-valued (TRUE/FALSE/UNKNOWN) predicate language. Operator whitelist; no regex; no eval; depth/leaf/literal bounds; field-prefix whitelist |
| `rules.py` | `SequenceRule` strict parser (unknown keys rejected), content hash, `RuleRegistry` with lifecycle DRAFT/TESTING/ACTIVE/DISABLED/DEPRECATED and immutable versions |
| `normalize.py` | Adapter: runtime canonical dict (M1 `canonical_bridge` / `windows_eventlog.to_canonical` shape) → EvidenceRecord. Tenant/endpoint come from the authenticated context; payload tenant mismatch is rejected; string/list bounds; future-timestamp rejection. Also the DETECTION-observation and MLSignal adapters |
| `provider.py` | `EvidenceProvider` / `EnrichmentProvider` protocols; `InMemoryEvidenceProvider` (bisect windows); store-agnostic `MongoEvidenceProvider` (injected field names + mapper); `NullEnrichmentProvider`; `StaticEnrichmentProvider` |
| `matcher.py` | Bounded deterministic DFS matcher; relationship evaluation with linkage grading |
| `suppression.py` | Rule exclusions, tenant-owned `SuppressionEntry`/`SuppressionPolicy`, confidence adjustments. UNKNOWN never suppresses |
| `detection.py` | Deterministic detection id, explanation, provenance, merge |
| `store.py` | `DetectionStore` protocol, in-memory store, Motor-style `MongoDetectionStore` (revision-based optimistic concurrency), `INDEXES` spec, `ensure_indexes` (test/staging only) |
| `engine.py` | `SequenceEngine.process()`: the single path for live and retro |
| `replay.py` | `ReplayRequest`, `CheckpointStore`, `run_replay` |
| `metrics.py` | Counters, per-rule outcomes, latency, window state size |
| `content.py`, `content/starter_rules.json` | Rule-pack loader + 8 starter rules |
| `integration.py` | Standalone `BehaviorIntegration` adapter (disabled by default, never raises) + `canonical_doc_mapper` |
| `backend/tests/edr_behavior/*` | conftest, factory and 4 test modules (58 tests) |
| `docs/e3/E3_BEHAVIORAL_SEQUENCE_RESEARCH_NOTE.md` | Research note |

## 3. Areas NOT touched (verified: `git diff --name-status base..HEAD` shows only `A` entries)
- `edr_plane/processing_queue.py`, the durable ACK/ingest (`routers/edr_enrollment.py`), and `edr_plane/canonical_bridge.py`.
- Response authority (`edr_plane/authority.py`, `response.py`), auth, tenancy and RBAC.
- Either canonical store, process identity (M1–M5, including M4 `process_identity.py`), `services/entity_resolution.py`, the TI clients, audit and approvals, Trajectory and Process Tree.
- `server.py`; no route was registered.

## 4. Contracts

### 4.1 Input: `EvidenceRecord`
- Fields: `tenant_id`, `endpoint_id`, `kind` ∈ {PROCESS, PROCESS_TERMINATION, FILE, REGISTRY, DNS, NETWORK, AUTH, DETECTION}, `event_time` (tz-aware), `ref: EvidenceRef`, `fields` (namespaced: `process.*`, `parent.*`, `file.*`, `registry.*`, `dns.*`, `network.*`, `auth.*`, `user.*`, `detection.*`), `process: ProcessRef` (M1 `process_iid`, pid, process_guid, parent_pid, parent_process_guid, start_time, attribution_state), `not_observed`, `not_supported`, `truncated_fields`, `provenance`.
- `EvidenceRef` holds `tenant_id`, `raw_id`, `canonical_event_id`, `generation`, `store` (RAW / SHADOW_OBSERVATION / XDR_CANONICAL / UNSPECIFIED), `record_id` and `sub_key`.
- `stable_key = "ev_" + sha256("evidence", tenant_id, raw_id, sub_key)[:32]`. It **excludes generation**, so a queue retry that mints a new generation maps to the same evidence (doc 2 §6).
- **Missing fields stay absent.** Predicates on absent fields evaluate UNKNOWN, never FALSE and never clean.

### 4.2 Rules: `SequenceRule` (JSON)
- **Top-level fields:** `rule_id`, `version`, `name`, `description`, `enabled`, `lifecycle`, `severity` (LOW–CRITICAL), `confidence` 0–100, `time_window_seconds` 1–86400, `entity_scope` (process / device / user / file), `ordered`, `stages[]` (≤10), `relationships[]` (≤20), `exclusions[]`, `confidence_adjustments[]`, `mitre[]`, `evidence_requirements[]`, `provenance` (`source` ∈ NATIVE / CUSTOMER / SIGMA_DERIVED / ML_SIGNAL / TI_TRIGGERED), `created_at`, `updated_at`.
- **Stage fields:** `id`, `type` ∈ PROCESS / COMMAND / PROCESS_TERMINATION / FILE / REGISTRY / DNS / NETWORK / AUTH / DETECTION / INTEL; `predicate`; `optional`; `negate`; `min_count` (≤100); `confidence_bonus`.
  - COMMAND = PROCESS plus `process.command_line` must exist; if it doesn't, the stage evaluates UNKNOWN.
  - INTEL takes `on_types`, `observable_field`, `observable_type`, `verdict_in`, `min_confidence`, resolved via the EnrichmentProvider.
- **Relationships:**
  - `parent_child` (`min_linkage` SOURCE_PROCESS_GUID or PID_SURROGATE).
  - `same_process` (process_iid, else process_guid).
  - `same_user`.
  - `same_value` (`stageA:field == stageB:field`, path-normalised; covers same file/hash/domain/IP and written-then-executed).
  - `dns_to_ip`.
  - Same-device is implicit: the provider query is per endpoint, and the engine re-checks every record.
- **Predicate operators:** eq, neq, in, not_in, contains, contains_any, startswith, startswith_any, endswith, endswith_any, exists, not_exists, gte, lte, len_gte; combinators all / any / not.
- **Rejected at parse time:** regex, eval, unknown keys, non-whitelisted field prefixes, nesting deeper than 6, more than 64 leaves, lists longer than 256, literals longer than 512.

### 4.3 Output: `Detection`
- **Fields:** `detection_id`, `tenant_id`, `endpoint_id`, `rule_id`, `rule_version`, `rule_content_hash`, `detection_type="BEHAVIORAL_SEQUENCE"`, `first_seen`, `last_seen`, `severity`, `confidence`, `status` (OPEN / TESTING / SUPPRESSED), `scope_key`, `matched_stages[]` (stage_id, type, optional, evidence_keys, linkage), `involved_entities`, `evidence_refs[]`, `evidence_keys[]`, `raw_refs[]`, `canonical_event_ids[]`, `process_identities[]`, `mitre[]`, `explanation`, `provenance`, `engine_version`, `created_at`, `suppression`. The store adds `revision`.
- `provenance.chain` = RAW → NORMALIZED → ENTITY_PROCESS → SEQUENCE_MATCH → RULE → MITRE → DETECTION. Provenance also carries the normalizers, process-identity authority (M1), evidence stores, rule {id, version, content_hash, lifecycle, source}, mode, trigger, unknowns, notes, confidence adjustments and truncated fields.
- **"Why did NivXForge produce this?"** is answered by `explanation` (deterministic text listing each stage's evidence key, raw id, time, summary and linkage) plus `provenance`.
- `build()` refuses to create a detection without evidence.
- **Contract invariant (enforced in `Detection.__post_init__`):** `len(evidence_refs) >= 1`. Empty or `None` evidence_refs raise `ValueError`; omitting the field raises `TypeError` (it is a required field). Every ref must carry a `stable_key`, and `evidence_keys` must be non-empty. An evidence-less Detection object cannot exist.

## 5. Evaluation semantics
- **Trigger:** `engine.process(record)`.
  1. Rules are **pre-filtered** by kind and by whether the record can satisfy at least one stage (TRUE or UNKNOWN).
  2. For each candidate rule there is one bounded provider query: `[t − W, t + W]`, tenant + endpoint, the rule's kinds, `limit = max_window_events + 1` (default 5000).
  3. The window is de-duplicated by `stable_key` (highest generation wins).
- **Matcher:**
  - Anchors are the TRUE events of the first stage.
  - For each anchor, a DFS over later stages: ordered `rec.time ≥ previous bound stage time`, within `anchor + W`; relationships are evaluated against already-bound stages; optional stages are tried and then skipped; `min_count` groups need distinct evidence keys in the same scope; negative stages invalidate the chain only when TRUE.
  - The global evaluation budget (default 20000 candidate checks) yields BUDGET_EXCEEDED.
- **Outcomes (always explicit):** MATCH / SUPPRESSED / NO_MATCH / **INSUFFICIENT_EVIDENCE** / BUDGET_EXCEEDED.
  - INSUFFICIENT_EVIDENCE is returned when the only blockers were UNKNOWN values: parent linkage absent, GUID required but absent, command line absent, user absent, intel UNKNOWN, or `evidence_requirements` unmet.
  - It is counted in `insufficient_evidence` and per rule as `per_rule["<rule>@v<n>:INSUFFICIENT_EVIDENCE"]`.
  - A missing relationship is never inferred.
- **Linkage grading:**
  - GUID: authoritative.
  - PID_SURROGATE: Linux / PID-only; requires parent time ≤ child time; confidence −15 with an explanation note.
  - UNKNOWN: INSUFFICIENT_EVIDENCE.
  - A negative stage that cannot be proven absent applies −10 with a note.
- **Live and retro use identical code;** retro only passes `mode=RETRO` and a `trigger`.

## 6. Dedup / idempotency algorithm
```
detection_id = "e3det_" + sha256("det.v1", tenant_id, endpoint_id, rule_id, rule_version,
                                 scope_key, floor(anchor_event_epoch / time_window_seconds))[:32]
scope_key   = per entity_scope: process → "process:<M1 process_iid>"; device → "device:<endpoint>";
              user → "user:<name>"; file → "file:<sha256>" | "path:<path>";
              fallback "evidence:<anchor stable_key>" (never a guess)
```
- Excluded: generation, ObjectId, lease, retry count.
- **On emit:**
  1. Read by id.
  2. If absent, find an existing detection of the same tenant / endpoint / rule / version / scope sharing ≥1 evidence key (covers a window-bucket boundary and late arrival).
  3. Merge: union evidence, min first_seen, max last_seen, max confidence, preserve stage order.
  4. If nothing material changed, count `duplicates_prevented`.
  5. Writes use revision-based optimistic concurrency (`ConcurrencyConflict` → re-read + retry, up to 3).
- **Rule versions:** a v3 detection stays v3 (rule_version is part of the id). Activating v4 deprecates v3 for live evaluation only.
- **Known bound:** at most one detection per (rule version, scope entity, window bucket). Distinct chains by the same scope entity inside one bucket merge into a single detection with the union of evidence.

## 7. FP controls (`ALLOWLIST ≠ DELETE EVIDENCE`)
- **Rule `exclusions[]`** (stage-scoped predicates): expected parent/child pairs, management tooling (e.g. E3-SEQ-004 Windows Update hosts), service accounts (`user.name`), paths and signers.
- **Tenant `SuppressionEntry`:** tenant-owned (tenant required), optional rule / endpoint / stage scope, expiry, `created_by`, reason.
- **Confidence adjustments**, `min_count` thresholds and windows.
- **Outcome:** status SUPPRESSED, with the full evidence and the suppression record retained. Suppression never touches evidence stores.
- **UNKNOWN never suppresses.** For example, a signer is `not_supported` by both sensors today, so "trusted signer" exclusions are noted as not evaluable and not applied.

## 8. Starter pack (`content/starter_rules.json`, all ACTIVE v1, NATIVE). Not full coverage.

| Rule | Chain | MITRE |
|---|---|---|
| E3-SEQ-001 | Office → script interpreter (parent_child) [+15 for download/encoding markers] | T1566.001, T1059 |
| E3-SEQ-002 | Encoded PowerShell → (DNS, optional) → external network, same process, dns_to_ip | T1059.001, T1027, T1071 |
| E3-SEQ-003 | Interpreter → child with LSASS/SAM credential-access command line | T1003.001, T1003.002 |
| E3-SEQ-004 | LOLBin → external network, same process (Windows Update exclusion) | T1218, T1105 |
| E3-SEQ-005 | Interpreter/LOLBin → Run/RunOnce/Winlogon/IFEO registry set, same process | T1547.001, T1546.012 |
| E3-SEQ-006 | Executable written → executed from the same path (file scope) | T1105, T1204.002 |
| E3-SEQ-007 | Script → writes payload (same process) → payload executed | T1059, T1105, T1204.002 |
| E3-SEQ-008 | Server process (w3wp / sqlservr / nginx / httpd…) → shell with recon command line | T1505.003, T1033 |

**Telemetry caveats (from Phase 1B/1C):**
- Registry, DNS and Sysmon GUID linkage exist on Windows only.
- Linux parent linkage is PID-only (PID_SURROGATE).
- Linux file events have no actor process, so E3-SEQ-007's `same_process(script, drop)` is INSUFFICIENT_EVIDENCE on Linux.
- Signer is not supported on either sensor.

## 9. Performance / scale
- **Per event:** O(R_k) predicate pre-filter (R_k = rules for that kind), then per candidate rule one indexed range query of at most `max_window_events` and a DFS bounded by `budget`.
- **Memory:** bounded by the window (≤5000 records) per evaluation. No unbounded in-process sequence state: state is re-derived from the provider, which gives at-least-once safety and order independence.
- **Known cost:** each triggering event re-queries its window. Hot endpoints pay O(events × window). Mitigations for later: per-endpoint window cache, trigger only on non-first stages, incremental partial-match state.
- **Index specs** (`store.INDEXES`; E3 branch only, never applied to production):
  - `e3_behavior_detections`: unique (tenant_id, detection_id); (tenant_id, endpoint_id, rule_id, rule_version, scope_key); (tenant_id, evidence_keys); (tenant_id, last_seen).
  - `e3_behavior_replay_checkpoints`: unique (tenant_id, replay_id, endpoint_id).
- **Evidence store index required for `MongoEvidenceProvider`:** compound (tenant, endpoint, event-time). The equivalent on the chosen canonical store is **UNVERIFIED** (doc 1 §3).
- **Concurrency:** the engine is async; optimistic revisioned writes; the E1 queue currently runs `worker_count=1`.

## 10. Security
- Telemetry is treated as attacker-controlled: 8 KiB string cap and 64-item lists with `truncated_fields`; timestamp sanity (future skew 300 s; malformed or overlong times rejected); payload tenant ≠ authenticated tenant is rejected (`TENANT_MISMATCH`).
- No regex (so no ReDoS), no eval/exec, no pickle, a strict rule schema and a 1 MB rule-pack cap.
- Provider results from a foreign tenant/endpoint are dropped and counted (`tenant_isolation_rejections`). No default tenant anywhere; every stateful object (detections, suppressions, checkpoints, enrichment cache keys) is tenant-keyed.

## 11. ML and TI boundaries (design only, no training, no new TI client)
- **`MLSignal`** (model_id, model_version, feature_schema_version, score, confidence, explanation, evidence_refs (required), inference_time).
  - `normalize.from_ml_signal` turns it into DETECTION evidence. A rule must consume it via a DETECTION stage, so ML never becomes a verdict by itself.
- **`Enrichment`** (observable, type, verdict, confidence, providers, first_seen, last_seen, enrichment_time, expiry, provenance) via `EnrichmentProvider.lookup`.
  - Default `NullEnrichmentProvider` makes INTEL stages INSUFFICIENT_EVIDENCE.
  - Production should implement an adapter over the TI authority chosen in E1 (consolidation D6; candidate `services/ioc_intelligence`). **Not implemented.**

## 12. Retrospection
- `run_replay(engine, ReplayRequest(reason ∈ RULE_ADDED / RULE_CHANGED / INTEL_CHANGED / MODEL_CHANGED / MANUAL, rule_keys, endpoint_ids, start, end, page_size), checkpoints)`.
- It pages the provider in (event_time, stable_key) order, calls `engine.process(mode=RETRO, trigger=…)`, and saves the checkpoint after each page. It is resumable (`max_pages`) and idempotent (deterministic ids).

## 13. Observability (`engine.metrics.snapshot()`)
- **Counters:** events_evaluated, events_rejected_malformed, tenant_isolation_rejections, candidate_rules, sequence_states, matches, suppressed_matches, insufficient_evidence, budget_exceeded, window_truncated, rule_errors, detections_created, detections_merged, duplicates_prevented, concurrency_retries, replay_runs, replay_events.
- **Also:** per-rule outcomes, latency (samples/avg/max ms) and window state size max.
- **No telemetry values** (tested).

## 14. Integration points (NOT applied)
1. **Live hook:**
   - In `edr_plane/canonical_bridge.py::bridge`, after the `CANONICAL_EVIDENCE_CREATED` derivation (≈L657-667), call `BehaviorIntegration(engine, enabled=<flag>).on_canonical(canonical, BridgeContext(tenant_id, endpoint_id, raw_id, canonical_event_id, generation, store=<chosen>))`.
   - The adapter never raises.
   - This requires an E1-approved edit plus a feature flag. **Not done** (E1 boundary).
2. **EvidenceProvider for production:** `MongoEvidenceProvider(collection, mapper, tenant_field, endpoint_field, time_field)` over the store the owner designates (doc 1, Q1). `integration.canonical_doc_mapper` fits a doc that embeds the bridge canonical shape. Mappers for the CEM (`v2_shadow_observations`) and DSM (`xdr_canonical_evidence`) shapes are **not written** (pending the decision).
3. **Detection store:** `MongoDetectionStore(db["e3_behavior_detections"])` plus `ensure_indexes` on a non-production database.
4. **Consumers:** the existing Device Trajectory / XDR incident surfaces could read `e3_behavior_detections` or a projection into `edr_findings` via the fabric. **Not done.**

## 15. E1 dependencies (recorded, not fixed)
- Canonical evidence authority (doc 1), so the provider mapper and index choice can be made.
- Live hook approval in `canonical_bridge` (no E1 edits were made).
- Process identity v1 (doc 2). The engine uses M1 `process_iid` and GUID/PID parent fields via `ProcessRef`, so it can swap to `process_key` later.
- TI authority (consolidation D6) for an EnrichmentProvider adapter.
- Signed audit (D10) for rule lifecycle and suppression changes. Today rule/suppression changes are in-process only and **unaudited**.
- Sensor gaps: signer, Linux DNS / file actor / registry, Sysmon 7 module loads.

## 16. Rollback
Everything is additive on a local branch.
- Delete the branch: `git -C /app/memory/nivxray-xdr checkout feature/rc2-alignment && git -C /app/memory/nivxray-xdr branch -D feature/e3-edr-engines`.
- Or revert the commits. There are no production collections, indexes, routes or E1 changes to undo.


## 17. Tests run and results

### 17.1 New E3 suite: 58 passed, 0 failed (69 after the §18 correction)
Command:
`cd backend && PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/edr_behavior -q -p no:cacheprovider -n 0 -o addopts=""`

Coverage:
- single-event non-match, full match, partial non-match
- ordering, window expiry, late arrival / order independence
- parent/child (GUID, PID surrogate, wrong parent, missing linkage → INSUFFICIENT_EVIDENCE + per-rule metric)
- cross-device and cross-tenant rejection, leaking-provider rejection, payload tenant spoofing
- retry / generation-change idempotency, duplicate evidence, deterministic ID
- missing telemetry (UNKNOWN ≠ clean), UNKNOWN never suppresses, tenant suppression keeps evidence
- rule versioning and lifecycle immutability, TESTING / DRAFT handling
- provenance, malformed input, injection / ReDoS / eval rejection, large-input bounds, window and DFS budgets
- replay (rule added, resumable, idempotent; intel change), integration adapter isolation, Mongo provider query shape
- ML boundary, metrics without telemetry values, 3-valued logic
- 8 starter-rule scenarios plus benign interpreters alone

### 17.2 Existing `backend/tests/edr` regression (offline subset)
- **Selection:** 51 of 91 files. Files referencing `requests`, httpx, `BACKEND_URL`, `MONGO_URL`, Motor/Mongo clients or `_live` were excluded so no endpoint is contacted.
- **Network guard:** an outbound-socket guard plugin was loaded (`-p e3_netguard`); `MONGO_URL` was unset.
- **pytest-asyncio:** installed with `--no-deps` into `.e3venv/extra` inside the clone. It is excluded via `.git/info/exclude` and not committed.

| Result | Files |
|---|---|
| Fully pass | 28 files, including Gate-4 `test_processing_queue_worker.py` (8/8) and `test_p0_reconcile_contract_ownership.py` (26/26), plus `test_b1`, `b2`, `b3`, `b4`, `dt2_*`, `gate10`, `trajectory_tenant_isolation`, `phase0_windows_canonical_bridge`, `sysmon`/`winsec` semantics, `event_id_propagation`, `wave0_contracts` |
| Fail or error for **environmental** reasons only | 20 files (below) |
| Timed out (90 s) under the network guard | 3 files: `test_p0_tenant_authority_fix2`, `fix5a`, `fix6b2` |

Environmental reasons for the 20 failing files:
- Hard-coded `/app/...` repository paths: the repo expects to live at `/app`, but the clone is at `/app/memory/nivxray-xdr`.
- Missing backend secrets `JWT_SECRET` / `EMERGENT_LLM_KEY`, which were deliberately not provided.
- Missing `reportlab`.
- Collection-time `/app` path imports.

**Baseline comparison:** a temporary `git worktree` of base `1800aeea` was created and then removed. Running `test_p0_f3_rule_store_binding`, `test_gate3_fabric_contracts` and `test_p0_platform_designation` there gave the **same 5 failures** as on the E3 branch, so they predate E3.

**Structural proof:** `git diff --name-status 1800aeea..HEAD` contains only `A` (added) entries, and no file under `tests/edr` imports `edr_behavior`.

## Progress log
- Step 1 (`7db48642`): contracts, predicates and rules.
- Step 2 (`bb1ef58f`): matcher, engine, suppression, detection, store, replay and metrics.
- Step 3 (`7766cadd`): starter pack + loader.
- Step 4 (`25600975`): standalone integration adapter.
- Step 5 (`f4e473ee`): 58 tests.
- Step 6: docs (`38e70688`), then this handoff update.
- Step 7 (pre-push correction gate): `fix(edr-behavior): enforce evidence-backed detections`. This adds the `Detection` evidence invariant, 11 tests in `test_evidence_invariant.py` (A–F), moves the net-guard plugin into the ignored `.e3venv/plugins/`, and updates this handoff (§18).

## 18. Pre-push correction gate (owner-approved)

### 18.1 Correction
- `contracts.Detection.__post_init__` enforces `len(evidence_refs) >= 1`, a `stable_key` on every ref, and non-empty `evidence_keys`. Empty or `None` evidence_refs raise `ValueError`. A missing field raises `TypeError`.
- Before this change only `detection.build()` guarded against evidence-less detections. Now the contract itself guards.
- Same-window chain merging was **not** changed (see §18.4).

### 18.2 Tests (`backend/tests/edr_behavior/test_evidence_invariant.py`, 11 cases)
- **A.** `evidence_refs=[]` and `()` are rejected.
- **B.** `None` is rejected; the missing field is rejected (TypeError); a ref without `stable_key` is rejected; empty `evidence_keys` is rejected.
- **C.** A legitimate MATCH persists ≥1 ref; ref keys equal `evidence_keys`; the doc round-trips through `Detection(**doc)`.
- **D.** INSUFFICIENT_EVIDENCE creates no detection and is distinct from NO_MATCH and CLEAN. MATCH, NO_MATCH and INSUFFICIENT_EVIDENCE are three distinct values.
- **E.** A retry plus a generation change leaves one detection with the same id, evidence keys and raw refs.
- **F.** `detection_id` is stable within a window bucket, tenant-sensitive, and identical across fresh engines.
- No existing test was modified or weakened.

### 18.3 Test environment
- **Net-guard plugin:** `.e3venv/plugins/e3_netguard.py`. It is ignored via `.git/info/exclude` (`.e3venv/`) and is not tracked. It blocks every non-AF_UNIX `connect`.
- **Command:** `cd backend && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=../.e3venv/plugins:../.e3venv/extra env -u MONGO_URL python3 -m pytest <target> -q -p no:cacheprovider -p e3_netguard -o addopts=""`

**Results:**
- E3 behavior suite: **69 passed, 0 failed** (58 previous + 11 new).
- Gate-4 focused (`test_processing_queue_worker.py` + `test_p0_reconcile_contract_ownership.py`): **34 passed, 0 failed**.
- Full `backend/tests/edr`: 91 files, run per file under the net guard with a 60 s cap, `MONGO_URL` / `BACKEND_URL` unset. Log: `.e3venv/regress-logs/full_edr.txt`.
  - 35 files fully pass.
  - 37 files fail or error.
  - 19 files hit the 60 s cap.
  - Completed-file totals: **1038 passed, 98 failed, 318 errors, 2 skipped**.
  - **Baseline:** all 72 completed files gave identical pass/fail/error counts on a temporary worktree of base `1800aeea` (since removed). E3 introduces no regressions.

**Environmental blockers:**
- Hard-coded `/app/...` paths, because the clone lives at `/app/memory/nivxray-xdr` (dominant: `FileNotFoundError`).
- Outbound network and Mongo blocked by the guard, with `MONGO_URL` / `BACKEND_URL` unset (`OSError: E3 network guard`). This causes the live/API tests to fail and the 19 time-outs.
- Missing modules: `e3_coverage_matrix`, `reportlab`.
- Secrets `JWT_SECRET` / `EMERGENT_LLM_KEY` deliberately not provided.

### 18.4 Known limitations (status unchanged)
- **Same-window chain merging:** at most one detection per (tenant, endpoint, rule version, scope entity, window bucket). Distinct chains by the same scope entity in one bucket merge into one detection with unioned evidence. This is documented only and not changed.
- The full EDR suite has not been proven green in this environment (blockers above).
- Not wired into the live pipeline. The integration adapter is disabled by default, and the E1 hook needs owner approval.
- `MongoDetectionStore` and `MongoEvidenceProvider` were never exercised against a real MongoDB.
- No CEM (`v2_shadow_observations`) or DSM (`xdr_canonical_evidence`) mappers exist. They are pending the canonical-authority decision.
- Rule and suppression changes are in-process and unaudited (pending D10 signed audit).
- TI and ML are boundaries only. No EnrichmentProvider adapter and no model exist.
- Process identity uses M1 `process_iid` and GUID/PID. PID-surrogate linkage is lower-confidence.
- Sensor gaps: signer, Linux DNS / file actor / registry, Sysmon 7.
- The starter pack has 8 rules and is not full coverage.
- The `merge()` path operates on stored dicts; it unions evidence and never shrinks it. Stored docs are not re-validated through `Detection` on read.
