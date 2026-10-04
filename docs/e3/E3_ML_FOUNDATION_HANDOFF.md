# NivXForge E3 ML Behavioral Analytics Foundation: Handoff

- **Branch:** `feature/e3-edr-engines` (local only; no push, PR, merge or deploy)
- **Base:** `bcb8d76618d4c30473db1137e94236395f1198de`, which equals the remote `feature/e3-edr-engines` the owner confirmed
- **Package:** `backend/edr_ml/`, tests in `backend/tests/edr_ml/`, docs in `docs/e3/` (this file, `ml_research_note.md`)
- **Nature:** a deterministic, explainable **signal** foundation. It is **not** a verdict engine and is **not wired** into any live pipeline.

## Progress log
- Step 0 (`16382646`): handoff skeleton + bounded research note.
- Step 1 (`007028a4`): `edr_ml` package. Covers the feature schema, baselines, extractor, models, signals, pipeline and metrics.
- Step 2 (`f17ec26e`): `edr_behavior` ML boundary v1, the minimal additive hook (§6).
- Step 3 (`410c9bc9`): 32 synthetic tests.
- Step 4 (`9616c5cc`): handoff.
- Step 5: `chore(edr-ml): ship starter models as TESTING pending real-data calibration`. Adds the TESTING marking on decisions and signals, plus one test. Results: edr_ml 33, edr_behavior 69, Gate-4 34. **DONE**

## 1. Architecture (data flow)

`EvidenceRecord` (existing `edr_behavior` contract, via the existing `EvidenceProvider`) feeds `FeatureExtractor`, then `score(model, vector)`, then a decision, then the signal store. Baseline update happens **after** scoring.

An EMITTED decision from an **ACTIVE** model continues as follows:
1. `evidence_from_decision` rebuilds the existing `edr_behavior.contracts.MLSignal`.
2. The existing `normalize.from_ml_signal` turns it into DETECTION evidence carrying the entity's `process_iid`.
3. That evidence feeds a `SequenceEngine` rule stage or a bounded optional-stage bonus.

**No second evidence abstraction exists.** `edr_ml` reuses `EvidenceRecord`, `EvidenceRef`, `EvidenceProvider`, `provider.dedupe`, `predicates.get_field`, `MLSignal`, `from_ml_signal` and the rule `LIFECYCLE`/`TRANSITIONS`.

## 2. FeatureSchema (`schema.py`, `content/feature_schema_v1.json`)
- `feature_schema_version = "fs-1.0.0"`, status `RELEASED`, `content_hash = fs_…` (sha256 over the canonical JSON, excluding status).
- **Immutability:** `SchemaRegistry` rejects re-registering a RELEASED version with different content. DRAFT versions may be replaced.
- **Per-feature declaration:** name, type (RATIO / BOOL / COUNT / NUMBER), unit, source evidence kinds, baseline scope (none / endpoint / tenant), and `missing_policy`. The only allowed `missing_policy` is `UNKNOWN`.
- **States:** `KNOWN` (must have a finite value), `UNKNOWN` (no value, with a reason) and `INSUFFICIENT_BASELINE` (cold start; no value). A missing value is never 0 and never clean.
- **Evidence:** every `FeatureValue` must carry ≥1 `evidence_refs`; the anchor ref always comes first; at most 16 refs.

### Starter features (13)

| Feature | Definition |
|---|---|
| `parent_child_rarity` | Parent>child image pair, endpoint baseline |
| `process_rarity_endpoint` / `process_rarity_tenant` | Image rarity per endpoint and per tenant |
| `cmdline_length` | Length; truncation is flagged as a lower bound |
| `cmdline_entropy` | Shannon entropy over ≤4096 chars |
| `cmdline_encoded_indicator` | PowerShell `-EncodedCommand` prefix, `FromBase64String`, or a base64 run of ≥100 chars; char-scan, no regex |
| `first_seen_binary` / `first_seen_domain` / `first_seen_ip` | Never seen in the endpoint baseline |
| `outbound_fanout` | Distinct outbound destination IPs for the entity |
| `registry_persistence_touches` | Writes to fixed persistence key fragments |
| `child_spawn_burst` | Children linked by **GUID only**; PID is never used |
| `off_hours` | UTC hour-of-day deviation from the endpoint histogram |

- **Rarity formula:** `log(total/count)/log(total)`; first-seen = 1.0.
- **Absence of NETWORK / DNS / REGISTRY evidence** for an entity gives UNKNOWN ("absence not provable"), not 0.
- **A truncated window** makes count features UNKNOWN.

## 3. Baselines (`baseline.py`)
- **Keying:** strictly `(tenant_id, scope)`, where scope is `endpoint:<id>` or `tenant`. An empty or `None` tenant raises. There is no default tenant and no cross-tenant state.
- **Families:** proc, bin, pc, dom, ip, hour. All counts are integers.

**Bounds:**
- `max_keys_per_family` (2048): deterministic eviction of the lowest `(count, token)`, never the token just inserted.
- `max_seen_keys` (4096): a FIFO of evidence stable keys, which makes retries and generation changes idempotent.
- Half-life decay (30 d) by integer right-shift.
- TTL (120 d): older events are rejected.
- Future-skew guard (300 s).

**Poisoning guards:**
- `max_updates_per_hour` (500), counted against the highest hour bucket seen, so back-dated events cannot reset it.
- A per-baseline `frozen` flag plus a global `BaselineConfig.frozen` learning-period freeze.
- `min_observations` (50) before a baseline is warm.

**Serialization:**
- Canonical JSON (`sort_keys`). `load()` rejects NaN/Infinity constants, negative or non-integer counts, over-cap families and foreign tenants. No pickle or msgpack.

**Fit interface:**
- `fit_baselines(..., data_label="SYNTHETIC")` uses the same path as online updates. Any other label raises.

## 4. Models (`models.py`, `content/starter_models.json`)
- **ModelSpec fields:** model_id, model_version, feature_schema_version, model_type, parameters, lifecycle, threshold, `content_hash = mc_…`.
- **Lifecycle:** DRAFT / TESTING / ACTIVE / DISABLED / DEPRECATED with the rule `TRANSITIONS`. Activating a version deprecates the other ACTIVE version. `(id, version)` is immutable.
- **Strict parsing:** unknown keys, non-finite or out-of-range numbers, unknown types, unknown schema versions, features missing from the schema, and type-incompatible features are all rejected.

**Scorers** (deterministic, dependency-free):

| Scorer | Method |
|---|---|
| `RARITY` | Mean of RATIO/BOOL features |
| `WEIGHTED` | Weighted mean of features linearly normalised over a declared `range` |
| `ROBUST_Z` | One-sided modified z `0.6745·(x−median)/MAD`, capped. MAD=0 is handled explicitly |

- **Coverage:** `coverage = known weight / total weight`. If it is below `min_coverage`, the outcome is `INSUFFICIENT_BASELINE` when cold weight dominates, otherwise `UNKNOWN`. No score is produced.
- **Confidence:** `round(100·coverage)`.
- **Optional scorer seam:** `register_scorer(name, terms, norm)` is code-only, for an optional sklearn-style adapter. Data files cannot introduce code. No new dependency was added.
- **Fit:** `fit_robust_z(template, vectors, data_label="SYNTHETIC")` is a deterministic median/MAD fit that returns a **new DRAFT doc**. It never activates anything and is order-independent.
- **Starter pack** (shipped as **TESTING** pending real-data calibration):
  - `ml.rarity.process_tree@1.0.0`: TESTING, threshold 0.7.
  - `ml.weighted.exec_behavior@1.0.0`: TESTING, threshold 0.6.
  - `content_hash` excludes `lifecycle`, so both hashes and versions are unchanged by the demotion and no provenance change was needed.
- **TESTING semantics** (these mirror the rule TESTING status):
  - TESTING models are evaluated and their signals are stored and EMITTED.
  - Decisions carry `model_lifecycle`; envelopes carry `lifecycle` and `status: "TESTING"`; the explanation carries `model_lifecycle`.
  - `to_evidence` / `evidence_from_decision` refuse non-ACTIVE signals, so TESTING signals never reach the behavioral engine.
  - Tests that exercise the evidence path promote the model to ACTIVE explicitly, in the test only.
- **Gate for ACTIVE (FUTURE ITEM, not built):** promoting a shipped model to ACTIVE requires validation and calibration on real telemetry. That means measured precision/recall and FP rate per tenant, a threshold calibration record, and an owner-approved, audited lifecycle change.

## 5. Signals (`signals.py`, `pipeline.py`)
- **Signal ID:** `signal_id = "e3mls_" + sha256("mlsig.v1", tenant, endpoint, model_id, model_version, feature_schema_version, anchor_stable_key)[:32]`. It excludes generation, clock and retry count.
- **MLSignal:** built through the **existing** `MLSignal` contract (evidence_refs mandatory; score/confidence range-checked, so NaN is rejected).
  - `inference_time` = the anchor event time (deterministic).
  - `evidence_refs` = the anchor first, then the refs of contributing features (≤32).
- **Explanation:**
  - `top_features` (≤5), each with value, weight, normalised value, share, transform (range or median/MAD/z), baseline and evidence keys.
  - The unknown and cold feature lists, coverage, model hash, schema hash and lifecycle.
  - `policy: "signal-not-verdict"`.
- **Envelope:** adds `signal_id`, `tenant_id`, `endpoint_id`, `entity` and `verdict: None`. Tenant and endpoint live in the envelope because the existing MLSignal has no such fields; that contract was deliberately not changed.
- **Decision store:** `InMemorySignalStore` records **every** decision (EMITTED / BELOW_THRESHOLD / INSUFFICIENT_BASELINE / UNKNOWN / SCHEMA_MISMATCH / MODEL_ERROR), first write wins. A retry returns the stored decisions without re-extracting or re-learning.
- **TESTING-model signals** are recorded but `to_evidence` refuses to turn them into behavioural evidence.

## 6. Correlation boundary: the minimal `edr_behavior` hook (`e3.ml-boundary.v1`)

**Changes (all additive, ~30 lines):**
- `normalize.ML_SIGNAL_NORMALIZER`, set in the `from_ml_signal` provenance.
- `normalize.is_ml_evidence(rec)`: a DETECTION record counts as ML if any of these hold:
  - its normalizer is the ML signal normalizer
  - `detection.source == "ML"`
  - `detection.rule_id` starts with `ml:`

  This is deliberately conservative, so a *spoofed* ML-looking detection observation is also treated as ML.
- `engine._evaluate`: a MATCH whose evidence is **entirely** ML returns `INSUFFICIENT_EVIDENCE` with `ML_ONLY_REASON` and increments the metric `ml_only_rejected`.
- `detection.build`: raises if all evidence is ML (defence in depth).
- `ENGINE_VERSION` moves from `e3-seq-1.0.0` to `e3-seq-1.1.0`, and `ML_BOUNDARY_VERSION` is added. Detection IDs are unchanged, because the engine version is not part of the ID.

**Allowed uses of an ML signal:**
1. A DETECTION rule stage (`detection.source == ML`, `detection.rule_id == ml:<model>`, `detection.score >= T`) alongside real evidence. `same_process` binds through the entity `process_iid`.
2. An optional ML stage with a `confidence_bonus` of 0–50 (bounded by the rule parser; detection confidence is capped at 100).

No existing `edr_behavior` test was changed; all 69 still pass.

## 7. Observability (`edr_ml.metrics`)
- **Counters:**
  - events processed / rejected, duplicates
  - features extracted / unknown / cold
  - cold_start, unknown_outcomes
  - signals emitted / suppressed (suppressed = scored below threshold)
  - model_errors, schema_mismatch
  - baseline updates / duplicates / rate-limited / frozen / time-rejected
- **Per-model outcomes**, latency (avg/max) and baseline state size.
- **No telemetry values** appear in metrics (tested).

## 8. Security
- All telemetry is treated as hostile. Strings are bounded (8192 from the normaliser; tokens 256; registry keys 1024). Entropy is computed over ≤4096 chars.
- Non-string or NaN fields become UNKNOWN; NaN/Infinity are rejected in model and baseline JSON; KNOWN values must be finite.
- Future, naive and too-old timestamps are rejected. Window records from foreign tenants or endpoints, or with future times, are filtered.
- No eval/exec/pickle/regex built from content. Models and schemas load from JSON data files only. No network and no Mongo access.
- **Baseline poisoning (residual risk):** an attacker who controls an endpoint before or while it learns can make malicious activity look common. The mitigations below *reduce* this risk but do not remove it.
  - rate limits
  - freeze
  - warm-up threshold
  - capped keys
  - robust statistics (median/MAD)
  - tenant-wide rarity as a second view

## 9. Tests (synthetic only, fixed seed 1337)
**Command:**
`cd backend && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=../.e3venv/plugins:../.e3venv/extra env -u MONGO_URL python3 -m pytest <target> -q -p no:cacheprovider -p e3_netguard -o addopts=""`

**Results:**
- `tests/edr_ml`: **33 passed** (32 + 1 TESTING-semantics test after the demotion)
- `tests/edr_behavior`: **69 passed**
- Gate-4 focused (`test_processing_queue_worker.py` + `test_p0_reconcile_contract_ownership.py`): **34 passed**

**Coverage:**
- determinism
- missing → UNKNOWN; cold start
- tenant isolation (colliding entity names, leaking provider, export/load); no default tenant
- retry and generation idempotency
- evidence_refs mandatory
- bounded state, rate limit, freeze, decay, time guards
- huge input / NaN
- schema mismatch and immutability; model lifecycle and validation
- explanation fidelity; benign-low vs attack-high
- fit determinism and the SYNTHETIC-only guard
- TESTING model → no evidence
- metrics hygiene
- ML-alone → no detection (including a spoofed observation)
- sequence + ML stage only with real evidence
- bounded ML confidence bonus
- build-guard

## 10. Limitations / UNVERIFIED
- **Not wired:** no live hook, no Mongo-backed baseline or signal store, no indexes. The Mongo path is unwritten and unverified.
- **Untuned:** thresholds and weights are hand-set starter values, tested only on synthetic data. Precision and recall on real telemetry are **UNVERIFIED**.
- **Feature limits:**
  - The off-hours feature uses UTC hours (endpoint timezone is unknown).
  - Rarity uses image *names* and paths; there are no signer or hash features (sensor gaps).
- **Retry vs. live-time scoring:** a cold or UNKNOWN decision is stored per anchor and is not re-scored when the baseline warms later. A future replay path needs an explicit, versioned `re-evaluate` reason.
- **Eviction:** a capped family evicts the rarest keys, so a token evicted under pressure looks first-seen again (it biases toward alerting).
- **Tenant baseline:** it shares the per-baseline seen-key FIFO across endpoints.
- **Residual poisoning risk:** see §8.
- **Research-note links:** links marked UNVERIFIED-LINK in `ml_research_note.md` were not re-fetched.
- **Full `backend/tests/edr` suite:** not re-run in this step. The previous run on base `bcb8d766` showed environmental blockers only; E1 files are unchanged.

## 11. Isolation
- **Changed since `bcb8d766`:** only `backend/edr_ml/**`, `backend/tests/edr_ml/**`, `docs/e3/**` (added), plus the five-file `backend/edr_behavior/` ML-boundary hook (modified).
- **No E1 / protected file changed:**
  - ACK/ingest, processing_queue, canonical_bridge, canonical stores
  - response/approval, auth/tenant, Gate-4, sensors
- **Rollback:** `git revert` the four commits, or reset to `bcb8d766`.
