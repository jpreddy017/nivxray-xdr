# EDR-P0-01 — Dependency Preservation and Recovery Manifest

**Reference:** P0-01 · **Date:** 2026-10-30 · **Mode:** STRICTLY READ ONLY · **Status:** no extraction, migration, copy or deployment authorized
**Anchor revision:** `/app` HEAD `5040c08cfd27e835c1ea9013c5d959ae9ea79c5c`, branch `fix/dt-v3-auth-contract-backend`
**Governing document:** `/app/memory/EDR_ISOLATION_DIRECTIVE.md` — followed without exception
**Inputs:** `EDR-A0-01` (production topology), `EDR-A0-02` (source ownership), `EDR-A0-03` (data ownership)
**Change performed:** NONE — no copy, repository, build, deployment, database read or write, credential change, agent action, VM action, cleanup or cutover.

---

## 1 · Closure reconciliation against exact Git revisions

| Check | Result |
|---|---|
| Transitive closure recomputed from all EDR seeds | **191 modules** — reconciles exactly with A0-03 |
| EDR-owned | **161** |
| Non-EDR required (direct + transitive) | **30** |
| Modules present in the `HEAD` tree | **191 / 191** — none untracked |
| `git status --porcelain -- backend` | **clean** — zero modified or untracked backend paths |

**Consequence:** because the backend worktree is clean at `5040c08c`, every blob hash recorded in Appendix A is simultaneously the committed object **and** the bytes on disk. The manifest is therefore anchored to immutable Git objects, not to a mutable checkout. Each row is independently re-verifiable with:

```bash
git -C /app rev-parse 5040c08c:backend/<path>          # expect the blob hash in Appendix A
git -C /app cat-file -s <blob>                         # size check
```

Any future copy must be proven to originate from these exact blob hashes — this is the preservation anchor for directive step 3.

**Test coverage mapping:** 105 of the 191 modules have at least one referencing test module in `backend/tests/`. 86 have none; for those, equivalence must be proven by contract/fixture comparison rather than by inherited tests (directive step 6, and prohibition 7 — a passing build is not equivalence).

---

## 2 · Component-level copy manifest — classification

| Class | Count | Treatment | Rationale |
|---|---|---|---|
| **A · Copy as-is into the EDR boundary** | 160 | copy, originals untouched | EDR-exclusive logic |
| **B · Copy with supporting code and tests** | 12 | `v2.ingestion.canonical`, `v2.ingestion.telemetry_bridge`, `v2.case_engine.schema`, `security.__init__`, `security.secret_policy`, `services.__init__`, `services.session_context`, `services.dashboard_lenses`, `services.activity.projector`, `services.mitre_catalogue.__init__`, `timeline.__init__`, `models.__init__` | shared libraries EDR genuinely executes; prohibition 3 forbids partial lifts |
| **C · Replace with newly authored EDR-owned component** | 3 in closure | `deps` → EDR-scoped config/deps; `routers.xdr_rbac` + `routers.xdr_audit_log` → EDR session/authorization authority. Plus one component **outside** the closure: an EDR-only ASGI entrypoint replacing `server.py`'s EDR portion | prohibition 4 — no new runtime dependency on XDR |
| **D · Reduce to an interface; do NOT copy** | 4 | `detection_content.xdr_pipeline`, `.xdr_threat_family`, `.library.registry`, `.rule_store_binding` | XDR-owned detection content — §4 |
| **E · Excluded from any copy** | 1 | `routers/edr_maintenance.py` | §6 |
| **F · Verify-then-decide** | 2 | `canonical.__init__`, `engine.__init__` | package inits only; confirm whether anything is actually executed |
| **G · Drops out once class D is cut** | 9 | `services.investigator.*` (7), `services.iue.*` (2) | zero direct EDR importers; reached only through `xdr_pipeline` |

Full per-module table with path, blob hash, owner, collections, write capability and test count: **Appendix A**.

---

## 3 · Reverse-dependency protections (what must NOT be touched)

Under prohibition 2 these originals keep working exactly as they are. The EDR product gets copies; the consumers below continue to import the originals.

| Protected original | Imported by | Protection |
|---|---|---|
| `backend/edr_plane/*` (package) | `detection_content.telemetry.nivxforge_sensor_dsm`, `detection_content.xdr_pipeline`, `scripts.wave_b_foundation_measure`, 5 `tools.*` modules | no edit, no move, no deletion. The EDR copy is **additive** |
| `backend/edr_plane/canonical_bridge.py` | `detection_content.telemetry.nivxforge_sensor_dsm` | same |
| `backend/edr_plane/canonical_index_contract.py` | `tools.apply_34h_target_indexes`, `tools.measure_34d_canonical_index`, `tools.measure_34e_identity_contract` | same |
| `backend/edr_trajectory/production_adapter.py` | `tools.preflight_34a`, `tools.preflight_34c` | same |
| `apps/.../src/nivxforge/*` | 8 XDR UI files (`ActivityDetailsPanel`, `StaticAnalysisBridge`, `XdrContextBar`, `XdrEndpointsPage`, `XdrControlCenterPage`, `XdrFleetFileTrajectoryPage`, `XdrEntity360Page`, `assets/AssetsPage`) | no package extraction that changes the original import path |
| `backend/server.py` | all products | the EDR-only entrypoint is a **new file**; `server.py` is not edited |

**Verification obligation before any copy is accepted:** prove these consumers still resolve and behave identically — their own tests, unchanged, on the unchanged originals.

---

## 4 · The `detection_content.xdr_pipeline` dependency and how EDR lives without it

### 4.1 Exact call sites (verified)

| Caller | Line | Symbol imported |
|---|---|---|
| `edr_plane/canonical_bridge.py` | 680 | `process_event_through_pipeline` |
| `edr_plane/detection_replay.py` | 133 (also 29, 150, 171) | `evaluate_detection` |
| `edr_plane/detection_replay.py` | 78 | `detection_content.library.registry.RUNTIME_DETECTION_RULES` |
| `routers/edr_wave0.py` | 137 | `detection_content.rule_store_binding.binding_report` |

Only **four symbols** — not the package. `xdr_pipeline` itself imports `detection_content.xdr_threat_family` and, transitively, `services.investigator.*` (7 modules) and `services.iue.*` (2), both of which write `workspace_cases`. That is the entire Workspace-writing exposure in EDR's chain, and it hangs off one import.

### 4.2 Transitive reach into Workspace writers

```
edr_plane.canonical_bridge / detection_replay
        └── detection_content.xdr_pipeline            (XDR-owned)
                ├── detection_content.xdr_threat_family
                ├── services.investigator.orchestrator ──► writes workspace_cases (6 collections)
                └── services.iue.service               ──► writes workspace_cases (4 collections)
```

Note: EDR never *calls* the investigator or IUE. The coupling is an **import-time** reach, which is precisely why it is cheap to remove and dangerous to ignore — a naive copy either drags the whole Workspace investigation stack into the EDR runtime or fails to import.

### 4.3 Proposed decoupling for the future EDR copy (design only — original untouched)

Introduce, **inside the EDR boundary only**, a detection port of four operations:

| Port operation | Replaces | Contract to pin before any copy |
|---|---|---|
| `evaluate(observation) -> findings[]` | `evaluate_detection` | input canonical observation shape; output finding shape incl. `references[]`, `severity`, ATT&CK IDs; determinism per fixture |
| `process_event(sensor_event, endpoint_id, hostname) -> detection_result` | `process_event_through_pipeline` | the authenticated-ingest provenance rule: only the authenticated path may stamp `REAL_SENSOR_DERIVED`; an unauthenticated caller must not be able to manufacture it |
| `rules() -> rule_set` | `RUNTIME_DETECTION_RULES` | rule identity, version and content hash |
| `binding_report() -> report` | `rule_store_binding.binding_report` | report shape consumed by `/edr/wave0` |

Implementation options for the port, in preference order:
1. **Versioned rule-content package** consumed by both products (no runtime call, no shared state) — preferred; detection content stays XDR-authored.
2. **Authenticated, versioned HTTP contract** XDR→EDR for rule distribution — acceptable only if EDR can still detect when XDR is unreachable (cached rule set with explicit staleness), otherwise it violates the independence definition.
3. Copying `xdr_pipeline` — **rejected**: it carries the Workspace investigation stack and duplicates XDR-owned detection authorship.

**Nothing is disconnected today.** The original `xdr_pipeline` keeps serving XDR and the current EDR path unchanged.

---

## 5 · `v2.ingestion.telemetry_bridge` — full call chain and the contract an EDR-owned version must honour

### 5.1 Call chain (verified, line-exact)

```
edr_plane/canonical_bridge.py:511
    from v2.ingestion.telemetry_bridge import persist_live_observation
        ↓
v2/ingestion/telemetry_bridge.py:369   async def persist_live_observation(db, canonical, *, envelope, tenant_id, sequence=0) -> str | None
v2/ingestion/telemetry_bridge.py:373       doc = observation_doc(canonical, envelope=…, tenant_id=…, sequence=…)
v2/ingestion/telemetry_bridge.py:375       res = await db[COLLECTIONS["shadow_observations"]].insert_one(doc)   # v2_shadow_observations
v2/ingestion/telemetry_bridge.py:376       return str(res.inserted_id) if res.inserted_id else None

v2/ingestion/telemetry_bridge.py:324   def observation_doc(canonical, *, envelope, tenant_id, sequence)
    → canonical_to_ces(canonical, envelope=…)          (CES shape)
    → ces_to_cem_dict(ces, case_id=None, sequence=…)   (CEM v1 shape)
    → observation_identity(ev, tenant_id=…)            → v2/ingestion/canonical.py:357
                                                         returns (observation_id, identity_state, identity_key)

v2/ingestion/telemetry_bridge.py:379   async def link_observations_to_incident(db, *, trace_id, incident_id) -> int
    update_many({"ingest_job_id": trace_id, "origin": LIVE_ORIGIN},
                {"$set": {case_id, promoted_incident_id, promoted_at}})
    # called ONLY after the VEEE gate actually materialised an incident
```

`COLLECTIONS` is imported from `v2.case_engine.schema:25` — the collection-name registry, which is why that module is in class B.

### 5.2 Contract to be preserved by an EDR-owned version

| Element | Requirement |
|---|---|
| **Schema** | CEM v1 document: `adapter`, `cem_version="v1"`, `case_id=None` (never fabricated), `tenant_id`, `observation_id`, `observation_identity_state`, `observation_identity_key`, `captured_at`, plus canonical `additional_fields` passthrough |
| **Identity** | `observation_identity()` from `v2.ingestion.canonical` must be copied verbatim with its tests — identity derivation is the association spine; `event.iid` is **content** identity and is deliberately not unique per record |
| **No-fabrication rule** | `case_id` stays `None` until an incident is genuinely promoted; `link_observations_to_incident` is the only writer of `case_id`/`promoted_*`, and only post-gate |
| **Indexes** | A0-03 records **no enforced unique index on `observation_id`** upstream; association fails closed around that gap. An EDR-owned store must either add the unique index (new, authorized separately) or preserve the fail-closed behaviour exactly — not silently change it |
| **Error semantics** | `persist_live_observation` returns `None` when no `inserted_id`; the caller treats a failed persist as non-fatal to ingest. Any EDR version must keep this (raising instead would change ingest behaviour) |
| **Ordering** | `sequence` is caller-supplied and must stay monotonic per envelope |
| **Tests** | 9 test modules reference `telemetry_bridge`, 8 reference `v2.ingestion.canonical`, 1 references `v2.case_engine.schema` — **all must be copied and must pass against the copy before any comparison is accepted** |

### 5.3 Equivalence proof required for this component

Identical input fixtures → byte-identical `observation_doc` output (excluding `_id`), identical `observation_id` / `identity_state` / `identity_key`, identical null-case handling, identical `link_observations_to_incident` modified-count semantics. Zero unexplained field additions or omissions.

---

## 6 · `routers/edr_maintenance.py` — excluded, and what must not be lost with it

### 6.1 Why it is excluded (verified facts)

| Fact | Evidence |
|---|---|
| Single endpoint: `POST /api/edr/maintenance/dev-reset` | `routers/edr_maintenance.py:205` |
| Mounted in production | `server.py:701-702` |
| **Hardcoded tenant** `TENANT = "ten_e759b7288598bd882e3dcac49d"` | line 32 |
| Guarded by `EDR_MAINTENANCE_TOKEN`; returns 404 when unset, 403 on mismatch (fail closed) | lines 74-80 |
| Deletes across EDR **and** 13 non-EDR collections — `xdr_canonical_evidence`, `xdr_correlation_matches`, `xdr_detection_matches`, `xdr_framework_mappings`, `xdr_response_timeline`, `xdr_spread_sightings`, `xdr_intelligence_overlays(+_audit)`, `xdr_investigations(+_findings,_activity)`, `xdr_iue_understanding`, `workspace_cases` | A0-03 §4.3 + `_wipe` call sites |
| Operates on whole-tenant filters with optional pins | `{"tenant_id": TENANT}`, `keep_ids`, `keep_raw` |

Copying this into an EDR-owned product would give the new product delete authority over XDR and Workspace data — a direct violation of prohibition 2.

### 6.2 Legitimate requirements that MUST be re-provided elsewhere

These are real operational needs the module currently satisfies; excluding the module must not silently drop them:

| # | Requirement | Current mechanism | EDR-owned replacement must |
|---|---|---|---|
| M1 | Pre-action inventory — count what exists before touching anything | `_names()`, `_count()`, `_classify()` | report-only mode, no deletion path by default |
| M2 | Classification of what would be removed vs retained | `_classify()`, `retained` counts | enumerate by ID, per collection |
| M3 | **Pinning / retention of explicitly protected records** | `keep_ids`, `keep_raw`, `_pins()` | preserve exact pin semantics |
| M4 | **Foreign-tenant detection** — refuse or report records outside the target tenant | `foreign_tenant` counter, `dep_filter` | fail closed on any foreign-tenant match |
| M5 | Dependent-record cleanup consistency | dependents stage | only within EDR-owned collections |
| M6 | Explicit confirmation + backup token in the request body | `confirm`, `backup` fields | require a verified restore point, not a string |
| M7 | Token-gated, fail-closed access | `EDR_MAINTENANCE_TOKEN`, 404 when unset | retain fail-closed default |
| M8 | Audit of the action | partially via counts returned | write an immutable audit record |
| M9 | **Scoped endpoint removal** (the pending `KUSHU` / `DESKTOP-A9HGFJJ` case) | **not supported today** — tenant-wide only | provide a genuinely endpoint-scoped operation, EDR collections only |

**Standing instruction unchanged:** `dev-reset` must not be used for any scoped cleanup. M9 is an unmet requirement, not an existing capability.

---

## 7 · Preservation and backup gap register (all seven)

| # | Gap | Current state | Evidence class | What would close it (read-only) | Blocks |
|---|---|---|---|---|---|
| G1 | **Production backups** | unknown whether any restore point exists for the production database | **UNKNOWN** | confirm platform backup/retention policy + schedule for the production app (names and schedule only) | directive step 3 — preservation cannot be asserted |
| G2 | **Production data inventory** | no collection counts, sizes or index footprint | **UNKNOWN** | name-level inventory after G4 is known | data-boundary design, cardinality reconciliation |
| G3 | **Deployed backend revision** | no build stamp; `/api/version`, `/api/build-info` → 404 | **UNKNOWN** | authorized platform read: deployment ID, image/revision, build log | every equivalence claim against production |
| G4 | **Environment-secret custody** | values correctly absent from Git; existence of an out-of-band custody record unproven | **UNKNOWN** | confirm a custody/rotation record exists — **never** the values | recovery after key loss |
| G5 | **Installer EXEs** | `NivXForgeEDRSetup.exe` / `NivXForgeSensor.exe` not in the repository; unsigned PyInstaller one-file build, not byte-reproducible | **GAP, confirmed** | record artifact + `payload-manifest.json` + SHA-256 in a durable store; on-VM cross-check against `m1-ownership.json → resources.service.evidence.service_image.sha256` | re-creating the exact deployed sensor |
| G6 | **G4 VM durable state** | `identity.json`, outbox, journal, bookmarks, policy state exist only on `NIVX-G4-WIN11` / `NIVX-G4-WIN02` | **GAP, confirmed** | VM snapshot before any future change (not required for A0/P0) | rollback of any sensor-side action |
| G7 | **`rocket-p0/` ownership** | 1.2 GB on disk, only 8 files tracked; unknown whether anything unique | **GAP, confirmed** | identify origin and owner; **decide nothing, delete nothing** | accurate preservation scope |

---

## 8 · Verified recovery assets — preservation evidence vs restore-test evidence

This distinction is the crux of directive step 3: *"verify required recovery backups"* means a **tested restore**, not the existence of an archive.

| Asset | Preservation evidence (exists, integrity-checked) | Restore-test evidence (proven to come back) |
|---|---|---|
| M1 installer source, 4 generations | **YES** — 13 `*.bundle` files; `git bundle list-heads`; `VERIFY.sh` = fsck + 18/18 blob SHA-1 + SHA-256 + credential scan + 373 portable tests; subtree `db21f422561f14fb4dcec91b70925f2b5291c500` | **PARTIAL** — bundles were cloned read-only in this environment and their refs resolved, which proves readability; a full restore-to-working-build has not been performed here |
| Frozen G3 candidate `d2f8b742` | **YES** — reviewer repo branch tip verified via GitHub API; full monorepo tree | **NO** — never checked out, built or run from that repo in this environment |
| G3 evidence report `681376555e…` | **YES** — branch + commit verified | **NO** |
| Deployed frontend sources (`35d47cc9…`, `e2f15a25…`) | **YES** — branch tips verified | **NO** — artifact→SHA linkage remains INHERITED (no commit stamp in the built bundle) |
| Work in progress (56 branches / 23 PRs, 27 local refs) | **YES** — enumerated | **NO** |
| Backend source at `5040c08c` | **YES** — 191/191 modules present in HEAD, worktree clean, blob hashes in Appendix A | **n/a** (live checkout) |
| Evidence corpora (`evidence/` 63 MB, `rocket-evidence/` 118 MB, `memory/evidence/` 2.4 MB, `test_reports/` 5.6 MB) | **YES** — present and tracked | **NO** |
| Test suites (159 backend + 13 frontend EDR modules) | **YES** | **PARTIAL** — last known results: trajectory 665 passed; EDR+behavior 2453 passed / 1 failed / 3 skipped; frontend 290 passed; M1 portable 373 passed |
| G4 lab database `nivx_g4_lab` | name observed only | **NO** |
| **Production database** | **NONE** | **NONE** — G1 |

**Honest summary: there is strong preservation evidence for source, and essentially none for data.** No restore has been tested for any asset in this environment.

---

## 9 · First safe component copy — prerequisites, tests, approval

### 9.1 Recommended first component

**`v2.ingestion.canonical` + `v2.ingestion.telemetry_bridge` + `v2.case_engine.schema` (class B), copied with all 18 referencing test modules.**

Why this one first: it is pure library code with no router, no worker and no XDR runtime dependency; it has the richest existing test coverage of any shared component in the chain; it is the single live write path into shared evidence (§5), so proving it is the highest-value early result; and a failure is contained to a copy nobody calls yet.

**Not first:** anything touching `deps`, `xdr_rbac`, the worker, or `xdr_pipeline`.

### 9.2 Prerequisites (ALL mandatory before the first copy is even authorized)

| # | Prerequisite | Status today |
|---|---|---|
| P1 | Gaps G1–G4 closed, or an explicit written acceptance that the copy is source-only and touches no data | **OPEN** |
| P2 | Source anchor fixed: copy provenance recorded as blob hashes from Appendix A at `5040c08c` | ready |
| P3 | Destination boundary defined (EDR-owned path layout) with **no** edit to any original path | not defined |
| P4 | Deterministic fixture set agreed for canonical → CES → CEM → observation identity | not defined |
| P5 | Isolated staging database, synthetic data only, never a production clone (prohibition 5) | not provisioned |
| P6 | Rollback rehearsed: the copy is additive, so rollback = delete the copy; proven by re-running the originals' tests unchanged | not rehearsed |
| P7 | Independent reviewer nominated under G0–G6 | not nominated |

### 9.3 Tests required for acceptance

1. **Originals unchanged:** all 18 referencing test modules pass against the untouched originals (baseline run, recorded).
2. **Copy passes the same suite** after path adaptation only — no logic edits.
3. **Byte-equivalence of `observation_doc`** across the agreed fixtures, `_id` excluded; identical `observation_id`, `observation_identity_state`, `observation_identity_key`.
4. **Null/failure semantics identical:** `persist_live_observation` returns `None`, not an exception, when no `inserted_id`.
5. **`link_observations_to_incident`** modified-count and the `case_id`-only-after-promotion rule reproduced exactly.
6. **Fail-closed preserved** where no unique `observation_id` index exists — identical refusal behaviour, not an improvement.
7. **Reverse-dependency regression:** `detection_content.telemetry.nivxforge_sensor_dsm`, `detection_content.xdr_pipeline` and the 5 `tools.*` consumers still import and pass their own tests.
8. **No new XDR/Workspace import** appears anywhere in the copied boundary (asserted by an import-graph check, not by eye).

### 9.4 Independent approval

G0–G6 sign-off by a reviewer who did not author the copy, on evidence only: baseline run, copy run, fixture diff, import-graph assertion, reverse-dependency regression, rollback rehearsal. Self-certification is not acceptable (directive step 8).

---

## 10 · Assessment

### **PARTIAL**

**Closed by this manifest**
- 191-module closure reconciled against `5040c08c` with blob hashes; worktree clean, so the anchor is immutable and independently re-verifiable.
- Every component classified A–G with its destination treatment; 160 copy-as-is, 10 copy-with-tests, 4 replace, 4 interface-only, 1 excluded, 2 verify-then-decide, 9 that disappear once the `xdr_pipeline` edge is cut.
- Reverse-dependency protections enumerated with their consumers, including the 5 `tools.*` modules and 8 XDR UI files.
- The `xdr_pipeline` → Workspace-writer path reduced to **four symbols**, with a concrete port design that removes it without touching the original.
- The `telemetry_bridge` chain documented line-exact, with schema, identity, no-fabrication, index, error and ordering contracts plus the 18 tests that must travel with it.
- `routers/edr_maintenance.py` excluded, with nine legitimate requirements listed separately — including M9, scoped endpoint removal, which **does not exist today**.
- All seven preservation gaps registered with the exact read that closes each.
- Preservation evidence separated from restore-test evidence: source is well preserved; **no restore has been tested, and data preservation is unproven**.
- First safe copy specified with 7 prerequisites, 8 acceptance tests and an independent-approval requirement.

**Not closed**
- G1–G4 (production backups, data inventory, deployed revision, secret custody) — permissions absent; documented, not guessed.
- 86 of 191 modules have no referencing test; equivalence for those needs fixtures that do not yet exist.
- Statement-level writer attribution for the ~70 single-product collections.
- Whether `canonical.__init__` / `engine.__init__` are executed or import-only (class F).
- No restore test has been performed for any asset.

**Directive position:** steps 1–2 substantially complete; **step 3 cannot be certified** because recovery is unverified and G1/G4 are open. Separation remains on **HOLD**. No copy is authorized by this document.

---


## Appendix A · Component manifest — all 191 modules at `5040c08c`

Class: **A** copy as-is · **B** copy with tests · **C** replace with new EDR component · **D** interface only, do not copy · **E** excluded · **F** verify then decide · **G** drops out when D is cut.
`W` = module contains write driver calls. `colls` = authoritative collection names referenced. `tests` = referencing test modules.

| # | module | path (backend/) | blob @5040c08c | class | colls | W | tests |
|---|---|---|---|---|---|---|---|
| 1 | `edr_behavior.__init__` | `edr_behavior/__init__.py` | `f66cb446b565` | A | — | — | 21 |
| 2 | `edr_behavior.content` | `edr_behavior/content.py` | `500ae08fe32a` | A | — | — | 1 |
| 3 | `edr_behavior.contracts` | `edr_behavior/contracts.py` | `c5c17a845551` | A | — | — | 11 |
| 4 | `edr_behavior.detection` | `edr_behavior/detection.py` | `2a02cd9892a8` | A | — | — | 4 |
| 5 | `edr_behavior.engine` | `edr_behavior/engine.py` | `dee5a00823c4` | A | — | — | 5 |
| 6 | `edr_behavior.integration` | `edr_behavior/integration.py` | `01433e85bd35` | A | — | — | 2 |
| 7 | `edr_behavior.matcher` | `edr_behavior/matcher.py` | `701181442843` | A | — | — | 2 |
| 8 | `edr_behavior.metrics` | `edr_behavior/metrics.py` | `8a8e6f3ebb8d` | A | — | — | 0 |
| 9 | `edr_behavior.normalize` | `edr_behavior/normalize.py` | `d41a91c0828e` | A | — | — | 4 |
| 10 | `edr_behavior.predicates` | `edr_behavior/predicates.py` | `65e4e364c0c2` | A | — | — | 1 |
| 11 | `edr_behavior.provider` | `edr_behavior/provider.py` | `9fe66bbfb38a` | A | — | — | 6 |
| 12 | `edr_behavior.replay` | `edr_behavior/replay.py` | `6440d793ef26` | A | — | — | 6 |
| 13 | `edr_behavior.rules` | `edr_behavior/rules.py` | `78776423a0a5` | A | — | — | 5 |
| 14 | `edr_behavior.store` | `edr_behavior/store.py` | `0cb1eea10807` | A | — | Y | 5 |
| 15 | `edr_behavior.suppression` | `edr_behavior/suppression.py` | `0fa995e50e8a` | A | — | — | 3 |
| 16 | `edr_investigation.__init__` | `edr_investigation/__init__.py` | `e01c9613b9c8` | A | — | — | 5 |
| 17 | `edr_investigation.builder` | `edr_investigation/builder.py` | `4075bd80819a` | A | — | — | 2 |
| 18 | `edr_investigation.causal` | `edr_investigation/causal.py` | `5f45eee83b58` | A | — | — | 0 |
| 19 | `edr_investigation.contracts` | `edr_investigation/contracts.py` | `4d9b8d991b1a` | A | — | — | 2 |
| 20 | `edr_investigation.ti` | `edr_investigation/ti.py` | `edea7cb87205` | A | — | — | 2 |
| 21 | `edr_investigation.ti_contracts` | `edr_investigation/ti_contracts.py` | `c6aa9f4f59f5` | A | — | — | 0 |
| 22 | `edr_ml.__init__` | `edr_ml/__init__.py` | `59ed75164887` | A | — | — | 6 |
| 23 | `edr_ml.baseline` | `edr_ml/baseline.py` | `ead68cd4f3eb` | A | — | — | 2 |
| 24 | `edr_ml.features` | `edr_ml/features.py` | `85c62daf733f` | A | — | — | 2 |
| 25 | `edr_ml.metrics` | `edr_ml/metrics.py` | `c7747157023b` | A | — | — | 0 |
| 26 | `edr_ml.models` | `edr_ml/models.py` | `f7f4d3c01509` | A | — | — | 2 |
| 27 | `edr_ml.pipeline` | `edr_ml/pipeline.py` | `394042b5ca3e` | A | — | — | 3 |
| 28 | `edr_ml.safe` | `edr_ml/safe.py` | `546d85d383d8` | A | — | — | 0 |
| 29 | `edr_ml.schema` | `edr_ml/schema.py` | `774620413f2f` | A | — | — | 4 |
| 30 | `edr_ml.signals` | `edr_ml/signals.py` | `5d96856d191f` | A | — | — | 2 |
| 31 | `edr_plane.__init__` | `edr_plane/__init__.py` | `010a1bb33e61` | A | — | — | 83 |
| 32 | `edr_plane.acquisition_integrity` | `edr_plane/acquisition_integrity.py` | `ff901d72d891` | A | edr_acquisition_gaps,edr_acquisition_integrity | Y | 0 |
| 33 | `edr_plane.authority` | `edr_plane/authority.py` | `ca4c2b4e954c` | A | users | — | 0 |
| 34 | `edr_plane.behavior_evidence_adapter` | `edr_plane/behavior_evidence_adapter.py` | `724c620ba90b` | A | — | — | 3 |
| 35 | `edr_plane.behavior_sd_provider` | `edr_plane/behavior_sd_provider.py` | `f7f3fa6e0ade` | A | — | — | 4 |
| 36 | `edr_plane.behavior_shadow_detection_store` | `edr_plane/behavior_shadow_detection_store.py` | `1bd14baf13cb` | A | e3_behavior_shadow_detections | Y | 2 |
| 37 | `edr_plane.behavior_shadow_frontier` | `edr_plane/behavior_shadow_frontier.py` | `f0d351f2cbc4` | A | — | — | 1 |
| 38 | `edr_plane.behavior_shadow_run` | `edr_plane/behavior_shadow_run.py` | `ed80c2138e48` | A | — | Y | 2 |
| 39 | `edr_plane.behavior_shadow_runner` | `edr_plane/behavior_shadow_runner.py` | `6d63a2190132` | A | — | — | 1 |
| 40 | `edr_plane.campaign_story` | `edr_plane/campaign_story.py` | `a40008899045` | A | edr_endpoints,edr_raw_events,workspace_cases | — | 0 |
| 41 | `edr_plane.canonical_bridge` | `edr_plane/canonical_bridge.py` | `35f4e557f7ca` | A | — | — | 6 |
| 42 | `edr_plane.canonical_identity_contract` | `edr_plane/canonical_identity_contract.py` | `04ca0f5081a6` | A | — | — | 0 |
| 43 | `edr_plane.canonical_index_contract` | `edr_plane/canonical_index_contract.py` | `78215c6aeb50` | A | — | — | 6 |
| 44 | `edr_plane.capability.__init__` | `edr_plane/capability/__init__.py` | `f1f1345bb982` | A | — | — | 1 |
| 45 | `edr_plane.capability.inventory` | `edr_plane/capability/inventory.py` | `f57fdfae3195` | A | — | — | 0 |
| 46 | `edr_plane.capability.model` | `edr_plane/capability/model.py` | `32b1db12b80c` | A | — | — | 1 |
| 47 | `edr_plane.capability.taxonomy` | `edr_plane/capability/taxonomy.py` | `53483e42ca3c` | A | — | — | 0 |
| 48 | `edr_plane.compromise_contract` | `edr_plane/compromise_contract.py` | `8ce73afd2e48` | A | — | — | 1 |
| 49 | `edr_plane.compromise_store` | `edr_plane/compromise_store.py` | `dfa74266b857` | A | edr_compromise_events | Y | 0 |
| 50 | `edr_plane.connector.__init__` | `edr_plane/connector/__init__.py` | `30b491f649c6` | A | — | — | 1 |
| 51 | `edr_plane.connector.catalog` | `edr_plane/connector/catalog.py` | `ce9e77450067` | A | — | — | 0 |
| 52 | `edr_plane.contracts.__init__` | `edr_plane/contracts/__init__.py` | `6b96739026f2` | A | — | — | 3 |
| 53 | `edr_plane.contracts.epistemic` | `edr_plane/contracts/epistemic.py` | `7a24d381284a` | A | — | — | 1 |
| 54 | `edr_plane.contracts.health` | `edr_plane/contracts/health.py` | `3d081af163ae` | A | — | — | 1 |
| 55 | `edr_plane.contracts.identity` | `edr_plane/contracts/identity.py` | `e9e6948e553c` | A | — | — | 3 |
| 56 | `edr_plane.contracts.response` | `edr_plane/contracts/response.py` | `189eca063c2e` | A | — | — | 1 |
| 57 | `edr_plane.contracts.schema_export` | `edr_plane/contracts/schema_export.py` | `feb8ceb5b32e` | A | — | — | 1 |
| 58 | `edr_plane.contracts.telemetry` | `edr_plane/contracts/telemetry.py` | `5787f78cb9b5` | A | — | — | 1 |
| 59 | `edr_plane.delivery_counters` | `edr_plane/delivery_counters.py` | `e32a9d4a6e85` | A | edr_delivery_counters | Y | 0 |
| 60 | `edr_plane.detection_replay` | `edr_plane/detection_replay.py` | `42182e8bfb90` | A | xdr_canonical_evidence | — | 0 |
| 61 | `edr_plane.endpoint_address_observation` | `edr_plane/endpoint_address_observation.py` | `1d782d3032b6` | A | edr_endpoint_address_observations | Y | 0 |
| 62 | `edr_plane.enrollment.__init__` | `edr_plane/enrollment/__init__.py` | `98fe105dcda2` | A | — | — | 6 |
| 63 | `edr_plane.enrollment.audit` | `edr_plane/enrollment/audit.py` | `a3a184bf01db` | A | edr_enrollment_audit | Y | 0 |
| 64 | `edr_plane.enrollment.identity` | `edr_plane/enrollment/identity.py` | `b9bb5ae65c7a` | A | — | — | 4 |
| 65 | `edr_plane.enrollment.instructions` | `edr_plane/enrollment/instructions.py` | `21117512d98f` | A | — | — | 0 |
| 66 | `edr_plane.enrollment.rejection` | `edr_plane/enrollment/rejection.py` | `64f88ecc3301` | A | edr_rejected_telemetry | Y | 0 |
| 67 | `edr_plane.enrollment.security` | `edr_plane/enrollment/security.py` | `6a4260ed147b` | A | — | — | 2 |
| 68 | `edr_plane.enrollment.store` | `edr_plane/enrollment/store.py` | `0435476a9675` | A | edr_agent_credentials,edr_agent_sessions,edr_endpoints,edr_enrollment_tokens | Y | 3 |
| 69 | `edr_plane.enrollment.transport` | `edr_plane/enrollment/transport.py` | `ebf7f7b696c6` | A | — | — | 1 |
| 70 | `edr_plane.evidence_resolution` | `edr_plane/evidence_resolution.py` | `77945f6ba4be` | A | v2_shadow_observations | — | 0 |
| 71 | `edr_plane.exclusions.__init__` | `edr_plane/exclusions/__init__.py` | `22fe414a1727` | A | — | — | 3 |
| 72 | `edr_plane.exclusions.contracts` | `edr_plane/exclusions/contracts.py` | `2cf0b1df683b` | A | — | — | 2 |
| 73 | `edr_plane.exclusions.enforcement` | `edr_plane/exclusions/enforcement.py` | `82fe39c8716e` | A | — | — | 0 |
| 74 | `edr_plane.exclusions.store` | `edr_plane/exclusions/store.py` | `b1964fd3f086` | A | edr_endpoint_exclusion_enforcement,edr_exclusion_sets,edr_exclusions | Y | 0 |
| 75 | `edr_plane.fabric.__init__` | `edr_plane/fabric/__init__.py` | `9308edc6d750` | A | — | — | 3 |
| 76 | `edr_plane.fabric.analyzers.__init__` | `edr_plane/fabric/analyzers/__init__.py` | `ed690bc993be` | A | — | — | 1 |
| 77 | `edr_plane.fabric.analyzers.deterministic_rule` | `edr_plane/fabric/analyzers/deterministic_rule.py` | `010d98b12e95` | A | — | — | 1 |
| 78 | `edr_plane.fabric.contracts` | `edr_plane/fabric/contracts.py` | `f115a497c0d0` | A | — | — | 3 |
| 79 | `edr_plane.fabric.evaluation_state` | `edr_plane/fabric/evaluation_state.py` | `bad765365d00` | A | — | Y | 0 |
| 80 | `edr_plane.fabric.registry` | `edr_plane/fabric/registry.py` | `f951d3604356` | A | — | — | 0 |
| 81 | `edr_plane.fabric.store` | `edr_plane/fabric/store.py` | `e775664fd777` | A | — | Y | 0 |
| 82 | `edr_plane.file_content_acquisition` | `edr_plane/file_content_acquisition.py` | `d03ed983530f` | A | — | — | 0 |
| 83 | `edr_plane.file_identity` | `edr_plane/file_identity.py` | `d12c85049050` | A | — | — | 0 |
| 84 | `edr_plane.findings_intake` | `edr_plane/findings_intake.py` | `a551d6c3f7b4` | A | — | — | 0 |
| 85 | `edr_plane.identity_backfill` | `edr_plane/identity_backfill.py` | `fafdb06b5ccd` | A | e3_migration_row_ledger | Y | 0 |
| 86 | `edr_plane.instant` | `edr_plane/instant.py` | `01e00cb85d98` | A | — | — | 2 |
| 87 | `edr_plane.isolation_policy` | `edr_plane/isolation_policy.py` | `11604c9aed3c` | A | edr_isolation_policy | Y | 0 |
| 88 | `edr_plane.migration_control` | `edr_plane/migration_control.py` | `53ce83077705` | A | e3_migration_locks,e3_migration_runs | Y | 0 |
| 89 | `edr_plane.observation_us_migration` | `edr_plane/observation_us_migration.py` | `2b06bcdc168e` | A | — | Y | 0 |
| 90 | `edr_plane.policy.__init__` | `edr_plane/policy/__init__.py` | `f87554190559` | A | — | — | 0 |
| 91 | `edr_plane.policy.contracts` | `edr_plane/policy/contracts.py` | `cb4485219741` | A | — | — | 0 |
| 92 | `edr_plane.policy.store` | `edr_plane/policy/store.py` | `a39bfda768c6` | A | edr_endpoints,edr_groups,edr_policies,edr_policy_audit… | Y | 0 |
| 93 | `edr_plane.process_identity` | `edr_plane/process_identity.py` | `1f8106730403` | A | — | — | 0 |
| 94 | `edr_plane.processing_queue` | `edr_plane/processing_queue.py` | `e04ca2269e52` | A | edr_processing_queue | Y | 1 |
| 95 | `edr_plane.raw_events` | `edr_plane/raw_events.py` | `b7b434c3ecc5` | A | edr_raw_events | Y | 4 |
| 96 | `edr_plane.reputation.__init__` | `edr_plane/reputation/__init__.py` | `238761a47efa` | A | — | — | 2 |
| 97 | `edr_plane.reputation.contract` | `edr_plane/reputation/contract.py` | `604255aca199` | A | — | — | 1 |
| 98 | `edr_plane.reputation.observables` | `edr_plane/reputation/observables.py` | `5f1e2da50dbe` | A | — | — | 0 |
| 99 | `edr_plane.reputation.providers.__init__` | `edr_plane/reputation/providers/__init__.py` | `58256b4e1b06` | A | — | — | 1 |
| 100 | `edr_plane.reputation.providers.local_ioc` | `edr_plane/reputation/providers/local_ioc.py` | `6c653f66cf6b` | A | — | — | 0 |
| 101 | `edr_plane.reputation.service` | `edr_plane/reputation/service.py` | `56fd14535ac6` | A | — | — | 0 |
| 102 | `edr_plane.response` | `edr_plane/response.py` | `6509b52d35ff` | A | edr_endpoints,edr_raw_events,edr_response_commands,v2_shadow_observations | Y | 0 |
| 103 | `edr_plane.temporal_authority` | `edr_plane/temporal_authority.py` | `62a2e48e2a8e` | A | — | — | 0 |
| 104 | `edr_plane.temporal_read_plan` | `edr_plane/temporal_read_plan.py` | `b4299ca2c156` | A | — | — | 0 |
| 105 | `edr_plane.trajectory.__init__` | `edr_plane/trajectory/__init__.py` | `494e279891c1` | A | — | — | 13 |
| 106 | `edr_plane.trajectory.behavior` | `edr_plane/trajectory/behavior.py` | `df9e93f57c87` | A | — | — | 0 |
| 107 | `edr_plane.trajectory.contract` | `edr_plane/trajectory/contract.py` | `7ebca99a4afb` | A | — | — | 0 |
| 108 | `edr_plane.trajectory.models` | `edr_plane/trajectory/models.py` | `3d53ad732f75` | A | — | — | 0 |
| 109 | `edr_plane.trajectory.projection` | `edr_plane/trajectory/projection.py` | `0eb6bb31e12d` | A | — | — | 0 |
| 110 | `edr_plane.trajectory.relationships` | `edr_plane/trajectory/relationships.py` | `42067aac6190` | A | — | — | 0 |
| 111 | `edr_plane.trajectory.sequence` | `edr_plane/trajectory/sequence.py` | `b839efd2c47e` | A | — | — | 0 |
| 112 | `edr_plane.trajectory_window` | `edr_plane/trajectory_window.py` | `e63846e985c4` | A | edr_finding_evaluations,edr_findings,edr_raw_events,v2_shadow_observations | — | 5 |
| 113 | `edr_plane.windows_eventlog` | `edr_plane/windows_eventlog.py` | `45f66a4526c6` | A | — | — | 0 |
| 114 | `edr_trajectory.__init__` | `edr_trajectory/__init__.py` | `a9d33ad25e1e` | A | — | — | 20 |
| 115 | `edr_trajectory.actions` | `edr_trajectory/actions.py` | `15ac3318a468` | A | — | — | 1 |
| 116 | `edr_trajectory.api` | `edr_trajectory/api.py` | `3545aa962d35` | A | — | Y | 1 |
| 117 | `edr_trajectory.artifacts_overlay` | `edr_trajectory/artifacts_overlay.py` | `d8cfc6bf7aa2` | A | e3_dt_dispositions,e3_dt_enforcement,e3_dt_ti,e3_kushu_events… | Y | 0 |
| 118 | `edr_trajectory.attack` | `edr_trajectory/attack.py` | `805f7db41527` | A | — | — | 0 |
| 119 | `edr_trajectory.contracts` | `edr_trajectory/contracts.py` | `9a355047a59f` | A | — | — | 3 |
| 120 | `edr_trajectory.disposition` | `edr_trajectory/disposition.py` | `fcb279b4dd64` | A | — | — | 1 |
| 121 | `edr_trajectory.e1_shape_preview` | `edr_trajectory/e1_shape_preview.py` | `8eacb63c635f` | A | e3_dt_detections,e3_dt_enforcement,e3_dt_status_events,e3_preview_meta… | Y | 0 |
| 122 | `edr_trajectory.fixtures` | `edr_trajectory/fixtures.py` | `44d4ca235003` | A | — | — | 2 |
| 123 | `edr_trajectory.identity` | `edr_trajectory/identity.py` | `d05c3e705eb2` | A | — | — | 2 |
| 124 | `edr_trajectory.kushu_import` | `edr_trajectory/kushu_import.py` | `fcc5589efe33` | A | — | Y | 0 |
| 125 | `edr_trajectory.lineage` | `edr_trajectory/lineage.py` | `9410436c85fb` | A | — | — | 1 |
| 126 | `edr_trajectory.paging` | `edr_trajectory/paging.py` | `30499b04dd3c` | A | — | — | 2 |
| 127 | `edr_trajectory.platform_seed` | `edr_trajectory/platform_seed.py` | `403866e49a74` | A | — | Y | 0 |
| 128 | `edr_trajectory.preview_mount` | `edr_trajectory/preview_mount.py` | `c45a912a7fc8` | A | — | — | 1 |
| 129 | `edr_trajectory.prodshape` | `edr_trajectory/prodshape.py` | `423293bfcfac` | A | — | — | 0 |
| 130 | `edr_trajectory.production_adapter` | `edr_trajectory/production_adapter.py` | `deefef06ec04` | A | — | — | 2 |
| 131 | `edr_trajectory.production_service` | `edr_trajectory/production_service.py` | `7c03c1b8f255` | A | — | — | 0 |
| 132 | `edr_trajectory.providers` | `edr_trajectory/providers.py` | `4872169f2167` | A | — | — | 5 |
| 133 | `edr_trajectory.service` | `edr_trajectory/service.py` | `9acefd6eb331` | A | e3_dt_seed_canonical_evidence | — | 2 |
| 134 | `edr_trajectory.stale_trace` | `edr_trajectory/stale_trace.py` | `d401781bc1ac` | A | — | — | 1 |
| 135 | `edr_trajectory.ti` | `edr_trajectory/ti.py` | `eb4ad8aa56b1` | A | — | — | 1 |
| 136 | `edr_trajectory.timeline` | `edr_trajectory/timeline.py` | `50eb82ad82a9` | A | — | — | 1 |
| 137 | `edr_trajectory.v3_presentation` | `edr_trajectory/v3_presentation.py` | `056391e66e66` | A | — | — | 0 |
| 138 | `routers.edr` | `routers/edr.py` | `e5dab8b3416a` | A | edr_endpoints | — | 14 |
| 139 | `routers.edr_audit` | `routers/edr_audit.py` | `bc6c148af1c3` | A | edr_connector_deployments,edr_endpoints,edr_enrollment_audit,edr_exclusions… | — | 0 |
| 140 | `routers.edr_connector` | `routers/edr_connector.py` | `9fd2e6fe1572` | A | edr_connector_deployments | Y | 0 |
| 141 | `routers.edr_enrollment` | `routers/edr_enrollment.py` | `aa0e99534c57` | A | — | — | 1 |
| 142 | `routers.edr_events` | `routers/edr_events.py` | `6bb1a9f88e46` | A | edr_raw_events | — | 1 |
| 143 | `routers.edr_exclusions` | `routers/edr_exclusions.py` | `732fbe2dc6f8` | A | — | — | 0 |
| 144 | `routers.edr_findings` | `routers/edr_findings.py` | `fb1023b5cd01` | A | — | — | 1 |
| 145 | `routers.edr_migration_control` | `routers/edr_migration_control.py` | `f8209fc1d97c` | A | — | — | 1 |
| 146 | `routers.edr_onboarding` | `routers/edr_onboarding.py` | `6d3abdb19a74` | A | edr_groups,edr_policies,edr_raw_events | Y | 0 |
| 147 | `routers.edr_policies` | `routers/edr_policies.py` | `d4b61ae7ad78` | A | — | — | 0 |
| 148 | `routers.edr_response` | `routers/edr_response.py` | `f4580beb3bef` | A | edr_endpoints | — | 0 |
| 149 | `routers.edr_saved_views` | `routers/edr_saved_views.py` | `367a782d347f` | A | edr_saved_views | Y | 0 |
| 150 | `routers.edr_session` | `routers/edr_session.py` | `ba76252d22c0` | A | — | — | 0 |
| 151 | `routers.edr_tenancy` | `routers/edr_tenancy.py` | `2705e44804f5` | A | — | — | 4 |
| 152 | `routers.edr_trajectory_v3` | `routers/edr_trajectory_v3.py` | `801c16b50b04` | A | — | — | 0 |
| 153 | `routers.edr_wave0` | `routers/edr_wave0.py` | `3a1db0f04798` | A | — | — | 0 |
| 154 | `services.edr.__init__` | `services/edr/__init__.py` | `9c4e6bd3c572` | A | — | — | 0 |
| 155 | `services.edr.device_identity` | `services/edr/device_identity.py` | `1233b512bf3d` | A | — | — | 1 |
| 156 | `services.edr.endpoint_health` | `services/edr/endpoint_health.py` | `8d2ce3696198` | A | — | — | 2 |
| 157 | `services.edr.endpoint_query` | `services/edr/endpoint_query.py` | `acbc03617b44` | A | — | — | 8 |
| 158 | `services.edr.file_trajectory` | `services/edr/file_trajectory.py` | `89c2f6554c85` | A | — | — | 0 |
| 159 | `services.edr.observation_narrative` | `services/edr/observation_narrative.py` | `fa3c04511d5d` | A | — | — | 0 |
| 160 | `services.edr.telemetry_freshness` | `services/edr/telemetry_freshness.py` | `369f0dab8f89` | A | — | — | 1 |
| 161 | `models.__init__` | `models/__init__.py` | `36e5d9ed3293` | B | — | — | 0 |
| 162 | `security.__init__` | `security/__init__.py` | `3b0a47074998` | B | — | — | 0 |
| 163 | `security.secret_policy` | `security/secret_policy.py` | `7519e839d138` | B | — | — | 0 |
| 164 | `services.__init__` | `services/__init__.py` | `8ddb4e53f5d6` | B | — | — | 0 |
| 165 | `services.activity.projector` | `services/activity/projector.py` | `1816cec7d603` | B | — | — | 1 |
| 166 | `services.dashboard_lenses` | `services/dashboard_lenses.py` | `7ac74e184d36` | B | — | — | 3 |
| 167 | `services.mitre_catalogue.__init__` | `services/mitre_catalogue/__init__.py` | `efc9c35354b9` | B | — | — | 0 |
| 168 | `services.session_context` | `services/session_context.py` | `69a8848da881` | B | — | — | 0 |
| 169 | `timeline.__init__` | `timeline/__init__.py` | `cfc5b2134603` | B | investigation_events | Y | 0 |
| 170 | `v2.case_engine.schema` | `v2/case_engine/schema.py` | `1c5860cab1ee` | B | — | Y | 1 |
| 171 | `v2.ingestion.canonical` | `v2/ingestion/canonical.py` | `f465a0b3b69d` | B | — | — | 8 |
| 172 | `v2.ingestion.telemetry_bridge` | `v2/ingestion/telemetry_bridge.py` | `388cfd57a331` | B | — | Y | 9 |
| 173 | `deps` | `deps.py` | `841f5eac17b8` | C | — | Y | 67 |
| 174 | `routers.xdr_audit_log` | `routers/xdr_audit_log.py` | `005bbdb7b56d` | C | — | Y | 1 |
| 175 | `routers.xdr_rbac` | `routers/xdr_rbac.py` | `061efc64fc33` | C | — | Y | 2 |
| 176 | `detection_content.library.registry` | `detection_content/library/registry.py` | `6802d094fcc7` | D | — | — | 5 |
| 177 | `detection_content.rule_store_binding` | `detection_content/rule_store_binding.py` | `34f5a9f20c84` | D | — | — | 3 |
| 178 | `detection_content.xdr_pipeline` | `detection_content/xdr_pipeline.py` | `f8c0b1f08a5b` | D | xdr_canonical_evidence,xdr_detection_matches | Y | 32 |
| 179 | `detection_content.xdr_threat_family` | `detection_content/xdr_threat_family.py` | `5dd58d447a60` | D | workspace_cases,xdr_canonical_evidence,xdr_correlation_matches,xdr_intelligence_observations | — | 1 |
| 180 | `routers.edr_maintenance` | `routers/edr_maintenance.py` | `bbdbf7b688b0` | E | — | Y | 0 |
| 181 | `canonical.__init__` | `canonical/__init__.py` | `687175b403d0` | F | — | — | 0 |
| 182 | `engine.__init__` | `engine/__init__.py` | `1da66991478b` | F | — | — | 0 |
| 183 | `services.investigator.__init__` | `services/investigator/__init__.py` | `6baa7cf76b03` | G | — | — | 0 |
| 184 | `services.investigator.capabilities.__init__` | `services/investigator/capabilities/__init__.py` | `b9f714e9858e` | G | — | — | 0 |
| 185 | `services.investigator.capabilities.base` | `services/investigator/capabilities/base.py` | `7e4cf58d0a07` | G | — | — | 0 |
| 186 | `services.investigator.lifecycle` | `services/investigator/lifecycle.py` | `eac13cdadfaf` | G | — | — | 0 |
| 187 | `services.investigator.models` | `services/investigator/models.py` | `b78c5e30c56f` | G | — | — | 1 |
| 188 | `services.investigator.orchestrator` | `services/investigator/orchestrator.py` | `806f45693ebe` | G | engine_executions,workspace_cases,xdr_canonical_evidence,xdr_investigation_activity… | Y | 0 |
| 189 | `services.investigator.planner` | `services/investigator/planner.py` | `0f5ec710a2cb` | G | — | — | 2 |
| 190 | `services.iue.artifacts` | `services/iue/artifacts.py` | `16f725d0c355` | G | — | — | 0 |
| 191 | `services.iue.service` | `services/iue/service.py` | `1d8e868a1ab7` | G | workspace_cases,xdr_canonical_evidence,xdr_correlation_matches,xdr_iue_understanding | Y | 4 |

**Class totals:** A=160 · B=12 · C=3 · D=4 · E=1 · F=2 · G=9
