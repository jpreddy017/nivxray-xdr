# NivXRay XDR · AG-Export vs Git Complete-Build Verification

> **Mode:** STRICT READ-ONLY. No code / tests / configs / UI / git history modified. UI freeze in force. Phase 1 remains NOT authorized.
> **Basis:** owner directive "Return the evidence and definitive conclusion before any implementation proceeds."
> **Product:** NivXRay XDR (product name used consistently throughout).

---

## 0 · Verification integrity

| Artifact                              | Value                                                                |
| ------------------------------------- | -------------------------------------------------------------------- |
| AG ZIP path                           | `/app/memory/ag_export/ag.zip`                                       |
| AG ZIP size                           | 25,026,798 bytes (23.87 MiB)                                         |
| AG ZIP SHA-256                        | `ba06f99d38e002b06949951f6e6749d40fa8e844efcd7470ae6e9697338aaa1f`   |
| SHA-256 expected                      | `ba06f99d38e002b06949951f6e6749d40fa8e844efcd7470ae6e9697338aaa1f`   |
| SHA-256 match                         | **✅ VERIFIED**                                                       |
| Comparison performed on branch        | `feature/rc2-alignment` (based off `feature/rc2`, no modifications this session applied) |
| Emergent preservation tag             | `preserve-pre-alignment-2026-09-05` (intact upstream)                |
| Comparison method                     | Deterministic filesystem diff of AG `01_COMPLETE_SOURCE/` vs `git ls-files`, then SHA-256 byte compare on every common relative path. |

---

## 1 · Top-line file counts

| Bucket                                                     | Count      |
| ---------------------------------------------------------- | ---------: |
| AG total files under `01_COMPLETE_SOURCE/`                 | **4,675**  |
| Git tracked files (`git ls-files`)                         | **10,388** |
| Common relative paths (present in both)                    | **4,311**  |
| **AG-only** (present in AG, absent from Git)               | **364**    |
| **Git-only** (present in Git, absent from AG)              | **6,077**  |
| Common paths — **byte-identical**                          | **4,260**  |
| Common paths — **modified** (same path, different bytes)   | **51**     |
| Common paths — modified rate                               | 1.18 %     |

Coverage sanity: 4,311 (common) + 364 (AG-only) = 4,675 (AG total). ✅
                4,311 (common) + 6,077 (Git-only) = 10,388 (Git total). ✅

The previous reconciliation number *"358 AG-only, 44 conflicts"* is **close but under-counted**. The authoritative figures from this verification are **364 AG-only** and **51 modified** (i.e. content-level conflicts). See §7 for reconciliation of the delta.

---

## 2 · AG-only files — breakdown (364 total)

| Top-level | Sub-cluster                              | Count | Category            |
| --------- | ---------------------------------------- | ----: | ------------------- |
| backend   | `backend/security_state/`                | 81    | Security engine     |
| backend   | `backend/detection_content/`             | 54    | Content Fabric      |
| backend   | `backend/.persisted_security_state/`     | 29    | Runtime ledgers (test fixtures) |
| backend   | `backend/tests/`                         | 23    | Tests               |
| backend   | `backend/services/`                      | 3     | Services            |
| backend   | `backend/v2/`                            | 1     | v2                  |
| backend   | `backend/verify_decoder_truth_e2e.py`    | 1     | Verification script |
| backend   | `backend/run_phase2_verification.py`     | 1     | Verification script |
| backend   | `backend/run_phase2_1_audit.py`          | 1     | Audit script        |
| backend   | `backend/run_enterprise_content_pipeline.py` | 1 | Content pipeline    |
| backend   | `backend/run_content_truth_audit.py`     | 1     | Audit script        |
| docs      | `docs/security-state/`                   | 116   | Documentation       |
| docs      | `docs/emergent-handoff-package/`         | 25    | Handoff docs        |
| docs      | `docs/handoff/`                          | 10    | Handoff docs        |
| docs      | `docs/uiux/`                             | 5     | UI/UX specs         |
| docs      | 2 root docs files                        | 2     | EDR handoff report + ZIP |
| apps      | `apps/nivxray-xdr/src/xdr/pages/*`       | 3     | UI pages            |
| apps      | `apps/nivxray-xdr/.env.example`          | 1     | Env template        |
| test_reports | 2 reports                             | 2     | Reports             |
| frontend  | 1 file                                   | 1     | Frontend            |
| deploy    | 1 file                                   | 1     | Deploy config       |
| root      | `Projects.code-workspace`, `NIVXRAY_XDR_SOURCE_EXPORT.html.gz` | 2 | Meta |
| **Total AG-only**                                    |         | **364** |                 |

### 2.1 Critical AG-only clusters (require deliberate integration decisions)

- **`backend/security_state/` — 81 files.** Includes: `attack_state/machine.py`, `capability/engine.py`, `causal/engine.py`, `counterfactual/engine.py`, `impact/engine.py`, `hydration/case_hydrator.py`, `hydration/provenance.py`, `adapters/ssot_adapter.py`, `benchmarks/`, `detection_bridge.py`, `contracts.py`. **This is the AG Security State authoritative implementation** per Truth Contract v3. Absent from Git.
- **`backend/detection_content/` — 54 additional files.** Includes: `artifact_router.py`, `canonical_ir/{evaluator,models,nodes}.py`, `corpus/{sigma,yara,eql,spl_kql,ioc_threat_intel,behavioral_correlation,hunting_anomaly,adversarial,mapping_response,ot_ics_rmm}_corpus.py`, `deduplication/`, `correlation_library.py`, `canonical_content_model.py`, `corpus_expansion.py`. These are Content Fabric assets. **Note:** Git already has `backend/detection_content/` — this delta is an *extension* of the existing Fabric.
- **`backend/tests/` — 23 files.** AG-side tests. Do NOT conflict with Emergent's `tests/edr/test_cross_tenant.py` (which is Git-only, see §3).
- **`apps/nivxray-xdr/src/xdr/pages/` — 3 files.** `XdrEvidenceExplorerPage.jsx`, `XdrInvestigationWorkspacePage.jsx` (58,988 bytes / 1,104 LOC — the target 8-tab), `XdrInvestigationsListPage.jsx`. **UI targets locked by UDR-2026-09-05.**
- **`backend/.persisted_security_state/` — 29 ledger fixtures.** These are runtime state snapshots (test artefacts). May be safe to skip or import into a fixtures folder; not production code.
- **`docs/security-state/` — 116 documentation files.** Architectural spec, target-architecture, industry benchmark. Documentation only, no runtime impact.

---

## 3 · Git-only files — 6,077 files (preservation set)

Top-level distribution:

| Top-level     | Count |
| ------------- | ----: |
| `memory/`     | 4,783 |
| `evidence/`   | 944   |
| `backend/`    | 186   |
| `test_reports/` | 61  |
| `frontend/`   | 54    |
| `docs/`       | 18    |
| Other         | 31    |

### 3.1 Emergent Gate-0.5 preservation set — CONFIRMED PRESENT IN GIT, ABSENT FROM AG

| File                                              | Status               |
| ------------------------------------------------- | -------------------- |
| `backend/routers/truth_inventory.py`              | ✅ Git-only          |
| `backend/tests/edr/__init__.py`                   | ✅ Git-only          |
| `backend/tests/edr/test_cross_tenant.py`          | ✅ Git-only          |

These MUST be preserved during any subsequent integration. `server.py` change that registers `truth_inventory_router` is in the **51 modified** set (§4).

### 3.2 Other Git-only backend clusters

- `backend/tests/` — 84 additional Emergent-side tests (excluding the 3 EDR files above).
- `backend/docs/` — 84 files.
- `backend/mitre_catalogue/`, `backend/finetune/`, `backend/xdr_state/`, `backend/training/`, `backend/exports/`, `backend/workspace_recovery/`, `backend/signatures.py`, `backend/sample_library.py`, `backend/models_studio.py`.
- `apps/nivxray-xdr-response/data/executions.db` — Emergent-side response execution store.
- `apps/nivxray-xdr/yarn.lock` — Emergent-side lockfile.

### 3.3 Very large `memory/` and `evidence/` clusters

The 4,783 `memory/` and 944 `evidence/` files are Emergent's accumulated audit / provenance record and are NOT AG runtime code. They must be preserved but are out of scope for functional integration.

---

## 4 · Modified files — 51 total (content-level conflicts)

These are same-path files with different bytes between AG and Git. Each is a **potential conflict** that requires an explicit resolution decision.

### 4.1 By domain

| Domain    | Count | Notes                                                      |
| --------- | ----: | ---------------------------------------------------------- |
| backend   | 32    | Includes `server.py`, `deps.py`, decoders, detection_content, services/decoder, engine, v2 |
| frontend  | 7     | `AnalystWorkspacePage.jsx`, `WorkspacePage.jsx`, `InvestigationWorkspace.jsx`, `DecodingTracePanel.jsx`, `v2/flags.js`, 2 public HTML |
| memory    | 6     | Historical evidence reports — Emergent side newer          |
| apps      | 3     | `App.jsx`, `XdrShell.jsx`, `RecordHeader.jsx`              |
| docs      | 1     | Single doc file                                            |
| root      | 2     | `README.md`, `.emergent` config                            |

### 4.2 Critical modified files (owner-relevant)

Backend hot spots (require deliberate merge):

- `backend/server.py` — Emergent side has Gate-0.5 `truth_inventory_router` registration. Naïve overwrite = loss of Gate-0.5. **RESOLUTION RULE: MERGE, prefer Emergent (Gate-0.5) but adopt AG additions**.
- `backend/deps.py` — auth seed / DB deps. Emergent side has SEC-001/002 credential rotation. **RESOLUTION RULE: MERGE, prefer Emergent security-hardened baseline**.
- `backend/detection_content/{contract_registry,rule_binding,sigma_strict,xdr_ice,xdr_iue,xdr_pipeline}.py` — Content Fabric core. Emergent side may have runtime fixes. **RESOLUTION RULE: MERGE, prefer AG authoritative implementation, but retain Emergent bug-fixes**.
- `backend/services/decoder/{base/transform,types}.py`, `backend/services/decoder_bridge/__init__.py`, `backend/services/die/preprocessor/recursive_decoder.py`, `backend/services/analyzers/shellcode.py`, `backend/services/canonicalizer/__init__.py` — Decoder engine. **RESOLUTION RULE: keep Emergent 100-% migrated deterministic decoder as authoritative; adopt AG additions only if they extend, not replace.**
- `backend/routers/{ops,xdr_correlation}.py` — Routers. **RESOLUTION RULE: MERGE, prefer AG for correlation engine, prefer Emergent for ops**.
- `backend/decoders/{batch_envvar_substitute,js_reconstruct,rc40_orchestrator_plugins}.py` — Legacy decoder tree. **RESOLUTION RULE: MERGE**.
- `backend/v2/flags.py`, `frontend/src/v2/flags.js` — feature flag registries. **RESOLUTION RULE: UNION** — no regression to flags either side knows about.
- `backend/engine/models.py` — Engine models. **RESOLUTION RULE: MERGE, deliberate**.
- `backend/tests/fixtures/corpus_batch_var_slicing_*.txt` (5 files), `backend/tests/decoder_harness/last_report.json` — Test fixtures. **RESOLUTION RULE: prefer Emergent (freshest observed run)**.
- `backend/rc22_adapter.py`, `backend/osint.py`, `backend/services/artifact_intelligence/analyzers/__init__.py`, `backend/services/recipe_planner.py`, `backend/v2/routers/investigation.py` — misc backend. **RESOLUTION RULE: MERGE**.

Frontend hot spots:

- `frontend/src/pages/AnalystWorkspacePage.jsx`, `frontend/src/pages/WorkspacePage.jsx`, `frontend/src/v2/pages/InvestigationWorkspace.jsx` — Investigation surfaces. **Per UDR-2026-09-05 §2**, canonical target is the AG 8-tab `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` (AG-only, §2 above). **RESOLUTION RULE: retire main-SPA pages AFTER migration; interim = preserve Emergent**.
- `frontend/src/components/DecodingTracePanel.jsx` — Decoder UI. **RESOLUTION RULE: retain Emergent (richer)**.
- `frontend/src/v2/flags.js` — feature flag registry. **RESOLUTION RULE: UNION**.
- `frontend/public/{batch_report,prod_batch_report}.html` — pre-rendered reports. **RESOLUTION RULE: prefer whichever is newer per-file**.

Apps hot spots:

- `apps/nivxray-xdr/src/App.jsx`, `apps/nivxray-xdr/src/xdr/XdrShell.jsx`, `apps/nivxray-xdr/src/xdr/pages/incidents/record/RecordHeader.jsx` — XDR shell. **RESOLUTION RULE: prefer AG (canonical XDR operator experience per UDR §0), but retain any Emergent routing hooks**.

Memory / docs / root:

- 6 `memory/evidence/*` history files — **RESOLUTION RULE: prefer Emergent (freshest audit trail)**.
- 1 `docs/*` file, `README.md`, `.emergent` — **RESOLUTION RULE: prefer Emergent (this repo's authoritative state)**.

Full list of 51 modified paths is available at `/tmp/modified.txt` and will be enumerated verbatim in the integration report at import time.

---

## 5 · Capability-level coverage (per owner-listed capabilities)

| Capability                             | AG source location                                      | Present in Git? | Modified? | Conclusion |
| -------------------------------------- | ------------------------------------------------------- | :-------------: | :-------: | ---------- |
| Evidence ingestion / canonical evidence | `backend/services/canonicalizer/`, `backend/canonical/` | ✅ | 1 file    | Extension needed |
| Artifact analysis                      | `backend/services/artifact_intelligence/`                | ✅ | 1 file    | Extension needed |
| Decoder / multi-stage decoding         | `backend/services/decoder/`, `backend/decoders/`         | ✅ | 6 files   | Merge; keep Emergent authoritative |
| Detection Content Fabric               | `backend/detection_content/`                             | ✅ | 6 files + 54 AG-only | **Major AG extension needed** |
| Detection Engine                       | `backend/detection_content/`, `backend/engine/`          | ✅ | 1 engine file | Merge |
| Sigma / YARA / EQL / SPL / KQL         | `backend/detection_content/corpus/*_corpus.py` (AG-only) | ❌ | — | **AG-only; needs import** (9 corpus files) |
| Correlation Engine                     | `backend/routers/xdr_correlation.py`, `backend/detection_content/correlation_library.py` (AG-only) | ⚠️ partial | 1 modified + 1 AG-only | Merge |
| IUE                                    | `backend/detection_content/xdr_iue.py`                   | ✅ | 1 modified | Merge, prefer AG |
| ICE                                    | `backend/detection_content/xdr_ice.py`                   | ✅ | 1 modified | Merge, prefer AG |
| VEEE / Verdict                         | `backend/detection_content/xdr_pipeline.py`, `verdict_stage2` | ✅ | 1 modified | Merge, prefer AG |
| IKG                                    | `backend/detection_content/` (via IKG projection)        | ✅ | — | Present |
| Attack Story                           | `backend/routers/attack_story.py`, `backend/security_state/attack_state/machine.py` (AG-only) | ⚠️ partial | — | **AG-only attack_state machine needs import** |
| MITRE ATT&CK                           | `backend/mitre_catalogue/`                               | ✅ Git-only | — | Emergent authoritative |
| Security State / causal FSM            | `backend/security_state/` (AG-only 81 files)             | ❌ | — | **Major AG import needed** |
| Reachability                           | `backend/security_state/capability/engine.py` (AG-only)  | ❌ | — | **AG-only** |
| Counterfactual analysis                | `backend/security_state/counterfactual/engine.py` (AG-only) | ❌ | — | **AG-only** |
| Impact analysis                        | `backend/security_state/impact/engine.py` (AG-only)      | ❌ | — | **AG-only** |
| Intervention optimization              | `backend/security_state/` (AG-only)                      | ❌ | — | **AG-only** |
| Response safety                        | `backend/routers/xdr_response_evidence.py`, `backend/security_state/` (AG parts) | ⚠️ partial | — | Merge |
| Response verification                  | `backend/routers/xdr_response_evidence.py`               | ✅ | — | Emergent implemented |
| Investigation                          | `backend/v2/routers/investigation.py`, `backend/routers/investigations.py` | ✅ | 1 modified | Merge |
| Reporting                              | `backend/routers/report*.py`                             | ✅ | — | Present |
| NivXForge EDR (backend)                | `backend/nivxforge/`                                     | ✅ Git-only 4 dirs | — | Emergent side; AG plane is via docs/uiux specs |
| Endpoint telemetry                     | `backend/routers/telemetry.py`, `routers/telemetry_adapters.py` | ✅ | — | Present (blueprint) |
| Endpoint investigation                 | `backend/routers/edr.py` (Device Trajectory, Process Tree) | ✅ | — | Emergent authoritative |
| Threat Hunting                         | —                                                        | ❌ | — | Neither has code; both spec |
| Forensics                              | —                                                        | ❌ | — | Neither has code; both spec |
| Live Query                             | —                                                        | ❌ | — | Neither has code; both spec |
| Endpoint Response                      | `backend/routers/xdr_response_evidence.py`, `response_alias.py` | ✅ | — | Emergent scaffold; no real drivers either side |
| Sandbox                                | AG docs only; no runtime code either side                | ❌ | — | **Spec-only in both**  |
| UBAE                                   | `backend/routers/behavioral.py`, baselines               | ✅ partial | — | Emergent side has baselines; AG has spec |
| Entity 360                             | `backend/layer_360.py`                                   | ✅ Git-only | — | Emergent authoritative |
| External integrations                  | `backend/enrichment/`, `backend/osint.py`                | ✅ | 1 modified | Merge |
| XDR orchestration                      | `backend/routers/xdr_*.py`                               | ✅ Git-only many | — | Emergent authoritative (Cortex/Wildfire/vendor wizards) |
| Administration / governance            | `backend/routers/admin*.py`                              | ✅ Git-only | — | Emergent authoritative |
| Multi-tenancy                          | `backend/deps.py`, RBAC routers                          | ✅ | 1 modified `deps.py` | Merge, prefer Emergent (SEC-001/002 hardening) |
| Observability                          | `backend/observability/`                                 | ✅ | — | Present |
| APIs (routers)                         | `backend/routers/*.py`                                   | ✅ | 2 modified | Merge |
| UI/UX                                  | `frontend/src/`, `apps/nivxray-xdr/src/`                 | ✅ | 10 modified + 4 AG-only | **Consolidation per UDR-2026-09-05 §1-4** |

Coverage summary (SOURCE plane):

- **Only in AG (missing from Git):** Security State (full 81-file engine), Content Fabric extensions (54 files including Sigma/YARA/EQL/SPL/KQL corpus and canonical IR), 4 UI pages, 158 docs.
- **Only in Git (missing from AG):** Gate-0.5 truth inventory + P0-D adversarial tests, MITRE catalogue store, entity-360, XDR vendor wizards (Cortex/Wildfire), 4,783 `memory/` audit artefacts, admin/governance surface.
- **Both, byte-identical:** 4,260 files (91.4 % of common paths).
- **Both, divergent:** 51 files (1.18 % of common paths) — this is the conflict resolution set.

**No capability is a byte-for-byte complete superset in one direction.** Every capability domain has either an AG-only extension, a Git-only extension, or a modified overlap.

---

## 6 · Runtime vs source truth

Per owner directive: *"No capability should be marked IMPLEMENTED merely because its source file exists. Use SOURCE → TEST → RUNTIME → EVIDENCE as the truth chain."*

This verification report speaks ONLY to the SOURCE plane. It does NOT claim any capability is IMPLEMENTED, PARTIAL, or NOT_AVAILABLE at the RUNTIME plane. The 4,260 byte-identical files include placeholder / spec / dead-code files on both sides; that cannot be discovered by hash comparison alone.

Runtime verification requires:

1. Backend service boot with the merged tree → `supervisorctl status`.
2. Full pytest suite (163/164 baseline; `mal-20` intentionally deferred).
3. Frontend build → `yarn build`.
4. P0-D adversarial suite (12 tests) → must remain green.
5. OpenAPI spec generation → route inventory match.
6. Runtime capability probes (Content Fabric registry count, decoder registry count) via existing `/api/xdr/detection/inventory` and `/api/decode/registry/inventory` (Gate-0.5 endpoints).

None of these were run in this verification (read-only invariant).

---

## 7 · Reconciliation of the 358 / 44 prior figure vs today's 364 / 51

The **prior reconciliation** (`docs/truth-contract/edr-review/NIVXRAY_MASTER_EXPORT_RECONCILIATION.md`, commit `975223dc`) recorded:

- 358 AG-only files
- 44 conflicts

**Today's authoritative comparison** finds:

- 364 AG-only files (+6)
- 51 modified files (+7)

**Possible explanations for the delta** (all are read-only observations, not claims):

1. The prior figure may have excluded `backend/.persisted_security_state/` runtime ledger fixtures (29 files). Including them would raise AG-only substantially, so this alone does not explain +6.
2. The prior figure may have excluded 2 `test_reports/*` and 2 root-level meta files (`Projects.code-workspace`, `NIVXRAY_XDR_SOURCE_EXPORT.html.gz`).
3. Files that were AG-only at reconciliation time and have since been added to Git in this session — **NONE**. This session has added only 2 documentation files to Git (`docs/truth-contract/edr-review/NIVXFORGE_UI_DECISION_RECORD.md` and `memory/edr_review/NIVXFORGE_UI_DECISION_RECORD.md`, both Emergent-authored; both untracked in Git currently).
4. The prior figure may have included some files as "modified" that the byte-hash reveals as "AG-only" or vice-versa.

**Conclusion for the delta:** The prior 358 / 44 was an approximation. The definitive numbers as of this verification are **364 / 51**. The AG import list published in this report SUPERSEDES the earlier 358-file list.

---

## 8 · Verdict — mandatory conclusion (A / B / C)

- **A. COMPLETE — Git contains the complete AG build.** ❌ Rejected.
- **B. PARTIAL — Git does not contain the complete AG build.** ⚠ Partially applies.
- **C. DIFFERENT / EVOLVED — Git and AG contain different implementations and neither can be called a complete superset.** ✅ **THIS IS THE TRUTH.**

**Definitive conclusion: C. DIFFERENT / EVOLVED.**

Evidence:

- Git is not a superset of AG (**364 AG-only files** — Security State engine, Content Fabric corpus, XDR investigation pages, 158 docs).
- AG is not a superset of Git (**6,077 Git-only files** including Gate-0.5 P0-D isolation suite, truth-inventory endpoints, MITRE catalogue, admin/governance, vendor wizards, `memory/` provenance).
- The overlap contains **51 divergent files** where the same relative path holds different content on each side.

The two trees share **~4,260 byte-identical files** (a strong common baseline), but the divergences are non-trivial and cover critical capability domains on both sides.

---

## 9 · Answers to the mandatory §B/C follow-up questions

1. **Exact missing AG file count:** **364**
2. **Exact AG-only file list:** Enumerated in this session as `/tmp/ag_only.txt` (364 lines). Summarised by cluster in §2 above. Full list will be committed alongside the integration branch at import time; not attached to this read-only report to avoid diff bloat.
3. **Exact Git-only file count:** **6,077**
4. **Exact conflict / modified file count:** **51**
5. **Capability-level gaps:** Enumerated in §5. Headline gaps:
   - Security State full engine (81 AG-only files) — **major**
   - Content Fabric extensions incl. Sigma/YARA/EQL/SPL/KQL corpus (54 AG-only files) — **major**
   - XDR investigation UI pages (3 AG-only including the 8-tab workspace) — **major (UI)**
   - `backend/security_state` reachability/counterfactual/impact/intervention engines — **AG-only, no Git counterpart**
6. **Is the previous 358-file figure still valid?** **No, superseded.** Use 364 (AG-only) / 51 (modified). See §7 for the reconciliation.
7. **Does the complete AG ZIP still need integration?** **Yes.** Verdict **C** confirms neither side is a complete superset. The AG ZIP's 364 AG-only files + 51 modified overlaps represent real capability that Git does not have (or has divergently). Conversely, Emergent Gate-0.5 work must be preserved.
8. **Recommended safe integration sequence** (proposed — not authorized; owner must confirm):
   1. **Freeze**. Preserve `preserve-pre-alignment-2026-09-05` tag (already intact).
   2. **Alignment branch** — `feature/rc2-alignment` already created off `feature/rc2` this session; no code changes applied.
   3. **Import pass 1 — safe additions.** Copy the 364 AG-only files (excluding `.persisted_security_state/` ledgers) into the alignment branch. This is additive; cannot cause regression by itself. Commit as one atomic "AG-only import".
   4. **Runtime verification.** `supervisorctl restart backend` → boot logs clean → P0-D suite green → Content-Fabric registry probe → decoder registry probe.
   5. **Import pass 2 — deliberate merges.** For each of the 51 modified files, apply the resolution rule from §4.2. Commit per-file with justification. Preserve `backend/routers/truth_inventory.py` and `backend/tests/edr/test_cross_tenant.py` (Git-only, so untouched).
   6. **Runtime verification (second gate).** Full pytest, P0-D, OpenAPI diff, frontend build.
   7. **UI consolidation** per UDR-2026-09-05 §1-4. Import the 3 AG UI pages (`XdrInvestigationWorkspacePage`, `XdrEvidenceExplorerPage`, `XdrInvestigationsListPage`) and wire them into the XDR shell. Retire main-SPA `InvestigationWorkspace.jsx` and `WorkspacePage.jsx` **only after** feature-parity migration.
   8. **Truth Contract v4** — new immutable snapshot documenting the merged state. Never amend v1/v2/v3.
   9. **Integration report** — `NIVXRAY_COMPLETE_AG_INTEGRATION_REPORT.md` per owner spec.
   10. **STOP.** Do not proceed to EDR Phase 1 / Sandbox / UBAE without explicit owner authorization.

---

## 10 · Invariants respected in this verification

- ✅ No pod file modified (verified via `git status --porcelain` — only untracked docs).
- ✅ No AG ZIP file modified. SHA-256 unchanged: `ba06f99d…aa1f`.
- ✅ No test executed against the pod (read-only invariant).
- ✅ No import staged. `feature/rc2-alignment` branch has zero code commits.
- ✅ Emergent preservation tag `preserve-pre-alignment-2026-09-05` intact.
- ✅ Immutable Truth Contract v1/v2/v3 not amended.
- ✅ UI freeze maintained.
- ✅ `mal-20` untouched.
- ✅ Product name **NivXRay XDR** used consistently.

---

## 11 · What this report does NOT do

- Does NOT authorize any file import.
- Does NOT authorize any conflict resolution.
- Does NOT modify any capability status flag.
- Does NOT lift the UI freeze.
- Does NOT authorize EDR Phase 1, Sandbox, UBAE.
- Does NOT alter Truth Contract v1 / v2 / v3.

---

## 12 · Standing next-authorized event

Owner reviews this verification report → confirms verdict **C** → issues explicit
**"OWNER AUTHORIZATION — COMPLETE AG BASELINE INTEGRATION"** authorization
with the resolution rules from §4.2 accepted or amended → then and only then
may Import Pass 1 begin on `feature/rc2-alignment`.

## END · NIVXRAY_XDR_AG_VS_GIT_COMPLETE_BUILD_VERIFICATION delivered · read-only · awaiting owner authorization
