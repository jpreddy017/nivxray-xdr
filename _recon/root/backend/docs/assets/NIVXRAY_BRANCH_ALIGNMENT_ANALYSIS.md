# NivXRay · Branch Alignment Analysis (Owner-Authorized D-1 Diff · READ-ONLY)

> **Gate:** post-Master-Reconciliation · **Mode:** READ-ONLY. No destructive Git ops. No file merges. No Phase 1. No content regeneration. No decoder changes. No UI changes.
> **Authorization:** Owner-approved D-1 controlled branch-alignment diff (evidence-only).
> **Inputs:** AG `01_COMPLETE_SOURCE/` (4,354 source files after filter) · POD live `feature/rc2` tree (4,055 source files after filter, `/app/memory/` and `/app/memory/ag_export/` excluded).
> **Machine-readable index:** `/app/memory/edr_review/alignment/alignment_index.json`.

---

## §1 · Aggregate Deltas

| Bucket | Count | Meaning |
|---|---:|---|
| **Shared files (same path)** | 3,996 | present in both trees |
| ├─ **Byte-identical** | **3,952** (98.9 %) | zero divergence risk |
| └─ **Conflict** (different SHA) | **44** (1.1 %) | require per-file resolution |
| **AG-only** | **358** | present in AG, absent on POD |
| **POD-only** | **59** | present on POD, absent in AG |
| Grand total files scanned | 4,354 (AG) + 4,055 (POD) | after `.py/.js/.jsx/.ts/.tsx/.json/.yml/.yaml/.md/.html/.css/.sh/.sql` filter and standard exclusions |

Interpretation: the two trees share a common ancestor. The 3,952 byte-identical files are the safe backbone. The remaining ~450 files (44 conflicts + 358 AG-only + 59 POD-only) are the alignment surface that requires owner decisions before any merge or rebase.

---

## §2 · AG-only trees (must NOT be recreated on POD — must be integrated verbatim to preserve provenance)

Grouped by top directory. Full list in `alignment_index.json.ag_only`.

| Top directory | AG-only file count | Why it matters |
|---|---:|---|
| `docs/security-state/` | 116 | AG Security-State architecture documentation & designs |
| `backend/security_state/` | 81 | **Full Causal Security State Engine module** (contracts, adapters, causal, counterfactual, detection_bridge, hydration, impact, intervention, ledger, model, orchestration, persistence, progression, reachability, response_safety, routers). **D-3 mandate: this IS the authoritative implementation.** |
| `backend/detection_content/` | 54 | Corpus modules + yara_engine + deduplication + library + telemetry + translation + validation_framework + canonical_ir. **D-2 mandate: this backs the 615 count.** |
| `backend/.persisted_security_state/` | 28 | Persisted runtime state for Security-State ledger (snapshot / replay evidence). NOT code — but MUST be preserved so ledger continuity holds. |
| `docs/emergent-handoff-package/` | 25 | Emergent Handoff package unpacked copy (already reviewed at Gate 0). |
| `backend/tests/` | 23 | Test files that back the AG's 733 count (POD baseline 731). Includes Security-State + corpus-verification tests. |
| `docs/handoff/` | 10 | Duplicate of handoff-package (flat layout). |
| `docs/uiux/` | 5 | UI/UX specs. |
| `apps/nivxray-xdr/` | 3 | Companion-SPA files — INCLUDES the 3 handoff-cited `XdrEvidenceExplorerPage.jsx`, `XdrInvestigationWorkspacePage.jsx`, `XdrInvestigationsListPage.jsx` (all AG_MODIFIED_BY_AG in Phase 0). |
| `backend/services/` | 3 | 3 service files missing on POD (audit at integration time). |
| `backend/run_content_truth_audit.py` | 1 | **Audit script that produces the 615.** |
| `backend/run_enterprise_content_pipeline.py` | 1 | Content ingestion pipeline. |
| `backend/run_phase2_1_audit.py` | 1 | Phase 2.1 audit runner. |
| `backend/run_phase2_verification.py` | 1 | Phase 2 verification. |
| `backend/verify_decoder_truth_e2e.py` | 1 | **Decoder truth verification script.** |
| `backend/v2/` | 1 | 1 v2 file missing on POD. |
| `test_reports/enterprise_content_truth_audit.json` | 1 | **1.36 MB audit JSON — empirical evidence of the 615.** |
| `test_reports/enterprise_content_inventory.json` | 1 | Inventory JSON. |
| `frontend/src/` | 1 | 1 frontend file. |
| `docs/NIVXFORGE_EDR_EMERGENT_HANDOFF_PACKAGE_REPORT.md` | 1 | Handoff package report. |

**Total AG-only: 358 files.** The critical subset for D-1/D-2/D-3 is `backend/security_state/` (81) + `backend/detection_content/` (54) + `backend/.persisted_security_state/` (28) + 5 audit-pipeline scripts + 2 audit JSONs = **170 core files** to integrate. The remaining 188 are documentation + tests + minor supporting files.

---

## §3 · POD-only files (**MUST be preserved through any alignment** — Emergent work)

| Path / cluster | Count | Origin |
|---|---:|---|
| `backend/tests/edr/*` (`__init__.py`, `test_cross_tenant.py`) | 2 | **Gate 0.5** — P0-D adversarial suite (12/12 pass) |
| `backend/routers/truth_inventory.py` (Gate 0.5 introspection endpoints) | 1 | **Gate 0.5** — GET `/api/xdr/detection/inventory`, GET `/api/decode/registry/inventory` |
| `backend/tests/` (other POD-only) | 25 | Emergent-added tests during earlier sprints (must be reviewed to keep) |
| `docs/truth-contract/**` | 10 | Gate 0/0.5 review artifacts (Truth v1 mirrors + Gate 0.5 reconciliation docs + edr-review subtree) |
| `backend/docs/**` | 10 | Emergent docs (public download assets: source-export HTML, review MDs) |
| `deployer-agent-docs/RCA_*.MD` | 3 | Deployer-agent RCA notes (probably safe to drop, owner confirms) |
| `test_reports/xray_salvage_v156*` | 3 | Emergent-run test reports |
| `backend/models_studio.py`, `backend/sample_library.py`, `backend/signatures.py`, `scripts/prod_validator.py`, `backend/v2/…` (small POD-only) | 5 | Emergent-added utility files (review to keep) |
| **Total POD-only** | **59** | — |

**Preservation rule (per D-1):** all Gate 0.5 additions MUST be preserved during branch alignment. The 25 pod-added test files and 5 utility files require row-by-row owner review to decide keep/drop before any merge.

---

## §4 · Conflict files (same path, different content — require per-file resolution)

44 files. Sorted by criticality:

### 4.1 · CRITICAL — reasoning / engine paths (must resolve carefully)

| Path | Notes |
|---|---|
| `backend/server.py` | POD has Gate 0.5 `+3` lines wiring `truth_inventory_router` after `xdr_detection_content` include. AG version is the earlier pre-Gate-0.5 state. **Resolution:** re-apply POD's 3-line addition on top of AG's baseline. |
| `backend/deps.py` | Divergent — audit blocker until diff reviewed. |
| `backend/detection_content/contract_registry.py` | Detection-content registry. AG version is authoritative per D-2. |
| `backend/detection_content/rule_binding.py` | Same. |
| `backend/detection_content/sigma_strict.py` | Same. |
| `backend/detection_content/xdr_ice.py` | ICE bridge. |
| `backend/detection_content/xdr_iue.py` | IUE bridge. |
| `backend/detection_content/xdr_pipeline.py` | Content pipeline. |
| `backend/routers/xdr_correlation.py` | ICE correlation router. |
| `backend/routers/ops.py` | Ops router. |
| `backend/engine/models.py` | Engine models. |
| `backend/rc22_adapter.py` | Adapter. |

**Resolution rule:** for engine/reasoning conflicts, AG side is the more-authoritative baseline (per D-3). POD-only additions on top of these files (if any) must be identified and re-applied after AG restore.

### 4.2 · Decoder-tree conflicts (freeze rule still applies)

| Path | Notes |
|---|---|
| `backend/decoders/batch_envvar_substitute.py` | Divergent — must check which is the frozen/canonical version. |
| `backend/decoders/js_reconstruct.py` | Same. |
| `backend/decoders/rc40_orchestrator_plugins.py` | Same. |
| `backend/services/decoder/base/transform.py` | DDO Plane-A codec. |
| `backend/services/decoder/types.py` | Decoder types. |
| `backend/services/decoder_bridge/__init__.py` | Legacy shim. |
| `backend/services/die/preprocessor/recursive_decoder.py` | Legacy re-export. |

**Resolution rule:** decoder scope is FROZEN. Diff MUST show whether POD or AG has the frozen/canonical version. If AG carries the authoritative version, POD accepts it verbatim; if POD carries a Gate 2D-B3-migrated superset, POD keeps it. **No content-level merging authorized without owner review.**

### 4.3 · Investigation / v2 paths

| Path | Notes |
|---|---|
| `backend/v2/routers/investigation.py` | v2 investigation router. |
| `backend/v2/flags.py` | v2 feature flags. |
| `frontend/src/v2/pages/InvestigationWorkspace.jsx` | Main-SPA investigation workspace. |
| `frontend/src/v2/flags.js` | Frontend v2 flags. |
| `frontend/src/pages/AnalystWorkspacePage.jsx` | Main-SPA analyst workspace. |
| `frontend/src/pages/WorkspacePage.jsx` | Main-SPA workspace. |
| `frontend/src/components/DecodingTracePanel.jsx` | UI component. |

**Resolution rule:** UI freeze applies. AG side takes precedence for these files if AG-modified; POD retains only if a specific Emergent-authored change exists that owner wants kept. **No frontend edits authorized here; the diff is documentation only.**

### 4.4 · Companion SPA (AG-modified in Phase 0)

| Path | Notes |
|---|---|
| `apps/nivxray-xdr/src/App.jsx` | AG_MODIFIED_BY_AG (172 LOC). |
| `apps/nivxray-xdr/src/xdr/XdrShell.jsx` | AG_MODIFIED_BY_AG (411 LOC). |
| `apps/nivxray-xdr/src/xdr/pages/incidents/record/RecordHeader.jsx` | AG_MODIFIED_BY_AG (272 LOC). |

**Resolution rule:** AG side takes precedence — these are AG-authored Phase-0 modifications.

### 4.5 · Support / test / doc conflicts

| Path | Notes |
|---|---|
| `README.md` (root) | Two divergent READMEs — reconcile textually. |
| `docs/truth-contract/README.md` | POD updated during Gate 0.5 (added source-export block). Keep POD. |
| `backend/tests/decoder_harness/last_report.json` | Generated artifact — regenerate on integration. |
| `backend/tests/fixtures/corpus_batch_var_slicing_00[1-5].txt` (5 files) | Test fixtures — pick AG canonical or POD current. |
| `frontend/public/batch_report.html`, `prod_batch_report.html` | Reports — pick AG or POD, both cases documented. |
| `backend/services/analyzers/shellcode.py` | Analyzer. |
| `backend/services/artifact_intelligence/analyzers/__init__.py` | Analyzer package. |
| `backend/services/canonicalizer/__init__.py` | Canonicalizer package. |
| `backend/services/recipe_planner.py` | Planner. |
| `backend/osint.py` | OSINT utility. |

---

## §5 · Preservation ledger (Emergent-only work that MUST survive alignment)

Ordered by criticality:

1. **`backend/routers/truth_inventory.py`** (Gate 0.5 authorized code · GET `/api/xdr/detection/inventory` + GET `/api/decode/registry/inventory`)
2. **`backend/tests/edr/__init__.py` + `test_cross_tenant.py`** (Gate 0.5 P0-D adversarial suite · 12/12 pass · owner-authorized)
3. **The `+3` lines in `backend/server.py`** that register the truth-inventory router
4. **`/app/docs/truth-contract/**`** (Truth Contract v1 mirror + Gate 0.5 review artifacts)
5. **`/app/memory/edr_review/**`** (all Gate 0/0.5/reconciliation artifacts + this analysis) — memory tree, not git-tracked; must be Save-to-Github before alignment work starts
6. **Any Emergent-added test files under `backend/tests/`** that back the Truth v2 baseline — 25 files to inventory before decision
7. **Emergent-added utility files** (`models_studio.py`, `sample_library.py`, `signatures.py`, `scripts/prod_validator.py`) — 5 files to inventory

Everything above is safe today. Nothing has been deleted or overwritten by this analysis.

---

## §6 · Recommended controlled-alignment sequence (owner authorization pending)

**None of the steps below is executed at this gate.** Each requires explicit owner authorization *after reviewing this document*.

- **Step 1 · Snapshot.** Save-to-Github the current POD branch (`feature/rc2` at post-Gate-0.5 state) with a distinct commit + tag `preserve-pre-alignment-2026-09-05`.
- **Step 2 · Publish alignment index.** This document + `alignment_index.json` becomes the reference.
- **Step 3 · AG-only integration (358 files).** In a new working branch: import AG-only trees verbatim (D-2 · `detection_content/`, D-3 · `security_state/`, audit scripts, corpus, persisted_security_state). Preserve provenance.
- **Step 4 · Conflict resolution (44 files).** Per §4 rules: AG-authoritative for reasoning/engine/detection-content; POD-preserving for Gate 0.5 additions to `server.py`; freeze rule for decoders; UI-freeze rule for frontend paths.
- **Step 5 · POD-only preservation replay (59 files).** Re-apply Gate 0.5 additions on top of the AG baseline. Verify Gate-0.5 tests still pass (P0-D 12/12; truth-inventory endpoints alive).
- **Step 6 · Independent-verification.** Run `python backend/run_content_truth_audit.py` and `python backend/verify_decoder_truth_e2e.py` on the aligned tree — record the actual counts (must equal AG's 615 / decoder categories) before declaring current truth.
- **Step 7 · Truth Contract v3 emission.** New immutable snapshot per D-5. v1 and v2 remain frozen.
- **Step 8 · Present evidence.** Return the aligned baseline + independent counts + P0-D re-run + full change ledger for owner review.
- **Step 9 · Owner authorizes Phase 1** only after Steps 1-8 close.

---

## §7 · What Emergent did NOT do at this gate

- ❌ Did NOT modify AG export.
- ❌ Did NOT copy AG files into POD.
- ❌ Did NOT resolve any conflict.
- ❌ Did NOT run destructive Git ops.
- ❌ Did NOT rebase, reset, checkout, cherry-pick, or merge.
- ❌ Did NOT regenerate corpus.
- ❌ Did NOT change decoder scope.
- ❌ Did NOT touch UI.
- ❌ Did NOT start Phase 1.

## §8 · What Emergent DID do at this gate

- ✅ Fully indexed AG source (4,354 files) and POD source (4,055 files) with SHA-256.
- ✅ Computed 3-way delta: 3,952 identical / 44 conflict / 358 AG-only / 59 POD-only.
- ✅ Categorised the AG-only tree by owner-decision relevance (D-2 corpus, D-3 security_state, audit scripts, persisted state).
- ✅ Enumerated the POD-only tree to guarantee preservation of Gate 0.5 work.
- ✅ Classified each of the 44 conflicts into resolution rules.
- ✅ Produced a step-by-step controlled-alignment sequence (owner-approval-required at each step).
- ✅ Preserved v1 and v2 Truth Contracts unchanged.
- ✅ AG export unchanged (SHA-256 `ba06f99d…aa1f`).

## END · alignment analysis delivered · read-only · awaiting owner review before Step 3
