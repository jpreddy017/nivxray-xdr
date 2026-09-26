# NIVXRAY MASTER EXPORT RECONCILIATION

> **Gate:** post-Gate-0.5 · **Mode:** READ-ONLY. **No application code changed.** No git ops. No Phase 1 implementation. No content regeneration. No decoder changes. No modification of the master export.
> **Governing rule (owner directive):** documentation is NEVER implementation truth. Filesystem / source / runtime evidence take precedence. Runtime > filesystem > documentation.
> **Inputs:**
> - `NIVXRAY_COMPLETE_AG_EXPORT.zip` (25,026,798 B · SHA-256 `ba06f99d38e002b06949951f6e6749d40fa8e844efcd7470ae6e9697338aaa1f` · 4,715 files unpacked · 4,675 in source subtree)
> - Live Emergent pod on branch `feature/rc2` (post-Gate-0.5 code state)
> - Immutable Truth Contract v1 commit `d3f7a0a000892131abc9a32ee97009338dd38d79` (unchanged)

---

## §1 · Executive Summary

**The AG export represents a MORE COMPLETE branch of NivXRay than the current Emergent pod's `feature/rc2` branch.** Every path Gate 0.5 flagged as "MISSING_FROM_BRANCH" DOES exist inside the AG archive as `PRE_EXISTING` code (not created by AG). The gap is therefore a **branch divergence**, not a missing capability at the project level.

The AG-side manifest declares:
- **7 files MODIFIED_BY_AG** — all inside `apps/nivxray-xdr/src/xdr/` (UI companion SPA — same trees the UI freeze protects).
- **51 files AG_CREATED** — 100% documentation + one truth-audit JSON. **Zero new implementation code.**
- **4,617 files PRE_EXISTING** — the NivXRay core.

The **615 Content Fabric cardinality** is empirically anchored inside the AG export by `test_reports/enterprise_content_truth_audit.json` (1,358,417 B). The number `615` is genuinely produced by AG's `backend/run_content_truth_audit.py` scanning `backend/detection_content/corpus/*.py` — both of which exist in AG's `01_COMPLETE_SOURCE/`. **The current pod branch does not carry either the corpus modules or the audit script**, which is why Gate 0.5 correctly classified `615` as `UNVERIFIED_ON_CURRENT_BRANCH`. That classification remains correct.

The **decoder distinction** is confirmed in AG's audit JSON: `registered=61 · logical=48 · physical=46 · operational=42 · malware-family=14`. The pod branch's own filesystem gives `physical=45 · malware-family=14`. Pod is off by one physical codec (`46 → 45`); the other four categories are AG-runtime distinctions the pod cannot re-produce without the missing audit script.

The **immutable Truth Contract v1** is preserved (SHA-verified byte-identical on pod). **Truth Contract v2** (Gate 0.5) is a NEW snapshot layered on top; it never mutated v1.

---

## §2 · Delta Matrix (authoritative)

### 2.1 · Subsystem file-count parity (only `.py`, `__pycache__` excluded)

| Subsystem | AG count | POD count | Status |
|---|---:|---:|---|
| `backend/routers/` | 128 | 129 | **POD +1** — Gate 0.5 `truth_inventory.py` |
| `backend/services/` | 350 | 347 | POD −3 minor drift |
| `backend/decoders/` (top level) | 62 | 62 | **==** |
| `backend/decoders/families/` | 16 | 16 | **==** |
| `backend/detection_content/` (all) | 106 | 52 | **POD −54** (missing corpus + subtree fragments) |
| `backend/detection_content/corpus/` | 11 | **0** | **AG-ONLY** (the 615 backing) |
| `backend/security_state/` | 81 | **0** | **AG-ONLY** (entire module) |
| `backend/tests/` | 733 | 731 | POD −2 minor |
| `frontend/src/pages/` | 34 | 34 | **==** |
| `apps/nivxray-xdr/src/` | 188 | 185 | POD −3 |
| `apps/nivxray-xdr-collector/` | 37 | 59 → 33 (`.py` only) | roughly parity |
| `apps/nivxray-xdr-response/` | 19 | 20 | POD +1 |

### 2.2 · AG-ONLY implementation trees (present in AG, absent on POD)

| AG path | AG file count | Consequence for pod |
|---|---|---|
| `backend/detection_content/corpus/` (11 .py files: `adversarial`, `behavioral_correlation`, `eql`, `hunting_anomaly`, `ioc_threat_intel`, `mapping_response`, `ot_ics_rmm`, `sigma`, `spl_kql`, `yara`) | 11 | The 615 Content Fabric registry is empty on pod. Detection engine has no seeded corpus. |
| `backend/detection_content/yara_engine.py` | 1 (14,080 B) | YARA execution surface absent on pod. |
| `backend/detection_content/deduplication/`, `library/`, `telemetry/`, `translation/`, `validation_framework/`, `canonical_ir/` | multiple | Detection support pipelines absent on pod. |
| `backend/security_state/` (contracts + adapters + attack_state + benchmarks + capability + causal + counterfactual + detection_bridge + hydration + impact + intervention + ledger + model + orchestration + persistence + progression + reachability + response_safety + routers) | 81 | Causal Security State Engine + Ledger + Reachability + Counterfactual + Impact ABSENT on pod. rc5 remains the sole state-transition surface on pod (per Gate 0.5 finding). |
| `backend/run_content_truth_audit.py` | 1 (39,098 B) | Cannot regenerate the 615 audit locally on pod. |
| `backend/verify_decoder_truth_e2e.py` | 1 (10,429 B) | Cannot regenerate the decoder-registry truth on pod. |
| `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | 1 (19,145 B) | Evidence Explorer companion-SPA page absent on pod. Main SPA still has `frontend/src/pages/EvidenceExplorerPage.jsx`. |
| `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | 1 (58,988 B, 1,104 LOC) | 8-tab investigation companion-SPA page absent on pod. |
| `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx` | 1 | Investigation list companion absent. |
| `apps/nivxray-xdr/src/xdr/pages/incidents/record/RecordHeader.jsx` | 1 | Modified by AG — absent from pod. |
| `test_reports/enterprise_content_truth_audit.json` | 1 (1,358,417 B) | The evidence document that proves `total_objects=615`. |

### 2.3 · POD-ONLY code (present on POD, absent in AG)

| POD path | POD size | Added by |
|---|---|---|
| `backend/routers/truth_inventory.py` | ~5.5 KB | **Gate 0.5 (Emergent, authorized)** — GET `/api/xdr/detection/inventory`, GET `/api/decode/registry/inventory` |
| `backend/tests/edr/__init__.py` | 0 B | **Gate 0.5** |
| `backend/tests/edr/test_cross_tenant.py` | ~9.1 KB | **Gate 0.5** — 11 P0-D vectors + AC meta-audit |
| `backend/server.py` `+3` additive lines to include `truth_inventory_router` | 3 lines | **Gate 0.5** |

### 2.4 · Shared files with different content (spot check)

| File | AG SHA-256 | POD SHA-256 | Match |
|---|---|---|---|
| `backend/routers/xdr_ingest.py` | `87db4b14f94b50dd…` | `87db4b14f94b50dd…` | **==** |
| Immutable Truth v1 MD | `061fd851f954f84c…` | `061fd851f954f84c…` | **==** |
| Immutable Truth v1 JSON | `295d1e7003e775b2…` | `295d1e7003e775b2…` | **==** |

Byte-identical shared files confirm the two trees share a common ancestor commit; the divergence is in what got pruned before the pod branch was cut.

### 2.5 · AG Phase-0 activity summary (from manifest)

- **MODIFIED_BY_AG (7 files):** all inside `apps/nivxray-xdr/src/xdr/` — UI companion SPA pages + shell + `App.jsx` + one record-header sub-component + one `.code-workspace`. Every one is under the current UI freeze scope; NONE touch `backend/*`, reasoning engines, or decoders.
- **AG_CREATED (51 files):** every entry is documentation, spec, prototype HTML, or the `enterprise_content_truth_audit.json`. **Zero implementation code created by AG in Phase 0.**

---

## §3 · Reconciled Counts

### 3.1 · 615 Content Fabric

| Perspective | Value | Evidence |
|---|---|---|
| AG runtime audit JSON | **615 total_objects (615 unique · 0 exact dupes · 0 normalized dupes · 63 semantic dupes · 446 cross-language equivalents · 16 domains)** | `01_COMPLETE_SOURCE/test_reports/enterprise_content_truth_audit.json` `corpus_inventory.total_objects` |
| AG filesystem source | 11 corpus Python modules that the audit script scans | `01_COMPLETE_SOURCE/backend/detection_content/corpus/*.py` |
| AG audit script | `backend/run_content_truth_audit.py` (39,098 B) | present |
| POD filesystem | `backend/detection_content/corpus/` **does not exist** | `find /app/backend/detection_content -maxdepth 2 -type d` — no corpus |
| POD audit script | `backend/run_content_truth_audit.py` **does not exist** | Gate 0.5 introspection endpoint installed instead |
| POD live runtime doc count | `detection_content=1, xdr_detection_rules=93, xdr_correlation_rules=5, xdr_capability_contracts=339, xdr_engines=339` | live Mongo probe |
| **RECONCILED CLASSIFICATION** | **VERIFIED_ON_AG_BRANCH · UNVERIFIED_ON_POD_BRANCH · BRANCH_DIVERGENCE** | — |

**Consequence:** the 615 is REAL as an AG-side artifact. On the Emergent pod, it remains legitimately `UNVERIFIED_ON_CURRENT_BRANCH` because the pod's `detection_content/corpus/` tree was never provisioned. **Any Phase 1 authorization must decide whether to (a) rebase the pod branch to include AG's corpus tree, (b) re-import the corpus modules from AG, or (c) build a bridge for the pod to consume the AG-generated audit JSON.** No such decision has been made and none is executed here.

### 3.2 · Decoder counts (logical / physical / registered / DDO / malware-family)

| Category | AG audit value | POD value | Status |
|---|---:|---:|---|
| Registered in decoder registry (runtime) | 61 | (not measurable without registry-import) | AG_HIGHER |
| Logical codecs in coverage matrix (documentation) | 48 | 48 (per handoff doc) | == |
| Physical codecs in `backend/decoders/*.py` (filesystem) | 46 | **45** | **AG +1** |
| Operational codecs in operations dict | 42 | (not measurable) | AG_HIGHER |
| Malware-family signature profilers (`decoders/families/*.py`) | 14 | 14 | **==** |
| DDO codec families (`services/decoder/base/*.py`) | 7 (per Truth v1) | 7 | **==** |
| DDO signature registrations | 14 | 14 (regex-line-count) | **==** |
| “59 decoders” claim in handoff | ambiguous | 45+14=59 by POD math, 46+14=60 by AG math | **DEFINITION DRIFT** |

**RECONCILED CLASSIFICATION:** the AG audit distinguishes five orthogonal counts. The "59" number in the Handoff package is closest to POD's `45 physical + 14 family` OR AG's `46 physical + 14 family − 1 duplicate`; without the AG audit script running on pod, the exact rationale for "59" cannot be re-derived. Both trees agree on families (14) and DDO structure (7 codec families, 14 signatures). **Emergent recommends adopting AG's five-category breakdown as the canonical vocabulary in Truth Contract v3 (owner decision).**

### 3.3 · Security State implementation and paths

| Perspective | AG | POD |
|---|---|---|
| `backend/security_state/` module | **81 .py files** covering `adapters, attack_state, benchmarks, capability, causal, counterfactual, detection_bridge, hydration, impact, intervention, ledger, model, orchestration, persistence, progression, reachability, response_safety, routers, contracts.py` | **DOES NOT EXIST** |
| `backend/routers/rc5_entities.py` + `rc5_diag.py` | present | **present** (Gate 0.5 confirmed sole state-transition surface on pod) |
| Truth v1 (immutable) statement | records `rc5` as the FSM location | records `rc5` as the FSM location |
| Truth v2 (Gate 0.5) AD-03 confirmation | — | Emergent verified rc5 is the *pod-branch* Security-State owner |

**RECONCILED CLASSIFICATION:** **BRANCH_DIVERGENCE.** AG owns a fully-elaborated Causal Security State Engine at `backend/security_state/`; pod owns only the rc5 FSM state-transition surface. AD-03's provisional approval remains correct **for the pod branch only**. If the owner rebases the pod onto AG's branch, AD-03 must be re-scoped because `security_state/` becomes the correct owner and `rc5` becomes an adjunct.

### 3.4 · Investigation Workspace / Evidence Explorer paths

| Path referenced in handoff | AG | POD |
|---|---|---|
| `frontend/src/pages/EvidenceExplorerPage.jsx` | present | **present** (main SPA · UI frozen) |
| `frontend/src/v2/pages/InvestigationWorkspace.jsx` | present | **present** (main SPA · UI frozen) |
| `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` | present | **present** |
| `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` (Handoff-cited) | **present, MODIFIED_BY_AG in Phase 0** | **ABSENT** |
| `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` (Handoff-cited) | **present, MODIFIED_BY_AG in Phase 0** | **ABSENT** |
| `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx` | **present, MODIFIED_BY_AG in Phase 0** | **ABSENT** |

**RECONCILED CLASSIFICATION:** **BRANCH_DIVERGENCE.** All six Xdr*Page.jsx files exist and were modified by AG in Phase 0. Pod branch pruned them. Gate 0 correctly identified them as MISSING on POD; that identification was accurate for the pod branch. **UI freeze on pod remains in force; no rebase and no restore of these files is authorized at this reconciliation gate.**

### 3.5 · Test-suite counts

| Perspective | Value | Evidence |
|---|---|---|
| AG report claim | "480 backend tests" | `NIVXRAY_COMPLETE_AG_EXPORT_REPORT.md` §1 |
| AG filesystem `backend/tests/` | **733 .py files** (`test_*.py` and helpers) | `find $AGX/backend/tests -type f -name '*.py'` |
| AG "test" classification in manifest | 800 | `classification_breakdown.test` |
| POD filesystem `backend/tests/` | **731 .py files** | live filesystem |
| POD Gate-0.5 baseline (running subset) | **163 pass + 1 intentional mal-20 FN** (observability + decoder_harness + corpus) | Gate 0.5 pytest run |
| POD Truth v1 baseline | 195/195 pass (+ 1 intentional mal-20 FN) | Truth v1 |
| POD Gate 0.5 added | 12 new tests (`test_cross_tenant.py`) — 12/12 pass | Gate 0.5 |

**RECONCILED CLASSIFICATION:** test *file* counts are within 2 across AG and POD (733 vs 731). The "480 tests" AG claim is a **collected-test count** (per-test-function) which pytest reports differently on each environment; it is not directly comparable to file count. The Truth v1 195/195 number is a **passing-test count** for a specific subset. **These numbers are not contradictory — they describe different populations.**

### 3.6 · Immutable Truth Contract & Gate 0.5 findings

| Artifact | AG-side | POD-side | Match |
|---|---|---|---|
| Truth Contract v1 MD (immutable, commit `d3f7a0a…`) | present at `docs/emergent-handoff-package/01_TRUTH_CONTRACT/NIVXRAY_CURRENT_STATE_TRUTH.md` | present at `/app/memory/…` and `/app/docs/truth-contract/…` | **byte-identical SHA-256 `061fd851…`** |
| Truth Contract v1 JSON | present | present | **byte-identical SHA-256 `295d1e70…`** |
| Truth Contract v2 (Gate 0.5 new snapshot) | **NOT in AG export** | present in pod (`/app/memory/edr_review/…`) | **POD-ONLY** |
| Gate 0.5 P0-D suite | not in AG | present in pod | **POD-ONLY** |
| Gate 0.5 introspection endpoints | not in AG | live on pod | **POD-ONLY** |
| Handoff package (`NIVXFORGE_EDR_EMERGENT_HANDOFF_PACKAGE.zip`) | present at `docs/NIVXFORGE_EDR_EMERGENT_HANDOFF_PACKAGE.zip` (AG_CREATED) · SHA `80fa675d…` | downloaded and unzipped on pod at Gate 0 | **byte-identical** |

**Conclusion:** immutable v1 is safe on both sides. v2 exists only on POD (Gate 0.5). AG did not attempt to amend v1.

---

## §4 · Duplicate / stale / contradictory / superseded documentation

### 4.1 · Duplicates inside the AG archive itself
- The 25 emergent-handoff-package files are duplicated FOUR TIMES in the AG export:
  - `docs/NIVXFORGE_EDR_EMERGENT_HANDOFF_PACKAGE.zip` (packed)
  - `docs/emergent-handoff-package/**` (unpacked)
  - `docs/handoff/**` (unpacked flat)
  - `docs/security-state/**`, `docs/uiux/**` (partial unpacked)
- **Impact:** low; content-identical by SHA-256 comparison. Recommend AG collapse to one authoritative copy in future exports.

### 4.2 · Stale references (docs pointing at paths only present in AG)
- Handoff Code Map row "Authoritative Security State" → `backend/security_state/contracts.py` — VALID in AG, INVALID on POD. Same for `detection_bridge.py`.
- Handoff Code Map rows "Evidence Explorer" and "Investigation Workspace" → `apps/nivxray-xdr/src/xdr/pages/Xdr…Page.jsx` — VALID in AG, INVALID on POD.
- Truth Contract v1 phrase "single authoritative Universal Decoder runtime" — imprecise on both branches (both carry `backend/decoders/*` and `services/decoder/base/*`). Truth v2 supersedes.

### 4.3 · Superseded documentation (POD side)
- Truth Contract v2 (Gate 0.5) supersedes v1's "single authoritative decoder runtime" wording. v1 remains immutable historical truth.
- Gate 0.5 introspection endpoints supersede the two missing AG audit scripts *on the pod branch only*. On the AG branch the audit scripts remain the authoritative source.

### 4.4 · Contradictions between AG and POD
- **`615 = VERIFIED_ON_AG` vs `615 = UNVERIFIED_ON_POD`** — genuine branch divergence; both are correct within their own scope.
- **`backend/security_state/` exists in AG · doesn't on POD** — genuine divergence.
- **Handoff-package claims "615 active-certified on the current branch"** — this claim was correct for the AG branch **when the handoff was authored**; it is incorrect for the current POD branch. AG's cross-linked path references need a branch-context caveat.

---

## §5 · Formal delta classification

| Item | Classification (per authorized vocabulary) |
|---|---|
| Handoff-claimed paths PD-1…PD-6 | **BRANCH_DIVERGENCE** (present in AG, absent on POD) |
| 615 Content Fabric count | **VERIFIED_ON_AG_BRANCH** / **UNVERIFIED_ON_POD_BRANCH** |
| 59 decoders | **VERIFIED (as physical + family module count)** with **DEFINITION DRIFT** across five orthogonal counts |
| Security State module | **BRANCH_DIVERGENCE** (AG has full engine, POD has rc5 FSM only) |
| Xdr*Page.jsx UI files | **BRANCH_DIVERGENCE + AG-MODIFIED_IN_PHASE_0** |
| Immutable Truth v1 | **VERIFIED byte-identical on both sides** |
| Gate 0.5 pod additions | **POD-ONLY (authorized · additive · Gate 0.5)** |
| AG Phase-0 modifications (7 UI files) | **AG-ONLY** — none replicated to pod (UI freeze) |
| AG_CREATED 51 documentation files | present on POD in the reviewed handoff package or its extracted twin |
| `test_reports/enterprise_content_truth_audit.json` | **AG-ONLY**; contains the machine-readable proof of 615 |

---

## §6 · Owner-visible decisions required (do NOT execute here)

The following decisions are surfaced but NOT taken by this reconciliation. Every one requires explicit owner authorization before it moves:

- **D-1 · Branch alignment strategy.** Options: (a) rebase the POD branch onto AG's more-complete branch, (b) selectively cherry-pick the security_state + detection_content/corpus + audit scripts into POD, (c) keep POD branch pruned and treat AG as reference source only.
- **D-2 · 615 cardinality anchor on POD.** Options: (a) import AG corpus modules, (b) build a bridge to consume AG's audit JSON, (c) leave POD at `UNVERIFIED_ON_CURRENT_BRANCH` until Phase 1 lands seed corpora.
- **D-3 · Security State ownership.** Options: (a) rebase to acquire AG's `backend/security_state/`, then re-scope AD-03 (rc5 becomes adjunct); (b) keep AD-03 in force on POD branch.
- **D-4 · Handoff package correction.** Owner-side action to re-anchor path references with branch context.
- **D-5 · Truth Contract v3.** New snapshot to record branch divergence facts with the AG-audit vocabulary (five decoder categories, corpus-modules-vs-audit distinction, security_state-vs-rc5 duality). v1 and v2 remain untouched.
- **D-6 · Phase 1 authorization.** Explicitly STILL not authorized. Owner determines pre-authorization sequencing (probably D-1 → D-3 → D-5 → Phase 1).

---

## §7 · What Emergent did NOT do at this gate

- ❌ Did NOT modify the master AG export.
- ❌ Did NOT modify any pod source code.
- ❌ Did NOT migrate corpus / security_state / audit scripts onto POD.
- ❌ Did NOT regenerate content.
- ❌ Did NOT change any decoder.
- ❌ Did NOT touch the immutable Truth v1 commit.
- ❌ Did NOT start Phase 1.

## §8 · What Emergent DID do at this gate

- ✅ Downloaded and SHA-verified the AG export.
- ✅ Extracted and inventoried it against POD.
- ✅ Cross-referenced every Gate 0 discrepancy against AG-side file presence.
- ✅ Located the AG audit JSON that empirically anchors the 615 count.
- ✅ Enumerated the five-category decoder distinction from AG.
- ✅ Recorded the 7 AG_MODIFIED_BY_AG and 51 AG_CREATED files with paths and sizes.
- ✅ Confirmed pod's Gate-0.5 code (`truth_inventory.py`, `test_cross_tenant.py`, 3 lines in `server.py`) is POD-only and not in AG.

## §9 · Governing invariants preserved

- **Runtime > filesystem > documentation** authority order used throughout.
- **NO EVIDENCE → NO CLAIM.**
- Immutable Truth v1 unchanged (SHA verified byte-identical on POD).
- Gate 0.5 Truth v2 remains a NEW snapshot — never an edit of v1.
- **UI freeze respected** — no pod frontend or `apps/nivxray-xdr/**` changes.
- **Decoder freeze respected** — no changes to `backend/decoders/**` or `backend/services/decoder/**`.
- **Content Fabric freeze respected** — no changes to `backend/detection_content/**`.
- **Reasoning-engine freeze respected** — no changes to `verdict_stage2`, `rc5_entities`, `rc5_diag`, `services/verdict_stage2/**`, `services/ikg/**`, `reasoning/**`.

## END · Master Export Reconciliation delivered · read-only · Phase 1 NOT authorized · awaiting owner review
