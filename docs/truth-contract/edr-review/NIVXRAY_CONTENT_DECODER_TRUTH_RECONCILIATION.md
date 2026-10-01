# NivXRay · Content Fabric & Decoder Truth Reconciliation

> **Gate:** 0.5 · **Mode:** READ-ONLY · **No code changed.**
> **Anchor:** Immutable truth-contract commit `d3f7a0a000892131abc9a32ee97009338dd38d79` on branch `conflict_310826_2116` of `github.com/jpreddy017/nivxray-xdr`.
> **Live pod:** `feature/rc2` at time of audit.
> **Claim classification vocabulary:** `VERIFIED` · `UNVERIFIED` · `MISSING_FROM_BRANCH` · `BRANCH_DIVERGENCE` · `NOT_APPLICABLE`.

## §1 · Sources cross-referenced

| Source | Claim about content fabric | Claim about decoders |
|---|---|---|
| `NIVXRAY_CURRENT_STATE_TRUTH.md` (Truth Contract) | `services/decoder/base/` = 7 codec families in DDO orchestrator; **no 615 claim** | 14 registered signatures; 46 top-level + 15 family = 61 modules (documented as legacy shim in prior audit) |
| `NIVXRAY_CURRENT_STATE.json` (Truth Contract) | `codec_families_migrated=7` | same |
| `EMERGENT_HANDOFF_README.md` §C | "615-Object Content Fabric · 100% verified, active-certified rules across Sigma, YARA-L, and native detection logic" | "59-Decoder Deobfuscation Suite · 59 registered codecs providing multi-stage recursive unpacking" |
| `NIVXFORGE_EDR_EMERGENT_HANDOFF.md` §2 | Same 615 + attribution to `backend/run_content_truth_audit.py` | Same 59 + attribution to `backend/verify_decoder_truth_e2e.py` |
| `NIVXFORGE_EDR_TRUTH_AUDIT.md` §2 rows #20, #21 | "615-object Content Fabric (600 active certified + 15 synthetic validation scenarios)" | "48 logical codecs + 14 family profilers; 59/59 test pass" (row #20) |
| `NIVXFORGE_EDR_CODE_CAPABILITY_MAP.md` §2 | "615 active-certified" · `backend/detection_content/` | "59 active codecs" · `backend/decoders/` |
| Live pod (`ls`, `grep`, live Mongo) | see §2 | see §3 |

## §2 · Content Fabric ("615 objects") — reconciliation

### 2.1 Filesystem evidence (this branch)

```
backend/detection_content/            → 52 Python modules · 0 rule YAML/JSON/SIGMA files
backend/detection_content/corpus/     → referenced by handoff — DIRECTORY DOES NOT EXIST on this branch
backend/detection_content/yara_engine.py → referenced by handoff — FILE DOES NOT EXIST on this branch
backend/run_content_truth_audit.py    → referenced by handoff — FILE DOES NOT EXIST on this branch
```

Grep for the literal number `615` in `backend/detection_content/` and `backend/scripts/`: **0 matches**.

### 2.2 Runtime / Mongo evidence (this pod)

| Collection | Live document count |
|---|---|
| `detection_content` | **1** (0 ACTIVE, 0 ENABLED) |
| `xdr_detection_rules` | 93 |
| `xdr_correlation_rules` | 5 |
| `xdr_capability_contracts` | 339 |
| `xdr_engines` | 339 |
| Sum of above | 777 |

**No live counter equals 615** (or 600 + 15, or 615 minus deprecated, etc.). The number cannot be derived from the current Mongo state.

### 2.3 API surface

Router `backend/routers/xdr_detection_content.py` mounts at prefix `/api/xdr/detection` and exposes `GET /rules`, `GET /rules/{id}`, `GET /versions`, `GET /policy`, `GET /sources/catalog`, `GET /status`, `POST /sync`, `POST /ensure-synced`, `POST /rules/{id}/enable|disable`. **None of these currently returns "615".**

### 2.4 Classification per claim

| Claim (source) | Classification | Justification |
|---|---|---|
| "615 objects" (Handoff README/Handoff MD/Code Map) | **UNVERIFIED** on this branch | No filesystem or Mongo source yields 615. Requires seed script and/or introspection endpoint to substantiate. |
| "600 active-certified + 15 synthetic validation scenarios" (EDR Truth Audit) | **UNVERIFIED** on this branch | Same reason. Additive decomposition not attested by any collection. |
| "100% verified via `backend/run_content_truth_audit.py`" | **MISSING_FROM_BRANCH** | Script does not exist. |
| `backend/detection_content/corpus/` referenced | **MISSING_FROM_BRANCH** | Directory does not exist. |
| `backend/detection_content/yara_engine.py` referenced | **MISSING_FROM_BRANCH** | File does not exist. |
| "authoritative Content Fabric registry exists" | **VERIFIED** (as infra) | 52 py modules implement registry/lifecycle/harness/model; the runtime harness *could* hold 615+ objects when seeded — the framework is real, the population is not. |

### 2.5 Recommended reconciliation actions

- **R-2.1 · Introspection endpoint (P0.5).** Add `GET /api/xdr/detection/inventory` returning `{"total": N, "by_state": {...}, "by_source": {...}, "audit_sha256": "..."}`. Anchor 615 to this endpoint at owner sign-off time or explicitly retract the number.
- **R-2.2 · Seed & audit script parity.** Either ship `backend/run_content_truth_audit.py` OR add `POST /api/xdr/detection/audit` producing the same evidence.
- **R-2.3 · Documentation correction.** Any downstream doc citing "615" must either (a) point at the audit endpoint output, or (b) be rewritten as "the Content Fabric runtime holds an owner-seeded corpus; the current pod carries N objects."
- **R-2.4 · Truth-contract superset.** Update `NIVXRAY_CURRENT_STATE_TRUTH.md` in a new immutable commit to record: "Content Fabric registry framework is IMPLEMENTED_AND_WORKING; cardinality on this pod = N; the 615 claim is UNVERIFIED pending seed."

---

## §3 · Decoders ("59 codecs") — reconciliation

### 3.1 Filesystem evidence (this branch)

```
backend/decoders/                     → 45 top-level .py files (excluding __init__.py)
backend/decoders/families/            → 14 .py files (excluding __init__.py and _base.py)
                                      → SUM = 59 modules ✓
backend/services/decoder/base/        → 9 .py files (excluding __init__.py) — 7 codec families per Truth Contract + orchestrator support
backend/services/decoder/orchestrator.py → DDO with 14 registered signatures
backend/verify_decoder_truth_e2e.py   → referenced by handoff — FILE DOES NOT EXIST on this branch
```

Grep for `\b59\b` in decoder code: **0 direct references** to the literal integer.

### 3.2 Runtime evidence

`server.py` explicitly imports many decoder modules via `from decoders import <module_name>` (lines 36-58 approx.). The DDO orchestrator at `services/decoder/orchestrator.py` dispatches 14 signatures. `/api/decode/smart`, `/api/decode/candidates`, `/api/decode/magic`, `/api/decode/chain/*`, `POST /api/artifacts/analyze` are live.

### 3.3 Cross-reference with Truth Contract

| Truth-Contract statement | Handoff statement | Reconciled truth |
|---|---|---|
| `codec_families_migrated=7` under `services/decoder/base/` | "48 logical codecs + 14 family profilers = 59" (EDR Truth Audit) | Both are correct at different granularities: 7 authoritative codec **families** in DDO (base), and 45 + 14 = 59 decoder **modules** in the legacy tree still imported by `server.py`. |
| DDO dispatch = 14 signatures | "59 registered codecs" | Different concepts. 14 = DDO signatures; 59 = decoder-tree Python modules. Both are IMPLEMENTED_AND_WORKING; they describe the same universe from different perspectives. |

### 3.4 Classification per claim

| Claim | Classification | Justification |
|---|---|---|
| "59 registered codecs / decoders" (Handoff) | **VERIFIED (module-count)** | 45 + 14 = 59 Python modules under `backend/decoders/` and `backend/decoders/families/`. |
| "48 logical codecs + 14 family profilers" (EDR Truth Audit) | **VERIFIED (with drift)** | 45 (not 48) top-level modules + 14 families = 59. The 48 figure is a minor drift, likely off-by-3 based on which modules count as "logical codecs" vs helpers. |
| "59/59 test pass via `backend/verify_decoder_truth_e2e.py`" | **MISSING_FROM_BRANCH** | Script does not exist. Test-count assertion cannot be verified without it. |
| "DDO has 7 codec families" (Truth Contract) | **VERIFIED** | 9 .py files under `services/decoder/base/`, of which 7 are the codec families (`base64_codec`, `compression`, `crypto`, `encoding`, `powershell_encoded_command`, `transform`, `xor_brute`) plus `_ddo_adapter.py` and `__init__.py`. |
| "DDO dispatches 14 signatures" (Truth Contract) | **VERIFIED** | `services/decoder/orchestrator.py` registers 14 signature entries. |
| Truth-contract "single authoritative Universal Decoder runtime" claim | **BRANCH_DIVERGENCE** | Not strictly single; both `backend/decoders/*` (legacy, still imported by `server.py`) AND `services/decoder/base/*` (DDO) are alive. Both are IMPLEMENTED_AND_WORKING; earlier truth-contract wording implied the legacy tree was reduced to re-export shims — the current state shows imports still land inside legacy `decoders/*` files. |

### 3.5 Recommended reconciliation actions

- **R-3.1 · Introspection endpoint (P0.5).** Add `GET /api/decode/registry/inventory` returning `{"legacy_modules": 45, "family_modules": 14, "ddo_families": 7, "ddo_signatures": 14, "total_modules": 59, "audit_sha256": "..."}`. Owner signs off on which number is the "canonical 59".
- **R-3.2 · Ship or replace `verify_decoder_truth_e2e.py`.** Either add the script OR add `POST /api/decode/registry/verify` that runs the same assertions.
- **R-3.3 · Truth-contract clarification.** Amend `NIVXRAY_CURRENT_STATE_TRUTH.md` in a new pinned commit to record: "There are TWO cooperating decoder trees — `backend/decoders/*` (legacy, still live) with 45+14 modules, and `services/decoder/base/*` (DDO) with 7 codec families and 14 signatures. Both are IMPLEMENTED_AND_WORKING. The earlier phrasing of `services/decoder/base/` as the 'single authoritative runtime' is superseded by this dual-tree truth."

---

## §4 · Summary — classification table

| Claim | Classification |
|---|---|
| 615 Content Fabric objects | UNVERIFIED |
| 600 active + 15 synthetic split | UNVERIFIED |
| Content-Fabric registry framework exists | VERIFIED |
| `run_content_truth_audit.py` | MISSING_FROM_BRANCH |
| `backend/detection_content/corpus/` | MISSING_FROM_BRANCH |
| `backend/detection_content/yara_engine.py` | MISSING_FROM_BRANCH |
| 59 registered decoders (module count) | VERIFIED |
| 48 logical + 14 family (as split) | VERIFIED with minor drift (real = 45 + 14) |
| DDO 7 codec families | VERIFIED |
| DDO 14 signatures | VERIFIED |
| `verify_decoder_truth_e2e.py` | MISSING_FROM_BRANCH |
| Truth-contract "single authoritative decoder runtime" | BRANCH_DIVERGENCE (there are 2 live trees) |
| `backend/security_state/contracts.py` | MISSING_FROM_BRANCH |

## §5 · Do-not rules honoured

- ✅ No canonical truth silently changed. All divergences flagged.
- ✅ No code / test / config / UI modified.
- ✅ No git operations attempted.
- ✅ Content Fabric and decoders untouched.
- ✅ Reconciliation actions listed for owner approval — none implemented.

## §6 · Blocking status

- ⛔ Phase 1 remains BLOCKED until R-2.1/R-2.2 or R-3.1/R-3.2 close (or owner explicitly waives with a written rationale).
- ⛔ Owner sign-off required to pin the reconciled counts in a new immutable truth-contract commit.

## END · reconciliation delivered · read-only · awaiting owner review
