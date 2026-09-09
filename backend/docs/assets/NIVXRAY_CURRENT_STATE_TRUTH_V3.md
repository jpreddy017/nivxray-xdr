# NivXRay · Current-State Truth Contract v3 (New Snapshot · Post-Master-Reconciliation)

> **This is a NEW artifact.** v1 (`d3f7a0a000892131abc9a32ee97009338dd38d79`) and v2 (`NIVXRAY_CURRENT_STATE_TRUTH_V2.md`) are PRESERVED unchanged and remain immutable historical anchors.
> **Purpose of v3:** record the two-branch reality established by the AG master export vs. the current Emergent pod, adopt the AG-audit five-category decoder vocabulary, register branch-divergence facts, and preserve v1 + v2 without amendment.
> **Governing rule:** documentation is NEVER implementation truth. Filesystem/source/runtime evidence takes precedence. AG-side and POD-side counts are recorded separately.

---

## §1 · Provenance chain

| Snapshot | Location | Status | Purpose |
|---|---|---|---|
| Truth v1 (immutable) | commit `d3f7a0a000892131abc9a32ee97009338dd38d79` in `docs/truth-contract/` | **FROZEN — DO NOT MODIFY** | historical baseline (pre-EDR-handoff pod) |
| Truth v2 (Gate 0.5 · new snapshot) | `docs/truth-contract/edr-review/NIVXRAY_CURRENT_STATE_TRUTH_V2.md` | **FROZEN — DO NOT MODIFY** | post-Gate-0.5 pod-branch superset |
| **Truth v3 (this file · new snapshot)** | `docs/truth-contract/edr-review/NIVXRAY_CURRENT_STATE_TRUTH_V3.md` after Save-to-Github | LIVE for the branch-alignment gate | records AG-vs-POD branch divergence, five-category decoder vocabulary, D-1…D-5 outcomes |

v3 does NOT amend, mutate, or replace v1 or v2. It layers new facts on top.

---

## §2 · Two-branch reality (authoritative)

- **AG-branch source of truth:** `NIVXRAY_COMPLETE_AG_EXPORT.zip` (SHA-256 `ba06f99d38e002b06949951f6e6749d40fa8e844efcd7470ae6e9697338aaa1f`, 4,675 source files). Contains a **fuller** NivXRay baseline than POD.
- **POD-branch source of truth:** live `feature/rc2` at post-Gate-0.5 state. Contains Gate 0.5 additions that AG does NOT have.
- **Divergence surface:** 44 conflict files + 358 AG-only files + 59 POD-only files (evidence in `NIVXRAY_BRANCH_ALIGNMENT_ANALYSIS.md` + `alignment_index.json`).
- **Shared safe backbone:** 3,952 byte-identical files.

**Authoritative source precedence (per owner D-3 + reconciliation §5):**
1. When AG and POD conflict on a *reasoning / engine / detection-content* file → AG is authoritative.
2. When AG and POD conflict on a *decoder-tree* file → freeze rule; owner reviews per file.
3. When AG and POD conflict on a *UI / frontend* file → AG is authoritative if AG_MODIFIED_BY_AG in Phase 0, otherwise POD retains.
4. When POD carries an *authorized Gate 0.5 addition* (truth-inventory router, P0-D tests, `+3` lines in `server.py`) → POD is authoritative and MUST be preserved.
5. Runtime + code evidence remains authoritative over documentation.

---

## §3 · 615 Content Fabric — canonical status per owner D-2

- **AG side (VERIFIED):** `test_reports/enterprise_content_truth_audit.json` (1,358,417 B) records `corpus_inventory.total_objects = 615` (615 unique · 0 exact dupes · 0 normalized dupes · 63 semantic dupes · 446 cross-language equivalents · 16 domains). Produced by `backend/run_content_truth_audit.py` scanning `backend/detection_content/corpus/` (11 corpus modules: adversarial, behavioral_correlation, eql, hunting_anomaly, ioc_threat_intel, mapping_response, ot_ics_rmm, sigma, spl_kql, yara).
- **POD side (UNVERIFIED_ON_CURRENT_BRANCH):** `backend/detection_content/corpus/` does not exist on POD; audit script does not exist on POD; live introspection endpoint `GET /api/xdr/detection/inventory` reports `content_fabric_cardinality_claim_615 = UNVERIFIED_ON_CURRENT_BRANCH` (see Gate 0.5 truth_inventory.py).
- **Canonical claim after alignment (per D-2):** the 615 IS the correct project-level cardinality once the AG corpus is restored/integrated. Until integration lands, POD's introspection endpoint MUST continue reporting `UNVERIFIED_ON_CURRENT_BRANCH`. **No regeneration, no synthetic recreation.** Import the AG modules verbatim and re-verify via the AG audit script.

---

## §4 · Decoder five-category vocabulary (adopted per owner D-5)

| Category | Definition | AG value | POD value |
|---|---|---:|---:|
| Registered codecs (runtime registry cardinality) | count of codecs registered at runtime | **61** | (not measurable without registry-scanning script) |
| Logical codecs (coverage matrix) | count in the documented coverage matrix | **48** | 48 (per handoff doc) |
| Physical codecs (`backend/decoders/*.py`) | filesystem-observed decoder modules at top level | **46** | **45** (AG +1) |
| Operational codecs (operations dict) | codecs wired into the runtime dispatch dict | **42** | (not measurable) |
| Malware-family signature profilers (`backend/decoders/families/*.py`) | family-level YARA/regex profilers | **14** | **14** |
| DDO codec families (`backend/services/decoder/base/*.py`) | DDO Plane-A families (per Truth v1) | 7 | 7 |
| DDO signature registrations (`services/decoder/orchestrator.py`) | dispatched signatures | 14 | 14 |

**Do-not-collapse rule:** these are seven orthogonal counts. **Do not** produce a single "N decoders" number without stating which category is meant.

**Legacy "59" reconciliation:** the "59 decoders" figure in the Handoff package is closest to POD's `physical (45) + malware-family (14) = 59` OR AG's `physical (46) + malware-family (14) − 1 collision = 59`. Both derivations are valid; the number is a *composite*, not a single-category count. Prefer the five-category vocabulary above.

---

## §5 · Security-State module — canonical status per owner D-3

- **AG side (AUTHORITATIVE per D-3):** `backend/security_state/` — 81 Python files covering `contracts.py`, `detection_bridge.py`, `adapters/`, `attack_state/`, `benchmarks/`, `capability/`, `causal/`, `counterfactual/`, `hydration/`, `impact/`, `intervention/`, `ledger/`, `model/`, `orchestration/`, `persistence/`, `progression/`, `reachability/`, `response_safety/`, `routers/`. **This is the complete Causal Security State Engine.**
- **POD side:** `backend/security_state/` does not exist. Only `backend/routers/rc5_entities.py` + `rc5_diag.py` exist (FSM transition surface).
- **Canonical claim after alignment (per D-3):** `backend/security_state/` IS the authoritative implementation. `rc5_entities.py` is NOT equivalent and MUST NOT replace it. During controlled integration, `security_state/` becomes primary; `rc5` becomes an adjunct surface (or is retired if the alignment analysis reveals full functional overlap).
- **AD-03 re-scoped:** the Gate 0.5 provisional approval of "reuse rc5_entities.py" was correct for the pod-branch scope but is REPLACED by D-3 in the project-level scope. AD-03 is now: "on the aligned branch, `backend/security_state/` owns the FSM; rc5 becomes adjunct."

---

## §6 · Investigation Workspace / Evidence Explorer paths

| Path | AG | POD |
|---|---|---|
| Main-SPA `frontend/src/pages/EvidenceExplorerPage.jsx` | present | **present** |
| Main-SPA `frontend/src/v2/pages/InvestigationWorkspace.jsx` | present | **present** |
| Companion-SPA `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | **present · MODIFIED_BY_AG in Phase 0** | absent |
| Companion-SPA `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | **present · MODIFIED_BY_AG in Phase 0** | absent |
| Companion-SPA `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx` | **present · MODIFIED_BY_AG in Phase 0** | absent |

Canonical claim: after alignment, the AG-modified companion-SPA files are restored. UI freeze on POD remains until owner lifts.

---

## §7 · Handoff-package status per owner D-4

- The `NIVXFORGE_EDR_EMERGENT_HANDOFF_PACKAGE.zip` (25 files) is **branch-context-specific** — its path references are correct against the AG branch, not against the pruned POD branch. It remains a valid reference document but MUST be read with the branch caveat.
- **The complete AG export supersedes it** as the broader project reference package for reconciliation and Phase-1 planning.

---

## §8 · Path-drift resolution matrix (six original Gate 0 discrepancies)

| ID | Handoff-claimed path | Reality on AG | Reality on POD | v3 canonical resolution |
|---|---|---|---|---|
| PD-1 | `backend/security_state/contracts.py` | **PRESENT** | absent | **AUTHORITATIVE on AG** — restore during alignment |
| PD-2 | `backend/security_state/detection_bridge.py` | **PRESENT** | absent | **AUTHORITATIVE on AG** — restore during alignment |
| PD-3 | `backend/run_content_truth_audit.py` | **PRESENT** | absent | **AUTHORITATIVE on AG** — restore verbatim (do not regenerate) |
| PD-4 | `backend/verify_decoder_truth_e2e.py` | **PRESENT** | absent | **AUTHORITATIVE on AG** — restore verbatim |
| PD-5 | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | **PRESENT (AG-modified)** | absent | **AUTHORITATIVE on AG** — restore during alignment (UI-freeze lift required) |
| PD-6 | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | **PRESENT (AG-modified)** | absent | **AUTHORITATIVE on AG** — restore during alignment (UI-freeze lift required) |

Note: the Gate 0.5 truth-inventory endpoints on POD REMAIN valuable *after* alignment as live-truth introspection — they do not become obsolete when the audit scripts land.

---

## §9 · What v3 records (delta over v1 + v2)

| Fact | v1 stated | v2 stated | v3 statement |
|---|---|---|---|
| Single vs dual decoder tree | "single authoritative Universal Decoder runtime" | "dual cooperating trees on POD" | "five orthogonal counts (registered · logical · physical · operational · malware-family) + DDO family/signature separately" |
| 615 Content Fabric | not named | `UNVERIFIED_ON_CURRENT_BRANCH` on POD | `VERIFIED_ON_AG` + `UNVERIFIED_ON_POD_UNTIL_ALIGNMENT` |
| Security-State | rc5 | rc5 (pod-branch confirmation) | `backend/security_state/` (project-level authoritative per D-3) |
| Handoff path drift | not addressed | 6 items flagged as pod-missing | 6 items resolved as AG-authoritative (restore during alignment) |
| Branch model | single branch assumed | pod-only | two-branch reality (AG-complete · POD-pruned) |

---

## §10 · Alignment / integration status

- **Alignment analysis produced:** `NIVXRAY_BRANCH_ALIGNMENT_ANALYSIS.md` + `alignment_index.json` (SHA-verified inventory of 44 conflicts, 358 AG-only, 59 POD-only files).
- **Integration NOT started.** No copy, no merge, no rebase.
- **Preservation:**
  - Immutable v1 SHA-256 verified byte-identical on POD (`061fd851…` MD, `295d1e70…` JSON).
  - v2 preserved.
  - Gate 0.5 code (truth-inventory router, P0-D suite, `+3` lines in `server.py`) present on POD and enumerated for post-alignment replay.
  - AG export SHA-256 `ba06f99d…aa1f` unchanged.

---

## §11 · Governing invariants preserved

- v1 unchanged. v2 unchanged. AG export unchanged.
- No destructive Git ops.
- No content regeneration.
- No decoder changes.
- No UI changes.
- No Phase 1 implementation.
- Runtime + code evidence remains authoritative over documentation.
- **NO EVIDENCE → NO CLAIM.**

---

## §12 · What v3 does NOT do

- v3 does NOT modify v1 or v2.
- v3 does NOT authorize Phase 1.
- v3 does NOT authorize any destructive operation.
- v3 does NOT execute the branch alignment.
- v3 does NOT declare the 615 as `VERIFIED_ON_POD` — that classification changes only after AG corpus is integrated and independently re-verified.
- v3 does NOT retire the rc5 module — that decision requires owner authorization following full alignment.

## END · Truth Contract v3 delivered · read-only · awaiting owner review + branch-alignment authorization
