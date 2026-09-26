# NivXForge EDR · PRODUCTION RELEASE GATES · MASTER INDEX

Owner rule (binding): a Gate becomes **PASS** only with objective
evidence. No gate is closed by assertion, by a build passing, or by a
document existing. `PRODUCTION READY` may not be declared while any
mandatory gate is `BLOCKED`, `FAILED` or `NOT_STARTED`.

Status vocabulary: `NOT_STARTED` · `IN_PROGRESS` · `BLOCKED` · `FAILED`
· `PASS` · `FROZEN`.

This index carries ONLY the row. The evidence lives in the per-gate
document. Raw machine output is preserved under `/app/test_reports/`.

| # | Gate | Status | Commit | Tests | Live proof | Blocker | Evidence |
|---|------|--------|--------|-------|-----------|---------|----------|
| 1 | Windows endpoint sensor · real host onboarding proof | BLOCKED | — | collector suite 154 passed (off-endpoint) | none | **No Windows host available in this session** (owner-only dependency). Postponed, NOT waived | `/app/memory/WINDOWS_ONBOARDING_PROOF_RUNBOOK.md` |
| 2 | Telemetry acquisition · durable delivery · endpoint event journal | IN_PROGRESS | — | `tests/edr` 360 passed | telemetry 200 → canonical → CONNECTED (preview, Linux sensor) | Endpoint-local Event Journal (retention/index/query/at-rest integrity) does not exist — `outbox.py` is a delivery outbox | `/app/memory/NIVXRAY_XDR_NIVXFORGE_EDR_WINDOWS_TELEMETRY_FORENSIC_GAP_ANALYSIS.md` |
| 3 | Detection & Prevention Fabric (deterministic + ML + behavioural) | IN_PROGRESS | this session | `tests/edr/test_gate3_fabric_contracts.py` **15 passed** | `scripts/gate3_fabric_real_evidence_proof.py` → 400 findings from real detections, read-only | Contracts frozen + bounded skeleton landed. No ML model, no correlation engine, no UI consumer yet | `GATE_03_DETECTION_PREVENTION_FABRIC.md` |
| 4 | Offline protection (local inference · local rules · journal persistence) | NOT_STARTED | — | — | — | Depends on Gate 3 contracts + Gate 2 journal | — |
| 5 | **Policy authority & endpoint policy enforcement** (owner-assigned) | NOT_STARTED | — | — | — | Requires the full chain Tenant→Group→Policy→Version→Assignment→Delivery→Acknowledgement→Effective→Verification with the nine states; today every computer honestly reads `POLICY UNASSIGNED` | — |
| 6 | Retrospection (re-evaluation without rewriting provenance) | IN_PROGRESS | — | — | — | Design complete; implementation blocked on Gate 3 findings store | `GATE_06_RETROSPECTION.md` |
| 7 | **Exclusions & declared protection blind spots** (owner-assigned) | NOT_STARTED | — | — | — | Serialised behind Gate 5 (an exclusion attaches to a policy version) and Gate 3 (it must change an engine's output). `EXCLUDED` / `NOT_EVALUATED_DUE_TO_EXCLUSION` already expressible in the fabric's Finding contract | — |
| 8 | Policies · tenant → group → policy application semantics | NOT_STARTED | — | — | — | Today every computer reads `POLICY UNASSIGNED` / `GROUP UNASSIGNED`; that is honest, not implemented | — |
| 9 | Exclusions · verifiably affecting detection engines AND UI visibility | NOT_STARTED | — | — | — | No exclusion model exists | — |
| 10 | Scale · performance · failure behaviour | IN_PROGRESS | this session | `tests/edr/test_gate10_trajectory_window_fast_paths.py` **5 passed** | trajectory first paint **8/8 reads 1.06-1.82 s** on 208,754 observations (was up to 2.6 s); warm slice 0.42 s; real SPA paint 1.26 s | p95 under concurrency not measured; legacy `/edr/device-trajectory` still 6.1 s; no failure injection | `GATE_10_SCALE_AND_PERFORMANCE.md` |
| 11 | **Estate-wide Events explorer & evidence pivots** (owner-assigned) | NOT_STARTED | — | — | — | No estate-wide event query API or cursor contract exists; `/edr/events` is declared NOT_IMPLEMENTED. Independent of the enforcement authorities, so it can run in parallel | — |
| 12 | UI/UX release quality (incl. two-theme correctness) | PASS_DESKTOP / RESPONSIVE_VALIDATION_PENDING | this session | `scripts/nvf_contrast_audit.py` 0 failures (both themes) · `scripts/nx_contrast_audit.py` 0 failures · production build PASS | 10 real-SPA captures, light AND dark, on the preview host | — | `GATE_12_UI_UX_TWO_THEME.md` |
| 13 | Production operations & reliability | NOT_STARTED | — | — | — | — | — |
| 14 | Security · RBAC · tenant isolation gates | IN_PROGRESS | — | `test_edr_route_tenant_authority.py` 169 passed · security gates 227 passed in one serial process | S1 live authz matrix 66 PASS · P0 response-execution isolation 21 PASS | Carried: 13 stale live-contract test defects (below) | `/app/memory/S1_INCIDENT_SUBRESOURCE_AUTHZ.md`, `/app/memory/P0_RESPONSE_EXECUTION_TENANT_ISOLATION.md` |
| 15 | Backup · recovery · restore equivalence | NOT_STARTED | — | — | — | — | — |

Gates 5, 7 and 11 were **assigned by the owner** (2026-06) and are no
longer a blocker. Two further gates were added by the owner's
architecture locks:

| # | Gate | Status | Tests | Blocker | Evidence |
|---|------|--------|-------|---------|----------|
| 16 | **NivXForge EDR independence** (own product, own origin, no XDR UI dependency) | IN_PROGRESS · gate live | `test_gate16_edr_independence.py` **5 passed** | The owner's acceptance walk cannot pass until Events/Files/Hunt/Live Query/Forensics/Policies/Exclusions/Outbreak/Audit EXIST — independence ≠ completeness | `GATE_16_EDR_INDEPENDENCE.md` |
| 17 | **Vendor-neutral Detection Source architecture** (NivXForge is one source among CrowdStrike/Defender/SentinelOne/Cortex) | DESIGN FROZEN | — | Serialised with Gates 3 and 6 (shared evidence semantics) | `GATE_17_DETECTION_SOURCE_ARCHITECTURE.md` |

Gate 12 is recorded per the owner's instruction as
**PASS_DESKTOP / RESPONSIVE_VALIDATION_PENDING**, and every newly
implemented surface inherits the same two-theme release requirement —
new pages are not exempt because Gate 12 passed.

## Test baseline — **RESOLVED**

`tests/edr` · **400 passed, 0 failed, 1 skipped** (session start: 347
passed / 24 failed). Every failure was classified and then actually
resolved — see `GATE_14_TEST_INTEGRITY_A1.md` and
`GATE_18_TEST_BASELINE_CLASSIFICATION.md`.

## Closed this session

* **A1 · Campaign Story + Process Tree test regression — CLOSED.**
  `GATE_14_TEST_INTEGRITY_A1.md`.
* **A2 · Light/Dark applied across the whole EDR console — CLOSED.**
  `GATE_12_UI_UX_TWO_THEME.md`.
