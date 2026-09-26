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
| 5 | **Policy authority & endpoint policy enforcement** (owner-assigned) | PASS · server-side lifecycle | 2026-09-26 | `tests/edr` 400 passed | `scripts/gate5_7_11_live_proof.py` — CREATED→ASSIGNED→PENDING_DELIVERY→DELIVERED→ACKNOWLEDGED→APPLIED→VERIFIED, plus OUT_OF_SYNC and FAILED, all proven on a real enrolled endpoint | Endpoint-side *enforcement* of settings is a connector capability gap, declared as `NOT_SUPPORTED_BY_CONNECTOR`, never claimed | `GATE_05_POLICY_AUTHORITY.md` |
| 6 | Retrospection (re-evaluation without rewriting provenance) | IN_PROGRESS | — | — | — | Design complete; implementation blocked on Gate 3 findings store | `GATE_06_RETROSPECTION.md` |
| 7 | **Exclusions & declared protection blind spots** (owner-assigned) | PASS · server-side enforcement proven | 2026-09-26 | `tests/edr` 400 passed | `GET /api/edr/exclusions/enforcement-proof` on real evidence: unapproved → 0 bypassed; approved → 3 bypassed / 2 findings suppressed; revoked → 0 bypassed. Both `EXCLUDED` and `NOT_EVALUATED_DUE_TO_EXCLUSION` preserved | Endpoint-side enforcement reports `EXCLUSION_NOT_SUPPORTED_BY_ENGINE` until a connector release declares the capability | `GATE_07_EXCLUSIONS.md` |
| 8 | Policies · tenant → group → policy application semantics | PASS | 2026-09-26 | see Gate 5 | precedence implemented and proven: endpoint override > group > enrolment placement > `POLICY_UNASSIGNED`. The platform default policy is now written through the SAME authority, so no second policy model exists | — | `GATE_05_POLICY_AUTHORITY.md` |
| 9 | Exclusions · verifiably affecting detection engines AND UI visibility | PASS | 2026-09-26 | see Gate 7 | the enforcement proof runs the REAL fabric with and without the gate and reports the delta; the console renders both truth axes per engine | — | `GATE_07_EXCLUSIONS.md` |
| 10 | Scale · performance · failure behaviour | IN_PROGRESS | this session | `tests/edr/test_gate10_trajectory_window_fast_paths.py` **5 passed** | trajectory first paint **8/8 reads 1.06-1.82 s** on 208,754 observations (was up to 2.6 s); warm slice 0.42 s; real SPA paint 1.26 s | p95 under concurrency not measured; legacy `/edr/device-trajectory` still 6.1 s; no failure injection | `GATE_10_SCALE_AND_PERFORMANCE.md` |
| 11 | **Estate-wide Events explorer & evidence pivots** (owner-assigned) | PASS | 2026-09-26 | `tests/edr` 400 passed | `/api/edr/events` + `/facets` + `/{raw_id}` live: keyset pagination with 0 overlap, server-side detection/activity filters, measured coverage (`NETWORK 11562 · PROCESS 887`, 5 classes NOT OBSERVED), tenantless query refused 403 | Saved searches, deep links and CSV export NOT implemented (labelled) | `GATE_11_EVENTS_EXPLORER.md` |
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


## Connector productization — 2026-09-26

The connector is now a **released product artifact** with a release
catalog, disclosed artifact identity and a deployment workflow that
generates context AROUND the release instead of rebuilding it. One
build, many devices; a release with no artifact reads
`ARTIFACT_NOT_PUBLISHED` and offers no download.
Evidence: `CONNECTOR_PRODUCTIZATION.md`.

## Documentation stream — first set PUBLISHED 2026-09-26

`/app/docs/nivxforge-edr/` — README (index + capability status), Quick
Start, User Guide, Windows Connector Deployment Guide, Policy Guide,
Exclusions Guide, Events Guide. Each documents implemented truth only;
planned guides are listed as NOT YET WRITTEN.

## Test baseline after this wave

`tests/edr` · **400 passed, 0 failed, 1 skipped**.
`scripts/gate5_7_11_live_proof.py` · **all live assertions PASSED**
(policy lifecycle, exclusion enforcement, events explorer, connector
deployment) against the preview host.
