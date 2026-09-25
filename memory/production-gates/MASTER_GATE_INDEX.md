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
| 5 | *(title not present in the available record)* | NOT_STARTED | — | — | — | **Owner to restate the verbatim gate title** — it is not quoted in any file in this workspace and will not be invented | — |
| 6 | Retrospection (re-evaluation without rewriting provenance) | IN_PROGRESS | — | — | — | Design complete; implementation blocked on Gate 3 findings store | `GATE_06_RETROSPECTION.md` |
| 7 | *(title not present in the available record)* | NOT_STARTED | — | — | — | **Owner to restate the verbatim gate title** | — |
| 8 | Policies · tenant → group → policy application semantics | NOT_STARTED | — | — | — | Today every computer reads `POLICY UNASSIGNED` / `GROUP UNASSIGNED`; that is honest, not implemented | — |
| 9 | Exclusions · verifiably affecting detection engines AND UI visibility | NOT_STARTED | — | — | — | No exclusion model exists | — |
| 10 | Scale · performance · failure behaviour | IN_PROGRESS | this session | `tests/edr/test_gate10_trajectory_window_fast_paths.py` **5 passed** | trajectory first paint **8/8 reads 1.06-1.82 s** on 208,754 observations (was up to 2.6 s); warm slice 0.42 s; real SPA paint 1.26 s | p95 under concurrency not measured; legacy `/edr/device-trajectory` still 6.1 s; no failure injection | `GATE_10_SCALE_AND_PERFORMANCE.md` |
| 11 | *(title not present in the available record)* | NOT_STARTED | — | — | — | **Owner to restate the verbatim gate title** | — |
| 12 | UI/UX release quality (incl. two-theme correctness) | PASS | this session | `scripts/nvf_contrast_audit.py` 0 failures (both themes) · `scripts/nx_contrast_audit.py` 0 failures · production build PASS | 10 real-SPA captures, light AND dark, on the preview host | — | `GATE_12_UI_UX_TWO_THEME.md` |
| 13 | Production operations & reliability | NOT_STARTED | — | — | — | — | — |
| 14 | Security · RBAC · tenant isolation gates | IN_PROGRESS | — | `test_edr_route_tenant_authority.py` 169 passed · security gates 227 passed in one serial process | S1 live authz matrix 66 PASS · P0 response-execution isolation 21 PASS | Carried: 13 stale live-contract test defects (below) | `/app/memory/S1_INCIDENT_SUBRESOURCE_AUTHZ.md`, `/app/memory/P0_RESPONSE_EXECUTION_TENANT_ISOLATION.md` |
| 15 | Backup · recovery · restore equivalence | NOT_STARTED | — | — | — | — | — |

Gates 5, 7 and 11 are deliberately left unnamed. The 15-gate directive
was issued in a chat message that is not part of this workspace, and
three of its titles are not quoted in any file here. Inventing them
would be exactly the failure mode the product forbids. **Owner: restate
those three titles and they will be filled in and executed.**

## Carried test debt (measured, not hidden)

`tests/edr` · **380 passed, 13 failed, 1 skipped** (baseline before this
session: 347 passed / 24 failed). All remaining failures are
`TEST_DEFECT_STALE` in *live-contract* suites, proven unrelated to this
session's changes (they assert hard-coded counts and pre-D15 refusal
shapes):

* `test_p1_10_live_contract.py` — 6 failures, e.g.
  `assert counts.get("implemented") == 5` while the protocol catalog now
  legitimately reports **6** implemented protocols.
* `test_p0_a2_adversarial_live.py` — 4-6 failures (live edge / admin-route
  expectations written before the current refusal envelope).
* `test_cross_tenant.py::test_v11_body_tenant_id_never_trusted` — asserts
  the body echoes the poisoned tenant or 422, while the platform now
  refuses earlier with `ACCESS_DENIED · unauthenticated` (a *stronger*
  outcome than the test was written for).

**Environment, not product:** in ONE full-directory run
`test_p0_f7_live_api.py` errored 9 times and **passed 14/14 when run
alone**; a later full run produced no errors at all. Its module-scoped
fixture logs in to the preview edge, and the edge throttles concurrent
login bursts (429) when several live suites start at once — already
recorded in the PRD. A live-suite concurrency artefact, not a regression.

They are recorded here so they are never reported as green and never
mistaken for the two defects closed this session.

## Closed this session

* **A1 · Campaign Story + Process Tree test regression — CLOSED.**
  `GATE_14_TEST_INTEGRITY_A1.md`.
* **A2 · Light/Dark applied across the whole EDR console — CLOSED.**
  `GATE_12_UI_UX_TWO_THEME.md`.
