# PR-2 · Architecture Compliance

**Blueprint version referenced**: v1.1
**User Journey version referenced**: v1.0
**Validation Matrix version referenced**: v1.0
**ARB Governance table** (new — enforced per ARB PR-1 amendment)
**Date**: 2026-08-04

---

## Governance Table

| Blueprint Sections | Journey Sections | Validation Matrix | Tests | Regression | Risk | Rollback |
|---|---|---|---|---|---|---|
| §7 Layered Arch (L1 layer) · §8.1 State Machine · §8.3 Workspace State · §8.4 Evidence Nav · §10 Data Contract | J1 · J2 · J3 · J4 · J5 (all read paths hydrate via new bundle endpoint) | §1 Workflow Matrix (all cells reachable via API) · §2 Cross-Feature Navigation (evidence anchors preserved in bundle payload) | 26 new API tests + 78 existing L2 unit tests + full L0 baseline | ✅ DCS 17/17 · R1 107/107 · L0 canonical 299 passed · `tests/investigation/` 491 passed | Cases require auth (JWT) and are owner-scoped (SEC-003 pattern). Illegal state transitions rejected 409. No production data touched — new collection only. | Router registration is a single `include_router` line at the bottom of `server.py`. Rollback = remove that block + drop `investigation_cases` collection. No schema migration, no shared state. |

---

## Sections implemented

| Blueprint section | How this PR satisfies it |
|---|---|
| §7 Layered Architecture — L1 Evidence Services | New package `backend/l1_evidence/` (persistence only). L2 reads from L1 via `EvidenceBundle`. |
| §8.1 State Model | `POST /api/investigation/{case_id}/state/transition` validates via `InvestigationStateMachine`, appends to persisted audit log. |
| §8.3 Persistence Requirements | `GET /workspace` and idempotent `PUT /workspace` on `WorkspaceState`. Two returns → byte-identical fingerprint (tested). |
| §8.4 Evidence Navigation Contract | Bundle payload preserves every provenance field (source_iteration, source_span, via_capability, source_iterations). |
| §10 Data Contract | 11 endpoints exposed under `/api/investigation/*`, matching Blueprint §10 verbatim. |

## Endpoints delivered

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/investigation` | Create case from EvidenceBundle payload |
| `GET`  | `/api/investigation` | List cases (owner-scoped) |
| `GET`  | `/api/investigation/{case_id}` | Full `workspace_bundle` (single-call hydration) |
| `GET`  | `/api/investigation/{case_id}/workspace` | Read Workspace State (§8.3) |
| `PUT`  | `/api/investigation/{case_id}/workspace` | Persist Workspace State (idempotent) |
| `POST` | `/api/investigation/{case_id}/state/transition` | Advance state machine (§8.1) |
| `GET`  | `/api/investigation/{case_id}/state` | Current state + history + allowed states |
| `GET`  | `/api/investigation/{case_id}/summary` | Executive Summary L2 service |
| `GET`  | `/api/investigation/{case_id}/story` | Attack Story L2 service |
| `GET`  | `/api/investigation/{case_id}/iocs` | IOC Intelligence L2 service |
| `GET`  | `/api/investigation/{case_id}/capabilities` | Capability Explorer L2 service |
| `GET`  | `/api/investigation/{case_id}/threat` | Threat Assessment L2 service |
| `GET`  | `/api/investigation/{case_id}/detections` | Detection Rules L2 service (P0 #3) |
| `GET`  | `/api/investigation/{case_id}/hunting` | Hunting Queries L2 service |
| `DELETE` | `/api/investigation/{case_id}` | Delete case (owner-scoped) |

## User Journeys supported

| Journey | Endpoint mapping |
|---|---|
| J1 Tier-1 Triage | `GET /summary` + `GET /iocs` (fast path) |
| J2 Standard Investigation | `GET /{case_id}` (single hydrate) → all lenses |
| J3 Deep Investigation | `GET /{case_id}` + `GET /detections` + `GET /hunting` |
| J4 Executive Report | `GET /summary` + `GET /story` (report generator will consume in PR-6) |
| J5 Reopen & Iterate | `POST /state/transition` `reported → reopened → correlating` (loop verified) |

## Principles preserved

- **P1 Investigation First**: `/api/investigation/{case_id}` returns the whole investigation in one call.
- **P2 Evidence First**: bundle preserves provenance fields verbatim.
- **P5 Single Workspace**: one route family `/api/investigation/*`, one shape.
- **P7 Zero Duplicate Workflows**: distinct from legacy `/api/investigations/*` plural router (which serves a different, older concept).
- **P9 Everything Explainable**: every state transition audit-logged with actor and reason.
- **P10 Deterministic Investigation First**: fingerprint tested identical on repeated GETs.

## L0 impact

**ZERO**. `backend/workspace/convergence/*` untouched. `frozen contract preserved`.

## What this PR does NOT do

- No UI (that is PR-3+).
- No L0 → EvidenceBundle bridge (that is a dedicated bridge landing with PR-3 input surface).
- No content generation beyond the scaffolds in PR-1 (PR-4/5/6).
- No client-side persistence wiring (PR-8).

## Rollback plan

- **Revert-file**: remove the two lines in `server.py` under the `# Aug 2026 — L4 Analyst Workspace · L1 Investigation APIs (PR-2)` comment.
- **DB cleanup** (optional): `db.investigation_cases.drop()`.
- **No dependents**: no other router or module imports `routers.workspace_investigation`. Rollback is a no-side-effect single-commit revert.

## Regression evidence

- `dcs_runner --strict`: 17/17 byte-identical.
- `r1_runner --strict`: 107/107 byte-identical.
- L0-canonical pytest (299) unchanged.
- `tests/investigation/` (491 existing tests) unchanged.
- Combined L0 + L2 (unit + API) = **403 passed / 1 skipped / 0 errors**.
- Live smoke-test via external `REACT_APP_BACKEND_URL`: create → hydrate → transition → delete all return 2xx.
