# PR-1 · Architecture Compliance

**Blueprint version referenced**: v1.1
**User Journey version referenced**: v1.0
**Validation Matrix version referenced**: v1.0
**Date**: 2026-08-04

## Sections implemented

| Blueprint section | How this PR satisfies it |
|---|---|
| §7 Layered Architecture | L2 package created at `backend/l2_investigation/` reading only from `workspace.convergence.certificate` (typed read-down). |
| §8.1 State Model | `InvestigationStateMachine` implements the exact `New → Collecting → Correlating → Reviewing → Completed → Reported → Reopened → Correlating` graph with audit log per transition. |
| §8.2 Workspace Modes | `WorkspaceMode` enum with default-lens mapping matching the §8.2 table. |
| §8.3 Persistence Requirements | `WorkspaceState` dataclass captures every §8.3 field with canonical-JSON fingerprinting. |
| §8.4 Evidence Navigation Contract | Evidence primitives (`IocEvidence`, `CapabilityEvidence`, `MitreEvidence`, `TransformationEvidence`) carry the source-iteration provenance every clickable object needs. |
| §9 Lens Inventory | Eight L2 service skeletons (one per lens/sub-panel + workspace bundle). |
| §10 Data Contract | `ServiceOutput` envelope is what PR-2's L1 endpoints will emit. `workspace_bundle` is the single-call aggregate for the shell. |

## User Journeys supported (Validation Matrix §1)

| Journey | Supported by |
|---|---|
| J1 Tier-1 Triage | `executive_summary`, `ioc_intelligence` |
| J2 Standard Investigation | + `attack_story`, `capability_explorer`, `threat_assessment` |
| J3 Deep Investigation | + `detection_rules`, `hunting_queries`, `workspace_bundle` |
| J4 Executive Report | Same set; export path lands in PR-6/PR-8 |
| J5 Reopen & Iterate | State machine `Reported → Reopened → Correlating` verified exhaustively |

## Validation Matrix entries satisfied (§4)

Every "Non-Structural Extension Reserved" L2 service now exists as a
registered skeleton:
`attack_story`, `detection_rules`, `hunting_queries`, `threat_assessment`,
`ioc_intelligence`, `capability_explorer`, `executive_summary`,
`workspace_bundle`.

## Principles preserved

- **P1 Investigation First**: services return content organized around
  the investigation, not around UI cards.
- **P2 Evidence First**: every service reads only from `EvidenceBundle`;
  no derived state, no side effects.
- **P6/P7 Zero Duplicates**: one registry entry per service.
- **P9 Everything Explainable**: every output carries evidence anchors
  (source_iteration, source_span, via_capability, ...).
- **P10 Deterministic Investigation First**: every service is a pure
  function; determinism is proven by SHA-256 fingerprint tests.

## L0 impact

**ZERO**. `backend/workspace/convergence/*` is unchanged. Only one
symbol is imported: `ConvergenceCertificate` (a frozen dataclass), used
solely as a type reference in `schemas.py`. No runtime coupling.

## Regression contract

- `pytest` L0-canonical suite: 299 passed (baseline preserved).
- `dcs_runner --strict`: 17/17 byte-identical.
- `r1_runner --strict`: 107/107 byte-identical.
- 24-transformation registry: unchanged.

## What this PR does NOT do

- No API routes (that is PR-2).
- No UI (that is PR-3+).
- No real content generation inside services (per-service content lands
  in PR-4/5/6).
- No persistence storage (PR-8 wires server-side + client-side).
- No touching of any file outside `backend/l2_investigation/` and
  `backend/tests/l2_investigation/`.

## Deviation from Blueprint (documented, non-structural)

Blueprint §7 references the L2 package as `backend/investigation/`.
The concrete Python package name is **`backend/l2_investigation/`**
because `tests/investigation/` (an existing test-package) already
occupies the short name `investigation` in pytest's collection
namespace. Renaming the *tests* directory would violate the ARB
Workspace Stability Contract; renaming the *new* package does not.

Impact on architecture: **NONE**.
- The URL prefix `/api/investigation/*` (Blueprint §10) is unchanged.
- The layer name "L2 Investigation Services" is unchanged.
- The internal Python import path (`from l2_investigation.services...`)
  is not exposed to any external contract.

Blueprint will be updated in a documentation-only sync (per ARB
Governance Rule 6) alongside PR-2 to record the concrete package name.
