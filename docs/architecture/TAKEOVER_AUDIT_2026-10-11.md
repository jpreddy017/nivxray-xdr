# GitHub Takeover Audit — 2026-10-11

Scope: read-only branch comparison and selective source inspection. This is not a test execution or production certification.

## Verified ancestry
- `feature/e3-edr-engines` is **64 commits ahead** of `feature/rc2-alignment` and 0 behind at audit time. This makes RC2 alignment an ancestor of E3, not an independent peer to blindly merge.
- Against `main`: E3 +767 commits, RC2 alignment +703 commits, `enhancement/edr-investigation-ui` +270 commits. These are history counts, not completeness scores.
- `feature/unified-xdr-edr-platform-blueprint` is a separate docs-only branch, +1 commit from `main`. It does not contain the implementation history.

## E3 delta compared with RC2
Observed added/modified paths include:
- Frontend device trajectory versions under `apps/nivxray-xdr/src/nivxforge/trajectory_amp/` and `trajectory_v3/`; MITRE pivot and heatmap.
- `backend/edr_behavior/`: contracts, detection, matcher, rules, suppression, replay, metrics.
- `backend/edr_investigation/`: causal builder and threat intelligence.
- `backend/edr_ml/`: feature schema, baseline, model pipeline and signals.
- `backend/edr_trajectory/`: trajectory APIs and supporting contracts.
Existence of these files does not prove behavior, test success, integration, or production readiness.

## Security / release blockers
1. Tracked `.tok` on existing branches: inspect secret handling in a secure environment. Do not print or copy token contents into reports. Assess whether rotation/history remediation is required.
2. Tracked `*.db`, `*.db-shm`, `*.db-wal` in runtime paths: assess for sensitive state and repository hygiene; do not delete without backup and owner approval.
3. Existing `rc4x_quality_gate.yml` is scoped to selected branches and paths; it does not, on its face, guarantee that E3-specific frontend or new behavioral/ML tests run for every E3 commit.
4. Existing Windows re-enrollment Gate 4 HOLD remains in force; no deployment, merge or containment claims.
5. Uncommitted Emergent E1/E3 workspace data is not available from GitHub. Reconcile only committed state until an authorized export exists.

## Recommended next engineering increment
- Establish a dedicated integration branch **from the verified E3 tip**, not from the docs-only `main` branch, after recording its exact commit SHA.
- Inventory trajectory API and UI contracts, identify fixture availability and test gaps, and add targeted deterministic tests.
- Add E3 branch/path coverage to CI on a review branch; do not change production workflows directly.
- Open a draft PR with acceptance checklist and no auto-merge.
- Separate any token or sensitive-state remediation from feature integration and coordinate rotation if a real secret is confirmed.

## Explicit nonclaims
- No unit/integration/end-to-end tests executed in this audit.
- No branch was merged or deployed.
- No direct Emergent workspace access was available.
- No determination that `.tok` contains an active credential.
