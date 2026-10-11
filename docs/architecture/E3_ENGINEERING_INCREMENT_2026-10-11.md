# E3 takeover: trajectory cursor and deterministic CI

## Baseline and scope

- Repository: `jpreddy017/nivxray-xdr`.
- Authoritative committed E3 baseline: `258c8854c8b89e5203ba2c0e80f631fb3e700315`.
- Work branch: `codex/e3-trajectory-contract-ci-20261011`, based directly on E3.
- Reviewed `TAKEOVER_AUDIT_2026-10-11.md` from the separate docs branch
  `feature/unified-xdr-edr-platform-blueprint` (blob `eda1c5d03abaee84c8bfde129f307b543d98b67d`).
- No reconstruction of existing engines, UI or response authority.

## Implementation

Trajectory cursors previously coerced arbitrary JSON boundaries and passed an
unchecked `as_of` into ingestion-time comparison. A string boundary could produce
a TypeError and HTTP 500. Boundaries now require integer times (excluding booleans)
and a nonempty string event ID. Invalid input becomes BadCursor and HTTP 400.
Generated cursors retain their existing format and snapshot semantics.

A separate read-only CI workflow covers E3 pushes, integration review branches,
and PRs targeting E3, RC2 alignment or main. It runs existing behavioral, ML,
causal and trajectory contract tests, trajectory UI suites, native time-window
tests and the standalone application build. It does not replace existing gates.
PR triggers intentionally have no path filter, avoiding missed cross-cutting
dependencies and checks stuck pending from path exclusions.

## Local validation

- Backend selected deterministic scope: **194 passed** (includes 13 new cursor tests).
- Trajectory Vitest scope: **207 passed** in 11 files.
- Native time-window suite: **18 passed**.
- Standalone Vite application build: passed.
- `git diff --check`: passed.
- Local backend runtime: Python 3.12; workflow runtime: Python 3.11. Hosted CI
  must validate the workflow runtime and frozen Yarn dependency installation.

## Pending validation and unchanged HOLDs

An exploratory run of `test_stale_trace.py` exposed MongoDB-dependent async
fixtures; two tests errored without async auto mode and a local MongoDB.
That suite is deliberately outside this deterministic CI scope, along with
live deep-link HTTP, MongoDB import and platform-seed tests. This does not claim
those integration tests pass. Live sensor and browser validation remain pending.

Windows re-enrollment Gate 4 HOLD and all existing security/release HOLDs remain
in force. Tracked token/runtime database artifacts were neither read for contents,
modified nor removed. Credential rotation/history remediation requires its
separate review. No merge, deployment, containment, execution or production
readiness claim is made. Uncommitted Emergent E1/E3 state is unavailable here.

## Review acceptance

- [ ] Hosted E3 contract workflow passes on this exact branch tip.
- [ ] Existing required quality/security gates pass.
- [ ] MongoDB/live trajectory and sensor integration validation is recorded.
- [ ] Existing Gate 4 and security HOLD owners explicitly clear applicable HOLDs.
- [ ] Owner approval obtained before any merge or deployment.
