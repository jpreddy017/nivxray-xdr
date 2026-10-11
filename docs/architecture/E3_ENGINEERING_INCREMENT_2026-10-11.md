# E3 deterministic CI increment — 2026-10-11

## Provenance and scope

- Baseline: `feature/e3-edr-engines` at `258c8854c8b89e5203ba2c0e80f631fb3e700315`.
- Review branch: `engineering/e3-deterministic-gate-20261011`.
- Read takeover audit from `feature/unified-xdr-edr-platform-blueprint`, blob
  `eda1c5d03abaee84c8bfde129f307b543d98b67d`.
- Existing engines, contracts and fixtures were reused. No capability rebuilt.

## Change

Added a separate read-only GitHub Actions job covering the existing behavior,
ML, causal investigation and trajectory suites. It runs on E3 pushes, isolated
engineering branch pushes, and pull requests targeting E3, RC2 alignment or main.
No path filter: shared dependency changes must also exercise these contracts.
The existing RC4 quality gate remains intact. The new gate uses a disposable
MongoDB service, async auto mode and a JUnit artifact. It has no deploy step.

## Local evidence and limits

Python 3.12 local run: **181 passed**, two Starlette deprecation warnings.
Command from `backend`:

```sh
python -m pytest tests/edr_behavior tests/edr_ml tests/edr_investigation tests/edr_trajectory \
  --ignore=tests/edr_trajectory/test_deeplink_http.py \
  --ignore=tests/edr_trajectory/test_kushu_import.py \
  --ignore=tests/edr_trajectory/test_platform_seed.py \
  --ignore=tests/edr_trajectory/test_stale_trace.py -q --no-header
```

An initial broader run produced 182 passes and eight async-fixture setup errors.
The existing unmarked async tests require `--asyncio-mode=auto`, included in CI.
MongoDB and Docker are unavailable locally: the database suites have NOT been
validated here. CI includes them rather than silently excluding them.
The Python 3.11 CI dependency installation and workflow execution are pending.
The deep-link HTTP suite needs a running preview backend and remains pending;
skipping it is not evidence of successful live integration.

## Release constraints

All existing security HOLDs remain in force, including Windows re-enrollment
Gate 4. Tracked token files and database state were not inspected or changed.
No merge, deployment, production certification or containment claim.
Before promotion: validate the new CI job, existing security gates, preview
deep links and frontend trajectory behavior; obtain required owner approval.

## Next increment

Run the database gate in CI and resolve actual failures, then inventory the
frontend trajectory/API contracts for fixture-backed end-to-end coverage.
Reconcile only committed E3 state until an authorized Emergent export exists.
