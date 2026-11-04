# RC4.x CI ACCEPTANCE RECORD — read-only, public API only

No PAT requested or used. No code/test/workflow/production/endpoint/database/
deployment change. Nothing republished.

Repo `jpreddy017/nivxray-xdr` (public), branch `feature/rc2-alignment`.

## 1 · Remote HEAD
`8c53c00206b5515e76a2c21900880034a63fca11` ("Auto-generated changes") —
identical to local HEAD.

## 2 · Commit order on the remote branch (newest → oldest)
```
8c53c002  Auto-generated changes                (.emergent/emergent.yml)
e51e6ce5  report commit
3aadd519  CI/test hermeticity …                  5 files  +304 −54
c8674384  report commit
20e7a38c  Auto-generated changes
45b8c5f7  report commit
d03d8523  CI: make tests/edr an authoritative …  1 file   +48 −1
80488e3c  report commit
7184daa5  report commit
86e02057  Windows activity projection …          5 files  +679 −11
```
Order and separation preserved: projection → CI gate → hermeticity.

## 3 · `86e02057` unchanged
Remote resolves `86e0205762d0ecac5b6734bed30e746d965338f8` with exactly
5 files, +679 −11. A Git commit id is a hash over its content and parents, so
the SHA appearing in the remote ancestry is cryptographic proof it was neither
amended nor squashed. Local patch-id `0479b1adb6b2…a002a5` unchanged.

## 4 · `3aadd519` matches the reviewed commit
Remote resolves `3aadd5199a7f857d164f73c6d2259711a0cb15c9`, 5 files,
+304 −54. Remote `.github/workflows/rc4x_quality_gate.yml` at HEAD is
byte-identical to the local file (`diff -q` clean), and all seven relevant
test files hash-match remote ↔ local (sha256 prefixes):
`test_windows_activity_projection.py cb82c274`,
`test_edr_suite_hermeticity.py 770bc7d9`,
`test_p0_f13_5_detection_handoff.py f6bad8d3`,
`test_p0_3_telemetry_freshness.py 67501c31`,
`test_p0prod2_enrollment_hardening.py 65e5472b`,
`test_windows_installer_scm_entrypoint.py cd5bf060`,
`test_windows_installer_service_stage4.py 95bcf5a0`.

## 5 · Authoritative runs (triggering SHA `8c53c002`)
| Trigger | Run | Job | Result |
|---|---|---|---|
| push | [36308919817](https://github.com/jpreddy017/nivxray-xdr/actions/runs/36308919817) | `quality-gate` 108590927780 | **success**, 3m52s |
| pull_request | [36308923628](https://github.com/jpreddy017/nivxray-xdr/actions/runs/36308923628) | `quality-gate` 108590939364 | **success** |

Previous red runs on `20e7a38c` (36306889702 push, 36306893948 PR) remain in
history as the first-failure record — not re-run, not deleted.

## 6-10 · Test results

Step 13 `Unit tests — EDR plane (deterministic scope)` = **success in both
runs** (all 19 steps of both jobs succeeded).

That step is `python -m pytest tests/edr …` with **no `continue-on-error` and
no `|| true`** (the only `|| true` in the workflow is line 191, the RC2.3
benchmark step). pytest exits non-zero on any failure OR error, so a green
step is proof of **zero failures and zero errors across the entire
deterministic scope**, which by the remote workflow's own ignore list includes:

| # | Required evidence | Status |
|---|---|---|
| 7 | `test_windows_activity_projection.py` — 41 tests (hash-matched file, collected count 41) | in scope, green |
| 8 | `test_sensor_runtime_state_is_never_committed`, `test_production_launcher_refuses_admin_credential_bootstrap` | both in scope, green |
| 9 | `test_p0_f13_5_detection_handoff.py` — 7 tests incl. the two 403 negative controls | in scope, green |
| 10 | `test_edr_suite_hermeticity.py` — 7 tests incl. the `subprocess.run` guard and the CI-config contract | in scope, green |

Collected counts for the three new/changed files on the pushed tree:
**41 + 7 + 7 = 55**.

Note — the hermeticity suite is itself a witness: had the runner's env been
incomplete, `test_every_required_config_var_is_present_without_a_dotenv` and
`test_the_ci_workflow_supplies_that_config_itself` would have failed the step.
They did not, so the CI-only `JWT_SECRET` / `EMERGENT_LLM_KEY` / `ADMIN_*` /
`NIVX_AI_ENABLED=false` values were actually in effect.

### Honest limitation on literal counts
The per-test/summary LINES from the CI log are not obtainable read-only:
`GET /actions/jobs/108590927780/logs` → `403 "Must have admin rights to
Repository"`, and the HTML job view returns "Sign in to view logs". Owner
forbade a PAT, so the totals above are established by scope + exit code rather
than by quoting the runner's own `N passed` line. If you want the literal line
in the record, paste the raw log for step 13 (or download it while signed in)
and I will map it line-for-line.

## 11 · Overall gate
**RC4.x Quality Gate: SUCCESS on both push and pull_request.** Also green on
this SHA: RC5 Semantic Engine Gates (36308923466), RC5 Golden Corpus CI Gate
(36308923528).

## 12 · Failures
None on `8c53c002`.

Commit statuses on this SHA:
```
SUCCESS  Vercel – nivxray-xdr-production
SUCCESS  Vercel – nivxray-edr-production
SUCCESS  Vercel – nivxmachines-workspace
FAILURE  Vercel – nivxray-xdr          ← legacy/root project
```
The `Vercel – nivxray-xdr` failure is recorded as **out of scope and
pre-existing** for this Windows EDR acceptance gate: it is the legacy root
Vercel project, distinct from `nivxray-xdr-production` and
`nivxray-edr-production`, both of which are green on this SHA. No
investigation performed, no change made.

## Production status
**HOLD.** Green CI does not mean the projection patch is live: the production
backend has NOT been republished. Awaiting explicit owner approval.
