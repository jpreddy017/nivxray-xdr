# RC4.x QUALITY GATE — FAILURE DIAGNOSIS AND CI-ONLY FIX

2026-09-29. No production deploy. No replay. No EID5 semantic change.

## REQUIRED OUTPUT

```
RC4_PUSH_GATE  = FAIL (before fix) -> expected PASS after push of the CI correction
RC4_PR_GATE    = FAIL (before fix) -> expected PASS after push of the CI correction
ROOT_CAUSE     = tests/edr/test_dt2_3_graph_read.py is a LIVE-integration suite
                 (module-scoped fixture POSTs /api/auth/login then GETs
                 /api/edr/endpoints/dev_0e10780f2c86/trajectory). It was added
                 2026-09-28 in commit dc7d86c7, AFTER the workflow's
                 live-suite exclusion list was last updated, so the hermetic
                 gate collected it. On a GitHub runner nothing listens on
                 localhost:8001 -> ConnectionRefusedError -> 10 fixture ERRORs.
BACKEND_REQUIRED_BY_FAILED_TESTS = YES (and a real enrolled Windows endpoint
                 with real telemetry as well -> NOT satisfiable hermetically)
BACKEND_STARTED_BY_OLD_WORKFLOW  = NO (deliberately: the gate is unit/deterministic
                 scope; it starts mongo:7 only, no uvicorn, no /api/health wait)
CI_FIX         = one line added to .github/workflows/rc4x_quality_gate.yml:
                 `--ignore=tests/edr/test_dt2_3_graph_read.py`
                 (plus the adjacent comment count "ten" -> "eleven")
SECURITY_CREDENTIAL_CHECK = REAL_ADMIN_CREDENTIAL_IN_TEST_SOURCE · OWNER_ACCEPTED
B5_FOCUSED_TESTS = PASS
EID5_BEHAVIOR_CHANGED = NO
NEW_COMMIT_SHA = pending platform auto-commit of this step (branch feature/rc2-alignment)
GIT_STATUS     = NOT_CLEAN before commit: exactly 1 modified file
                 (.github/workflows/rc4x_quality_gate.yml). No other change.
PROD_DEPLOYMENT = NOT_STARTED
```

## 1. FAILING WORKFLOW AND STEP

`.github/workflows/rc4x_quality_gate.yml`, job `quality-gate`, step
**"Unit tests — EDR plane (deterministic scope)"**. Triggered on `push` to
`feature/rc2-alignment` and on `pull_request`, paths `backend/**`.

## 2. CLASSIFICATION OF THE FAILING TESTS

Category **(B) live/deployed-environment tests that should already have been excluded
from this hermetic CI job.** Not (A), and not a misconfiguration of the test itself.

Its own header says so: *"DT2-3 · the trajectory READ exposes the render graph
(live preview) ... EVIDENCE LABELLING — REAL. Read-only GETs against the live preview
surface on already-enrolled endpoints."* It asserts against the real enrolled endpoint
`dev_0e10780f2c86` and its real telemetry. Starting a uvicorn in CI would NOT make it
pass: a fresh runner has no enrolled endpoint and no Windows telemetry, so the suite
would then fail on `dt2.graph missing` instead of on connection refused. Excluding it
is the correct action, matching the existing treatment of the ten other live suites and
of the RC4.2/RC4.3 HTTP suites.

## 3. COMPLETE FAILURE COUNT (reproduced hermetically BEFORE changing anything)

Reproduction: the exact CI pytest invocation and CI-only env, with the backend made
unreachable (`REACT_APP_BACKEND_URL=http://127.0.0.1:1`).

```
1698 passed, 10 errors
ERROR tests/edr/test_dt2_3_graph_read.py::test_graph_is_served_with_the_window
ERROR tests/edr/test_dt2_3_graph_read.py::test_every_edge_names_its_evidence
ERROR tests/edr/test_dt2_3_graph_read.py::test_edges_only_connect_nodes_present_in_the_payload
ERROR tests/edr/test_dt2_3_graph_read.py::test_parent_claims_are_backed_by_a_real_edge
ERROR tests/edr/test_dt2_3_graph_read.py::test_no_process_exit_is_invented
ERROR tests/edr/test_dt2_3_graph_read.py::test_activity_attaches_to_a_real_process_at_its_own_time
ERROR tests/edr/test_dt2_3_graph_read.py::test_activity_families_are_reported_honestly
ERROR tests/edr/test_dt2_3_graph_read.py::test_ordering_makes_no_causal_claim
ERROR tests/edr/test_dt2_3_graph_read.py::test_focus_is_exact_or_explicitly_not
ERROR tests/edr/test_dt2_3_graph_read.py::test_graph_read_is_tenant_scoped
```

**10 errors, all in one file, all at the module-scoped login fixture.** 1698 tests in
the same step pass. This matches the owner's log: the EDR suite reaches ~92% and then a
single block of errors appears. No other suite in the gate fails for this reason.

## 4. WHAT THE OLD WORKFLOW DID AND DID NOT DO

| Step | Present? |
|---|---|
| starts MongoDB (`services: mongodb: image: mongo:7`, 27017) | **YES** |
| starts the NivX backend / uvicorn on 8001 | **NO** |
| waits for `/api/health` | **NO** |
| symlinks `sudo ln -sfn "$GITHUB_WORKSPACE" /app` then runs pytest directly | **YES** |
| excludes live suites by name | YES — ten of them, but not the 11th (DT2-3) |

Confirmed by reading the workflow, not assumed. The absence of a backend is intentional
and documented in the workflow's own comments for the RC4.2/RC4.3 HTTP suites.

## 5. THE CORRECTION (CI-only, smallest possible)

Only the workflow file changed. No test was weakened, skipped, xfailed, deleted or
rewritten. No product code touched. No CI-only credential added or changed — the
existing CI-only synthetic env block (`DB_NAME: nivxray_ci`, `ci-only-*` values,
`NIVX_AI_ENABLED: "false"`) is untouched and no production credential was introduced.

```diff
             --ignore=tests/edr/test_wave0_api_smoke.py \
+            --ignore=tests/edr/test_dt2_3_graph_read.py \
             -q --no-header
```

DT2-3 remains a real gate where it can actually run: locally via supervisor and against
the live preview/production surface. It is not lost, only removed from the hermetic job
that cannot satisfy it.

## 6. VERIFICATION AFTER THE CORRECTION (all run locally/hermetically)

| Check | Result |
|---|---|
| EDR plane step, CI command + CI env, backend unreachable | **1698 passed, 0 failed, 0 errors** |
| All other gate pytest steps (RC2.3 baseline, RC4.0 decoder pack, RC4.2 semantic evaluator, RC4.3 PS normalizer, RC4.4 CMD reconstruction, RC4.5 backtick+alias, RC4.5 mitre ReDoS) | 133 passed, 1 failed — see §8, that suite SKIPS on CI |
| RC2.3 chain-completeness benchmark gate | **PASS** — chain_complete 96.8% (floor 77.4%), false_positive_iocs 0 (ceiling 0), precision 30/31, avg 294 ms (ceiling 500 ms) |
| B5 focused regression (b5 termination, b2 process identity, c1 canonical event identity, c5 identifier end-to-end, phase0 windows canonical bridge) | **96 passed** |

## 7. EID5 SEMANTICS UNCHANGED

`EID5_BEHAVIOR_CHANGED = NO`. `backend/edr_plane/windows_eventlog.py` is byte-identical
to the reviewed state: `("sysmon", 5): ACTIVITY_PROCESS_TERMINATION` at line 83, and the
EID5 branch writing `"exit_time": activity_time` with provenance
`":UtcTime (EventID 5)"`, never `start_time`. ProcessGuid identity authority untouched.
The only modified file in the working tree is the workflow YAML.

## 8. SEPARATE PRE-EXISTING ISSUE OBSERVED (NOT CI-BLOCKING, NOT FIXED)

`tests/test_rc42_semantic_mini.py::test_flow4_regression_rc4_inline` fails **locally**:
the RC4-inline PowerShell flow returns 200 but `output_raw` carries only the
`CRYPTO API DETECTED (RC4.1 · honest-verdict)` header plus the substituted script, and
no longer contains the expected decoded `http://c2.evil.io/beacon`.

Why it does not affect the gate: that suite's `token` fixture calls `pytest.skip(...)`
when login fails, so on a runner with no backend the whole module SKIPS and the step
passes. It only executes here because this pod has a backend on 8001.

It is unrelated to EID5/B5 and was NOT touched. Flagging it for a separate decision.

## 9. CREDENTIAL NOTE (value never printed)

The rendered request body in the CI log is the project's **real admin credential** — the
same one recorded in `/app/memory/test_credentials.md` — hardcoded in the source of two
live test files (`tests/edr/test_dt2_3_graph_read.py`, `tests/test_rc42_semantic_mini.py`)
and therefore now present in the GitHub repository and in public Actions logs. It is not
a disposable CI fixture. **Owner has explicitly accepted this and did not request
rotation**, so no rotation was performed and nothing was changed. Recorded here once,
without the value, so the decision is traceable.

## WHAT WAS NOT DONE

No production deploy · no replay · no endpoint/Sysmon/sensor/outbox change · no product
code change · no test weakened or bypassed · no credential rotated or introduced · no
synthetic telemetry · no UI work · no E3.

STOP FOR OWNER REVIEW — the CI correction must be pushed to GitHub before the gate can
re-run.
