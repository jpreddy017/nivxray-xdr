# RC4.x Quality Gate — FIRST CI FAILURE TRIAGE (READ-ONLY)

Owner rule honoured: no rerun, no exclusion, no republish, no deploy, no
migration, no backfill, no production call, no endpoint action, and **no
code / workflow / test file was modified**. Evidence below was produced by
running the existing suites locally against a throwaway local Mongo DB
(`nivxray_ci_probe`, `nivxray_ci_probe2`).

## Classification of every tests/edr failure

| # | Failure set | Class |
|---|---|---|
| A | `test_p0c_durable_findings.py` (10), `test_p0_f4_endpoint_process_tree.py` (1 F + 4 E), `test_p0_f3_rule_store_binding.py` (1), `test_gate3_fabric_contracts.py` (1) | **CI environment / configuration** — `deps.validate_config()` fail-closed on missing `JWT_SECRET`, `EMERGENT_LLM_KEY` |
| B | `test_p0_f13_5_detection_handoff.py` (5) | **CI data-seed dependency** — suite depends on an ambient seeded `users` document; fresh mongo:7 has none |
| C | `test_sensor_runtime_state_is_never_committed`, `test_production_launcher_refuses_admin_credential_bootstrap` | **Test-harness global state leakage** (not the assertions) |
| D | 41 Windows projection tests | **No genuine projection defect found** — 41/41 pass locally, incl. under the CI-simulated env |

## A · Why CI had MONGO_URL/DB_NAME but not JWT_SECRET/EMERGENT_LLM_KEY

`backend/deps.py` (line 52) calls `load_dotenv(backend/.env)` at import.
Locally that file supplies `JWT_SECRET`, `EMERGENT_LLM_KEY`, `ADMIN_*`. It is
gitignored, so it does not exist on a GitHub runner. `backend/conftest.py`
defaults `MONGO_URL`, `DB_NAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`,
`EDR_AUTH_PEPPER` and the `NIVX_FLAG_*` set — but **not** `JWT_SECRET` or
`EMERGENT_LLM_KEY`, both of which are in `deps._REQUIRED_ENV` and are enforced
by `validate_config()` (deps.py:88). The `env:` block authored in `d03d8523`
therefore listed only what was visibly missing locally; the `.env` masked the
gap. Authoring defect in the CI commit, not an application defect.

Proof (A/B on the same code):
- secrets emptied → `18 failed, 571 passed, 4 errors` (23.0s)
- secrets present, same 5 suites → durable-findings / f4 / f3 / gate3 all pass
  (`5 failed, 50 passed`, remaining 5 = class B)

Exact error: `RuntimeError: NivXRay config error — missing required env
var(s): ['JWT_SECRET', 'EMERGENT_LLM_KEY']`.
The `findings_persisted == 0` assertion the owner quoted is a downstream
symptom of the same fail-closed path, not a persistence regression.

## B · test_p0_f13_5_detection_handoff

`routers/edr_tenancy.edr_scope` → `services/dashboard_lenses.resolve_tenant_scope`
reads `sync_collection("users").find_one({"email": ...})`. With an empty CI
database the admin principal resolves to `tenant_ids: []`, so the router
correctly raises `403 TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`. The suite passes in
the pod only because the pod DB already holds a seeded `role=admin` user.
Ambient-state dependency in the test, correct fail-closed behaviour in the app.
`86e02057` does not touch `trajectory_focus` / `_tenant_scope` (its `edr.py`
hunks are `list_endpoint_detections` and `list_endpoint_commands` only).

## C · Lifetime and scope of `fake_run()` — confirmed contamination

- `tests/edr/test_windows_installer_scm_entrypoint.py:68` and
  `tests/edr/test_windows_installer_service_stage4.py:80,97,122,133,148` do
  `mod.subprocess.run = fake_run`.
- `nivxforge_setup.py` does a plain `import subprocess` (line 35), so
  `mod.subprocess` **is** the `sys.modules["subprocess"]` singleton. The
  assignment replaces `subprocess.run` **process-wide**.
- It is a raw attribute assignment, **not** `monkeypatch.setattr`: there is no
  fixture teardown, so the lifetime is the remainder of the xdist worker
  process.
- `fake_run(cmdline, **kw)` calls `cmdline.startswith(...)`, valid only for the
  installer's string command lines. Any later test calling `subprocess.run`
  with a **list** argv raises `AttributeError: 'list' object has no attribute
  'startswith'`.
- Victims are exactly the two owner-protected tests:
  `test_p0_3_telemetry_freshness.py:142` (`["git", "check-ignore", ...]`) and
  `test_p0prod2_enrollment_hardening.py:434` (`[sys.executable, LAUNCHER]`).

Deterministic reproduction (serial, `-n 0`):

```
pytest tests/edr/test_windows_installer_scm_entrypoint.py \
       tests/edr/test_p0_3_telemetry_freshness.py::test_sensor_runtime_state_is_never_committed -n 0
→ 1 failed, 45 passed   (AttributeError inside fake_run)
```

Same two selections under the configured `-n 2 --dist loadscope` → 46 passed.
That worker-placement dependence is the "intermittency": the assertions never
flaked; whether the poisoned worker also runs the victim does.

## Totals of the CI-simulated local run

Scope = the CI ignore list of `d03d8523`, `JWT_SECRET=""`,
`EMERGENT_LLM_KEY=""`, mongo 27017, addopts `-n 2 --dist loadscope`:

```
18 failed, 571 passed, 4 errors, 0 skipped, 24 warnings  in 23.02s
```

Failures = 10 durable-findings + 1 f4 + 1 f3 + 1 gate3 + 5 f13_5.
Errors = 4 × f4 fixture (`validate_config`). **No projection test in either
list.** `tests/edr/test_windows_activity_projection.py` → `41 passed`.

## Not yet establishable from this workspace

Per-test CI status inside the GitHub job (including the 41 projection tests as
the authoritative runner saw them) requires the raw job log or the run URL —
this workspace has no git remote and no GitHub token. Local evidence above is a
faithful reproduction of classes A and C; class B depends on the runner's empty
DB, which matches.

## Smallest proposed remediation — NOT APPLIED, for owner approval

Proposed as one CI-scope commit plus one test-harness commit, both separate
from `86e02057`, which stays untouched:

1. **Harness leakage (test-only, fixes C without weakening it)** — in the two
   installer suites, set/restore the patched `run` in a `try/finally` (or
   `monkeypatch.setattr(mod.subprocess, "run", fake_run)`) so the stdlib module
   is never left mutated, and let `fake_run` tolerate a list argv. No change to
   either protected test.
2. **CI env (fixes A)** — add CI-only `JWT_SECRET` and `EMERGENT_LLM_KEY`
   placeholders to the `tests/edr` step `env:` block, matching the fail-closed
   validator. No production secret ever enters CI.
3. **Ambient DB dependency (fixes B)** — give `test_p0_f13_5_detection_handoff`
   its own principal fixture (insert the `users` doc it needs) instead of
   relying on a pre-seeded database. Preferred over seeding the CI DB globally,
   because the ambient dependency is the real defect.

No exclusions are proposed anywhere.
