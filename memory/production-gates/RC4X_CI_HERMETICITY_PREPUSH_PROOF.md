# RC4X CI DETERMINISM / HERMETICITY HARDENING — PRE-PUSH PROOF

Commit `3aadd519` (local, NOT pushed). `86e02057` untouched; `d03d8523`
still in history. No application code changed, no deploy, no migration, no
endpoint action.

## 1 · Root cause → fix mapping

| Root cause (from the CI triage) | Fix |
|---|---|
| `mod.subprocess.run = fake_run` replaced the **stdlib** `subprocess.run` for the whole xdist worker; later list-argv calls hit the fake | `patch_run` fixture in both installer suites → `monkeypatch.setattr(subprocess, "run", fake)`, restored at teardown; fakes now normalise str **or** list via `list2cmdline` |
| No regression guarded the above | New `tests/edr/test_edr_suite_hermeticity.py`: forbids the assignment statement repo-wide in `tests/edr`, proves monkeypatch restoration, drives the real `_install_service` with a scoped fake, then proves `subprocess.run is <original>` and that a list-argv call works |
| Runner had no `backend/.env`, so fail-closed `validate_config()` killed 13 tests + 4 fixtures | Workflow step now sets CI-ONLY `JWT_SECRET`, `EMERGENT_LLM_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` (+ existing `MONGO_URL`/`DB_NAME`) and `NIVX_AI_ENABLED=false`; two hermeticity tests assert the config contract and that the values are obviously synthetic |
| `test_p0_f13_5` depended on a pre-seeded `users` document | `principal` fixture inserts a unique `ci-principal-<uuid>@tests.invalid` with `role=admin` and deletes it in `finally`; 5 tests now take it |
| Risk of "green by weakening authority" | Two negative controls added: unknown principal → `403 TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` (and searched nothing), anonymous → `403 ACCESS_DENIED` |

`validate_config()` itself was NOT weakened (negative control G below).

## 2 · Files changed (`3aadd519`)

```
.github/workflows/rc4x_quality_gate.yml              +13
backend/tests/edr/test_edr_suite_hermeticity.py      +137 (new)
backend/tests/edr/test_p0_f13_5_detection_handoff.py +81 −…
backend/tests/edr/test_windows_installer_scm_entrypoint.py  +71 −…
backend/tests/edr/test_windows_installer_service_stage4.py  +56 −…
5 files changed, 304 insertions(+), 54 deletions(-)
```

## 3 · Config inventory (what `.env` was silently supplying)

`deps._REQUIRED_ENV` = `MONGO_URL, DB_NAME, JWT_SECRET, ADMIN_EMAIL,
ADMIN_PASSWORD, EMERGENT_LLM_KEY`. `conftest.py` already defaulted
`MONGO_URL`, `DB_NAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `EDR_AUTH_PEPPER`,
`EDR_*_TTL_SECONDS` and the four `NIVX_FLAG_*`. Only `JWT_SECRET` and
`EMERGENT_LLM_KEY` were coming from `.env` — all four are now explicit in the
workflow anyway. The only other env keys any `tests/edr` module reads are
`EDR_AUTH_PEPPER` (conftest), `NIVXFORGE_ENROLLMENT_TOKEN_FILE` (set by the
test itself), and `REACT_APP_BACKEND_URL` / `TEST_ANALYST_NIVXLIVE_PASSWORD`
— both only inside the 10 excluded live suites.

## 4 · Proof results (worktree at `3aadd519`, `backend/.env` ABSENT)

| # | Proof | Result |
|---|---|---|
| A | deterministic `tests/edr` CI scope, empty DB | **602 passed, 0 failed, 0 errors, 0 skipped** (23.3s) |
| B | `test_windows_activity_projection.py` | **41 passed** |
| C | the two previously contaminated tests, alone | **2 passed** |
| D | installer suites → those two, serial `-n 0` | **63 passed** |
| D2 | those two → installer suites, serial `-n 0` | **63 passed** (order independent) |
| E | same scope, `-n 2 --dist loadscope` | **110 passed** |
| F | `test_p0_f13_5` on a fresh empty DB | **7 passed** |
| G | negative control: `validate_config()` with vars removed | still raises `missing required env var(s): ['JWT_SECRET', 'ADMIN_EMAIL', 'ADMIN_PASSWORD', 'EMERGENT_LLM_KEY']`; and the new contract test correctly **FAILS** on an incomplete env (it is a real gate) |
| H | negative control: unseeded + anonymous principal | **2 passed** — 403 preserved |
| I | full scope twice from reset DBs | **602 passed / 602 passed**, identical totals |
| J | diff scan for `skip`/`xfail`/`deselect`/new `--ignore`/`retry`/`sleep` | **no occurrences added** |

Teardown proof: after every run, `users` documents matching `ci-principal-`
in each test DB = **0**.

### Honest note on one intermediate run
One intermediate full-scope run showed `4 failed` —
`test_approval_for_another_endpoint_authorizes_nothing`,
`test_revoked_credential_cannot_open_a_session`,
`test_enrollment_consumes_the_token_and_replay_is_refused`,
`test_concurrent_consumption_yields_exactly_one_success`. Every one of the
four failed with `pymongo.errors.AutoReconnect: connection closed` /
`Connection reset by peer`, and `supervisorctl` showed this workspace's
`mongodb` had restarted 40 s earlier (uptime 0:00:40). It is a local pod
infrastructure flap, not test or product behaviour: three later runs on a
stable mongod were 602/602. Recorded rather than discarded — if the GitHub
mongo service container ever flaps, these four are the tests that will show it.

## 5 · Confirmations

- `86e02057` unchanged: patch-id `0479b1adb6b28e76b44b7c6927e923fbd5a002a5`,
  `git show` sha256 `8c8e72bd…a4880f`.
- No application authorization/security behaviour changed: the commit touches
  4 test files and 1 workflow file only. `validate_config()`, `edr_scope`,
  `resolve_tenant_scope` and every router are untouched.
- No production credentials used. CI values are literal `ci-only-*` strings;
  `NIVX_AI_ENABLED=false`, and a test asserts none of them look like a real
  key (`sk-`, `sk_live`, `nvx_`, …).
- `backend/.env` was absent for every proof (separate git worktree).
- Not pushed, CI not re-run, nothing republished.

## 6 · Remaining known limitations

1. The 10 live suites are still excluded **by filename**; marker proposal in
   `RC4X_TEST_MARKER_PROPOSAL.md` (deliberately not implemented here).
2. Two workspace-only lint findings pre-date this commit and were left alone
   (`PLR0402` import alias, `RUF100` unused noqa).
3. `tests/edr` shares one database name across both xdist workers. No
   collision surfaced in 5 full runs, but the isolation is by unique
   identifiers inside fixtures, not by per-worker databases. A future
   `DB_NAME-$PYTEST_XDIST_WORKER` change would make that structural.
4. `test_edr_and_xdr_resolve_the_same_authority` harness debt (missing
   `oracle=`) is still deferred and is outside this scope.
5. This proves the gate is hermetic against the three demonstrated causes —
   it cannot promise CI never goes red again; it makes a red result far more
   likely to mean a real regression.
