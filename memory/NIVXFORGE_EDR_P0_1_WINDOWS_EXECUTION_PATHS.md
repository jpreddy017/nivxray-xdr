# NIVXFORGE EDR — P0-1 WINDOWS EXECUTION-PATH VERIFICATION
## READ-ONLY source inspection · no design, no fixes

Repository `jpreddy017/nivxray-xdr` · Trunk **`f971c765`** · M1 **`388bb3d6`** ·
Frozen M1 subtree **`db21f422561f14fb4dcec91b70925f2b5291c500`**
Working tree `/app` (`HEAD 40779b51`) carries Windows subtree
`54fe56bdf7ae55c1ed8727a3d58f87f3743d0a33`, **byte-identical to
`f971c765:agents/nivxforge-windows`** — so a test that reads `/app` reads the
trunk baseline (this matters in §3).

No merge, no implementation, no CI, no Windows execution, no database write, no
publication. Evidence is `git show` / `grep -c` against the two revisions plus
two portable `pytest` runs over `git archive` exports in `/tmp` (§3.3).

---

## 0 · Headline findings

| # | Finding | Evidence |
|---|---|---|
| **F-1** | **A third, production-advertised install path was not in scope of any prior reconciliation document.** `Install-NivXForgeSensor.ps1` installs the sensor as a **SYSTEM scheduled task**, not as an SCM service, by invoking `nivxforge_sensor.py enrol` directly — bypassing `nivxforge_setup.py`, the attempt marker, ownership and every M1 contract. It is **byte-identical in both lineages** (blob `61e08b43`) and is the **default `windows-x64` connector entrypoint** served by Management → Downloads. | `Install-NivXForgeSensor.ps1:91,181-186`; `backend/routers/edr_onboarding.py:71-89` |
| **F-2** | **One name, three mechanisms.** The scheduled task (`$TaskName = 'NivXForgeSensor'`), the trunk SCM service (`SERVICE_NAME = "NivXForgeSensor"`) and the M1 service adapter (`_svc_name_ = SERVICE_NAME`) all use the same name. `setup.exe uninstall` never touches the task; `-Uninstall` never touches the service. Either "uninstall" can report success while the other mechanism keeps delivering telemetry as SYSTEM. | `PS1:58,124-127`; `trunk setup.py:54`; `m1.py:1434` |
| **F-3** | **The M1 lineage has already lost two capabilities.** `install --re-enrol` → `SystemExit("transaction recovery never re-enrolls an endpoint")`; `uninstall()`/`--purge` → `SystemExit("uninstall/purge unavailable in transaction validation builds…")`. Trunk has both. | `m1 setup.py:1148-1149, 1213-1217` |
| **F-4** | **Queued evidence is attributed by session, not by row, on every sender.** Journal rows carry `endpoint_id`/`tenant_id`, but `_drain_journal`, `_deliver_batch` and the legacy `_drain` all post only `payload` under a bearer token, and the backend writes `source=who.endpoint_id` from the session. **The legacy outbox has no identity columns at all**, so per-row attribution is not merely unused there — it does not exist. | `journal.py:106-107`; `sensor.py:1332-1340, 974-993`; `edr_enrollment.py:480-490` |
| **F-5** | **`--discard-queued-evidence` destroys journal rows but not the legacy outbox.** `telemetry_baseline` (M1 only) deletes `ACQUIRED/QUEUED/REFUSED_UNACCEPTABLE` rows and re-baselines cursors; `outbox.jsonl` and `outbox.offset` are untouched and stay deliverable. | `m1 setup.py:1318-1327`; `m1 journal.py:433-452` |
| **F-6** | **Every Windows installer test except `test_m1_clean_install.py` hard-codes `AGENT_DIR = Path("/app/agents/nivxforge-windows")`.** They read the live working tree regardless of which checkout pytest runs in — so "run the M1 tests in an isolated worktree" is **unsound** for them, and any such run silently grades trunk source. | `test_windows_installer_v1.py:23`, `…scm_entrypoint.py:34`, `…service_stage4.py:21`, `…reenrol_staging_race.py:39`, `test_s1_2_c2_clean_install_atomicity.py:53`, `test_edr_suite_hermeticity.py:22`, `test_b5gap1_enrolment_secret_stdin.py:41` |
| **F-7** | **`test_s1_2_c2_clean_install_atomicity.py` does not exist at `388bb3d6`.** The file asserting the five atomicity guarantees is trunk-only. | `git ls-tree 388bb3d6 backend/tests/edr/` |
| **F-8** | **An asynchronous mutation worker exists only on M1.** `--transaction-scm-worker` is a hidden entrypoint; `WindowsBackend.call` spawns it via `subprocess.Popen` inside a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job and records `worker_pid` + creation-time token **before** releasing the request. No threads, no asyncio, no timers, no `atexit` anywhere in either lineage. | `m1 setup.py:2055-2058`; `transaction.py:680-741`; `scm_worker.py:329-352` |
| **F-9** | **Real-Windows CI proves only a *failing* re-enrol.** Gate 4 runs `install --re-enrol` with an **empty stdin** and requires a non-zero exit. No gate on either lineage exercises a successful re-enrol on Windows. | `.github/workflows/windows-sensor-installer.yml:531-660` |
| **F-10** | **Transport-level retry can double-send an enrolment on both lineages.** `_Transport.request` retries once on `HTTPException`/`OSError`. Only `m1-install` passes `attempts=1` + an attempt marker; the production `install`, the sensor CLI and the PS1 path all enrol with the default two attempts and **no marker**. | `trunk sensor.py:285-305`; `m1 sensor.py:300-341, 612-676`; `m1 setup.py:2029-2036` |

---

## 1 · Execution-path matrix

`T` = trunk `f971c765` · `M` = M1 `388bb3d6`. Line numbers are of the named
revision's file.

### 1.1 Fresh installation

| Operation | Entrypoint | Functions (call chain) | Durable state changes | Security boundary | Existing tests | Evidence |
|---|---|---|---|---|---|---|
| **Fresh install · SCM service (T)** | `NivXForgeEDRSetup.exe install --backend --tenant --token-stdin` → `main()` → `install()` | `_assert_backend` → `_assert_admin` → `_service_state` (prior) → `INSTALL_DIR.mkdir(exist_ok=True)` → `_stop_service_and_wait` → `copy2(self→INSTALLED_EXE)` → `_stage_service_host`→`_replace_tree` → `_protect_state_dir` → `sensor.enrol` → `_install_service`→`sc create/description/failure/start` → `_service_config` | `INSTALL_DIR`, `sensor\service\` tree, `identity.json`, state-dir ACL, SCM entry + failure actions, service RUNNING | elevation (`_assert_admin`), production-origin + explicit-tenant guards, stdin-only secret, state dir `icacls /inheritance:r` SYSTEM+Admins | `test_windows_installer_v1.py` (20), `…scm_entrypoint.py` (≈30), `…service_stage4.py` (14), `test_s1_2_c2_clean_install_atomicity.py` (10), `…reenrol_staging_race.py` (18) | `T setup.py:535-620, 470-508, 441-467` |
| **Fresh install · transaction engine (M)** | same CLI → `install()` | `Engine(INSTALL_DIR, backend).run(payload, manifest, prepare)`; `prepare()` = `backend.protect(STATE_DIR)` → `sensor.enrol` → `_validate_identity`; engine → `Owner` lock → `Store` intent → `WindowsBackend.call(stop/create/set_path/start)` → `scm_worker` | `INSTALL_DIR/versions/<id>`, `active.json`, `operations/*.json`, transaction intent record, `identity.json`, SCM entry | elevation; **unpinned build refused** (`payload-manifest.json` required); `Owner` exclusive lock; operations dir ACL | `test_installer_transaction.py`, `test_p0_installer_upgrade_repair.py` | `M setup.py:1142-1179`; `transaction.py:580-675` |
| **Fresh install · M1 clean install (M)** | `… m1-install --m1-config <path>` → `m1_dispatch` → `m1.m1_install` | `load_config` → `Ownership(root/"m1-ownership.json")` (`ALREADY_INSTALLED`/`PRIOR_ATTEMPT_UNRESOLVED`) → `host.exclusive_lock` → `clean_host_report` → `ownership.create` → `create_directory_protected`+`directory_security` → `m1_payload_check`/`copy_payload`/`verify_installed_binary` → `enroll` (marker, single attempt) → `service_create` (**DEMAND_START first**) → `service_set_security`+read-back → `service_start` → `verify_running_image` → `AUTO_START` → `ownership.mark CREATE_CONFIRMED` | `m1-ownership.json`, protected install/state dirs, verified payload, `identity.json`, service with explicit SD, start-type transitions | `AUTH_INSTALLER` context; pristine-host refusal where **UNKNOWN refuses as PRESENT**; create-only; attested payload; DACL/SD verified by read-back | `test_m1_clean_install.py` (**636 passed** with the two sibling files, §3.3) | `m1.py:1117-1293` |
| **Fresh install · scheduled task (T = M)** | `Install-NivXForgeSensor.ps1 -BackendUrl -TenantId -EnrollmentToken` | `Assert-Administrator` → `Resolve-Python` → copy 4 `.py` files → `Protect-StateDirectory` (`SetAccessRuleProtection`, SYSTEM+Admins) → `Invoke-Enrolment` (`sensor.py enrol`, secret on stdin) → `schtasks /Create /SC ONSTART /RU SYSTEM /RL HIGHEST /F` → `/Run` | `C:\Program Files\NivXForge\sensor\*.py`, state-dir ACL, `identity.json`, **scheduled task `NivXForgeSensor`** | elevation; SecureString → stdin; **requires Python 3.11+ on the endpoint**; no payload attestation, no digest, no service SD | `backend/tests/test_edr_onboarding_v1.py`, `test_w1_windows_enrolment_instruction_contract.py` (catalog/instruction level only) | `PS1:120-190`; `edr_onboarding.py:71-89` |

### 1.2 Existing-endpoint re-enrolment

| Operation | Entrypoint | Functions | Durable state | Security boundary | Tests | Evidence |
|---|---|---|---|---|---|---|
| **`install --re-enrol` (T) — WORKS, overwrites** | `main()` → `install(..., re_enrol=True)` | skips the RESUME branch → `_assert_tenant` → `--token-stdin` required → `sensor.enrol` → **`IDENTITY_FILE.write_text(...)`** (plain overwrite, `chmod 0o600` best-effort) → `_install_service` | `identity.json` **replaced in place**; journal/outbox/cursors untouched; service re-created and restarted | elevation + tenant + stdin token; **no ownership check, no prior-identity comparison, no archive** | `…reenrol_staging_race.py::test_successful_reenrol_preserves_identity_outbox_offset_cursors` — **but `sensor.enrol` is monkeypatched**, so publication itself is unproven; CI Gate 4 is a *negative* test | `T setup.py:570-585`; `T sensor.py:504-511`; workflow `:631` |
| **`install --re-enrol` (M) — REFUSED** | same | `install()` line 2 | none | n/a | no positive test exists | `M setup.py:1148-1149` |
| **RESUME (no `--re-enrol`, identity present) (T)** | `install()` | `_validate_identity` → prints RESUME → **no token consumed** → `_install_service` | service re-created; identity untouched | fail-closed `_validate_identity` | `test_resume_after_a_failed_stage_needs_no_token`, `…stage4::test_resume_*` | `T setup.py:573-581` |
| **Sensor-module CLI (T, M)** | `python nivxforge_sensor.py enrol --api --tenant --token-stdin` | `refuse_secret_on_command_line` → `read_enrolment_secret` → `enrol(api, tenant, token)` — **T overwrites; M calls `publish_identity`, which refuses an existing destination** | T: `identity.json` replaced. M: refusal (`_rename_no_replace` → target exists) | **no elevation check at all**; relies on the state-dir ACL | T: `test_b5gap1_enrolment_secret_stdin.py`. M: `publish_identity` covered by `test_m1_clean_install.py`; **the CLI-on-an-enrolled-host case is untested on both** | `T sensor.py:473-519`; `M sensor.py:612-676, 505-558` |
| **`-ReEnroll` (PS1, T = M)** | `Install-NivXForgeSensor.ps1 -ReEnroll` | `Invoke-Enrolment` → sensor CLI `enrol` | T: overwrite. **M: breaks** — the no-overwrite publication refuses, the script throws `enrolment failed (exit 1)` after the ACL is reapplied and before the task is (re)created | elevation; stdin secret | none (the `-ReEnroll` branch is asserted nowhere) | `PS1:155-179` |
| **`m1-reconcile-enrollment` (M)** | `… m1-reconcile-enrollment --m1-config --operator-confirmed` | `m1_reconcile_enrollment(…, session_probe, operator_confirmed)`; probe = `sensor._open_session` | marker closed/amended; identity **never** replaced | `AUTH_INSTALLER` + explicit operator confirmation; UNKNOWN refuses | `test_m1_clean_install.py` | `m1.py:1354-1392`; `M setup.py:2037-2047` |

### 1.3 Identity publication and replacement

| Operation | Entrypoint | Functions | Durable state | Security boundary | Tests | Evidence |
|---|---|---|---|---|---|---|
| **Publication (T)** | `sensor.enrol` | `_post /api/edr/agent/enroll` → `IDENTITY_FILE.write_text` → `os.chmod 0o600` (OSError swallowed) | `identity.json` created **or silently replaced**; no fsync, no read-back | ACL inherited from the state dir | `test_p0_a2_enrollment.py`, `test_p0prod2_enrollment_hardening.py` | `T sensor.py:504-515` |
| **Publication (M)** | `sensor.enrol(single_attempt=…, attempt_marker=…)` | `validate_enrolment_response` → `publish_identity`: temp `O_CREAT\|O_EXCL` → `write` → `fsync` → `_rename_no_replace` → **read-back equality** | `identity.json` **created only onto an absent destination**; `enrolment_attempt.json` opened before the request, closed only after publication + read-back | no-overwrite is structural; an `OPEN` marker **blocks** automatic re-enrolment | `test_m1_clean_install.py` | `M sensor.py:491-676` |
| **Replacement** | — | **No replacement, archival or transition code exists in either lineage.** T replaces by overwriting; M refuses. No archive file, no transition record, no fence. | — | — | — | absence verified by `grep` for `retire`, `archive`, `transition`, `pending` across both subtrees |
| **Identity read** | `_read_identity`, `status` | reads `IDENTITY_FILE` **only** — no archived or alternate identity path exists | none | credential value never printed | `status` asserted in installer suites | `T/M sensor.py:335/341` |

### 1.4 SQLite journal delivery

| Operation | Entrypoint | Functions | Durable state | Security boundary | Tests | Evidence |
|---|---|---|---|---|---|---|
| **Journal delivery (T = M in shape)** | service loop → `sensor.run` → `_cycle` | `open_journal` → `acquire`→`commit_page` (evidence + cursor in ONE transaction) → `_drain_journal` → `next_undelivered` → `_deliver_batch` (`/telemetry/batch`) **or** per-row `/telemetry` → `mark_accepted` / `quarantine` / `mark_attempt_failed` | `evidence_journal.db` (WAL, `synchronous=FULL`), row states, `counters`, `gauges`, cursors, `channels.json` mirror | bearer **session** token; `401/403` drops the token and re-opens; batch route 404/405 → bounded fallback; **row-level `endpoint_id`/`tenant_id` are stored but never transmitted** | `test_b5_gap1_journal_durability.py` (28), `test_p0_sensor_delivery_repair.py` (13), `test_c3_delivery_counters.py` | `journal.py:98-120, 320-480`; `sensor.py:1246-1363` |
| **Integrity / heartbeat / policy / enforcement** | `_cycle` | `_report_integrity` → `/acquisition-integrity`; `_heartbeat` → `/heartbeat`; `_sync_policy` → `GET /policy` + `/policy-ack`; `_report_enforcement` → `/exclusion-enforcement` | `integrity snapshot` file, policy/enforcement journals, gauges | all four are session-bearer, `SENSOR_SCOPED` in the tenancy table | integrity/policy covered in EDR suites; enforcement in `test_gate7_endpoint_enforcement.py` | `sensor.py:977-1066, 1365-1447`; `edr_tenancy.py:105-143` |

### 1.5 Legacy outbox delivery

| Operation | Entrypoint | Functions | Durable state | Security boundary | Tests | Evidence |
|---|---|---|---|---|---|---|
| **Legacy drain (T = M, byte-identical)** | `_cycle` → `_drain` | `QUEUE_FILE` read from `OFFSET_FILE` → per-line `_post /api/edr/agent/telemetry` → advance `outbox.offset` after each accept; **wall-clock budget**; `401/403` → clear token, `seek(offset)`, `continue` | `outbox.offset` advances; `outbox.jsonl` **never rewritten or deleted** | session bearer; **lines carry no identity fields — the writer `_enqueue` stores raw events only** | `test_p0_sensor_delivery_repair.py` partially; `_legacy_remaining` surfaced by `status` | `sensor.py:910-1005` (T) / `1067-1162` (M), `diff` empty |
| **Legacy writer** | — | `_enqueue` is **retained but unused by the run loop** | appends + `fsync` when called | — | — | `sensor.py:910-925` |
| **Legacy cursor migration** | `open_journal` | `migrate_legacy(journal, BOOKMARK_FILE)` → `seed_cursor` (never disturbs an existing cursor) | `cursors` seeded once | — | `test_b5_gap1_journal_durability.py` | `journal.py:729-773` |

### 1.6 Service stop, restart, recovery

| Operation | Entrypoint | Functions | Durable state | Security boundary | Tests | Evidence |
|---|---|---|---|---|---|---|
| **Stop before mutation (T)** | `install()` | `_stop_service_and_wait` → `_wait_for_service_state("STOPPED")` → `_wait_for_image_release` (`_image_is_released` = non-destructive open) | none | timeout **fails closed**, replaces nothing | `…reenrol_staging_race.py::test_*stop*`, `test_locked_executable_refuses…` | `T setup.py:240-268, 208-238` |
| **Rollback / restore (T)** | `install()` `except BaseException` | `prior_state` → `_restore_service` **or** `_abort_incomplete_clean_install` → `_remove_partial_service` (`sc stop`+`sc delete`, no PID, no exit proof, infers absence from `_service_exists`) → `_remove_partial_staging` (`rmtree(INSTALL_DIR, ignore_errors=True)`, **no ownership proof**) | service entry and `INSTALL_DIR` may be removed; state dir never touched | truthful messaging incl. `THIS ENDPOINT IS NOT COLLECTING`; **path-match deletion** of a directory reached via `mkdir(exist_ok=True)` | `test_s1_2_c2_clean_install_atomicity.py` (10) | `T setup.py:294-360, 535-620` |
| **Restore (M)** | engine failure | `_restore_service(prior, previous_exe, snapshot)` → `_capture_service_config`/`_require_service_snapshot`/`_verify_restored_config`/`_restore_service_config`, `_sc_argv` (no hand-escaping), `_verify_running_image` | `active.json` committed only after a **MATCH** verdict | live-image proof, not a binPath claim | `test_p0_installer_upgrade_repair.py` | `M setup.py:338-525, 681-768, 916-933` |
| **Crash recovery (T = M)** | SCM | `sc.exe failure … actions= restart/60000 ×3 reset= 86400` | SCM failure actions | the SCM restarts the service **automatically** — an independent startup path | `test_real_windows_service_not_a_scheduled_task` asserts the literal string | `T:498-500` / `M:1076-1078` |
| **Service runtime stop (T)** | SCM control | `SvcStop`/`SvcShutdown` → `SetEvent` → loop breaks → log `STOPPED` **before** `ReportServiceStatus(STOPPED)`; cycle exceptions never stop the service | diagnostics log; journal state | start-up refuses a non-production backend from the SCM argv | `…scm_entrypoint.py` (≈30) | `T setup.py:701-808` |
| **Service runtime (M adapter)** | `--m1-service-run --m1-config` | `m1_service_run`: `AUTH_SERVICE` → `running_identity` → **`SERVICE_NOT_LOCAL_SYSTEM` refusal** → `load_config` **before** binding the state dir → `CONFIG_STATE_DIR_MISMATCH` → `sensor.run(once=True)` loop | none beyond the sensor's | config verified before any credential read or socket | `test_m1_clean_install.py` | `m1.py:1393-1458` |
| **Async SCM worker (M only)** | `--transaction-scm-worker` (stdin JSON) | `WindowsBackend.call` → job object + `Popen` → record `worker_pid`/creation-time token → `scm_worker.main` (`ChangeServiceConfig`/`StartService`/`ControlService`/`DeleteService` + `wait_for_state`) → acknowledgement validated against the expected operations dir and a 32-hex stem | `operations/<uuid>.json` REQUESTED→FINISHED/UNCERTAIN, with history | kill-on-job-close so a dead parent cannot leave an SCM writer; ACK path validated; `ACK_FAILED` **preserves intent rather than inferring cancellation** | `test_installer_transaction.py` | `transaction.py:676-741`; `scm_worker.py:214-352` |
| **Operator settlement (M)** | `recover-transaction`, `resolve-operation --id --expect-state` | `Owner` lock → `backend.protect` → `Engine.reconcile` / `resolve_operation` (operator assertion **checked against the live SCM**; record amended, never deleted) | transaction and operation records amended | elevation + operations-dir DACL + verification | `test_installer_transaction.py` | `M setup.py:1181-1211`; `transaction.py:787-885` |
| **Task restart (PS1)** | `/SC ONSTART` + `schtasks /Run` | Task Scheduler launches `python nivxforge_sensor.py run` as SYSTEM at boot | none | **no failure actions, no state-dir argument** — the task relies on `ProgramData` resolution (`NIVXFORGE_SENSOR_STATE` is *not* set in the task action) | none | `PS1:181-186`; `sensor.py:49-72` |

### 1.7 Uninstall and purge

| Operation | Entrypoint | Functions | Durable state | Security boundary | Tests | Evidence |
|---|---|---|---|---|---|---|
| **`uninstall [--purge]` (T)** | `main()` → `uninstall()` | `_assert_admin` → `sc stop` → `sc delete` (neither waited nor verified) → `rmtree(INSTALL_DIR, ignore_errors=True)` → if `--purge`: `rmtree(STATE_DIR, ignore_errors=True)` | service entry, `INSTALL_DIR`, optionally **identity + journal + cursors + evidence** | elevation only — **no ownership proof, no exit proof, no inventory, no confirmation; failures are silent** | `test_windows_installer_v1.py::test_uninstall_keeps_evidence_unless_purge_is_requested` (source-text assertion only) | `T setup.py:622-639` |
| **`uninstall` (M)** | same | `SystemExit("uninstall/purge unavailable…")` | none | n/a | — | `M setup.py:1213-1217` |
| **`m1-uninstall` (M)** | `… m1-uninstall --m1-config` | `m1_uninstall`: `Ownership.read`/`owns("service")` → **`NOT_OWNED` refusal** → PID identified **before** stop → proven exit → delete → `ERROR_SERVICE_DOES_NOT_EXIST` or honest `PENDING_DELETION`; identity, journal, cursors, queued evidence, audit and the state dir are **preserved** | ownership record amended; service removed | ownership-bound, fail-closed, no purge by design | `test_m1_clean_install.py` | `m1.py:1294-1353` |
| **`-Uninstall [-Purge]` (PS1)** | PowerShell | `schtasks /End` → `/Delete /F` → `Remove-Item $InstallDir -Recurse -Force` → `-Purge`: `Remove-Item $StateDir -Recurse -Force` | task, program files, optionally the whole state dir | elevation only; **path-match deletion**; does not touch the SCM service | none | `PS1:124-137` |
| **Evidence destruction outside uninstall (M)** | `telemetry-baseline --from-current-tails --discard-queued-evidence` | `_assert_admin` → service must be `STOPPED`/absent → every configured channel must have a baseline → `discard_undelivered()` (DELETE `ACQUIRED/QUEUED/REFUSED_UNACCEPTABLE`) → `rebaseline_cursor` (forward-only) → refresh `channels.json` | **journal rows deleted**, cursors moved forward | well gated and explicit, but **`outbox.jsonl`/`outbox.offset` are not considered** (F-5) | `test_m1_clean_install.py` | `M setup.py:1268-1348`; `M journal.py:407-452` |

---

## 2 · Additional senders, retries, startup paths, async workers

Enumerated rather than assumed.

**Senders (9 routes, all session-bearer, all attributed by session):**
`/agent/enroll`, `/agent/session`, `/agent/telemetry` (×2 call sites — batch
fallback and legacy drain), `/agent/telemetry/batch`, `/agent/heartbeat`,
`/agent/acquisition-integrity`, `/agent/policy` (GET), `/agent/policy-ack`,
`/agent/exclusion-enforcement`. **Identical route sets in both lineages**
(`grep -o '"/api/...'` counts match exactly).

**Retries:** transport reconnect-once (`attempts`, default 2) · `401/403`
token refresh in `_drain_journal`, `_deliver_batch` and `_drain` · batch-route
404/405 bounded cooldown with re-probe · SCM failure actions `restart ×3` ·
service-loop exception swallow + next cycle · `scm_worker.wait_for_state`
budgeted polling. **No exponential backoff, no retry queue, no dead-letter.**

**Startup paths:** `setup.exe --service-run` (SCM, trunk + M1) ·
`setup.exe --m1-service-run` (M1) · `--transaction-scm-worker` (M1) ·
`python nivxforge_sensor.py run` (module CLI) · scheduled task `ONSTART` as
SYSTEM (PS1) · SCM automatic restart after failure.

**Asynchronous work:** exactly one — the M1 SCM worker subprocess (F-8).
`threading`, `Thread(`, `asyncio`, `atexit`, `signal.`, `Timer(` all **zero**
across `nivxforge_{sensor,setup,m1,transaction,scm_worker,content_acquisition}.py`
in both lineages. The sensor is strictly single-threaded and cycle-driven.

---

## 3 · Test coverage, measured

### 3.1 Inventory
Trunk Windows-relevant EDR test files: 18. M1 adds exactly three —
`test_m1_clean_install.py`, `test_installer_transaction.py`,
`test_p0_installer_upgrade_repair.py` — and **removes**
`test_s1_2_c2_clean_install_atomicity.py` (F-7).
Identical blobs across both revisions: `test_windows_installer_v1.py`
(`be136968`), `…reenrol_staging_race.py` (`0099891d`),
`…scm_entrypoint.py` (`bbbc4997`).

### 3.2 Path-resolution styles (decides what a run actually grades)

| Style | Files | Consequence |
|---|---|---|
| `Path("/app/agents/nivxforge-windows")` — absolute | `test_windows_installer_v1.py`, `…scm_entrypoint.py`, `…service_stage4.py`, `…reenrol_staging_race.py`, `test_s1_2_c2_clean_install_atomicity.py`, `test_edr_suite_hermeticity.py`, `test_b5gap1_enrolment_secret_stdin.py`, `fixtures_b5_gap1_source.py`, `test_gate7_endpoint_enforcement.py` | always grades `/app`, whatever tree pytest runs in |
| `Path(__file__).resolve().parents[3] / "agents/nivxforge-windows"` — relative | `test_m1_clean_install.py:24`, `test_p0_installer_upgrade_repair.py:52`, `test_installer_transaction.py:21` | grades the tree it ships in |

### 3.3 Two portable runs performed in this pass

| Run | Target | Result |
|---|---|---|
| `test_windows_installer_v1.py` + `…reenrol_staging_race.py` from a `388bb3d6` export | **graded `/app` = trunk** (absolute paths) | `53 passed` — **valid trunk evidence, zero M1 evidence** |
| `test_m1_clean_install.py` + `test_installer_transaction.py` + `test_p0_installer_upgrade_repair.py` from the same export | genuinely M1 (relative paths) | **`636 passed in 25.41s`** |

The second run is the first measured figure for M1's installer-path tests
beyond the previously recorded `373`. It is **portable-only** and is not
Windows evidence.

### 3.4 Named coverage gaps

No test on either lineage covers: a **successful** publication-level
re-enrolment (the trunk's positive test monkeypatches `sensor.enrol`); the
sensor-module CLI `enrol` against an already-enrolled host; the PS1 `-ReEnroll`
or `-Uninstall` branches; task-versus-service coexistence; legacy-outbox
behaviour across an identity change; or `discard_undelivered` versus the legacy
outbox.

---

## 4 · Material source-access limitations

1. **GitHub Actions run history — UNKNOWN.** Workflow definitions were read;
   whether `windows-sensor-installer.yml` has ever completed is not
   determinable without authorized read-only Actions access. Gate 4's re-enrol
   assertions and the SCM lifecycle gate are therefore **defined, not proven**.
2. **No Windows host.** Every `sc.exe`, `schtasks`, Authz, SD, SCM and
   PyInstaller behaviour is read from source. No native result exists; **G4
   remains NOT RUN**.
3. **No built artifact.** `agents/nivxforge-windows/dist/` is absent in both
   revisions (the connector catalog itself reports the EXE as
   `CI_BUILD_REQUIRED`), so `payload-manifest.json`, `_MEIPASS` layout and
   `self_digest()` were not verified against a real binary.
4. **Backend behaviour inferred from source**, not exercised: no request was
   made to any `/api/edr/agent/*` route and no database was read or written.
5. **ARM64 / x86 packages `NOT_BUILT`** — no Windows execution path exists for
   them to inspect.
6. `nivxforge_transaction.py` upgrade/predecessor logic was mapped structurally
   only; it remains **outside M1's G3 approval** and unreviewed.

---

## 5 · Unchanged-state declaration

`git status --porcelain agents backend apps/nivxray-xdr/src .github docs` →
**0 entries**. No ref created or moved, no commit, no merge, no push, no
workflow run, no installer executed, no database touched, no credential value
read or printed, no artifact published. The frozen subtree
`db21f422561f14fb4dcec91b70925f2b5291c500` is untouched. Exports used for the
two pytest runs were written to `/tmp` via `git archive` and carry no `.git`
metadata; no worktree was registered.

**Reporting stops here. No fixes are designed in this document.**
