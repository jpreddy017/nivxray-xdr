# NIVXFORGE M1 — G3 INTEGRATED CORRECTION · ENGINEERING HANDOFF

Status: **G2 CORRECTED — READY FOR INDEPENDENT G3 VERIFICATION**
Windows-native verification: **NOT RUN** (no Windows host in this environment)

---

## A · Source

| Field | Value |
|---|---|
| Branch | `engineering/m1-g3-integrated` |
| **Commit** | `a4e544f45772a90686d478a19a7ce80201616506` |
| **Tree** | `68f9f0a92515e2b6ee5fefe373912757aa9b8d5b` |
| **Parent** | `601eaa4625984b062be01848004744a5ba6d2603` (tree `9d07cb6c…`, verified clean before editing) |
| Windows agent subtree | `9c7dc0f588e684ef893eb3a1ab04a36e7d152712` |
| Build subtree | `342244773daeff440bf421f2b97e427df516ae77` (unchanged) |
| Frozen candidates | `601eaa46`, `4b3b6a2c`, `0fd09b3a`, `bc8147be` — none mutated |

**Changed files — 3, +1004 / −73**

| File | Δ | What |
|---|---|---|
| `agents/nivxforge-windows/nivxforge_m1.py` | +540/−? | `classify_attributes`, `ancestry_report`, `is_self_process`, `path_state`, `self_process_identity`, `_enumerate_processes`, `worker_processes`, `running_identity`, `_service_access_context`, `_authz_contexts`, `_authz_access_check`, `_sddl_to_descriptor`, authorization-aware `access_context`/`access_check`, `load_config`, `clean_host_report`, `m1_payload_check`, `m1_service_run` |
| `agents/nivxforge-windows/nivxforge_setup.py` | +1/−1 | installer declares `AUTH_INSTALLER` |
| `backend/tests/edr/test_m1_clean_install.py` | +535/−? | 55 new tests; FakeHost gained production-shaped process-table and path-state adapters |

Untouched: the transaction engine, SCM worker, journal, sensor, P0-2 policy, build script, backend, frontend, and every XDR module.

### Export

| Artifact | SHA-256 | Bytes |
|---|---|---|
| `NIVXFORGE_M1_G3_INTEGRATED_SNAPSHOT.bundle` | `f1d11fa9f9a298616519c675359f000ff61895471f3fd0a419c687e8d2dba38b` | 170,347 |
| `NIVXFORGE_M1_G3_INTEGRATED_PROVENANCE.md` | `c4476276c35ec863be46ad940b076a51419f7fbc5f7eda30f935143e6d0ffdfd` | 7,970 |

```
git clone NIVXFORGE_M1_G3_INTEGRATED_SNAPSHOT.bundle m1 && cd m1 && bash VERIFY.sh
python3 -m pytest backend/tests/edr/test_m1_clean_install.py -q
```

Self-contained — "The bundle records a complete history." No external Git
prerequisites. Sanitization and provenance limits: see `PROVENANCE.md` §1/§4,
summarised in §D below.

---

## B · Defect closure

### G3-B1 · installer self-detection

**Root cause.** `worker_processes()` matched `"nivxforge" in name.lower()`.
The installer is `NivXForgeEDRSetup.exe`, so **the running installer matched
itself**, `clean_host_report` recorded `live_worker=PRESENT`, and every
install refused. Compounding it, the installer is a PyInstaller **onefile**
build (`build_windows_installer.ps1:149`), so its bootloader **parent runs the
same executable** and matched too — two phantom competitors.

**Correction** — `nivxforge_m1.py`: `self_process_identity()`,
`_enumerate_processes()`, `worker_processes()`, pure `is_self_process()`.

* Own identity from `GetCurrentProcessId` + `GetProcessTimes` +
  `QueryFullProcessImageNameW`.
* A candidate is excluded only when **pid AND creation timestamp AND image
  path** all agree → a reused pid cannot hide a competitor behind our number.
* The parent bootloader is excluded only when it is really our parent, really
  runs our image, and really started before us.
* A match that cannot be identified is **reported** as `…:unverified`.
* An unknown self identity ⇒ `worker_processes() → None` ⇒ `live_worker`
  UNKNOWN ⇒ refuse.
* `wmic` remains gone (absent from current Windows 11).

**Before/after.** `test_reproduce_b1_bare_name_match_classifies_the_installer`
reproduces both phantoms and the `HOST_NOT_CLEAN` refusal; with the correction
`worker_processes() == []` and the install completes. A second process running
the same executable is still a competitor
(`test_b1_a_second_process_with_the_same_name_is_a_competitor`), as is the real
service worker.

### G3-B2 · fresh destination and Windows path attributes

**Root cause — two faults.**
1. `GetFileAttributesW` had **no `restype`**, so ctypes returned a signed
   `int`: the `INVALID_FILE_ATTRIBUTES` sentinel `0xFFFFFFFF` arrived as `-1`,
   `attributes == 0xFFFFFFFF` was False, and `-1 & FILE_ATTRIBUTE_REPARSE_POINT`
   is truthy — **every absent or inaccessible path was reported as a reparse
   point**. The error code was never consulted at all.
2. `path_ancestry()` included the destination itself, and `clean_host_report`
   ran `directory_security` over the whole chain, so the **expected absence**
   of a fresh destination came back as `unreadable:` and refused.

**Correction** — pure `classify_attributes()`, `ancestry_report()`;
`path_state()`, `is_reparse_point()`, `path_exists()`.

* `path_state` → `ABSENT / DIRECTORY / FILE / REPARSE / UNKNOWN`, from a
  `DWORD` result plus `GetLastError`. Only `ERROR_FILE_NOT_FOUND` and
  `ERROR_PATH_NOT_FOUND` mean absence; `ERROR_ACCESS_DENIED`,
  `ERROR_INVALID_NAME`, `ERROR_BAD_NETPATH`, `ERROR_NOT_READY` and anything
  else are UNKNOWN and refuse.
* A verified-absent leaf is **normal**. An existing one is
  `destination_present`. An UNKNOWN one is `destination_unknown`.
* An absent **intermediate** is named `parent_absent`: `CreateDirectoryW` does
  not build parents, so it is an impossible precondition stated up front
  instead of a later `WinError 3`.
* Existing ancestors are still fully judged: reparse, file-where-directory,
  unreadable, non-administrator-writable.
* The **drive root** is now part of the chain (it was previously skipped).
* **TOCTOU**: `m1_payload_check` re-classifies the destination ancestry at
  time of use, with UNKNOWN refusing, so a link planted after the clean-host
  verdict is caught before a payload byte is written. The leaf itself is
  closed by `CreateDirectoryW`'s create-new semantics.

**Before/after.** `test_reproduce_b2_absent_destination_was_classified_unsafe`
asserts the signed-sentinel arithmetic that caused the misclassification, then
the corrected result. Twelve attribute/error rows, plus absent, existing,
unknown, file-instead-of-directory, absent-parent, reparse-at-leaf/parent/root
and two race injections.

### G3-B3 · LocalSystem versus interactive administrator

**Root cause.** `access_context()` could only build a probe principal by
filtering **the caller's own token**. The service runs as **LocalSystem**,
whose token carries neither `S-1-5-4` (INTERACTIVE) nor `S-1-5-32-545`
(Users). `REQUIRED_CONTEXT_SIDS` was therefore permanently incomplete at
service time → every path check UNKNOWN → `load_config` refused →
**the service could never verify its configuration and could never start.**

**G1 conflict assessment — no accepted requirement was weakened.** The
accepted R4 Amendment A2 requires *"token-aware `AccessCheck` **or** correctly
populated `AuthzAccessCheck`"*. The conflict was with an **implementation
assumption** (that the probe must be filtered from the caller's own token),
not with the accepted contract. The second mechanism A2 already names is
exactly the one that works from LocalSystem, so the contract is satisfied as
written and no amendment is requested.

**Correction** — explicit authorization contexts declared by the entrypoint:

| Context | Declared at | Probe principal |
|---|---|---|
| `AUTH_INSTALLER` | `nivxforge_setup.m1_dispatch` | `DuplicateTokenEx` → `CreateRestrictedToken`, administrative groups deny-only; deny-only and disabled SIDs excluded from the reported context |
| `AUTH_SERVICE` | `m1_service_run` | `AuthzInitializeResourceManager` + `AuthzInitializeContextFromSid` **per required non-administrator SID**, evaluated with `AuthzAccessCheck` |

* `WindowsHost(authorization=…)` validates the value; an unknown one raises.
* `m1_service_run` **proves** it is LocalSystem (`running_identity()`,
  `TokenUser == S-1-5-18`) *before* `load_config`, and refuses with
  `SERVICE_NOT_LOCAL_SYSTEM` or `SERVICE_IDENTITY_UNKNOWN` otherwise.
* `_service_access_context` refuses to apply the service context from a
  non-LocalSystem process.
* **No membership is manufactured.** Unresolved principals are reported as
  `unprobed` and are still required by the completeness check, so they refuse.
* Service-time evaluation probes **each** principal separately — broader than
  one composite token. Granted to any ⇒ grant; denied requires **all** denied;
  one indeterminate principal ⇒ UNKNOWN ⇒ refuse.
* The exhaustive dangerous-trustee ACE walk is **identical** under both
  contexts; only the construction of the probe differs.
* `AuthzInitializeContextFromSid` is declared with its real 7-parameter
  signature and `Identifier` as an **LUID by value**.

**Before/after.** `test_reproduce_b3_a_localsystem_token_cannot_satisfy_the_probe`
computes the missing SIDs (`['S-1-5-4', 'S-1-5-32-545']`);
`test_b3_a_correctly_configured_localsystem_service_can_verify_itself` shows the
path is now reachable;
`test_b3_dangerous_trustee_checks_are_unchanged_under_both_contexts` shows the
ACE walk did not move.

---

## C · Production-path verification (source-backed trace)

Caller identity: **I** = elevated interactive administrator (installer
process), **S** = LocalSystem (service process).

| # | Transition | Who | Production function | Precondition | State change | Failure / UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | entry | I | `nivxforge_setup.main` → `m1_dispatch` | `--m1-config` given | host built as `AUTH_INSTALLER` | unknown authorization raises |
| 2 | self identity | I | `self_process_identity` | own pid resolvable | own pid+created+image known | `None` ⇒ worker probe UNKNOWN ⇒ refuse |
| 3 | exclusivity | I | `exclusive_lock` | named mutex free | installer is sole writer | `CONCURRENT_INSTALLER`; nothing touched |
| 4 | config load | I | `load_config` | file exists; chain exists and verified | `M1Config` + digest | `CONFIG_ABSENT/_ANCESTRY_UNSAFE/_ACL_UNKNOWN/_ACL_UNSAFE/_MALFORMED/_ORIGIN_NOT_HTTPS/_CERT_POLICY` |
| 5 | prior ownership | I | `Ownership.exists/read` | no prior record | proceed | `ALREADY_INSTALLED`, `OWNERSHIP_TORN`, blocking states refuse |
| 6 | clean host | I | `clean_host_report` | service/task/worker ABSENT; destinations verified **absent**; ancestors verified | `clean: True` | any PRESENT **or** UNKNOWN ⇒ `HOST_NOT_CLEAN`, now with per-probe detail |
| 7 | ownership intent | I | `Ownership.create` | config root writable by admin only | durable `CREATE_INTENDED` record | `ALREADY_EXISTS` (no-overwrite) |
| 8 | directories | I | `create_directory_protected` | parent exists, not a link | `C:\…` created with `O:BAG:BAD:PAI(SY,BA)` | `ALREADY_EXISTS` ⇒ refuse; failure ⇒ `CREATE_OUTCOME_UNKNOWN` |
| 9 | directory proof | I | `directory_security(role=owned)` | SD readable | `CREATE_CONFIRMED` + evidence | `None`/unsafe ⇒ `DIR_ACL_UNVERIFIED` |
| 10 | payload gate | I | `m1_payload_check` | manifest supplied; ancestry re-classified | payload admitted | `PAYLOAD_NOT_SUPPLIED/_PATH_UNSAFE/_MISSING/_UNEXPECTED_FILE/_DIGEST_MISMATCH` |
| 11 | delivery | I | `copy_payload` + `_apply_protected_sd` | destination verified | files written, explicit protected SD each | `FILE_SD_APPLY_FAILED` |
| 12 | image provenance | I | `verify_installed_binary` | member in manifest, inside install dir | `sha256` recorded | `SERVICE_EXE_*` — **nothing registered** |
| 13 | enrolment | I | `enroll` → `sensor.enrol` | marker written **first** | `endpoint_id`, `credential_id` | lost/ambiguous ⇒ `CREATE_OUTCOME_UNKNOWN`, no replay |
| 14 | identity publish | I | `sensor` no-overwrite publish | no existing identity | `identity.json` + ACL verified | refuses to overwrite |
| 15 | service create | I | `service_create(start_type=DISABLED)` | service ABSENT | **registration that cannot run** | `SERVICE_NOT_ABSENT`, `SERVICE_CREATE_FAILED` |
| 16 | registration proof | I | `service_qc` | readable | binPath, `DISABLED`, `LocalSystem` confirmed | `SERVICE_UNVERIFIABLE/_NOT_DISABLED/_ACCOUNT_MISMATCH/_IDENTITY_MISMATCH` |
| 17 | SD apply + proof | I | `service_set_security` → `service_security` → `service_security_verdict` | service still DISABLED | descriptor verified by readback | `SERVICE_SD_APPLY_FAILED/_UNREADABLE/_UNSAFE` — stays DISABLED |
| 18 | authorize | I | `service_set_start_type(DEMAND)` | SD verified | eligible for controlled start | `SERVICE_AUTHORIZATION_UNVERIFIED`; binPath+SD re-verified after |
| 19 | start | I | `service_start` | demand-start | SCM reports **RUNNING** | `SERVICE_START_FAILED/_TIMEOUT` |
| 20 | **service config** | **S** | `m1_service_run` → `running_identity` → `load_config` | **proven LocalSystem**; Authz principals resolved | configuration verified under the correct context | `SERVICE_NOT_LOCAL_SYSTEM`, `SERVICE_IDENTITY_UNKNOWN`, `CONFIG_*` |
| 21 | sensor init | S | `sensor.use_state_dir` → `sensor.run(origin, interval, once=True)` | config verified **first** | existing journal + collection loop | config failure precedes any state binding |
| 22 | image proof | I | `verify_running_image` | SCM pid for **this** service | path + digest + association stable | `NOT_RUNNING/NO_PROCESS/IMAGE_MISMATCH/DIGEST_MISMATCH/ASSOCIATION_UNSTABLE/None` ⇒ `SERVICE_IMAGE_UNVERIFIED` |
| 23 | auto-start | I | `service_set_start_type(AUTO)` | running image verified | survives reboot | `SERVICE_AUTOSTART_UNVERIFIED` |
| 24 | record | I | `Ownership.mark(ACTIVATION_VERIFIED)` | all of the above | durable terminal evidence | — |
| 25 | interrupt/restart | I | `Ownership.read` + `blocking` | — | blocking states refuse re-install | `ALREADY_INSTALLED`; uninstall is ownership-bound |

Boundary 19→20 is the one the three defects made unreachable: **2** and **6**
blocked the installer from ever starting, and **20** blocked the service from
ever verifying itself. The trace is asserted by
`test_the_whole_install_path_is_reachable_end_to_end`, which runs the real
orchestration and then performs step 20 under the service context.

### G2 readiness audit — finding → evidence

| Checked for | Method | Result |
|---|---|---|
| Unreachable successful states | full trace above + end-to-end test | none remaining in this path |
| Wrong Windows identity assumptions | B3 | corrected; both contexts explicit and proven |
| Missing host methods / dead calls | AST: every `host.<m>` referenced vs `WindowsHost` members | **none missing** |
| Test-double drift | AST: orchestration calls vs `FakeHost` members | **no gap** |
| Native signature / return errors | `GetFileAttributesW` restype (B2), `AuthzInitializeContextFromSid` 7 params + LUID by value, `AccessCheck` contract (G3-01), HANDLE restypes | corrected |
| Impossible filesystem preconditions | absent-parent vs `CreateDirectoryW` | named as `parent_absent` |
| Process self-identification | B1 | corrected |
| Inconsistent service start conditions | create-disabled → demand → auto ordering test | consistent |
| Result/state propagation | UNKNOWN-propagation tests, ownership evidence | fail-closed |
| UNKNOWN treated as success | every adapter returns `None`; callers refuse | asserted throughout |
| Installer/service context contradiction | B3 | removed |
| Package dependencies | `authz.dll`/`advapi32` are `ctypes.WinDLL` (no hidden import); `win32api`/`win32con`/`win32security` already declared | complete |

**No known material source-level blocker remains in the M1 installation
path.** Remaining risk is native-behaviour risk, listed in §E.

---

## D · Test evidence

Environment: Linux container, Python 3.11, pytest, **pywin32 absent**, no
Windows host, no network, no backend. All results are **simulated**.

```
python3 -m pytest backend/tests/edr/test_m1_clean_install.py -q
    → 330 passed in 2.20s      (275 before; +55 new)

python3 -m pytest backend/tests/edr/test_windows_installer_v1.py \
    test_windows_installer_service_stage4.py test_windows_installer_scm_entrypoint.py \
    test_b5gap1_enrolment_secret_stdin.py test_p0_sensor_delivery_repair.py \
    test_b5_gap1_windows_gate0_ci_contract.py -q
    → 159 passed in 5.07s

python3 -m pytest backend/tests/edr/test_installer_transaction.py \
    test_p0_installer_upgrade_repair.py test_p0_windows_reenrol_staging_race.py \
    test_p0prod2_enrollment_hardening.py -q
    → 306 passed in 24.77s
```

From the **fresh isolated clone** of the published bundle: `git fsck --full
--strict` exit 0, subtree hashes match, 18/18 blob+SHA-256 match, and
`330 passed in 1.92s`. The **downloaded** artifact was re-cloned end to end and
re-verified: `330 passed in 1.78s`.

### Negative controls — reproducing Codex's failures against the defect

Reintroducing all three defects into the corrected source:
**98 failed, 232 passed**. Per defect:

| Defect | Mutation | Result |
|---|---|---|
| B1 | `is_self_process → False` (bare name match) | **7 failed**, 10 passed |
| B2 | signed sentinel + destination walked as an ancestor | **9 failed**, 16 passed |
| B3 | probe must come from the caller's own token | **2 failed**, 8 passed |

Restored and re-run to 330 passed before committing.

### Coverage added

Production process-enumeration adapter (`process_table`, `parent_pid`,
unverifiable pids, mid-sweep exit); existing and absent Windows paths; Windows
API error simulation (12 attribute/error rows, 6 error codes); both token
roles; full clean-install orchestration; service initialization ordering;
payload validation; filesystem security; enrolment identity protection; service
creation/activation ordering; interruption and retry safety; UNKNOWN and
fail-closed behaviour in every adapter.

### Known limitations

* **Test counts are not acceptance.** No test here executes a Win32 call.
* The `FakeHost` mirrors the production adapters' *semantics*; the simulation
  is ours and cannot establish that Windows behaves as documented.
* Two pre-existing `F401` lint findings inherited from `bc8147be` remain; no
  new `F`/`E9` finding.
* **Sanitization.** The candidate tree contains credential material (a bearer
  JWT in `.tok`, JWTs in two `memory/` evidence files, hardcoded admin
  passwords in six unrelated `backend/tests/edr/` live suites). Those paths are
  withheld; no value is printed. **These remain flagged for rotation /
  revocation and exposure assessment — that action is still outstanding and is
  not addressed by this commit.** The snapshot therefore cannot prove the Git
  commit identity `a4e544f4`; it proves content identity (`PROVENANCE.md` §1).

---

## E · Windows G4 readiness — **NOT RUN**

**VM.** Windows 11 23H2+ x64, freshly imaged, isolated network, snapshot
taken before each run, Secure Boot on, one local administrator, an isolated
test backend reachable over HTTPS with a normally-trusted certificate.

**Prerequisites.**
```
icacls C:\ProgramData\NivXForgeM1 /setowner Administrators /T
icacls C:\ProgramData\NivXForgeM1 /inheritance:r ^
  /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
```
Run `m1-install` from an **elevated interactive console session** — not as
SYSTEM, not via `PsExec -s`: the installer context needs an interactive token.
The destination's parent must exist; the destination itself must not.

**Build.** `build\build_windows_installer.ps1` on the VM (PyInstaller,
pywin32 present), then verify the payload manifest is embedded.

**Verification procedures.**
1. SCM: `sc qc`, `sc queryex` — created **DISABLED**, final **AUTO**,
   `LocalSystem`, binPath exact.
2. ACL: `sc sdshow`, `accesschk -c`, `Get-Acl` — owner, protected DACL,
   SYSTEM + Administrators only; a standard user can neither start, stop,
   reconfigure nor delete.
3. Token: confirm `AccessCheck` with a real standard-user token and
   `AuthzAccessCheck` from each required SID agree with the ACE walk; confirm
   the installer context carries all four required SIDs.
4. Paths: `fsutil reparsepoint query`, `icacls` on every ancestor; confirm an
   absent destination is accepted and an existing one refused.
5. Self-detection: confirm the install proceeds with the onefile bootloader
   running, and refuses when a second copy of the installer is started.
6. Enrolment: single attempt against the test backend, including a lost
   response; confirm no re-enrolment.
7. Telemetry: a genuine Windows event → journal → backend → raw evidence →
   canonicalisation → **Device Trajectory**, correct endpoint and tenant.
8. Negative security: unsafe service DACL, tampered binary, planted link,
   non-LocalSystem service account, pre-existing service/task/identity — each
   must refuse without activating anything.
9. Reboot: auto-start after reboot; interrupt after create and after
   `DEMAND_START`, reboot, confirm the service does not run in the first case
   and is fully secured in the second; confirm ownership-bound uninstall
   preserves evidence.

G4 operational success — secure install → protected service → enrolment →
real telemetry → correct tenant → investigation visibility → reboot recovery —
is a **separate milestone** and is not claimed here.

---

## Boundaries honoured

No G0/G1 restart; no sensor rebuild; no transaction-engine rewrite; no
unrelated backend/frontend change; no new detection features; no weakened
authentication, ACL or tenant isolation; no disabled tests; no merge or
deployment; no HOLD removed. The author of the baseline, the designs and this
correction **cannot self-approve** — independent Codex G3 verification is
required before native G4.
