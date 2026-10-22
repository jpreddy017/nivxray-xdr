# NIVXFORGE EDR — M1 G2 CORRECTIVE IMPLEMENTATION HANDOFF
## Repair of the five defects raised by the independent G3 review

| Field | Value |
|---|---|
| Repository | `jpreddy017/nivxray-xdr` |
| Corrective branch | `engineering/m1-g3-corrective` |
| Commit | `4b3b6a2c7c7fc2f339bd2725c28d942f6693d575` |
| Tree | `c9fae8dd5abd526fc53306717e9ae449a658a9ad` |
| Parent (G3-FAIL candidate) | `0fd09b3a1f9eacfab12e41ef7c6d971a98ecdcae` |
| Parent tree, verified before edit | `c9dc8ab9062d16e370a79e497e78d954dc4ec1b8` |
| Baseline of the parent | `bc8147be15af46e87a95612322e7d17f3859f587` |
| Status | **M1 G2 CORRECTED — READY FOR INDEPENDENT G3 RE-REVIEW** |
| Windows-native verification | **NOT RUN** (no Windows host in this environment) |

The existing commit `0fd09b3a` was **not mutated**. The corrective branch was
created from it and contains exactly one additional commit.

### Artifacts

| Artifact | SHA-256 | Bytes |
|---|---|---|
| `NIVXFORGE_M1_G3_CORRECTIVE.bundle` | `0657a5784bc1f57d5272a1d92c6fc18ecee6089177a46de5e3b23460e9bc4691` | 24,756 |
| `NIVXFORGE_M1_G3_SOURCE_DIFF.patch` | `930e29aa19e915090bdf2ccaeef313887a076586cf863574fbcba7b92972d9bf` | 108,159 |

The bundle requires `0fd09b3a1f9eacfab12e41ef7c6d971a98ecdcae` to be present
in the receiving repository. `git bundle verify` reports it as ok.

---

## 1 · Changed files

`4 files changed, 1770 insertions(+), 149 deletions(-)`

| File | Change |
|---|---|
| `agents/nivxforge-windows/nivxforge_m1.py` | +1103/−? — native host surface, filesystem verdict, payload provenance, activation ordering |
| `agents/nivxforge-windows/nivxforge_setup.py` | +37/−? — `m1_payload_source()` wired into `m1_dispatch`, win32 packaging declaration |
| `agents/nivxforge-windows/build/build_windows_installer.ps1` | +1 — `--hidden-import win32con` |
| `backend/tests/edr/test_m1_clean_install.py` | +778 — negative tests for the five defects |

Untouched, by design: `nivxforge_transaction.py`, `nivxforge_scm_worker.py`,
`nivxforge_journal.py`, `nivxforge_sensor.py` (no change in this commit), the
P0-2 policy surface, the backend, the frontend, and every XDR component.

---

## 2 · Five-defect closure matrix

### P0-1 — native Windows security methods · CLOSED

| Obligation | Implementation | Source |
|---|---|---|
| Apply the service SD | `SetServiceObjectSecurity` with OWNER+GROUP+DACL+PROTECTED_DACL | `nivxforge_m1.py:1588 service_set_security` |
| Read the SD back | `QueryServiceObjectSecurity`, normalised, never trusted from the write | `:1616 service_security` |
| Access-token context | `DuplicateTokenEx` → `CreateRestrictedToken` disabling Administrators, Domain/Schema/Enterprise Admins; deny-only and disabled SIDs excluded | `:1803 access_context` |
| Token-aware effective access | `win32security.AccessCheck`, one dangerous right per call | `:1864 access_check` |
| Generic rights | every ACE mask resolved through the object GENERIC_MAPPING **before** the SD reaches the OS | `:432 map_generic`, `:1377 _descriptor_to_sd` |
| Owners | owner must be SYSTEM / Administrators / TrustedInstaller; an owner holds WRITE_DAC implicitly | `:616 filesystem_ace_inspection`, `:490 ace_inspection` |
| Groups and service SIDs | compared by SID, so nesting cannot hide a grant; service SIDs (`S-1-5-80-…`) are not privileged trustees | `DANGEROUS_*` tables, tested in `DANGEROUS_PATH_CASES` |
| Deny ACEs | recorded, never credited as cancelling a dangerous allow; emitted first when M1 writes an ACL | `:616`, `:1377` |
| Unsupported descriptors | object/callback ACE layouts are recorded by TYPE and refuse; an undecodable ACL is `malformed`; a NULL DACL is distinguished from an empty one | `:713 normalise_descriptor` |
| Uncertainty prevents activation | every host method returns `None` for UNKNOWN and every call site treats `None` as unsafe | `m1_install`, `path_security_verdict` |

Also repaired here: `OpenProcess`, `CloseHandle`, `CreateMutexW`,
`GetProcessTimes`, `QueryFullProcessImageNameW` and
`CreateToolhelp32Snapshot` now carry explicit `restype`/`argtypes`. Without
them ctypes truncates a HANDLE to a C int on 64-bit Windows and every
handle-based proof silently degrades.

### P0-2 — service activation ordering · CLOSED

The sequence in `m1_install` (`nivxforge_m1.py:930`–`1010`):

1. `service_create(..., start_type=SERVICE_DISABLED)` — **created disabled**.
2. Read back and verify `bin_path`, `start_type_code == DISABLED`, and
   `account == LocalSystem`. Any mismatch → `CREATE_OUTCOME_UNKNOWN`, refuse.
3. Apply the restrictive descriptor **while the service cannot run**.
4. Read the descriptor back and run both A2 checks. Unsafe or unreadable →
   refuse; the service stays DISABLED.
5. Verify the delivered binary's identity and hash (P1-3).
6. Authorise `DEMAND_START`, re-verify the start type, re-verify the binPath
   and **re-verify the descriptor** after the config change.
7. Start, and wait for the SCM to report RUNNING.
8. Verify the running image (path, SCM-reported pid, digest, stability).
9. Only now `AUTO_START`, read back and confirm.

An interruption or reboot anywhere before step 6 leaves a service the SCM
will not launch; between 6 and 9 it leaves a demand-start service that no
reboot starts, and whose descriptor and binary have already been verified.
`start= auto` at creation time — the defect — is gone.

### P1-3 — trusted payload delivery · CLOSED

| Obligation | Implementation | Source |
|---|---|---|
| Wire `bundle_root`/`manifest` to the real entrypoint | `m1_payload_source()` resolves `sys._MEIPASS` + `payload-manifest.json` and is passed into `m1_install` | `nivxforge_setup.py: m1_payload_source`, `m1_dispatch` |
| No payload, no install | `PAYLOAD_NOT_SUPPLIED` — the kwargs are no longer optional in effect | `nivxforge_m1.py:900` |
| Trusted provenance | the service image must be a manifest MEMBER inside the install directory | `:796 resolve_service_binary` |
| Hash verification | on-disk digest compared to the manifest after delivery, and the RUNNING image's digest compared again | `:826 verify_installed_binary`, `:1760 verify_running_image` |
| Ambiguity | two members differing only in case are `SERVICE_EXE_AMBIGUOUS`, because the filesystem cannot tell them apart | `:796` |
| Never execute an existing unverified binary | directories are CREATE_NEW (an existing one refuses), the image is hash-verified before registration, and the registration is only authorised after that | `m1_install` |

Refusal codes: `SERVICE_EXE_OUTSIDE_PAYLOAD`, `SERVICE_EXE_NOT_IN_MANIFEST`,
`SERVICE_EXE_AMBIGUOUS`, `SERVICE_EXE_MISSING`, `SERVICE_EXE_UNPROTECTED`,
`SERVICE_EXE_UNVERIFIABLE`, `SERVICE_EXE_DIGEST_MISMATCH`. None of them
registers a service.

### P1-4 — filesystem security validation · CLOSED

The previous `_security()` unpacked `GetAce` incorrectly, judged only a write
mask, credited `-512`, and ignored owner, inheritance and token semantics. It
is replaced by the same two-mechanism design used for the service object:

* `filesystem_ace_inspection` (`:616`) — exhaustive allow-ACE walk with the
  FILE generic mapping, SID comparison, owner control, inherit-only handling,
  and refusal of unknown ACE types, unparseable trustees, masks and flags.
* `filesystem_token_verdict` (`:672`) — per-right `AccessCheck` against the
  restricted non-administrator token, with the FILE mapping.
* `path_security_verdict` (`:699`) — both must pass; `None` means UNKNOWN and
  every call site treats UNKNOWN as unsafe.

Three roles, because the question differs by object:

| Role | Dangerous rights | Protected DACL required |
|---|---|---|
| `ancestor` | WRITE_DATA, DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER | no |
| `file` | the above + APPEND_DATA, WRITE_EA, WRITE_ATTRIBUTES | no |
| `owned` | the above | **yes** |

`FILE_APPEND_DATA` is deliberately not dangerous on an **ancestor**: the
default Windows 11 `C:\` DACL grants Authenticated Users "create folders /
append data" on that folder only, which permits a NEW subdirectory but cannot
replace an existing one — and M1's own directory creation is CREATE_NEW, so an
attempt to pre-create the target refuses. Treating it as dangerous there would
refuse every default host while protecting nothing. On an object M1 owns it IS
dangerous, and is in the table. This asymmetry is asserted by
`test_append_data_is_dangerous_on_an_owned_path_only`.

Inherit-only ACEs do not apply to the object that carries them, which is why
`C:\`'s inherit-only "Modify for Authenticated Users on subfolders and files"
does not condemn the ancestry — and exactly why every directory M1 creates is
PROTECTED and re-verified in the `owned` role.

### P1-5 — native process and image verification · CLOSED

| Obligation | Implementation | Source |
|---|---|---|
| Authoritative termination evidence | `OpenProcess` + `GetProcessTimes`; ERROR_INVALID_PARAMETER is ABSENT, ACCESS_DENIED is UNKNOWN | `:1713 process_identity` |
| PID reuse | the identity (creation timestamp) is captured **before** the stop and compared after; a different timestamp means the number was reused and our process is gone | `:751 exit_verdict`, `m1_uninstall` |
| Running image identity | `QueryFullProcessImageNameW`, compared with Windows path semantics, then the digest compared to the attested one | `:1760`, `:773 image_path_matches` |
| Service/PID association | the pid comes from `QueryServiceStatusEx` for THIS service, not from a name match | `:1760` |
| SCM uncertainty | re-read after inspection; a changed pid or a changed process behind it is `ASSOCIATION_UNSTABLE`, not a match | `:1760` |
| Unknown is never success | `None` and every non-`MATCH` verdict raise `SERVICE_IMAGE_UNVERIFIED` / `PROCESS_EXIT_UNPROVEN` / `PROCESS_IDENTITY_UNKNOWN` | `m1_install`, `m1_uninstall` |

`m1_uninstall` now refuses with `PROCESS_IDENTITY_UNKNOWN` **before** issuing
the stop when the process identity cannot be established.

---

## 3 · Additional material blockers found in the bounded M1 audit

All were guaranteed-refusal or silent-degradation defects on a supported
Windows 11 host. All are repaired in this commit.

| # | Finding | Repair |
|---|---|---|
| A1 | `worker_processes` used `wmic`, which is deprecated and **absent from current Windows 11 images**. The probe would answer UNKNOWN forever and refuse every install. | `CreateToolhelp32Snapshot` enumeration |
| A2 | `scheduled_task_lookup` matched the English string "cannot find", so every non-English Windows answered UNKNOWN and refused. | a task IS a file under `%SystemRoot%\System32\Tasks` — a locale-independent probe |
| A3 | `service_qc`/`service_lookup` parsed `sc.exe` text, which is localised, and could not report the start type or pid that P0-2 and P1-5 now depend on. | `QueryServiceConfig` + `QueryServiceStatusEx`; `DeleteService` 1072 detected by winerror, not by substring |
| A4 | ctypes HANDLEs were declared as C ints. | explicit `restype`/`argtypes` |
| A5 | Objects created by an elevated administrator are owned by the **creating user account**, not the Administrators group (Windows default "object creator"). Every created directory and the copied service image would have failed the owned-role owner check, refusing every install. | `O:BAG:BA` in the creation SDDL, and an explicit protected descriptor applied to each copied payload member |
| A6 | `win32con` became a new runtime dependency and was not declared. | `--hidden-import win32con`, plus `_M1_REQUIRED_WIN32`, kept out of the cross-platform provenance gate so it stays importable off Windows |
| A7 | `service_start` returned as soon as the start request was accepted. | waits for the SCM to report RUNNING; an immediate stop reports the exit code |

**OPEN (not a code defect, a documented prerequisite).** `access_context()`
reports only the SIDs the token actually carries and substitutes nothing. A
LocalSystem token carries neither INTERACTIVE (`S-1-5-4`) nor Users
(`S-1-5-32-545`), so the required context would be incomplete and the install
would refuse. **`m1-install` must be run from an elevated interactive console
session on the test VM, not as SYSTEM and not via a service or PsExec -s.**

**OPEN.** The pre-provisioned configuration root must be owned by
Administrators or SYSTEM and must not be writable by a non-administrator.
Provision it explicitly, e.g.:

```
icacls C:\ProgramData\NivXForgeM1 /setowner Administrators /T
icacls C:\ProgramData\NivXForgeM1 /inheritance:r ^
  /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
```

Otherwise `load_config` refuses with `CONFIG_ACL_UNSAFE` or
`CONFIG_ANCESTRY_UNSAFE`, naming the owner or the trustee at fault.

---

## 4 · Tests — commands and actual results

All results below were produced in this environment, on Linux, with pywin32
absent. They are **simulated**, not native Windows evidence.

```
cd <repo>
python3 -m pytest backend/tests/edr/test_m1_clean_install.py -q
    → 187 passed in 1.87s

python3 -m pytest backend/tests/edr/test_windows_installer_v1.py \
    backend/tests/edr/test_windows_installer_service_stage4.py \
    backend/tests/edr/test_windows_installer_scm_entrypoint.py \
    backend/tests/edr/test_b5gap1_enrolment_secret_stdin.py \
    backend/tests/edr/test_p0_sensor_delivery_repair.py \
    backend/tests/edr/test_b5_gap1_windows_gate0_ci_contract.py -q
    → 159 passed in 4.97s

python3 -m pytest backend/tests/edr/test_installer_transaction.py \
    backend/tests/edr/test_p0_installer_upgrade_repair.py \
    backend/tests/edr/test_p0_windows_reenrol_staging_race.py -q
    → 281 passed in 24.32s

python3 -m pytest backend/tests/edr/test_p0prod2_enrollment_hardening.py \
    backend/tests/edr/test_p0_a2_enrollment.py -q
    → 54 passed in 1.49s
```

Isolation smoke, from a fresh interpreter:

```
engine modules at import: []
m1 parse ok: m1-install /x/m1-config.json
enterprise default backend: https://nivxray.nivxforge.com
```

Lint: `ruff check --select F,E9` reports two pre-existing F401s
(`import sys`, a nested `import ctypes`) that are present in the parent
commit and were not introduced here. No new F or E9 finding.

### Negative control

Reintroducing the P0-2 defect — a single edit changing
`start_type=SERVICE_DISABLED` back to `SERVICE_AUTO_START` in `m1_install` —
produces **46 failed, 135 passed**. The ordering tests are load-bearing, not
decorative. The original file was restored and the suite re-run to 187 passed
before the commit.

### What the new tests cover

* **P0-1** — no `NOT_IMPLEMENTED_NATIVE` remains; each security-critical method
  calls its documented API; pointer-sized handle declarations; descriptor
  normalisation of a standard ACL, a NULL vs empty DACL, an unreadable ACE, an
  unknown ACE layout and an unresolvable SID.
* **P0-2** — created disabled; descriptor applied while disabled; the full
  create → secure → authorise → start → verify → auto-start order; a crash
  before authorisation leaving a service the SCM refuses to start; an unsafe or
  unreadable descriptor leaving it disabled; a service created enabled refused;
  a wrong service account refused; a binPath or descriptor that changes during
  authorisation refused; auto-start withheld until the image verifies.
* **P1-3** — install without a payload; the entrypoint wiring; an image outside
  the payload, absent from the manifest, case-ambiguous, tampered, missing,
  unprotected or with an unreadable ACL; the running-image digest comparison;
  the attested digest recorded in the ownership evidence.
* **P1-4** — the approved descriptor safe in all three roles; 10 dangerous
  trustee/right combinations × 2 roles refused; seven unparseable-descriptor
  cases; the protected-DACL requirement for owned objects only; inherit-only
  handling; the append-data asymmetry; deny-before-allow; FILE generic mapping;
  an unknown role; per-right probing with the FILE mapping; indeterminate and
  incomplete-context refusals; a token grant invisible to the ACE walk still
  refusing; the install verifying its own directories in the `owned` role.
* **P1-5** — nine `exit_verdict` cases including PID reuse and both unknown
  directions; the exit proof bound to the pre-stop identity and ordered after
  the stop; an unknown identity preventing the stop; an already-absent process
  not blocking removal; six path-comparison cases; the image verified before
  auto-start; structured image evidence.
* **Audit** — explicit owner in both SDDLs, the creator-owned refusal, the three
  approved owners, no child process in any host probe, and the win32 packaging
  declaration.

---

## 5 · Residual limitations — what is still NOT proven

**No Windows-native verification was executed.** Nothing below has been
observed; all of it is inference from documentation and code review.

1. `SetServiceObjectSecurity` with `PROTECTED_DACL_SECURITY_INFORMATION` and an
   explicit owner, and whether setting the owner to Administrators succeeds
   from an elevated admin token without `SeRestorePrivilege`.
2. The pywin32 `AccessCheck` return convention. The implementation handles both
   — `(granted, status)` and a raised `ERROR_ACCESS_DENIED` — and treats every
   other failure as UNKNOWN. A denial misread as UNKNOWN refuses, which is the
   safe direction; a grant can only come from an explicit positive status.
3. Whether the restricted token carries the four required context SIDs in the
   intended session (see the OPEN prerequisite above).
4. `PySECURITY_DESCRIPTOR.GetAce` tuple layout for every ACE type encountered on
   a real service and a real directory.
5. SCM semantics: create-disabled, `ChangeServiceConfig` transitions, start
   timing, `ERROR_SERVICE_MARKED_FOR_DELETE` (1072), pending deletion with a
   live handle.
6. `CreateDirectoryW` with a `SECURITY_ATTRIBUTES` SD, and `SetNamedSecurityInfo`
   on each copied member.
7. `GetProcessTimes` / `QueryFullProcessImageNameW` under
   `PROCESS_QUERY_LIMITED_INFORMATION` for a LocalSystem service process.
8. The frozen build: PyInstaller hidden imports, the embedded payload manifest,
   and `_MEIPASS` resolution for the M1 path.
9. The M1 service adapter actually hosting the existing sensor collection loop
   under the SCM.
10. Everything downstream of the endpoint: enrolment against an isolated test
    backend, raw ingestion, canonicalisation, Device Trajectory association.
    The reviewed snapshot does not contain a complete backend/frontend for this
    (M1-10, unchanged).

The FakeHost simulates the OS surface. Every security verdict the tests assert
is produced by the real implementation reading simulated state — but the
simulation is ours, and it cannot establish that Windows behaves as documented.

---

## 6 · G4 Windows VM acceptance checklist

On one freshly imaged, isolated Windows 11 test VM, from an **elevated
interactive console session**:

1. Provision the configuration root per §3, and confirm `m1-install` refuses
   with a named owner/trustee problem when it is not provisioned.
2. Confirm the fresh-host refusals: a pre-existing service, task, directory,
   identity, live worker, and each UNKNOWN probe.
3. Install. Confirm from an independent tool (`sc qc`, `icacls`,
   `Get-Acl`, `accesschk`) that the service was created DISABLED, that the SD
   was applied while disabled, and that the final start type is AUTO.
4. Verify the service SD independently: owner, protected DACL, SYSTEM and
   Administrators only, and that a standard user can neither start, stop,
   reconfigure nor delete it.
5. Verify `AccessCheck` behaviour against the live descriptor with a real
   standard-user token, and confirm the required context SIDs are present.
6. Verify the install/state directory and payload ACLs and owners.
7. Confirm the running image: SCM pid, image path, digest equal to the manifest.
8. Inject each P1-3 failure (member removed, byte changed, manifest entry
   removed, image placed outside the payload) and confirm no registration.
9. Interrupt after create and after `DEMAND_START`, reboot, and confirm the
   service does not run in the first case and is correctly secured in the
   second.
10. Single-attempt enrolment against the isolated test backend, including a lost
    response, and confirm no re-enrolment.
11. `m1-uninstall`: owned-only removal, pending-delete and live-process paths,
    PID reuse, and preservation of identity, journal, cursors and evidence.
12. Genuine Windows event → journal → test backend → raw evidence →
    canonicalisation → Device Trajectory, with the correct endpoint and tenant.

---

## 7 · Independent reviewer checklist

1. Verify `git bundle verify`, the commit, the tree and the parent; confirm
   `0fd09b3a` is unchanged.
2. Confirm nothing outside the four changed files moved, and that the
   transaction engine, SCM worker, journal, sensor, backend and frontend are
   byte-identical to the parent.
3. For each of P0-1…P1-5, read the cited source and decide whether the defect is
   closed **at the mechanism level**, not merely tested.
4. Attack the role split in §P1-4. The append-data asymmetry and the
   inherit-only exclusion are the two places where a narrowing was accepted for
   a stated reason; both are asserted by tests. Decide whether the reasons hold.
5. Attack the `AccessCheck` dual-convention handling and the argument that a
   raised ERROR_ACCESS_DENIED cannot be a missing TOKEN_QUERY.
6. Re-run the four test commands in §4 and the negative control.
7. Confirm no test, fake or ACL rule was weakened: the FakeHost answers no
   security question with a hardcoded "safe", and the inherit-only skip in the
   fake mirrors the real SD builder.
8. Decide G3. The author of the baseline, the G1 designs, the G2 candidate and
   this correction is the same agent and **cannot self-approve**.

Security, release and rollout HOLDs remain in force. No production deployment,
merge, rollout or HOLD removal has been performed or is requested here.
