# NIVXFORGE M1 — G3-B3 AUTHZ RESULT CORRECTION · ENGINEERING HANDOFF

**Status: G2 corrective implementation complete. Awaiting independent Codex G3
review. Not approved, not merged, not deployed, not signed. No Windows-native
execution has taken place.**

| Field | Value |
|---|---|
| Repository | `jpreddy017/nivxray-xdr` |
| Branch | `engineering/m1-g3-integrated` |
| Commit | `388bb3d637a076f36d78fc9d1e218c878b082b9b` |
| Tree | `df8eb48b5719b01c936c8dec3442aeba7763a59f` |
| Parent | `a4e544f45772a90686d478a19a7ce80201616506` |
| `agents/nivxforge-windows` subtree | `db21f422561f14fb4dcec91b70925f2b5291c500` |
| `agents/nivxforge-windows/build` subtree | `342244773daeff440bf421f2b97e427df516ae77` (unchanged) |
| Diff against parent | `2 files changed, 453 insertions(+), 28 deletions(-)` |
| Worktree | clean for both exported paths (`git status --porcelain agents backend` empty) |

---

## A · The defect

`WindowsHost._authz_access_check()` in
`agents/nivxforge-windows/nivxforge_m1.py` read the AuthzAccessCheck outcome
as a single flag:

```python
return access_check_verdict(bool(ok) and int(error[0]) == 0,
                            1 if mask else 0, mask, wanted)
```

`AuthzAccessCheck` reports **two separate things** and this collapsed them.
The `BOOL` return says whether the evaluation **ran**;
`AUTHZ_ACCESS_REPLY.Error[i]` is the status of **that evaluation**. Microsoft
documents `ERROR_ACCESS_DENIED` in `Error[i]` as the ordinary per-result
status for a request the descriptor does not grant — a **verified denial**,
not a failure.

Consequences in the production path:

1. A correctly restrictive descriptor (SYSTEM and Administrators only) returns
   `Error[0] = 5`, `GrantedAccessMask[0] = 0` for every non-administrator
   principal. The collapsed flag turned that into "the call failed", and
   `access_check_verdict` then returned **UNKNOWN**.
2. `token_access_verdict()` therefore recorded
   `access evaluation for <right> was indeterminate` for every dangerous right,
   so `service_security_verdict()` was never `safe` and `load_config()` always
   refused — under LocalSystem the service could never validate its own
   configuration or start. **The B3 path was unreachable for a legitimate,
   correctly configured install.**
3. A second, opposite error was latent in the same expression: when a
   successful evaluation reported `ERROR_SUCCESS` with a **zero** granted mask
   — a self-contradictory reply — `1 if mask else 0` produced
   `AccessStatus = FALSE`, and the code reported a **verified denial from a
   reply it did not understand**. One defect refused valid denials; its
   mirror manufactured one.

A separate ABI defect in the same wrapper: `AuthzAccessCheck.argtypes[0]`
(`Flags`) was declared `ctypes.c_longlong`. `Flags` is a `DWORD`.

---

## B · The correction

### B.1 `authz_access_verdict()` — a pure four-way contract (new, module level)

```
True  — call SUCCEEDED, Error == ERROR_SUCCESS, every requested right present
        in GrantedAccessMask
False — call SUCCEEDED, Error == ERROR_ACCESS_DENIED, none of the requested
        rights present. The ONLY verified denial.
None  — the call failed; or the reply code is one we do not understand; or the
        code and the mask contradict each other.
```

Refused as UNKNOWN, explicitly: `ok` that is not literally `True`; a
non-integer or `bool` reply code, granted mask or desired mask; a negative
reply code or mask; an empty desired mask or one still carrying unmapped
generic bits; `ERROR_SUCCESS` with the request not fully granted;
`ERROR_ACCESS_DENIED` with a requested bit still granted; every other
per-result code (`ERROR_INVALID_SECURITY_DESCR`, `ERROR_PRIVILEGE_NOT_HELD`,
anything unforeseen).

`access_check_verdict()`, which governs the installer-time `AccessCheck` path,
is **untouched**; the G3-01 correction (a native exception, including
WinError 5, is UNKNOWN and never a denial) stands unchanged.

### B.2 `_authz_access_check()` — lifetime plus interpretation only

Converts the SDDL, calls the native edge, frees the descriptor with
`LocalFree` in a `finally` so it is released on **every** path including a
raised call, and defers the verdict entirely to `authz_access_verdict()`. An
unconvertible descriptor returns UNKNOWN without invoking anything and frees
nothing. The method contains no `return False` of its own.

### B.3 `_authz_invoke()` — the native call, raw outputs only (new)

Carries the `AUTHZ_ACCESS_REQUEST` / `AUTHZ_ACCESS_REPLY` structures, the
`restype`/`argtypes` declarations and the call; returns
`(ok, Error[0], GrantedAccessMask[0])` and interprets nothing, or `None` when
the resource manager was never built. `Flags` is now `wintypes.DWORD` per the
published ABI; the remaining widths, structure layouts, the single-result
reply arrays and the handle/descriptor lifetimes are preserved as they were.

### B.4 What was deliberately NOT changed

Fail-closed behaviour on genuine native failure; `ace_inspection()` and the
exhaustive dangerous-trustee walk; `APPROVED_TRUSTEES`; the requirement that
every one of `REQUIRED_CONTEXT_SIDS` be resolved (an `unprobed` principal
still refuses); the per-principal combination rule in `access_check()`
(granted to any = GRANTED, denied to all = DENIED, one unknown = UNKNOWN); the
installer-time restricted-token context; the LocalSystem proof at the service
entrypoint; every accepted G1 contract and every security HOLD.

---

## C · Production path trace

`m1_service_run(argv)` — `nivxforge_m1.py`

| # | Step | Behaviour |
|---|---|---|
| 1 | `os.name != "nt"` | `M1Error("NOT_WINDOWS")` |
| 2 | `--m1-config` absent | `M1Error("CONFIG_ABSENT")` |
| 3 | `host = WindowsHost(authorization=AUTH_SERVICE)` | the service context is **declared** by the entrypoint, never inferred |
| 4 | `host.running_identity()` | `None` → `SERVICE_IDENTITY_UNKNOWN`; not S-1-5-18 → `SERVICE_NOT_LOCAL_SYSTEM`. Ordered **before** step 5 |
| 5 | `load_config(config_path, host)` | see below |
| 6 | state-dir agreement, then the existing sensor loop under the SCM | unchanged |

`load_config(path, host)` → the corrected wrapper

| # | Step | Behaviour |
|---|---|---|
| 1 | `host.is_file(path)` | `CONFIG_ABSENT` |
| 2 | `ancestry_report(path, host, leaf_must_be_absent=False, leaf_is_file=True)` | each existing ancestor is classified (B2) and judged; `CONFIG_ANCESTRY_UNSAFE` |
| 3 | `host.file_security(path)` → `path_security_verdict(descriptor, ROLE_FILE, host)` | `None` → `CONFIG_ACL_UNKNOWN` |
| 4 | → `filesystem_ace_inspection()` | a dangerous allow ACE is disqualifying on its own, independent of any probe |
| 5 | → `filesystem_token_verdict()` → `host.access_context()` | service role → `_service_access_context()` → LocalSystem proof → `_authz_contexts(REQUIRED_CONTEXT_SIDS)`; `None` or an incomplete set refuses |
| 6 | → `host.access_check(descriptor, context, right, FILE_GENERIC_MAPPING)` | `descriptor_to_sddl`, `map_generic`, then one `_authz_access_check` per resolved principal, per right |
| 7 | → `_authz_access_check()` → `_sddl_to_descriptor` → `_authz_invoke` → `authz_access_verdict` | **the correction**: error 5 with no granted right is now DENIED, not UNKNOWN |
| 8 | verdict combination in `access_check()` | granted to any = GRANTED → `non-administrator context is granted <right>`; one unknown = UNKNOWN → `access evaluation for <right> was indeterminate`; denied to all = DENIED → no problem recorded |
| 9 | `nonadmin_writable` for ANY problem | `CONFIG_ACL_UNSAFE` |
| 10 | digest, required keys, HTTPS origin, certificate policy, metadata ACL and digest drift | unchanged |

Net effect: step 7 is the only behavioural change, and it is what makes steps
8–10 reachable for a legitimately restrictive configuration under LocalSystem.
The installer-time path reaches step 6 and then `_access_check_native()`,
which is untouched.

### Related authorization-result interpretation, audited

- `access_check_verdict()` — installer path, unchanged; a failed call is never
  a denial (G3-01).
- `_authz_contexts()` — resource-manager failure → `None` (refuse); an
  unresolved SID is absent from the result and reported as `unprobed`, never
  as "checked".
- `_service_access_context()` — refuses unless the process is actually
  LocalSystem.
- `_service_handle()` / `service_lookup()` — only WinError **1060**
  (`ERROR_SERVICE_DOES_NOT_EXIST`) reads as ABSENT; every other code is
  UNKNOWN. No other site collapses a Windows error code into a verdict.

---

## D · Evidence

### Regression proof — the tests fail against the defective code

The defective reading was reintroduced into the corrected source (the
collapsed `access_check_verdict(bool(ok) and reply_error == 0, 1 if granted
else 0, …)` and `Flags = c_longlong`) and the suite was re-run:

```
7 failed, 366 passed in 3.30s
```

Failing under the defective behaviour:

| Test | Proves |
|---|---|
| `test_b3_the_production_wrapper_denies_on_error_five_with_no_rights` | the verified denial was reported as UNKNOWN |
| `test_b3_an_inconsistent_granted_mask_is_unknown[reply0]` | `ERROR_SUCCESS` with a zero mask was reported as a **denial** |
| `test_b3_one_indeterminate_principal_still_makes_the_answer_unknown` | per-principal combination over real replies |
| `test_b3_a_restrictive_descriptor_now_passes_service_time_validation` | the blocker itself: the legitimate descriptor was unevaluable |
| `test_b3_load_config_validates_under_the_real_authz_wrapper` | the full service-time `load_config` trace |
| `test_b3_the_wrapper_no_longer_collapses_the_reply_code` | the collapsed expression is gone |
| `test_b3_the_native_edge_reads_the_reply_arrays_it_was_given` | `Flags` is a `DWORD`; the edge returns raw outputs |

Source was then restored and re-run: **373 passed**.

### Suites run (portable, Linux, no Windows host)

| Suite | Command | Result |
|---|---|---|
| M1 clean installer | `pytest backend/tests/edr/test_m1_clean_install.py -q` | **373 passed in 3.01s** (+43) |
| B1 subset | `-k "b1 or self_detect or worker"` | 19 passed |
| B2 subset | `-k "b2 or absent or reparse or ancestry"` | 35 passed |
| B3 subset | `-k "b3"` | 53 passed |
| Installer group | `backend/tests/edr -k "installer or m1"` | 736 passed, 2 skipped |
| Transaction / upgrade / re-enrolment | `-k "transaction or upgrade or reenrol"` | 286 passed, 2 skipped |
| Fresh snapshot clone | `VERIFY.sh` | all checks passed, **373 passed in 2.57s** |
| Downloaded bundle, re-cloned | `VERIFY.sh` | all checks passed, **373 passed in 2.59s** |

### What the new tests exercise

The production `_authz_access_check()` and `access_check()` run for real; only
the two native edges are supplied (`_sddl_to_descriptor`, `_authz_invoke`), so
every controlled case passes through the real descriptor lifetime, the real
per-principal combination and the real contract function. Covered: successful
grant; successful denial with error 5 and a zero mask; native API failure
(`ok=False` in three shapes, and no reply at all); unexpected reply codes
(1, 87, 122, 1300, 1314, 1338, `0xFFFFFFFF`); four inconsistent
code-and-mask combinations; an unconvertible descriptor; a raising native call
(descriptor still freed, UNKNOWN through `access_check`); the 16-row reply
contract table; an exhaustive enumeration showing only
`(True, ERROR_ACCESS_DENIED, no requested right)` is a denial; a restrictive
`m1_service_descriptor()` passing service-time validation; an effective grant,
an unsafe ACE and an unknown reply each still refusing; an incomplete context
probing nothing; the `load_config` trace end to end; and `_authz_invoke`
itself driven with a fake `authz` module, asserting it populates and reads the
reply arrays and declares nine argtypes with `Flags` and
`OptionalSecurityDescriptorCount` as `DWORD` and `restype` as `BOOL`.

---

## E · Limitations — read before approving anything

**Windows-native verification: NOT RUN.** No real `AuthzAccessCheck`,
`AuthzInitializeContextFromSid`, `AccessCheck`, SCM, ACL, token, LocalSystem,
filesystem or process call was made. No payload was frozen or built, no
installer or service was executed, no enrolment, telemetry journal, backend
tenant association, Device Trajectory check or reboot/recovery test was
performed.

Specific to these tests: `ctypes.wintypes.DWORD` is **8 bytes on 64-bit
Linux** and 4 on Windows, so the structure layouts exercised portably are
**not** the Windows binary layouts. The reply-array handling is verified; the
marshalling is not. The documented Authz semantics relied upon here
(`ERROR_ACCESS_DENIED` as a per-result status) must be confirmed against the
real API on Windows.

Portable test counts are indicative of source logic only and are not
acceptance.

### G4 checklist still outstanding

1. Elevated interactive install on a Windows 11 VM, with the frozen onefile
   payload.
2. Service created disabled, descriptor written, read back and verified; then
   demand-start, then auto-start.
3. Real `AuthzAccessCheck` under LocalSystem against the real service and
   configuration descriptors: confirm the grant, denial and unknown branches
   observed above, including that a restrictive descriptor yields
   `Error[0] = ERROR_ACCESS_DENIED` with a zero mask.
4. Real `AccessCheck` under the installer's restricted token.
5. `GetFileAttributesW` behaviour for absent, denied, reparse and raced paths.
6. Process identity and PID-reuse behaviour with the real bootloader parent.
7. Enrolment, telemetry journal, backend tenant association, Device Trajectory
   visibility, reboot and recovery.

### Still outstanding, unrelated to this commit

The credential material found in the candidate tree — a bearer JWT in `.tok`,
two `memory/` evidence JWTs and six live-suite admin passwords — **remains
flagged for rotation/revocation and exposure assessment**. Nothing in this
commit addresses it.

---

## F · Artifacts

| Artifact | SHA-256 | Bytes |
|---|---|---|
| `NIVXFORGE_M1_G3_B3_AUTHZ_SNAPSHOT.bundle` | `43b8daa62b0673a5197de5d06b991be45729aa380f683f93ae29a7070b5288ba` | 175,182 |
| `NIVXFORGE_M1_G3_B3_AUTHZ_PROVENANCE.md` | `05379d844a10a5f63b8f88401ac559d7b58144634e66a114218ef3d9ba7ee5fe` | 7,573 |

Snapshot repository commit `53a965ff6413de2d6a40858a4415080617323101`;
`git bundle verify` reports a complete history; `git fsck --full --strict`
exits 0; 18 source files verified by blob SHA-1 **and** SHA-256; the
`agents/nivxforge-windows` subtree reproduces `db21f422…` exactly.

```
git clone NIVXFORGE_M1_G3_B3_AUTHZ_SNAPSHOT.bundle m1 && cd m1 && bash VERIFY.sh
python3 -m pytest backend/tests/edr/test_m1_clean_install.py -q
```

The snapshot is sanitized and self-contained; it **cannot** prove Git commit
identity (`PROVENANCE.md` §1), and the full history is deliberately not
exported because it carries the credential material listed in §4 there.

---

## G · Reviewer checklist (independent G3)

1. `authz_access_verdict()` against the Authz documentation: is
   `ERROR_ACCESS_DENIED` with no granted right the only denial, and is every
   other code UNKNOWN?
2. Are the contradictory combinations correctly refused rather than resolved?
3. `_authz_invoke()` ABI: nine parameters, `Flags` and
   `OptionalSecurityDescriptorCount` as `DWORD`, pointer widths, the
   single-result reply arrays, `restype = BOOL`.
4. Descriptor lifetime: `LocalFree` on every path; nothing invoked and nothing
   freed when conversion fails.
5. That `access_check_verdict()` and the installer-time path are unchanged,
   and the G3-01 correction still holds.
6. That the dangerous-ACE walk, `REQUIRED_CONTEXT_SIDS` completeness and the
   LocalSystem proof are unweakened.
7. That the added regressions genuinely fail against the defective reading
   (§D).
8. B1 and B2 closure is unaffected (19 and 35 subset tests pass).

**No self-approval.** G3 is Codex's to decide; G4 requires an authorized
Windows host.
