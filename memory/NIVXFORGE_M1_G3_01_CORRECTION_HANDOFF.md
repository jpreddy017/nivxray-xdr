# NIVXFORGE M1 — G3-01 CORRECTION HANDOFF
## `WindowsHost.access_check()` — the AccessCheck contract, read correctly

| Field | Value |
|---|---|
| Branch | `engineering/m1-g3-corrective` |
| **Commit** | `601eaa4625984b062be01848004744a5ba6d2603` |
| **Tree** | `9d07cb6c4285a30142d915761ef5a9324840921b` |
| **Parent** | `4b3b6a2c7c7fc2f339bd2725c28d942f6693d575` (tree `c9fae8dd…`, verified before edit) |
| Scope | 2 files, +361/−26. `nivxforge_m1.py` +170, `test_m1_clean_install.py` +217 |
| Status | **G3-01 CORRECTED — READY FOR INDEPENDENT G3 VERIFICATION** |
| Windows-native verification | **NOT RUN** |

### Artifacts

| Artifact | SHA-256 | Bytes |
|---|---|---|
| `NIVXFORGE_M1_G3_01_ACCESSCHECK.bundle` | `f25a7d97e1f1113acd3f17fecc2a3d76e7e8c60966ed5fb4acb7301bcd8b969a` | 38,792 |
| `NIVXFORGE_M1_G3_01_CORRECTION.patch` | `8a36daa77153b2dda37038e4c1219a0d1e94289f2ed0c1a9aa1496154a6082b3` | 23,504 |

The bundle carries `0fd09b3a..601eaa46` and requires `0fd09b3a` in the
receiving repository. The patch is the G3-01 correction alone
(`4b3b6a2c..601eaa46`). `git bundle verify` reports it as ok.

---

## 1 · API contract verification, performed first

**The reviewer's finding is confirmed, and the premise underneath it was
worse than the branch itself.**

Checked against the pywin32 source
(`win32/src/win32security.i`, 4120 lines, `main`) and the Win32 documentation:

1. **pywin32 does not wrap `AccessCheck`.** The module exports
   `MapGenericMask` — `%native(MapGenericMask) PyMapGenericMask`, taking
   `(mask, (GenericRead, GenericWrite, GenericExecute, GenericAll))` — but
   there is no `AccessCheck` export anywhere in the pywin32 sources.
   `win32security.AccessCheck(...)` would have raised **`AttributeError`** on
   every real Windows host. The generic `except Exception` below it swallowed
   that into `None`, so the token-aware mechanism was **permanently
   indeterminate** and every install would have refused at
   `SERVICE_SD_UNSAFE`. The `WinError 5 → denied` branch was unreachable dead
   code resting on a false premise.
2. **The native contract** (`securitybaseapi.h`): the `BOOL` return reports
   whether the **call** succeeded; `AccessStatus` carries the **verdict**; the
   two are independent. On denial the API sets `GrantedAccess` to **zero**. A
   `FALSE` return with `ERROR_ACCESS_DENIED` means the **ClientToken lacked
   TOKEN_QUERY** — a statement about the caller, not about the descriptor.
3. **`PRIVILEGE_SET` is not optional in practice**: without a real buffer of
   at least `sizeof(PRIVILEGE_SET)` = 20 bytes the call fails with
   `ERROR_INSUFFICIENT_BUFFER` (122).
4. **A hand-assembled absolute descriptor is not valid input** and is a
   documented source of `ERROR_INVALID_SECURITY_DESCR` (1338). A valid
   self-relative descriptor comes from
   `ConvertStringSecurityDescriptorToSecurityDescriptorW`.

---

## 2 · The correction

### `access_check_verdict(ok, status, granted, wanted)` — pure, portable

| Input | Reading |
|---|---|
| `ok is not True` | **UNKNOWN** — for every error code, including 5, and whatever residual output accompanies it |
| `status` or `granted` not an int | **UNKNOWN** |
| `wanted <= 0`, or still carrying generic bits | **UNKNOWN** — not a question the API can be asked |
| `ok`, `status` false, `granted == 0` | **DENIED** — the only verified denial |
| `ok`, `status` false, `granted != 0` | **UNKNOWN** — contradicts the documented behaviour |
| `ok`, `status` true, `granted & wanted == wanted` | **GRANTED** |
| `ok`, `status` true, `granted` missing a requested right | **UNKNOWN** — a result we do not understand |

The native wrapper no longer decides a denial at all; a test asserts
`return False` does not appear in `access_check`'s body.

### `_access_check_native()` — a real call

`advapi32.AccessCheck` with full `argtypes`/`restype`, a 20-byte
`PRIVILEGE_SET`, a `GENERIC_MAPPING` struct built from the object-type
mapping, and `LocalFree` of the descriptor in a `finally`. Every outcome is
handed to `access_check_verdict`; any exception on the way is UNKNOWN.

### `descriptor_to_sddl(descriptor, mapping)` — pure, portable

Renders the parsed descriptor as SDDL with every generic bit resolved
through the **object-type** mapping, deny ACEs first for canonical order,
inherit-only ACEs omitted because they do not apply to the object, and
`None` for anything unrenderable — so the API receives a valid self-relative
descriptor or is never called.

`_descriptor_to_sd` (the `SetServiceObjectSecurity` apply path, which pywin32
does wrap) is **unchanged**. A test asserts both renderings follow the same
rules — generic resolution, deny-first ordering, inherit-only exclusion — so
they cannot drift.

---

## 3 · How UNKNOWN reaches an installer refusal

```
WindowsHost.access_check  → None
  token_access_verdict / filesystem_token_verdict
      → problems += "access evaluation for <RIGHT> was indeterminate"
    service_security_verdict → {"safe": False}      path_security_verdict → {"nonadmin_writable": True}
      m1_install → M1Error SERVICE_SD_UNSAFE           load_config → M1Error CONFIG_ANCESTRY_UNSAFE
        service is still DISABLED                         nothing created, enrolled or registered
        service_set_start_type is never called
        service_start is never called
```

Both paths are asserted end-to-end:
`test_an_indeterminate_service_check_leaves_the_service_disabled` confirms
`start_type_code == SERVICE_DISABLED`, `config_calls == []` and
`started is False`; `test_an_indeterminate_path_check_refuses_before_anything_is_created`
confirms `host.calls == []`, no install directory and no ownership record.

UNKNOWN therefore cannot produce an activated service. The only way past the
gate is an explicit, successful, documented **denial** of every dangerous
right.

---

## 4 · Test results (actual)

```
python3 -m pytest backend/tests/edr/test_m1_clean_install.py -q
    → 275 passed in 1.96s        (187 before this correction; +88 new)

python3 -m pytest backend/tests/edr/test_windows_installer_v1.py \
    test_windows_installer_service_stage4.py test_windows_installer_scm_entrypoint.py \
    test_b5gap1_enrolment_secret_stdin.py test_p0_sensor_delivery_repair.py \
    test_b5_gap1_windows_gate0_ci_contract.py -q
    → 159 passed in 5.10s

python3 -m pytest backend/tests/edr/test_installer_transaction.py \
    test_p0_installer_upgrade_repair.py test_p0_windows_reenrol_staging_race.py -q
    → 281 passed in 24.16s

python3 -m pytest backend/tests/edr/test_p0prod2_enrollment_hardening.py \
    test_p0_a2_enrollment.py -q
    → 54 passed in 1.39s
```

`ruff check --select F,E9`: the same two pre-existing F401s inherited from
`bc8147be`; nothing new.

### Negative control

Reintroducing the defect in its purest form — `access_check_verdict` returning
`False` instead of `None` when the call did not succeed — produces
**57 failed, 218 passed**. The file was restored and the suite re-run to
275 passed before the commit.

### The new regressions

* **50 cases** of `(winerror × residual output)` proving an API failure is
  UNKNOWN and that `False` is unreachable when `ok` is not `True`.
* `test_only_a_literal_true_counts_as_a_successful_call` — `0`, `None`, `""`
  and `"True"` are all UNKNOWN.
* 13 contract rows covering grant, denial, partial grant, status/mask
  contradictions, non-integer outputs, an empty mask and an unmapped generic.
* `test_a_denial_is_only_reported_on_a_successful_call_with_status_false` —
  an exhaustive sweep of `ok × status × granted` showing `(True, 0, 0)` is the
  **only** input that yields a denial.
* `test_the_winerror_five_denial_branch_is_gone` — asserts the branch and the
  non-existent `win32security.AccessCheck(` call are both absent, that
  `access_check` contains no `return False`, and that the native helper uses
  advapi32, `PRIVILEGE_SET`, `LocalFree` and `access_check_verdict`.
* SDDL rendering: generic resolution per object type, deny-first ordering,
  inherit-only omission, and ten unrenderable descriptors that yield `None`
  so the API is never called.
* The two UNKNOWN-propagation tests in §3, plus an absent-token case.

The FakeHost gained a separate `granted_path` override, because a service
right and a file right can be the **same bit** (`SERVICE_CHANGE_CONFIG` and
`FILE_WRITE_DATA` are both `0x2`); the real host distinguishes them by the
`GENERIC_MAPPING` in use, and the fake now does too.

---

## 5 · Residual, for G4

Unchanged from the previous handoff, minus the pywin32 return-convention
uncertainty, which is now settled. Newly added to the native checklist:

1. `advapi32.AccessCheck` against a real service and a real directory
   descriptor with a real restricted token — confirm `GRANTED` / `DENIED` /
   `UNKNOWN` each occur as read here, and that the 20-byte `PRIVILEGE_SET` is
   accepted.
2. `ConvertStringSecurityDescriptorToSecurityDescriptorW` round-trips the
   rendered SDDL for a descriptor read back from the SCM, including numeric
   masks and raw SID strings.
3. The `SetServiceObjectSecurity` apply path still uses the pywin32-built
   descriptor and remains a native obligation.

No build, signing, Windows execution, enrolment, deployment, push, merge or
release. Security, release and rollout HOLDs preserved. The author of the
baseline, the designs and this correction cannot self-approve: independent G3
verification is required before native G4 validation on the Windows VM.
