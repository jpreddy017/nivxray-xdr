# NIVXFORGE EDR — M1 G2 IMPLEMENTATION HANDOFF

Implementation of the independently accepted M1 clean-installer scope.
**No build, no signing, no Windows execution, no enrollment, no deployment,
no push or merge.** All security HOLDs remain in force. G3 is not self-approved.

## 1. Provenance

| | |
|---|---|
| Repository | `jpreddy017/nivxray-xdr` |
| Base commit | `bc8147be15af46e87a95612322e7d17f3859f587` |
| Base tree | `3333fd37737588e3c1be2f632d572d5e2631bb0a` (verified by `git rev-parse` before any edit) |
| Reviewed snapshot | `b13e1f3e70d9e2fa8fc8b76d773d0c7cf1cfca974dadc9b10d861c1c6bcde6ac` — verified, 22/22 per-file checksums OK, read before implementation |
| **Branch** | **`engineering/m1-clean-installer`** |
| **Commit** | **`0fd09b3a1f9eacfab12e41ef7c6d971a98ecdcae`** |
| **Tree** | **`c9dc8ab9062d16e370a79e497e78d954dc4ec1b8`** |
| Specifications | `NIVXFORGE_M1_SCOPE_V3.md` + `AMENDMENT_A2_R4` (A2 supersedes R4) |

**Provenance limitations, stated rather than implied.** (a) The snapshot
checksum proves byte integrity of 21 source files; it does **not** prove
commit attribution — that comes from the bundle chain. (b) Work was done in a
**sparse** worktree containing `agents/`, `backend/` and `.github/`; files
outside those paths were never checked out and therefore never modified, but a
reviewer re-running the full suite should use a complete checkout. (c) Frozen
R5 `a14c6693`, the successor `1c398858`, the repair `8a2c3e91` and the P0-1
candidate `bc8147be` are untouched; this branch is a child of `bc8147be` only.

## 2. Changed files — 5 files, +2278 / −19

| File | Change |
|---|---|
| `agents/nivxforge-windows/nivxforge_m1.py` | **NEW**, 1098 lines — the whole M1 path |
| `agents/nivxforge-windows/nivxforge_sensor.py` | +193 / −19 — identity publication, response validation, attempt marker, opt-in single-attempt enrolment |
| `agents/nivxforge-windows/nivxforge_setup.py` | +66 — additive subparsers, `m1_dispatch`, `--m1-service-run` branch, `_REQUIRED_BUNDLED` |
| `agents/nivxforge-windows/build/build_windows_installer.ps1` | +3 — required sources and hidden imports |
| `backend/tests/edr/test_m1_clean_install.py` | **NEW**, 937 lines — 99 portable regressions |

Nothing else changed. `nivxforge_transaction.py`, `nivxforge_scm_worker.py`,
the predecessor policy (P0-2), `nivxforge_journal.py`, the collection loop,
backend and frontend are byte-identical to the base.

## 3. What was implemented, against the accepted contract

**B1 isolation.** `nivxforge_m1.py` imports no engine module and references no
engine symbol; its own `m1_payload_check()` validates canonical member names
(traversal, ADS, reserved device names, trailing dot/space), the **exact** file
set (no missing and no unexpected member), per-file size and SHA-256, and
refuses a reparse point anywhere in the destination ancestry. `_validate_staged`
and the destructive helpers are not used.

**M1-02/M1-03.** `clean_host_report()` returns tri-state probes for service,
scheduled task, live worker, install and state directories, prior identity,
enterprise records and path ancestry. **PRESENT or UNKNOWN both refuse**, and a
failed enumeration returns UNKNOWN rather than ABSENT. Service registration is
`sc create` only, gated on `ABSENT`; the M1 path contains no stop, delete or
replace during installation.

**R1 ownership.** The record lives in the **administrator pre-provisioned**
configuration root, which the installer verifies and never creates, so a
durable record exists before the first installer-created directory. Four
states — `CREATE_INTENDED`, `CREATE_CONFIRMED`, `CREATE_OUTCOME_UNKNOWN`,
`ACTIVATION_VERIFIED` — with a digest envelope, `O_EXCL` creation, and the rule
that intent authorises nothing. `CreateDirectoryW` is called with a protected
SD applied **at creation**, and `ERROR_ALREADY_EXISTS (183)` is a refusal.

**R2/B4 credential publication.** `sensor.publish_identity()` refuses an
existing destination, writes an `O_EXCL` temp in the same directory, checks the
write, fsyncs, and publishes by a **no-overwrite rename** —
`MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` **without** `MOVEFILE_REPLACE_EXISTING`
on Windows, `os.link` on POSIX — then re-reads and compares. Replacement of
owned metadata is a separate operation.

**R3/B5 enrolment.** The protected attempt marker is written **before** the
request; the M1 call uses `single_attempt=True`; success is recorded only after
publication and readback; a lost or ambiguous outcome leaves the marker OPEN
and blocks automatic re-enrolment; `m1_reconcile_enrollment()` requires both an
explicit operator confirmation **and** a successful authenticated session probe.
Only the fields the API actually returns are validated — `endpoint_id`,
`credential_id`, `agent_credential`; the tenant is operator-supplied.

**B6/R6 configuration.** Trust comes from DACL and ancestry verified by
read-back, at install time and again in the service adapter before any logging,
credential access or socket; the digest only detects drift. Exactly one
`https://` origin; `certificate_policy` must be `windows-default`; the M1 path
contains no reference to the production constant.

**R4 + Amendment A2 service security.** Both checks are implemented and both
must pass: `ace_inspection()` resolves every ACE mask through the service
`GENERIC_MAPPING` and permits a dangerous right **only** to `S-1-5-18` or
`S-1-5-32-544` compared by SID, refusing NULL DACL, unsupported ACE types,
unparseable SIDs, unresolvable masks, an unapproved owner and an unprotected
DACL, and never letting a deny ACE justify a dangerous allow;
`token_access_verdict()` probes each of the eight dangerous rights
**individually** against a context that must carry `S-1-5-11`, `S-1-5-4`,
`S-1-1-0`, `S-1-5-32-545`. Security is applied and verified **before** any
start; on refusal the service stays `CREATE_CONFIRMED` and is never started.

**R5 adapter.** `--m1-service-run` dispatches to `m1_service_run()`, which
verifies configuration first and then hosts the **existing, unmodified**
`sensor.run()` loop. It does not call the enterprise service entrypoint, which
remains the single caller of `--service-run`.

**M1-07 uninstall.** Ownership-bound: refuses without a confirmed record,
refuses a binPath that is not the one M1 created, refuses an uncertain stop,
refuses when process exit is unproven, reports pending deletion rather than
claiming completion, and preserves identity, journal, cursors and evidence.

**M1-08 packaging.** `nivxforge_journal.py` and `nivxforge_m1.py` added to the
required-source gate and hidden imports; `_REQUIRED_BUNDLED` extended to ten
modules including the exclusion, delivery-counter and content-acquisition
components.

## 4. Test results — actually executed, portable only

| Suite | Result |
|---|---|
| `backend/tests/edr/test_m1_clean_install.py` | **99 passed in 0.91 s** |
| Windows installer v1 + stage4 + SCM entrypoint + secret-stdin + delivery repair | **146 passed in 6.19 s** |
| `test_p0prod2_enrollment_hardening.py` + `test_w1_windows_enrolment_instruction_contract.py` | **38 passed in 145.78 s** |
| Enterprise transaction suite (`build/run_transaction_tests.py`) | **349 passed in 65.57 s** |
| Import/compile smoke | `nivxforge_setup` imports with **no** engine module in `sys.modules`; all three modules compile |

Coverage of the mandated negative controls: enterprise isolation (static AST
scan + **fresh-interpreter `sys.modules` assertion** + defective-variant
control + "enterprise commands preserved"); existing/unknown host refusal (7
parametrised cases incl. UNKNOWN service and failed process enumeration);
unsafe ancestry and reparse; concurrent installer; crash between create and
confirm, and the refusal of the next attempt with nothing adopted or deleted;
torn ownership record; no-overwrite identity publication including a **race
injection** where the destination appears between `CREATE_NEW` and the rename,
and an interruption that leaves no partial identity; five malformed enrolment
responses; lost response proving **exactly one POST**; open-marker blocking;
identity-present-with-open-marker; configuration refusals before any network;
**16 dangerous-trustee cases** (Authenticated Users, INTERACTIVE, Everyone,
Users, unrelated individual user, non-member group, nested group, service SID)
plus 8 "not fully understood" cases, deny-before-allow, incomplete and absent
access context, indeterminate evaluation, per-right probing, generic mapping,
and the ordering assertion that `set_sd` precedes `start`; create-only
semantics; five uninstall refusals; packaging completeness and its negative
control; evidence preservation.

**These are portable results. They do not establish Windows behaviour.** The
`FakeHost` simulates the OS surface; every security verdict asserted is
produced by the real implementation reading simulated state, and no test
asserts a safety outcome through a double that assumes the disputed guarantee.

## 5. Unresolved defects and limitations

1. **`WindowsHost` is incomplete by design.** `service_set_security`,
   `service_security`, `access_context`, `access_check`, `process_exited` and
   `verify_running_image` return `None` or raise `NOT_IMPLEMENTED_NATIVE` off
   Windows — every caller treats that as UNKNOWN and **fails closed**, so the
   current code cannot complete an installation on a non-Windows host, and on
   Windows these five methods are the native work that must be exercised
   before G4. They are deliberately not faked.
2. **`_security()` ACE parsing is provisional.** The pywin32 `GetAce` tuple
   shape differs by ACE type; the current unpacking is defensive but has never
   run against a real descriptor. Native verification required.
3. **`mslex`** remains an undeclared test dependency of the pre-existing
   transaction suite (unchanged by this work).
4. **Behaviour narrowing, verified compatible:** `enrol()` now publishes
   through the no-overwrite path, so it refuses an existing identity file. The
   enterprise installer calls `enrol` only when `IDENTITY_FILE` does not exist
   (`nivxforge_setup.py:1168`), so no enterprise flow regresses; 533 existing
   tests confirm it.
5. No frozen artifact exists; packaging completeness is asserted statically
   only.

## 6. G4 Windows VM acceptance checklist (all NOT RUN)

Isolated, freshly imaged Windows 11 VM under exclusive administrative control.

1. Frozen EXE runs with **no developer Python**; journal round-trip on the VM.
2. Pre-provisioned config root with protected DACL; installer refuses if absent,
   user-writable, reparsed or digest-drifted.
3. `CreateDirectoryW` + protected SD applied at creation; `ERROR_ALREADY_EXISTS`
   refusal; DACL read-back and standard-user denial.
4. Clean-host refusals against a real existing service, a real scheduled task,
   a running sensor, real ACCESS_DENIED / 1722 / 1072 and a real junction.
5. `sc create` with a quoted `binPath`; account, start type and arguments
   verified; no stop/delete issued.
6. Service SD applied with `SetServiceObjectSecurity`, read back with
   `OWNER | GROUP | DACL`; `MapGenericMask`; `LogonUser` +
   `DuplicateTokenEx(SecurityImpersonation)` + `AccessCheck`, and the
   `AuthzAccessCheck` equivalent; all 24 negative cases must block startup;
   owner-less descriptor must give `ERROR_INVALID_SECURITY_DESCR (1338)`.
7. Identity publication: no-overwrite rename, kill-during-publish, and a
   concurrently appearing destination.
8. Enrolment against the lab backend: one POST, connection reset after
   server-side commit, open marker blocks re-enrolment, reconcile closes it
   only on a successful session probe.
9. Service starts, live image `MATCH`, state directory is the configured one.
10. Uninstall: real process-exit evidence, handle-held pending deletion,
    identity/journal/cursors/queued evidence all preserved.
11. Reboot and power-loss recovery of records, marker and identity.
12. Windows trust evaluation of the lab certificate, plus an untrusted-cert
    negative control.

## 7. Backend / Device Trajectory integration dependencies (open)

Pinned isolated backend revision; the authenticated enrolment, identity and
tenant-binding contract as implemented (including any idempotency or
machine-facts deduplication — unverifiable from this snapshot); ingestion
endpoint; raw-event storage; asynchronous canonicalisation worker; canonical
evidence schema; Device Trajectory endpoint and UI; endpoint/tenant
association. **Nothing backend- or frontend-side was modified.** Service health
and telemetry health remain **separate** verdicts: RUNNING, CONNECTED, HTTP 200,
an uncanonicalised row or a synthetic UI event are individually and jointly
insufficient.

## 8. Reproducible handoff

```
NIVXFORGE_M1_G2_CLEAN_INSTALLER.bundle
  sha256 c5e9e7c2beefcd5899dd0d12519f64b5419989b79fc71410e7e6c7be2aeac0a9
  28,690 bytes · requires bc8147be… · provides
  refs/heads/engineering/m1-clean-installer → 0fd09b3a…

NIVXFORGE_M1_G2_SOURCE_DIFF.patch
  sha256 6e4b19bcbc4be7bba610a2714636d1f45509956c1afbadc46d19603283bb5905
  109,165 bytes · git diff bc8147be..0fd09b3a
```
Verify: fetch the bundle chain, then
`git rev-parse 0fd09b3a1f9eacfab12e41ef7c6d971a98ecdcae^{tree}` must print
`c9dc8ab9062d16e370a79e497e78d954dc4ec1b8`. Re-run
`python -m pytest backend/tests/edr/test_m1_clean_install.py` and
`python agents/nivxforge-windows/build/run_transaction_tests.py`.

---

## STATUS: **M1 G2 IMPLEMENTED — READY FOR INDEPENDENT G3 REVIEW**

Code complete within the approved boundary; all available portable tests
executed with the actual results above. **Windows-native verification: NOT RUN
and not claimed.** No build, signing, execution, enrollment, deployment, push
or merge. The author of the baseline, the G1 designs and this implementation
(this agent) is ineligible to review it.
