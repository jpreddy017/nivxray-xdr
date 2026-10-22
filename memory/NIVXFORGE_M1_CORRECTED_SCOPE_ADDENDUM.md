# NIVXFORGE EDR — M1 CORRECTED SCOPE ADDENDUM (Phase A, design/scope only)

One isolated Windows 11 test VM. Clean install → service start → genuine
Windows telemetry → authenticated test backend → canonical evidence → Device
Trajectory. **No code was written, no commit, no branch, no build, no Windows
execution.** G2 NOT AUTHORIZED. All release/security HOLDs remain.

---

## 0. Mandatory inputs — status

| Input | Status |
|---|---|
| Reviewed source snapshot | **VERIFIED.** `NIVXFORGE_G1_REVIEW_SOURCE_SNAPSHOT.tar.gz` SHA-256 `b13e1f3e70d9e2fa8fc8b76d773d0c7cf1cfca974dadc9b10d861c1c6bcde6ac` = expected; extracted; all 22 per-file checksums OK; source read before proposing any change |
| Independent G1 DESIGN BLOCKED review | present (`f15c25d7…`), used for method only — **no G1 v3 work here** |
| **Codex M1 clean-install assessment** | **MISSING — requested (§13)** |
| **Independent Work M1 SCOPE FAIL report** | **MISSING — requested (§13)** |
| Approved G0–G6 governance | **MISSING** — conformance not certified |

The ten findings below are taken **verbatim from the assignment**, not
reconstructed from the missing reports. Where a required outcome needed a
mechanism, the mechanism is derived from the source, cited by line. **If either
missing report contains a finding outside M1-01…M1-10, or a different required
outcome, this addendum must be revised before G2.**

## 1. Baseline and verification limits

Commit `bc8147be15af46e87a95612322e7d17f3859f587`, tree
`3333fd37737588e3c1be2f632d572d5e2631bb0a` — re-verified in this workspace with
`git rev-parse`. **Attribution ≠ checksum:** the tarball's SHA-256 proves byte
integrity of 21 source files; it cannot prove they came from that commit. A
third party must verify attribution from the bundle chain, not the tarball.
Frozen R5, the successor, the failed P0-1 candidate and every enterprise
installer path are preserved unchanged.

## 2. Architecture decision (minimal, isolated, reusing what works)

| New | `agents/nivxforge-windows/nivxforge_m1.py` — the entire M1 clean-install path: `M1Config`, `clean_host_report()`, `m1_install()`, `m1_uninstall()`, `m1_protect_dir()`, ownership record |
|---|---|
| New | `backend/tests/edr/test_m1_clean_install.py` — portable regressions incl. negative controls |
| Changed | `nivxforge_setup.py` — add `m1-install` / `m1-uninstall` subcommands that dispatch **only** into `nivxforge_m1`; nothing else in the file changes |
| Changed | `nivxforge_sensor.py` — atomic identity publication, returned-field validation, enrollment-specific transport policy |
| Changed | `build/build_windows_installer.ps1` — complete required-source list and hidden imports |
| Preserved verbatim | sensor collection, `nivxforge_journal.py`, service host/`_run_as_service`, enrollment protocol and secret handling, `nivxforge_transaction.py`, `nivxforge_scm_worker.py`, predecessor policy (P0-2), `install()`, `recover-transaction`, `resolve-operation`, existing `uninstall()` refusal |

**Deliberate duplication, declared up front.** `_protect_state_dir()`
(`nivxforge_setup.py:994`) imports `WindowsBackend` from the transaction module.
M1 therefore cannot reuse it without re-coupling to the engine M1-01 forbids, so
`m1_protect_dir()` re-implements the DACL application directly over
`win32security`. The alternative — extracting a shared ACL helper — was rejected
for Phase A because it edits a module on the enterprise path. **Owner decision
D-M1-4.**

## 3. Finding → change → invariant → test → preserved → native obligation

### M1-01 clean install must not enter the transaction engine
*Source:* `install()` (`setup.py:1142`) imports `Engine, WindowsBackend,
TransactionError` and calls `Engine(INSTALL_DIR, backend).run(payload, manifest,
prepare)`; `_protect_state_dir()` and `_stage_service_host()` also reach into it.
*Change:* `m1_install()` performs staging-free, transaction-free installation:
validate config → clean-host report → acquire an M1-only exclusive lock (a named
mutex distinct from `Owner`) → copy the onedir payload from `sys._MEIPASS` to a
fixed M1 directory with a file-by-file digest check reusing the **pure** helpers
`_file_digest`/`_manifest`/`_validate_staged` (side-effect boundary: digest and
compare only) → enroll → publish identity → create service → start → verify.
*Invariant:* no enterprise transaction, reconciliation, settlement, upgrade or
predecessor logic is reachable from an M1 command.
*Test:* a `sys.meta_path` tripwire finder raises if `nivxforge_transaction` or
`nivxforge_scm_worker` is imported during `m1_install`/`m1_uninstall`; plus an
AST scan of `nivxforge_m1.py` rejecting `Engine`, `WindowsBackend`, `reconcile`,
`resolve_operation`, `_create_service`, `_install_service`,
`_stop_service_and_wait`, `_restore_service`, `_restore_service_config`. **Any
invocation is a hard failure.**
*Preserved:* every enterprise command, byte-identical.
*Native:* frozen-binary import graph must show the same isolation.

### M1-02 create-only service registration
*Source:* `_create_service()` (`setup.py:1061`) does `sc.exe stop` →
`_wait_for_service_state("STOPPED")` → `sc.exe delete` before `create`;
`_install_service()` (1081) prints "existing service found — replacing".
*Change:* M1 creates via `_sc_argv("sc.exe","create",…)` only, strictly gated on
`_service_lookup()[0] == "ABSENT"`. No stop, delete, overwrite or replace exists
in the M1 path. `_sc`/`_sc_argv`/`_service_lookup`/`_service_qc`/
`_verify_running_image` are reused — each is a read-only or argv-pass-through
utility with a verified side-effect boundary.
*Invariant:* M1 never mutates a service it did not create in this attempt.
*Test:* with a PRESENT service, `m1_install` refuses and performs zero `sc.exe`
state-changing calls (asserted on a recording `sc` double).
*Preserved:* `_create_service` unchanged for enterprise use.
*Native:* real `sc create` with a quoted `binPath` containing spaces.

### M1-03 fail-closed fresh-host verification
*Source:* `_service_exists()` (220) collapses `UNREADABLE` → `False`;
`_service_state()` (261) returns `""` for both absent and unreadable; on
non-Windows `_service_lookup` returns `ABSENT` (215). No scheduled-task, worker
process, prior-path, prior-identity or path-ancestry check exists.
*Change:* `clean_host_report()` returns per-probe tri-state
`ABSENT | PRESENT | UNKNOWN` over: service; legacy scheduled task; live sensor or
installer worker process; prior installation at the standard and requested paths;
prior protected identity/journal/cursor state; enterprise transaction records and
staging directories; competing installer ownership; path canonicalisation,
ancestry ACLs and reparse points. **Any PRESENT or UNKNOWN refuses**, with the
exact failing probes printed. On non-Windows the verdict is `UNKNOWN`, never
`ABSENT`. Every critical probe is re-run immediately before mutation, under the
M1 lock.
*Invariant:* unknown never means absent; refusal is the default.
*Test:* each probe independently forced to PRESENT and to UNKNOWN ⇒ refusal
(denied/1722/1072 SCM returns included); unsafe ancestry and a reparse-point
redirect ⇒ refusal; two concurrent `m1_install` runs ⇒ exactly one proceeds.
*Preserved:* `_service_lookup` tri-state semantics (the R4 repair).
*Native:* real ACCESS_DENIED/1722/1072 returns, real junctions, real task store.

### M1-04 durable, protected identity publication
*Source:* `sensor.enrol()` (`sensor.py:473`) does
`IDENTITY_FILE.write_text(json.dumps(...))` — **not atomic, no fsync, no
directory sync** — then `os.chmod(…, 0o600)` inside `try/except OSError: pass`,
which is not a Windows ACL. A truncated file is later refused by
`_validate_identity()` (1117), and `install()` rejects `--re-enrol` (1148) — a
dead end.
*Change:* `publish_identity(record)` = create/verify the state directory ACL →
**verify effective permissions** → write a temp file in the same directory →
flush + `os.fsync` → atomic replace → directory sync → re-read and verify
content and permissions. `enrol()` calls it instead of `write_text`. Returned
`endpoint_id`, `credential_id`, `agent_credential`, `tenant_id` are validated for
presence, type and shape **before** publication. Startup refuses on incomplete
persistence (existing behaviour, retained).
*Invariant:* an identity file is either absent or complete, protected and
readable only by SYSTEM/Administrators; no secret is ever logged.
*Test:* interruption injected before replace, between replace and fsync, and
after replace ⇒ never a half-identity; weak directory ACL ⇒ refusal before any
credential is written; invalid returned fields ⇒ no file created.
*Preserved:* enrollment protocol, stdin-only secret handling, redaction.
*Native:* real DACL/effective-permission verification and standard-user denial.

### M1-05 no blind enrollment replay
*Source:* `_Transport.request()` (`sensor.py:286`) retries `for attempt in
(1, 2)` on `OSError`/`HTTPException`, and `enrol()` posts through it, so a lost
response after backend acceptance re-POSTs a consumed one-time token. `enrol()`
then converts any failure to `SystemExit` — no unknown-outcome state, no
diagnostic evidence.
*Change:* the enrollment POST uses a **single-attempt** transport policy (a
parameter honoured only by this call; shared telemetry retry is untouched). If
the backend exposes an authenticated idempotency contract it is verified and
used; otherwise a lost/ambiguous response writes a durable
`ENROLLMENT_OUTCOME_UNKNOWN` record (non-secret diagnostics only: timestamp,
tenant, machine facts, transport error class, no token) and the installer stops,
requiring backend reconciliation or the supported operator resolution.
*Invariant:* a second endpoint identity is never created because a response was
lost.
*Test:* server accepts then the response is dropped ⇒ exactly **one** POST
reaches the backend and the outcome is UNKNOWN; UNKNOWN present ⇒ a later
`m1-install` refuses rather than re-enrolling; no token appears in any record,
log or exception chain.
*Preserved:* telemetry delivery retry, journal attempt accounting.
*Native:* real connection reset after server-side commit.

### M1-06 nonproduction configuration, fail-closed
*Source:* `--backend` defaults to `DEFAULT_BACKEND =
"https://nivxray.nivxforge.com"` (`setup.py:59`, parser 1599); `_service_args()`
(1541) falls back to the same production constant when `--backend` is absent from
the binPath and silently defaults a malformed `--interval` to 30;
`_assert_backend` (103) *rejects* `.local`, localhost and preview origins, so a
lab origin can be accepted only by accident of hostname.
*Change:* M1 config is explicit and complete or the run refuses — approved test
HTTPS origin (matched against an **M1 allow-list**, not the production blacklist),
test tenant id, canonical state directory, enrollment parameters, trusted
certificate configuration, and the exact approved service arguments. **No
defaults, no implicit localhost, no production fallback, in the M1 path only.**
The service is given `--m1-config <path>` plus `--state-dir`, and on startup
verifies the config digest the installer recorded; a mismatch refuses to start.
Enterprise defaults are unchanged.
*Invariant:* no M1 network request can reach a non-approved origin; installer
and service read the same verified configuration.
*Test:* missing/invalid origin, tenant, state dir or certificate ⇒ refusal before
any socket; a config whose digest differs from the recorded one ⇒ service refuses
to start; no request is attempted against `DEFAULT_BACKEND` anywhere in the M1
path.
*Native:* real certificate trust against the lab backend.

### M1-07 ownership-bound M1 uninstall
*Source:* `uninstall()` (1213) refuses unconditionally.
*Change:* `m1_uninstall()`, gated on the durable M1 ownership record: verify the
installation and service identity are M1's (service name, binPath, image digest,
state dir, install id) → stop **only** that service → wait on **real process
evidence**, not an SCM state alone → treat SCM timeout/unreadable conservatively
(refuse, never force) → request removal only when safe → verify removal including
**pending-deletion** (1072 / not-1060) → retain identity, journal, cursors and
audit evidence per the retention policy. Never remove a payload still used by a
live or uncertain process; never touch unrelated directories.
*Invariant:* uncertainty refuses with a named operator action; nothing unowned is
ever deleted.
*Test:* foreign service with the same name ⇒ refusal; unreadable SCM ⇒ refusal;
process termination unverifiable ⇒ refusal and no deletion; pending deletion with
a held handle ⇒ reported, not claimed complete; evidence directories survive.
*Preserved:* enterprise `uninstall()` refusal text.
*Native:* real handle-held pending deletion and process-exit evidence.

### M1-08 complete, verified frozen payload
*Source:* `build_windows_installer.ps1:38-42` requires only seven sources and
**omits `nivxforge_journal.py`**, although it is a hidden import (line 88);
`_REQUIRED_BUNDLED` (`setup.py:1655`) covers five modules and omits
`nivxforge_exclusions`, `nivxforge_delivery_counters`,
`nivxforge_content_acquisition` and `nivxforge_m1`.
*Change:* the required-source list, hidden imports and `_REQUIRED_BUNDLED` are
brought into one agreed set covering sensor, service host, journal, SQLite/native
`_sqlite3`, enrollment/config components, collection modules, exclusion/policy
support, delivery dependencies and `nivxforge_m1`; `_packaging_regression_ok`
keeps its fail-closed `in_frozen_bundle` rule.
*Invariant:* packaging is never declared successful because an import
*declaration* exists.
*Test:* removing `nivxforge_journal.py` ⇒ packaging validation fails; each
required module absent ⇒ provenance reports `present: false` and the gate fails.
*Native:* **mandatory** — the frozen EXE must run on a VM with **no developer
Python**, and must execute the journal round-trip there.

### M1-09 service health ≠ telemetry health
*No source change.* Acceptance is split into two independent verdicts:
**(a) service** — created, AUTO_START, correct account/arguments/state dir,
restricted permissions, expected binary identity, and live-image `MATCH` via the
existing `_verify_running_image` (472); **(b) telemetry** — a *genuine* Windows
event, traced by identity through sensor → durable journal row → authenticated
ingest → raw evidence → asynchronous canonicalisation → Device Trajectory.
RUNNING, CONNECTED, HTTP 200, an uncanonicalised raw row, or a synthetic UI event
are **individually and jointly insufficient**.
*Test:* portable tests cover journal persistence and payload shape only.
*Native:* the end-to-end trace of one correlated event id across all layers.

### M1-10 backend/frontend are an external dependency
The snapshot contains no backend or frontend. **Nothing backend- or
frontend-side is modified under this assignment.** Before Phase B can be called
complete, these must be named and pinned: isolated backend revision; test
enrollment/identity contract; ingestion endpoint; raw-event storage;
canonicalisation worker; canonical evidence schema; Device Trajectory endpoint
and UI; endpoint/tenant association. **If the isolated backend is unavailable,
this is reported as an integration blocker, not worked around.**

## 4. Interrupted M1 installation

A durable ownership record (`m1-install.json`, protected, append-only) names
every resource this attempt created, written **before** each creating step. On
interruption: identity and evidence are preserved; the host is **not** treated as
clean again; reinstallation is refused; the exact partially owned resources are
printed; resolution is a narrowly scoped, verified operator cleanup procedure
limited to those named resources. **No second transaction/recovery engine is
introduced** — there is no state machine here, only an owned-resource list.

## 5. Portable tests vs native obligations

Portable (Linux, synthetic `sc`): isolation tripwire and AST scan; every
clean-host probe in all three states; concurrency; atomic publication under
injected interruption; single-attempt enrollment and UNKNOWN handling; config
refusal matrix and digest binding; create-only semantics; ownership-bound
uninstall refusals; packaging validation; evidence preservation; **a negative
control for every critical check**. Mocks may not assert the disputed guarantee —
a recording `sc` double is evidence about *our* call sequence only.

Native (NOT RUN, and not implied by any portable result): real SCM returns and
quoting; real DACLs and standard-user denial; real process-exit evidence; pending
deletion; frozen EXE without Python; certificate trust; genuine event → Device
Trajectory.

## 6. Out of scope

P0-2; enterprise upgrade/recovery; the G1 transaction redesign; any replacement
sensor, journal or framework; new product features; backend/frontend changes;
production or KUSHU access; build, signing, publication, enrollment against
production, or any Windows execution.

## 7. Owner decisions required before Phase B

| ID | Decision |
|---|---|
| **D-M1-1** | Approve the M1 origin allow-list and lab certificate policy (the production guard rejects `.local`/localhost by design) |
| **D-M1-2** | M1 service failure actions: **none** (recommended — keeps M1 clear of the unresolved deferred-restart problem) vs the enterprise 3×60 s restart |
| **D-M1-3** | Retention policy for identity, journal, cursors and queued evidence on M1 uninstall |
| **D-M1-4** | Accept the deliberate `m1_protect_dir()` duplication rather than editing an enterprise-path module |
| **D-M1-5** | Supply the Codex assessment, the Work M1 SCOPE FAIL report and the G0–G6 governance document |

---

## STATUS: **M1 CORRECTED SCOPE READY FOR INDEPENDENT REVIEW**

Phase A only. **No implementation has begun and none is authorised.** G2 starts
only after this scope passes independent review *and* the owner explicitly
authorises it. The author of `bc8147be` and of the G1 designs (this agent) is
ineligible to review this scope. Windows-native evidence: **NOT RUN**.
