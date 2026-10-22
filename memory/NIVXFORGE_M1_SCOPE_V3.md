# NIVXFORGE EDR — M1 SCOPE V3 (residual correction delta + consolidated scope)

Phase A, read-only design correction. **No code, no commit, no branch, no build,
no Windows execution, no enrollment, no deployment.** G2, enterprise upgrades,
KUSHU, production and rollout remain **HOLD**.

Supersedes V2 (`6ec7a7f9fce698ad3813576bda1f53a22516a9172774a47894494a7896b36c39`).
Every accepted B1–B6 requirement from V2 is **retained unchanged** except where a
delta below explicitly narrows or replaces it.

Baseline: snapshot `b13e1f3e70d9e2fa8fc8b76d773d0c7cf1cfca974dadc9b10d861c1c6bcde6ac`
(verified, 22/22 files), candidate `bc8147be15af46e87a95612322e7d17f3859f587`,
tree `3333fd37737588e3c1be2f632d572d5e2631bb0a`.

---

# PART I — V3 DELTA (six residual blockers)

## R1 — Bootstrap and ownership

**Revised contract.** Two directory classes, never conflated:

| Class | Who creates it | Installer behaviour |
|---|---|---|
| **Pre-provisioned trusted root** (`<M1Root>\config\` holding `m1-config.json`, `m1-config.meta.json`, and the **ownership record**) | the administrator, **before** the installer runs | the installer **never creates it**; it verifies existence, DACL, ancestry and content, and refuses if absent or unverified |
| **Installer-created roots** (install root, payload/version dir, state dir, log dir) | the installer | created with `CreateDirectoryW` + a protected SD; **already-exists is a refusal** |

This resolves the bootstrap circularity V2 left open: the ownership record lives
in the **pre-provisioned** root, so a durable record exists *before* the first
installer-created directory, and no "first root" has to be adopted on trust.

**Creation primitive.** `CreateDirectoryW(path, &SECURITY_ATTRIBUTES{ nLength,
lpSecurityDescriptor = SD, bInheritHandle = FALSE })` where SD = SYSTEM +
Administrators full control, **inheritance disabled, DACL protected**
(`SE_DACL_PROTECTED`), owner Administrators. `ERROR_ALREADY_EXISTS (183)` ⇒
**explicit refusal**, never "continue into an existing directory". The SD is
applied **at creation**, not afterwards, so no window exists in which the
directory is inherit-ACL'd.

**Four durable states** (V2's three, plus activation):

| State | Written | Authorises |
|---|---|---|
| `CREATE_INTENDED` | before the creating call | **nothing** |
| `CREATE_CONFIRMED` | call returned **and** ownership evidence read back | M1 uninstall of that resource |
| `CREATE_OUTCOME_UNKNOWN` | ambiguous return, crash before confirmation, torn record | **nothing** — conservative refusal + operator investigation |
| `ACTIVATION_VERIFIED` | service security applied+verified, started, live image `MATCH`, config digest bound | the installation may be reported as complete |

A crash during first-root creation or during service creation yields
`CREATE_INTENDED` or `CREATE_OUTCOME_UNKNOWN` and therefore **never authorises
automatic adoption or deletion**. Exclusive administrative control of the
isolated, disposable VM remains a **required operating condition**, and no
immunity is claimed against a malicious local administrator.

*Boundary:* `nivxforge_m1.py` only. *Refusal:* print the resource list, the state
of each, and the required operator investigation; exit non-zero; mutate nothing.
*Tests:* 183 on each root ⇒ refusal; crash injected before/after each creating
call and mid-record-write ⇒ no adoption, no deletion; missing or unverified
pre-provisioned root ⇒ refusal before any creation; concurrent installers ⇒ one
proceeds, the other refuses. *Native:* real `CreateDirectoryW` + SD application,
real 183, real protected-DACL read-back.

## R2 — Credential publication: atomic no-overwrite

**Revised contract.** V2's `MOVEFILE_REPLACE_EXISTING` is **withdrawn for initial
publication** — it cannot express "must not exist".

| Operation | Mechanism |
|---|---|
| **Initial publication** | temp via `CreateFileW(..., CREATE_NEW, ...)` in the same directory with the final SD → checked write → `FlushFileBuffers` (return checked) → `MoveFileExW(tmp, final, MOVEFILE_WRITE_THROUGH)` **with `MOVEFILE_REPLACE_EXISTING` deliberately NOT set** ⇒ the rename itself fails with `ERROR_ALREADY_EXISTS (183)` if the destination exists **or appears concurrently**. This is the atomic no-overwrite enforcement point |
| **Replacement of already-owned metadata** | a **separate** operation, gated on `CREATE_CONFIRMED` ownership of that exact file, which may set `MOVEFILE_REPLACE_EXISTING` |

Using a temp file rather than writing the final name directly also prevents a
torn final file: the destination name appears only via an atomic rename.

**Verification after publication:** re-open, parse, compare every field to what
was published, and re-verify the DACL and the **effective** rights (standard-user
denial). **Durability limits retained verbatim:** flush + `WRITE_THROUGH` covers
process crash and is best-effort under power loss; with volatile disk caches
power-loss durability is **not guaranteed and not claimed**; Windows exposes no
POSIX directory fsync and none is asserted.

*Boundary:* `publish_identity()` in `nivxforge_sensor.py`, plus its M1 call site.
*Refusal:* existing or concurrently appearing destination ⇒ refuse, leave the
temp for evidence, no identity published. *Tests:* destination pre-created ⇒
refusal; destination created by a competing thread between `CREATE_NEW` and the
rename ⇒ refusal (race injection); interruption before rename, between write and
flush, after rename ⇒ never a partial identity; replacement path rejected without
confirmed ownership. *Native:* real `MoveFileEx` no-replace semantics, real
effective-rights check, kill-during-publish.

## R3 — Enrollment lifecycle

**Retained from V2:** protected marker written **before** the POST; exactly one
attempt; no blind replay; telemetry retry untouched; **no claim of server-side
tenant enforcement** — the implemented response is `endpoint_id`,
`credential_id`, `agent_credential` (+ optional `sensor_state`); `tenant_id` is
operator-supplied and never returned (`nivxforge_sensor.py:506`); tenant binding
is exercised only later by `POST /api/edr/agent/session` (521).

**Added — success definition.** The marker is closed `ENROLLMENT_CONFIRMED` only
after identity publication **and** post-publication verification both succeed.
Nothing earlier counts: not a 2xx, not a parsed response, not a written file.

**Added — existing valid identity with an unfinished marker.** This is now an
explicit class: `ENROLLMENT_UNCONFIRMED_IDENTITY_PRESENT`. The installer **does
not** re-enroll and **does not** silently adopt the identity. The only supported
resolution is an explicit operator reconcile step that: (a) confirms backend-side
that this `endpoint_id`/`credential_id` is the sole identity for these machine
facts, and (b) requires a successful authenticated
`POST /api/edr/agent/session` probe using the stored credential — a **machine**
check that the credential is live and bound. Both succeed ⇒ the marker is closed
`ENROLLMENT_CONFIRMED_BY_RECONCILE` with the evidence appended. Either fails ⇒
refuse; nothing is deleted.

**Scope.** Marker and single-attempt policy are **M1-only call paths**: `enrol()`
gains an off-by-default parameter, and enterprise enrollment keeps its existing
behaviour. Shared enterprise compatibility is tested regardless (identity path,
JSON keys and formatting unchanged; `_validate_identity()` (1117) unchanged and
passing; existing enterprise enrollment tests green).

*Boundary:* `nivxforge_sensor.py` (marker, single-attempt parameter,
`publish_identity`) + `nivxforge_m1.py` (call site, reconcile command).
*Refusal:* any open marker blocks automatic re-enrollment on every later run.
*Tests:* crash after server acceptance, dropped response, malformed success (each
required field removed/emptied/mistyped), publication failure, restart with an
open marker, **valid identity + open marker** ⇒ refusal then successful reconcile
only when both checks pass; exactly one POST observed in every case; no token in
any record, log or exception chain; enterprise path unchanged. *Native:* real
connection reset after server-side commit; real session probe against the lab
backend.

## R4 — Directory and service permissions

**Owned objects.** M1-created directories and files get the protected SD of R1
applied at creation and verified by read-back.

**Shared ancestors** (e.g. `C:\Program Files`): **validated, never modified** —
read-only check that no non-administrator principal holds write, create-child,
delete-child, `WRITE_DAC` or `WRITE_OWNER`, and that no component is a reparse
point. Unsafe ancestry ⇒ refusal. The installer never writes an ACL it does not
own.

**Service security descriptor.** Applied with `SetServiceObjectSecurity` and
verified with `QueryServiceObjectSecurity` **before activation** (before any
start):

- **Required:** SYSTEM and Administrators `SERVICE_ALL_ACCESS`; owner
  Administrators or SYSTEM; DACL present and protected.
- **Forbidden for any non-administrator principal** (including
  `Authenticated Users`, `INTERACTIVE`, `Everyone`, `Users`):
  `SERVICE_CHANGE_CONFIG (0x0002)`, `SERVICE_START (0x0010)`,
  `SERVICE_STOP (0x0020)`, `SERVICE_PAUSE_CONTINUE (0x0040)`,
  `SERVICE_USER_DEFINED_CONTROL (0x0100)`, `WRITE_DAC`, `WRITE_OWNER`, `DELETE`.
- **Generic-right mapping is mandatory:** every ACE mask is passed through the
  service `GENERIC_MAPPING` (`MapGenericMask`) before evaluation, so
  `GENERIC_ALL` / `GENERIC_WRITE` / `GENERIC_EXECUTE` ACEs cannot hide a
  forbidden specific right. An unmapped-mask evaluation is itself a defect.
- **Effective rights, not ACE inspection:** the verdict comes from an effective
  access computation for a standard-user SID (`GetEffectiveRightsFromAcl` /
  authz), not from reading ACEs by eye.
- **Fail closed:** if application or verification is uncertain — API failure,
  unmapped mask, unreadable SD, unresolvable SID — the service is **not
  started**. It remains `CREATE_CONFIRMED`, never `ACTIVATION_VERIFIED`, and the
  run refuses with the exact object and reason.

*Boundary:* `nivxforge_m1.py`. *Tests:* each forbidden right injected for a
standard user ⇒ refusal before start; a `GENERIC_ALL` ACE for a standard user ⇒
refusal (negative control proving mapping is applied); unreadable SD ⇒ refusal;
ancestor made user-writable or reparsed ⇒ refusal, with the assertion that **no
ancestor ACL was modified**. *Native:* real `Set/QueryServiceObjectSecurity`,
real generic mapping, real effective-rights evaluation, real standard-user denial.

## R5 — Allowed edit boundary (explicit and final)

| # | Permitted change | Constraint |
|---|---|---|
| 1 | **New** `agents/nivxforge-windows/nivxforge_m1.py` | all M1 logic: validator, clean-host report, ownership record, ACL/SD helpers, install, uninstall, reconcile, **and the M1 service adapter** |
| 2 | **Changed** `nivxforge_setup.py` | **only** new subparsers (`m1-install`, `m1-uninstall`, `m1-reconcile-enrollment`) and new `main()` dispatch branches, including a dedicated `--m1-service-run` branch. **No existing function body is edited.** |
| 3 | **Changed** `build/build_windows_installer.ps1` + `_REQUIRED_BUNDLED` | required-source list, hidden imports, provenance set |
| 4 | **Changed** `nivxforge_sensor.py` | `publish_identity()`, returned-field validation, attempt marker, opt-in single-attempt enrollment parameter — nothing else |
| 5 | **New** `backend/tests/edr/test_m1_clean_install.py` | B1–B6 and R1–R6 regressions, crash/race injection, negative controls |

**The M1 adapter does not call `_run_as_service()`.** `--m1-service-run`
dispatches to `nivxforge_m1.m1_service_run(argv)`, which: parses `--m1-config`
and `--state-dir` without argparse → verifies configuration, DACL and ancestry
→ binds the state directory → opens logging → hosts a **minimal M1 service class
that drives the existing, unmodified `sensor.run()` collection loop** via
`servicemanager`. `_run_as_service`, `_service_args`, `_service_class` and every
enterprise command remain byte-identical and production-oriented.
`nivxforge_transaction.py`, `nivxforge_scm_worker.py`, the predecessor policy and
`nivxforge_journal.py` are untouched.

*Tests:* static assertion that no M1 symbol references `_run_as_service`,
`_service_args`, `_service_class`, `DEFAULT_BACKEND` or any engine symbol;
fresh-process `sys.modules` assertion (V2 B1) retained; defective-variant
negative control. *Native:* the frozen EXE's `--m1-service-run` branch reaching
`StartServiceCtrlDispatcher` without touching the enterprise path.

## R6 — Certificate policy

**Revised and simplified.** The lab backend presents a certificate that Windows
trusts through **normal verification**. Custom CA-bundle support is **deferred**
and will not be implemented without separate, independently justified owner
approval. **Certificate and hostname verification are never disabled, weakened
or bypassed.**

Implementation facts that make this concrete: `_Transport._connect`
(`nivxforge_sensor.py:266`) uses `http.client.HTTPSConnection(netloc,
timeout=30)` with **no explicit context**, so CPython's default context applies —
verification and hostname checking **on** — and no code in the snapshot creates
an unverified context. `http.client` does not follow redirects, so "no redirect
to an unapproved origin" holds **by construction**, not by a new mechanism. Two
limits are recorded rather than hidden: (a) CPython loads the Windows `ROOT`
store at context creation and does **not** use CryptoAPI chain building or
automatic root update, so the lab certificate must chain to a root **already
present** in the store at install time; (b) `_connect` selects
`HTTPConnection` for a non-`https` scheme, so the M1 config allow-list — exactly
one `https://` origin — is the control that prevents a downgrade, and it is
verified at install **and** at service start.

*Boundary:* configuration and validation only; no transport code change.
*Refusal:* non-https origin, origin mismatch, verification failure, or hostname
mismatch ⇒ refuse before any credential use. *Tests:* `http://` origin ⇒
refusal; origin not equal to the approved value ⇒ refusal; untrusted/mismatched
certificate ⇒ connection refused and no identity published; static assertion that
no unverified SSL context, `check_hostname = False` or `CERT_NONE` exists in the
M1 path. *Native:* real Windows trust evaluation against the lab certificate,
and an explicit negative control with an untrusted certificate.

---

# PART II — CONSOLIDATED SCOPE (V3)

**Retained from V2 unchanged:** B1 M1-local `m1_payload_check()` (exact file set,
sizes, SHA-256, traversal/ADS/reserved-name/path-length rejection, reparse
ancestry) with three-method isolation evidence — static closure scan,
**fresh-interpreter `sys.modules` assertion**, defective-variant control — and
the exclusion of `_validate_staged`, `_protect_state_dir`, `_stage_service_host`,
`_stage_version`, `_create_service`, `_install_service`, `_restore_service*`.
B2 config verified **before** state-dependent logging, credential access and
network. B3 create-only SCM gated on `ABSENT`, `O_EXCL` records, abandoned mutex
⇒ UNKNOWN. B4 the Win32 publication contract (as narrowed by R2). B5 marker
before send, one attempt (as extended by R3). B6 DACL-and-ancestry trust, digest
for drift only, service object DACL verified, no TLS bypass, no production
fallback (as narrowed by R4/R6).

**Clean-host contract** (M1-03, unchanged): tri-state probes over service,
scheduled task, live sensor/worker process, prior installation paths, prior
identity/journal/cursor state, enterprise transaction records and staging,
competing ownership, path canonicalisation, ancestry ACLs and reparse points.
**PRESENT or UNKNOWN refuses; UNKNOWN never means absent**; non-Windows yields
UNKNOWN; critical probes re-run under the M1 lock immediately before mutation.

**Acceptance split** (M1-09, unchanged): service health (created, AUTO_START,
correct account/arguments/state dir, restricted SD, expected binary identity,
live-image `MATCH`) and telemetry health (genuine Windows event → sensor →
durable journal row → authenticated ingest → raw evidence → asynchronous
canonicalisation → Device Trajectory) are **separate verdicts**. RUNNING,
CONNECTED, HTTP 200, an uncanonicalised row and a synthetic UI event remain
individually and jointly insufficient.

**Native proof obligations — ALL NOT RUN:** `CreateDirectoryW` + SD and
`ERROR_ALREADY_EXISTS`; `MoveFileEx` no-replace atomicity and kill-during-publish;
effective-rights and standard-user denial on files, directories and the service
object; service generic-mask mapping; real SCM returns (ACCESS_DENIED, 1722,
1072) and quoted `binPath`; reparse/junction rejection; process-exit evidence and
pending deletion on uninstall; the frozen EXE with **no developer Python**
including the journal round-trip; Windows trust evaluation of the lab
certificate; and the end-to-end genuine-event trace.

**External dependencies (unchanged, still open):** pinned isolated backend
revision; the authenticated enrollment / identity / tenant-binding contract
actually implemented, including any idempotency or machine-facts deduplication;
ingestion endpoint; raw-event storage; canonicalisation worker; canonical
evidence schema; Device Trajectory endpoint and UI; endpoint/tenant association.
Nothing backend- or frontend-side is modified here.

**Owner approvals:** D-M1-1 one approved non-production HTTPS origin and test
tenant with **standard Windows certificate verification** (custom CA bundle
deferred per R6); D-M1-2 no SCM failure/restart actions for M1; D-M1-3 preserve
identity, journal, cursors, queued evidence and audit/ownership records on
uninstall; D-M1-4 bounded M1-local ACL/SD helper, independently tested.

**Reconciliation and the retained verification gap (D-M1-5).** The residual
blockers R1–R6 were taken from the supplied V2 FAIL findings and each was
re-verified against the snapshot source before acceptance; V2's B1–B6 remain
reconciled with the earlier Codex and Work findings as recorded in V1/V2. The
**approved G0–G6 governance document remains unavailable in this workspace**, so
**no conformance to G0–G6 is asserted** and that verification gap is explicitly
retained. If the Codex assessment or the Work FAIL review contains a requirement
beyond B1–B6/R1–R6, this scope must be revised before G2.

---

## STATUS: **M1 G1 V3 — READY FOR INDEPENDENT VERIFICATION**

Contradictions resolved in this revision: the ownership bootstrap circularity
(R1, record in the pre-provisioned root), replace-vs-no-overwrite (R2, rename
without `REPLACE_EXISTING`), valid-identity-with-open-marker (R3), ACE inspection
vs effective rights and generic masks (R4), and the enterprise service entry
boundary (R5, no `_run_as_service`). Two items remain **flagged, not claimed**:
the backend reconciliation contract (external) and every native obligation (NOT
RUN) — in both cases the defined behaviour is refusal, so neither is a
contradiction.

Phase A ends here. No implementation is authorised. The author of `bc8147be`
and of the G1 designs (this agent) is ineligible to verify this scope.
