# NIVXFORGE EDR — M1 SCOPE V2 (corrects the six G1 SCOPE FAIL blockers)

Phase A scope only. **No code, no commit, no branch, no build, no Windows
execution, no enrollment.** Supersedes v1
(`425012677c6975f86a80bc47c768d9ec97fe1645fd7f8e641415aa1d52a9f515`). Revised
sections only: §2–§8 below replace v1 §2–§5 and §7; v1 §1 (baseline), §4
(interrupted install, now folded into B3), §6 (out of scope) and the M1-01…M1-10
mapping stand unless contradicted here.

Baseline: snapshot `b13e1f3e70d9e2fa8fc8b76d773d0c7cf1cfca974dadc9b10d861c1c6bcde6ac`
(verified, 22/22 files), candidate `bc8147be15af46e87a95612322e7d17f3859f587`,
tree `3333fd37737588e3c1be2f632d572d5e2631bb0a`. Enterprise transaction/recovery
engine: **unchanged**. All HOLDs in force. G2 subject to independent G1 PASS and
explicit owner authorisation.

---

## 1. Blocker-resolution matrix

| # | Blocker | Resolution | Invariant | Test |
|---|---|---|---|---|
| **B1** | v1 reused `_validate_staged`, which imports the engine | M1-local validator `m1_payload_check()`; no engine import anywhere in the M1 closure; isolation proven in a **fresh process**, not only by `sys.meta_path` | Engine code is unreachable from M1 install/uninstall | §2 |
| **B2** | Allowed-change inventory omitted the M1 service adapter; service could still read production defaults | Six explicitly enumerated changes incl. an M1 service dispatch/config adapter; config validated **before** state-dependent logging, credential access or network | The M1 service never resolves a production origin | §3 |
| **B3** | Ownership record was a single state; intent could authorise cleanup | Three durable statuses; `O_EXCL` creation; create-only SCM; intent alone authorises nothing | No resource is stopped, deleted or adopted without confirmed ownership evidence | §4 |
| **B4** | POSIX directory-sync assumption on Windows | Concrete Win32 publication contract; **no directory fsync is claimed**; durability limits stated | Identity is absent-or-complete, protected, verified | §5 |
| **B5** | Marker written after the POST; invented returned `tenant_id` | Protected marker **before** the POST; one attempt; real response contract (`endpoint_id`, `credential_id`, `agent_credential`) | A lost or ambiguous enrollment never auto-reenrolls | §6 |
| **B6** | Digest-only configuration trust | Trust from DACL + ancestry, verified by read-back; digest detects drift only | No unapproved origin, no TLS bypass, no production fallback | §7 |

## 2. B1 — M1-local payload validation and proven isolation

**Removed from scope:** `_validate_staged` (`nivxforge_setup.py:836` — `from
nivxforge_transaction import inventory, validate, TransactionError`). Also
excluded: `_protect_state_dir` (994), `_stage_service_host` (1008),
`_stage_version`, `_sweep_staging`, `_prune_tree`, `_write_active`,
`_create_service`, `_install_service`, `_restore_service*`.

**`m1_payload_check(bundle_root, dest_root, manifest)`** — stdlib + `ctypes`
only (`os`, `pathlib`, `hashlib`):

1. **Canonical paths.** Resolve both roots; require every destination under
   `dest_root`; reject `..`, absolute or drive-relative members, UNC, alternate
   data streams (`:` in a component), trailing dot/space, reserved device names
   (`CON PRN AUX NUL COM1-9 LPT1-9`), and any component over the path limit
   without an extended-length prefix.
2. **Reparse ancestry.** Every component of `dest_root` is checked for
   `FILE_ATTRIBUTE_REPARSE_POINT`; any hit refuses.
3. **Exact file set.** Set equality with the embedded `payload-manifest.json`:
   no missing files and **no unexpected files**.
4. **Size then SHA-256** per file, compared to the manifest.
5. **Trust root, stated honestly.** The manifest travels inside the one-file EXE
   (`sys._MEIPASS`), so its integrity derives from the EXE. Signing is not
   authorised, therefore until it is, the operator-verified `self_digest()`
   value printed before any change is the only trust root, and that limit is
   recorded in the acceptance runbook.

**Isolation evidence — three independent methods, because a cached module
defeats an import hook:**

| Method | What it proves |
|---|---|
| **Static closure scan** | AST walk of `nivxforge_m1.py` and its first-party import closure: no `import nivxforge_transaction / nivxforge_scm_worker`, and no reference to `Engine`, `WindowsBackend`, `inventory`, `validate`, `reconcile`, `resolve_operation`, `Owner`, or the excluded helpers above. Module-level imports of `nivxforge_setup` are safe to scan because that file imports the engine only **inside functions** |
| **Fresh-process assertion** | `m1_install` / `m1_uninstall` are driven in a **new interpreter** (`subprocess`), which then prints `sorted(sys.modules)`; the forbidden names must be absent at exit. A pre-cached module cannot hide here |
| **Hook (supporting only)** | a `sys.meta_path` tripwire inside the test process, kept as a fast signal, never as the sole evidence |
| **Negative control** | a deliberately defective M1 variant that calls the engine **must fail** all three |

## 3. B2 — allowed source-change inventory (exhaustive)

| # | Change | Bound |
|---|---|---|
| 1 | **New** `agents/nivxforge-windows/nivxforge_m1.py` | all M1 install/uninstall logic, validator, clean-host report, ownership record, ACL helper |
| 2 | **Changed** `nivxforge_setup.py` | add `m1-install` / `m1-uninstall` subcommands and the `--m1-service-run` dispatch branch; **no existing function is edited** |
| 3 | **New** M1 service dispatch/configuration adapter (in `nivxforge_m1.py`, reached from the new dispatch branch) | loads and verifies the M1 config, then hands off to the existing service host |
| 4 | **Changed** `build/build_windows_installer.ps1` + `_REQUIRED_BUNDLED` | required-source list, hidden imports, provenance set |
| 5 | **Changed** `nivxforge_sensor.py` | `publish_identity()`, returned-field validation, enrollment attempt marker, single-attempt enrollment policy — nothing else |
| 6 | **New** `backend/tests/edr/test_m1_clean_install.py` | regressions for B1–B6 |

Nothing else may change. `nivxforge_transaction.py`, `nivxforge_scm_worker.py`,
the predecessor policy, the collection loop, `nivxforge_journal.py`, the existing
`install()` / `recover-transaction` / `resolve-operation` / `uninstall()` and
`_run_as_service` remain byte-identical.

**M1 service start order** (inverting today's order, where `_run_as_service`
(1561) logs into the state directory *before* parsing, and `_service_args`
(1541) falls back to `DEFAULT_BACKEND`):

1. read `--m1-config` and `--state-dir` from argv without argparse;
2. verify the config's DACL, ancestry and content (§7) — **before** any logging,
   any credential read and any socket;
3. only then bind the state directory, open the diagnostics log, and start the
   existing collection loop with the approved origin and interval.

Absent, unreadable, unverified or non-approved configuration ⇒ the service
refuses to start, logging only to the Windows event log. **The M1 path contains
no reference to `DEFAULT_BACKEND`.**

## 4. B3 — trustworthy ownership

Three durable statuses per created resource, in a protected, digest-enveloped
record:

| Status | Meaning | Authorises |
|---|---|---|
| `CREATE_INTENDED` | written **before** the creating call | **nothing** — no cleanup, no stop, no delete, no adoption |
| `CREATE_CONFIRMED` | creating call returned **and** ownership evidence read back | M1 uninstall of that resource only |
| `CREATE_OUTCOME_UNKNOWN` | creating call ambiguous, crash before confirmation, or torn/unverifiable record | **nothing**; conservative refusal + operator investigation |

- **Ownership evidence for the service:** name, the exact `binPath` string, the
  image SHA-256, the config digest and the `install_id` — read back via
  `sc qc` plus the existing live-image `MATCH` check (`_verify_running_image`,
  472). Anything less is `UNKNOWN`.
- **Exclusive creation:** the ownership record and every M1-created root are
  created with `O_CREAT|O_EXCL`; an existing path is never opened for writing.
- **Create-only SCM:** `sc create` strictly gated on `_service_lookup()[0] ==
  "ABSENT"`; the M1 path contains no `stop`, `delete` or `config` call against a
  service it has not confirmed.
- **Record initialisation:** `O_EXCL` temp in the same protected directory →
  checked write → flush → atomic replace (§5) → read back and verify the digest
  envelope. A missing, unparseable or digest-mismatched record ⇒ `UNKNOWN`.
- **Competing installers:** a named M1 mutex (distinct from `Owner`) plus the
  `O_EXCL` record; an **abandoned** mutex is treated as `UNKNOWN`, never as a
  free lock. Critical probes are re-run under the lock immediately before each
  mutation.
- **Crash between create and confirm ⇒ refusal**, printing the resource list and
  the required operator investigation. No adoption, ever.
- **Trust boundary:** M1 requires **exclusive administrative control of a
  disposable VM**. No immunity is claimed against a malicious local
  administrator or an unrelated privileged installer.

## 5. B4 — Windows credential publication contract

v1's "directory sync" is **withdrawn**: Windows exposes no POSIX directory
fsync, and none is claimed.

| Step | Contract |
|---|---|
| Directory | create with an explicit SD — SYSTEM + Administrators full control, inheritance disabled, DACL **protected**; then **read back** with `GetNamedSecurityInfo` and verify no additional ACEs |
| Permission proof | verify the DACL composition exactly; where an effective-access check (`AuthzAccessCheck`) is available it is used, and where it is not, the limit is recorded rather than implied |
| Temp file | `CreateFileW` with **`CREATE_NEW`** (exclusive), non-inheritable handle, the **same SD as the final file**, in the **same directory** |
| Write | checked write (bytes written compared), then `FlushFileBuffers` with its **return value checked** |
| Publish | `MoveFileExW(tmp, final, MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` — same volume, atomic replace |
| Durability limits | the flush plus `WRITE_THROUGH` covers **process crash** and is best-effort for power loss; with volatile disk caches, power-loss durability is **not guaranteed** and is not claimed |
| Readback | re-open, parse, compare field by field, re-verify the DACL |
| Pre-existing identity | an unexpected identity file ⇒ **refuse**; never overwrite |

**Scope: shared implementation, M1-driven.** `publish_identity()` lands in
`nivxforge_sensor.py` and `enrol()` uses it, so the enterprise path benefits too.
Enterprise compatibility regressions therefore required: identical file path,
identical JSON keys and formatting, `_validate_identity()` (1117) unchanged and
passing, existing enterprise enrollment tests green, and **no transaction-engine
import added to the sensor**.

## 6. B5 — enrollment protected before transmission

**Marker first.** `enrollment_attempt.json` is created `O_EXCL` with the
protected DACL and published per §5 **before** the POST. It records attempt id,
UTC, tenant, origin, a digest of the machine facts — **never the token**.

**Exactly one attempt** by default: the enrollment POST uses a single-attempt
transport policy. The shared 2-attempt retry in `_Transport.request`
(`sensor.py:286`) is **retained unchanged for telemetry delivery**.

**Real response contract**, read from the implementation: `POST
/api/edr/agent/enroll` yields `endpoint_id`, `credential_id`, `agent_credential`
and an optional `sensor_state`; **`tenant_id` is operator-supplied and is never
returned** (`sensor.py:506`). v1's claim that a returned `tenant_id` is validated
is **withdrawn**. Tenant binding is proven later by `POST
/api/edr/agent/session {tenant_id, agent_credential} → session_token`
(`sensor.py:521`). No field outside that set is assumed to exist.

| Covered case | Outcome |
|---|---|
| crash after server acceptance | marker open ⇒ `ENROLLMENT_OUTCOME_UNKNOWN` |
| lost response | marker open ⇒ UNKNOWN |
| malformed success (any required field missing, wrong type, empty) | nothing published ⇒ UNKNOWN |
| identity publication failure | marker open, no partial identity ⇒ UNKNOWN |
| restart with an open marker | **refuse**; print attempt id; no automatic re-enrollment |

Resolution is backend reconciliation or the supported operator procedure.
**External dependency:** whether the backend deduplicates by `processor_id` /
`machine_guid`, and whether an authenticated idempotency contract exists, is
**not verifiable from this snapshot**; until confirmed against the pinned backend
revision, an UNKNOWN attempt is terminal-until-operator.

## 7. B6 — configuration trust and service permissions

Administrator-provisioned, protected `m1-config.json` + `m1-config.meta.json`
under the M1 install root: **exactly one** approved non-production HTTPS origin,
the test tenant id, the canonical state directory, the certificate policy
(standard verification; optional pinned CA bundle), the permitted service
executable and its exact argument vector, and metadata (provisioned_by,
provisioned_at, config digest, install_id).

**A digest alone is insufficient — accepted.** Trust comes from **DACL and
ancestry**, not from the digest:

- config, metadata and **every ancestor directory**: SYSTEM/Administrators only,
  inheritance disabled, DACL protected, verified by **read-back** at install time
  and again by the service before any logging, credential access or network use;
- no reparse point anywhere in the ancestry; no ordinary-user write anywhere;
- the digest detects accidental drift only, and is never presented as protection
  against a privileged attacker;
- **service object DACL** verified after creation (`QueryServiceObjectSecurity`):
  no non-administrator `SERVICE_CHANGE_CONFIG`, `WRITE_DAC`, `WRITE_OWNER` or
  `SERVICE_START`.

Rejections: path substitution, unsafe ancestry, user-writable config, origin not
equal to the approved value, `http://`, **any** redirect (none are followed), TLS
verification disabled or weakened, and any production fallback.

**Trust boundary, stated accurately:** a compromised local administrator is
**outside** this guarantee. M1 protects against ordinary users, accidental
misconfiguration and path substitution — not against a privileged adversary on
the same host.

## 8. Regression tests, including crash and race injection

**B1** static closure scan; fresh-process `sys.modules` assertion for install and
uninstall; defective-variant negative control; validator rejects each of missing
file, extra file, wrong size, wrong digest, `..`, ADS, reserved name, reparse
ancestry.
**B2** service refuses on absent/unreadable/unapproved config; **assertion that
no state-directory write, credential read or socket occurs before validation**
(ordering asserted by instrumented call log); no `DEFAULT_BACKEND` reference
reachable from the M1 path (static + runtime).
**B3** crash injected (a) after `CREATE_INTENDED` and before the SCM call,
(b) after the call and before confirmation, (c) mid-record-write ⇒ each yields
refusal with no stop/delete/adopt; two concurrent installers ⇒ exactly one
proceeds; abandoned mutex ⇒ UNKNOWN; `O_EXCL` collision ⇒ refusal.
**B4** interruption injected before replace, between write and flush, and after
replace ⇒ never a partial identity; weak directory DACL ⇒ refusal **before** any
credential is written; pre-existing identity ⇒ refusal; enterprise
format/path/`_validate_identity` compatibility.
**B5** server accepts and the response is dropped ⇒ **exactly one POST** observed
and the state is UNKNOWN; crash after acceptance ⇒ UNKNOWN; malformed response
(each required field individually removed/emptied/mistyped) ⇒ nothing published;
open marker ⇒ later run refuses; no token in any record, log or exception chain;
telemetry retry behaviour unchanged.
**B6** config/metadata/ancestry made user-writable, substituted, or reparsed ⇒
refusal; digest valid but DACL wrong ⇒ refusal; `http://`, redirect to an
unapproved origin, and verification-disabled policy ⇒ refusal.

**Every critical check carries a negative control**, and no control may assert
the disputed guarantee through a mock. Portable results are reported separately
from native results and do not imply them.

## 9. Native Windows proof obligations (all NOT RUN)

Real `sc create` with a quoted `binPath`; real ACCESS_DENIED / 1722 / 1072
returns; real junction/reparse rejection; real DACL read-back, protected DACL and
standard-user denial; `AuthzAccessCheck` availability; `MoveFileEx` +
`WRITE_THROUGH` atomicity under process kill and power cut; service object
security read-back; real process-exit evidence and pending deletion on
uninstall; the frozen EXE operating with **no developer Python**, including the
journal round-trip; certificate trust against the lab backend; and the genuine
event → Device Trajectory trace.

## 10. External dependencies (unchanged, still open)

Pinned isolated backend revision; the authenticated enrollment / identity /
tenant-binding contract actually implemented (incl. any idempotency or
machine-facts deduplication); ingestion endpoint; raw-event storage;
canonicalisation worker; canonical evidence schema; Device Trajectory endpoint
and UI; endpoint/tenant association. **Nothing backend- or frontend-side is
modified here.** If the isolated backend does not exist, that is reported as an
integration blocker.

## 11. Owner approvals

Proposed defaults, incorporated as written and still requiring explicit
approval: **D-M1-1** one approved non-production HTTPS origin and test tenant,
standard certificate verification. **D-M1-2** no SCM failure/restart actions for
M1. **D-M1-3** preserve identity, journal, cursors, queued evidence and
audit/ownership records on uninstall. **D-M1-4** bounded M1-local ACL helper,
independently tested.

**D-M1-5 — inputs reconciled, with gaps reported rather than papered over:** the
original **Codex M1 assessment**, the **latest independent Work M1 SCOPE FAIL
review** and the **authoritative G0–G6 governance document** are **not available
in this workspace**. The six blockers were taken verbatim from the assignment
and each was re-verified against the snapshot source before being accepted. **No
conformance to G0–G6 is asserted.** If any of those documents contains a finding
or required outcome beyond B1–B6, this scope must be revised before G2.

---

## STATUS: **M1 G1 SCOPE V2 — READY FOR INDEPENDENT VERIFICATION**

Two items are flagged rather than claimed: the backend enrollment-reconciliation
contract (§6, external) and every native obligation (§9, NOT RUN). Neither
contradicts the scope — the behaviour is defined as refusal in both cases.

Phase A ends here. No implementation is authorised. The author of `bc8147be` and
of the G1 designs (this agent) is ineligible to verify this scope.
