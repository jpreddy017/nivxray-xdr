# NIVXFORGE EDR — P0 SOURCE RECONCILIATION · G1 **V3**
## Final material correction · READ-ONLY design amendment

Supersedes `NIVXFORGE_EDR_P0_RECONCILIATION_G1_V2.md`
(`d0cf63aa995ec6c8f0f28ed6b9997a10d384bd9d7896a64f1f1eb0e70be4bce2`) in the
sections named below; `NIVXFORGE_EDR_P0_RECONCILIATION_G1.md` (`e5fafcbc…`)
remains the base document for every section neither V2 nor V3 amends.
Corrects the four material defects in Codex's independent **G1 V2 FAIL**.

**Scope: design only.** No code, no commit, no merge, no CI trigger, no
publication, no deployment, no HOLD removal. **Independent Codex verification
and owner approval remain mandatory before any G2 work.**

Baselines, re-verified in this pass:

| Role | Id |
|---|---|
| Active trunk | `f971c765` |
| M1 G3-approved candidate | `388bb3d637a076f36d78fc9d1e218c878b082b9b` |
| Common ancestor | `ae340563` |
| Frozen M1 Windows subtree | `db21f422561f14fb4dcec91b70925f2b5291c500` |
| Trunk Windows subtree (for contrast) | `54fe56bdf7ae55c1ed8727a3d58f87f3743d0a33` |

---

## 0 · Four-defect correction matrix

| ID | Codex V2 FAIL finding | Why V2 failed | Amended in | Class |
|---|---|---|---|---|
| **D-1** | `install --re-enrol` was a refusal dressed as an alias | V2 §2.1 kept the flag only to print a directive to `retire-identity`; the operator path the installer advertises still did not work | **§1** — two functioning modes, ownership proved not manufactured, RE-1…RE-12 | design resolved · UNIMPLEMENTED |
| **D-2** | Identity replacement was a 5-row prose table, not a recoverable transaction | V2 §2.3/§2.4 named an archive and some failure points but defined no durable record, no quiescence, no fence, no session or credential disposition, and left queued evidence open to silent re-attribution | **§2** — durable transition record, phase table, recovery table, attribution fence | design resolved · UNIMPLEMENTED |
| **D-3** | Phase 1 was internally incoherent: keep the trunk entrypoint **and** require M1 tests that need entrypoint symbols the trunk does not have | V2 §4.4 kept the trunk `build_windows_installer.ps1` and §4.5 imported `test_m1_clean_install.py`; those two statements cannot both hold — the proof is enumerated in §3.2 | **§3** — four separate gates, test reachability matrix, no skip-as-PASS | design resolved · UNIMPLEMENTED |
| **D-4** | Cleanup/rollback/purge had no precedence and could delete by path match | V2 §3.2 listed owners for the five invariants but never ordered the refusal conditions, so an uncertain engine, an unproven worker, a pending deletion and an un-owned directory all fell through to the same `rmtree` | **§4** — strict precedence ladder, ownership-proof requirement, truthful messaging | design resolved · UNIMPLEMENTED |
| **P-5** | Provenance and baselines under-specified | V2 §4.3 asserted a subtree hash but no file manifest; §5 named no per-test manifest schema | **§5** — exact blob manifest, build-commit separation, per-test baseline schema | design resolved · UNMEASURED |

**C-2, C-4, C-8 and C-9 are carried forward unchanged.** C-8 is restated in §3.4
because new evidence narrows *why* it holds — the decision itself does not
change.

### 0.1 Two V2 statements corrected for accuracy

A design document that carries a false premise cannot be verified, so:

1. **V2 §4.4 said** the trunk entrypoint has "zero `__main__` guards, zero
   `argparse`". **False as written.** `f971c765:nivxforge_setup.py` contains an
   `argparse` parser (8 references, `--re-enrol` registered at line 885,
   dispatched at line 1244) and one `__main__` guard. The true and narrower
   fact — which is what C-8 rests on — is that `nivxforge_m1.py`,
   `nivxforge_transaction.py` and `nivxforge_scm_worker.py` each contain **zero**
   `__main__` guards and **zero** `argparse` references, so they are reachable
   only through `nivxforge_setup.py`, and the trunk `nivxforge_setup.py`
   references `nivxforge_m1` **zero** times.
2. **V2 §3.3 attributed `_active_service_exe()` to the trunk.** It exists only in
   `388bb3d6:nivxforge_setup.py` (3 references); the trunk has **zero**. The
   legacy-layout refusal therefore arrives *with* the M1 entrypoint in Phase 2
   and cannot be relied on during Phase 1.

---

## 1 · D-1 · A functioning `install --re-enrol`

**Decision: `--re-enrol` works.** It is not an alias, not a directive and not a
refusal. It is gated, it is mode-selected from observable facts, and in the
common case it changes no endpoint identity at all.

### 1.1 The fact that makes this safe

`EndpointIdentity.mint()` is **deterministic**:

```
_iid("ep", tenant_id, kind, value)  →  f"ep_{sha256(...)[:20]}"
# precedence: processor_id > machine_guid > device_iid > hostname
```
(`backend/edr_plane/contracts/identity.py:22-28, 96-110`;
`backend/routers/edr_enrollment.py:275-279`.)

The same machine in the same tenant therefore re-enrols to the **same
`endpoint_id`**, and `store.enroll()` upserts that record while deliberately
preserving the delivery history (`store.py:292-307`, the P0-3 defect fix).
**Re-enrolment is, in the overwhelming majority of real cases, a credential
replacement under a stable endpoint identity — not an identity change.** V2
treated every re-enrolment as a retirement, which is why it could only refuse.

### 1.2 The three modes

| Mode | Trigger | Endpoint identity | Transaction required |
|---|---|---|---|
| **R — credential repair** | `install --re-enrol --credential-stdin`, after an operator rotation in the console | **unchanged** | in-place credential update (§1.5) |
| **N-same — token re-enrolment, same endpoint** | `install --re-enrol --tenant <t> --token-stdin`; the backend returns an `endpoint_id` **equal** to the local one | **unchanged** | in-place credential update (§1.5) |
| **N-change — true identity transition** | same command, but the returned `endpoint_id` **differs** (tenant changed, or the durable attribute changed: hardware replaced, MachineGuid reset, or a fallback to `hostname`) | **replaced** | full durable transition (§2), and it additionally requires `--allow-identity-change` |

Mode is **discovered, never asserted by the operator**: the agent compares the
authenticated `endpoint_id` with the local one and refuses to proceed down the
N-change path unless `--allow-identity-change` was supplied
(`IDENTITY_CHANGE_NOT_AUTHORIZED`). The reverse is also refused: supplying
`--allow-identity-change` when the identity does **not** change is reported, and
the operation continues as N-same rather than fabricating a transition.

Mode R exists because the backend already supports it properly:
`store.rotate_credential()` issues the new credential, revokes the old one,
increments `auth_epoch` and kills every session minted under it, with **no
overlap window** (`store.py:464-507`). Mode R is therefore the **recommended**
repair path and the one `_validate_identity`'s advice should name once §1.6
lands.

### 1.3 Ownership proof for an existing trunk installation

A trunk installation has **no M1 ownership record**, and one must never be
invented: `Ownership.create()` is a no-overwrite `write_new_file` of a record
describing *resources this attempt created* (`nivxforge_m1.py:425-431`), and
`m1_uninstall` keys destructive authority off `Ownership.owns(record,
"service")` (`nivxforge_m1.py:1294-1305`). Writing a record for resources the
installer did not create would convert an un-owned host into an owned one and
hand M1's destructive paths authority over an operator's installation.

**Rule: prove, do not adopt.** Re-enrolment authority comes from evidence
gathered at run time, recorded in a **separately named, non-authoritative**
artifact:

| # | Proof | How it is established | Failure verdict |
|---|---|---|---|
| 1 | the caller is an elevated administrator | `_assert_admin()` | refuse |
| 2 | the state directory is protected | its DACL grants only SYSTEM + Administrators, evaluated with M1's existing `path_security_verdict` / `filesystem_token_verdict`; **UNKNOWN refuses** | `STATE_DIR_UNSAFE` / `STATE_DIR_UNKNOWN` |
| 3 | the identity is this machine's | the local `identity.json` `endpoint_id` **equals** `EndpointIdentity.mint(tenant_id, this host's processor_id/machine_guid)` as returned by the authenticated backend; a mismatch means the state directory belongs to another machine's image | `IDENTITY_NOT_THIS_MACHINE` |
| 4 | the installation is the one being repaired | the SCM `binPath` for `SERVICE_NAME` resolves inside `INSTALL_DIR`, and the running image is read back (`verify_installed_binary` semantics); an absent service is acceptable (that is the repair case) but a service pointing **outside** `INSTALL_DIR` is not | `FOREIGN_SERVICE_IMAGE` |
| 5 | no enrolment attempt is open | `read_attempt_marker()` is `None` or closed; `OPEN` or `TORN` refuses and directs to reconciliation | `ENROLLMENT_ATTEMPT_OPEN` |

Recorded as `reenrolment_attestation.json` in the configuration root, written
with `O_CREAT|O_EXCL` + `fsync`, carrying the same digest envelope as
`Ownership` (`_digest_bytes(canonical_record(...))`). Three hard constraints:

* it is **not** `m1_ownership.json` and is never read by `Ownership.read()`;
* `Ownership.owns()` keeps returning **false** for every resource, so
  `m1_uninstall` on a trunk installation still refuses with `NOT_OWNED` —
  **NC-19 asserts exactly this**;
* it grants exactly one authority: performing §1.5 or §2 on **this** endpoint.
  It authorizes no deletion, no service mutation and no staging removal.

### 1.4 Authorization — all of it, fail-closed

Mode R and N-same: proofs 1-5, plus `--operator-confirmed`.
Mode N-change: proofs 1-5, `--operator-confirmed`, `--allow-identity-change`,
and a transition record (§2). A cross-tenant change additionally requires
`--allow-tenant-change`, because queued evidence carries the **old** `tenant_id`
(§2.5).

No default, no inference, no environment variable may supply any of these
flags, and every refusal names the proof that failed.

### 1.5 In-place credential update — the no-overwrite invariant is preserved by scope

M1's invariant is about **publication of an endpoint binding**:
`publish_identity()` refuses when the destination exists
(`nivxforge_sensor.py:528-558`) and `_rename_no_replace` fails on any
pre-existing target (`505-526`). Modes R and N-same do not publish a binding;
they maintain the credential of a binding that already exists. They therefore
use a distinct operation:

```
update_credential_in_place(new_credential_id, new_agent_credential)
```

with these post-conditions, each separately asserted:

1. the file **must already exist** (the mirror image of `publish_identity`);
2. `tenant_id` and `endpoint_id` are byte-identical before and after — any
   difference refuses with `IDENTITY_REBINDING_REFUSED`;
3. only `credential_id`, `agent_credential` and an appended
   `credential_history[]` entry (`credential_id`, `rotated_at`, `reason`,
   never the secret) change; every other field is compared and preserved;
4. durability: temp file with `O_CREAT|O_EXCL`, `os.write`, `os.fsync`, then
   `os.replace` — the same owned-metadata replacement
   `close_attempt_marker()` already uses (`nivxforge_sensor.py:596-609`);
5. read-back equality, as `publish_identity` does, or the update refuses;
6. the DACL is re-asserted after the replace.

**`publish_identity()` itself is not modified.** NC-20 asserts
`update_credential_in_place` cannot change `endpoint_id`, and NC-21 asserts it
refuses when `identity.json` is absent — so it can never become a second
publication path.

### 1.6 The superseded credential — a real, currently unhandled exposure

`store.enroll()` inserts the new credential as `ACTIVE` and **does not revoke
the previous one**, does not increment its `auth_epoch` and does not revoke its
sessions (`store.py:271-307`; contrast `rotate_credential`, `464-507`, and
`revoke_endpoint`, `510-542`, which both do). `_active_credential()` resolves
by presented secret, so **after a token-based re-enrolment the superseded
credential still authenticates until an operator revokes it.**

Contract:

* Mode R is **preferred** precisely because rotation closes this by itself.
* Modes N-same and N-change must print a **REQUIRED OPERATOR ACTION** naming the
  superseded `credential_id` and `POST /api/edr/endpoints/{endpoint_id}/revoke`,
  and record it as an **OPEN obligation** in the attestation/transition record.
  `status` surfaces the open obligation until an operator records its closure.
* The agent never revokes anything itself — revocation is an authenticated
  console action, and an agent that could revoke its own lineage is an agent
  that can erase its own supersession.
* Backend repair (`enroll()` should revoke superseded credentials for the same
  `endpoint_id`) is registered as **RISK-14** and is **out of scope** here.

### 1.7 Tests — RE-1…RE-12

Positive: **RE-1** first publication onto an absent destination succeeds ·
**RE-2** `publish_identity()` onto an existing identity still refuses
(the M1 invariant, unchanged) · **RE-3** Mode R replaces the credential,
`endpoint_id`/`tenant_id` byte-identical, `credential_history` appended ·
**RE-4** Mode N-same: the backend returns the same `endpoint_id`; no archive is
created, no transition record is opened, the journal is byte-identical before
and after · **RE-5** Mode N-change with `--allow-identity-change`: the full §2
transition completes and every §2.4 post-condition holds · **RE-6** the
superseded `credential_id` is printed and recorded as an OPEN obligation and
`status` shows it · **RE-7** attestation is written as
`reenrolment_attestation.json`, passes its envelope, and `Ownership.owns()`
still returns false for every resource.

Refusals: **RE-8** no `--operator-confirmed` → nothing is read, written or
sent · **RE-9** each of proofs 2-5 failing individually refuses with its own
code, and `UNKNOWN` refuses exactly as `PRESENT` does · **RE-10** an identity
change **without** `--allow-identity-change` refuses with
`IDENTITY_CHANGE_NOT_AUTHORIZED` after the authenticated probe and **before**
anything on disk is touched · **RE-11** a cross-tenant change without
`--allow-tenant-change` refuses · **RE-12** `--re-enrol` on a host with an
`OPEN` attempt marker refuses and directs to reconciliation, never enrolling a
second time.

**RE-3, RE-4 and RE-5 are the positive re-enrolment tests the independent
review found to be absent on both lineages.**

---

## 2 · D-2 · The durable identity transition (Mode N-change only)

Only Mode N-change replaces an endpoint identity. It is a transaction with a
durable record, an ordered phase sequence, one recovery rule per interruption
point, and an attribution fence that makes silent re-attribution structurally
impossible.

### 2.1 The durable record

`identity_transition.json` in the state directory:

* created with `O_CREAT|O_EXCL|O_WRONLY`, `0o600`, `os.write`, `os.fsync` —
  the pattern `open_attempt_marker()` already uses
  (`nivxforge_sensor.py:562-584`);
* phase advances are `write temp + fsync + os.replace`, as
  `close_attempt_marker()` does;
* integrity-enveloped with `_digest_bytes(canonical_record(...))`, so a torn
  record is **detected, not interpreted** → `TRANSITION_RECORD_TORN`, manual
  recovery, nothing touched;
* contents: `transition_id`, `phase`, `from{endpoint_id,tenant_id,credential_id}`,
  `to{endpoint_id,tenant_id,credential_id}`, `delivery_fence`,
  `fenced_row_count`, `archive_path`, `pending_path`, `probe`,
  `operator_reason`, `revocation_obligation`, UTC stamps per phase. **No
  secret value is ever written to it.**
* Durability is stated, not implied: `fsync` covers process and OS crash and is
  best-effort under power loss; Windows exposes no POSIX directory `fsync`, so
  none is claimed — the same limit `publish_identity()` already documents
  (`nivxforge_sensor.py:531-534`).

Corroborating evidence lives in the journal, which is already a durable store:
`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`
(`nivxforge_journal.py:249-253`). The fence value is written to the journal
`meta` table in the same cycle, so the record and the evidence store agree.

### 2.2 Exclusive ownership and quiescence — before anything

| Requirement | Mechanism | Failure |
|---|---|---|
| single writer | M1's named mutex (`WindowsHost.exclusive_lock()` / `_NamedMutex`, `nivxforge_m1.py:2524-2543`) is held for the whole transition | refuse; a concurrent operation is never raced |
| service quiesced | the PID is identified **before** the stop, the stop is proven `STOPPED`, and the process exit is proven — M1's `m1_uninstall` standard (`nivxforge_m1.py:1315-1333`), not the trunk's unproven `sc.exe stop` | `SERVICE_STOP_UNCERTAIN` / `PROCESS_EXIT_UNPROVEN` → refuse; **nothing is archived** |
| no live session on the host | guaranteed by quiescence: the session token lives only in the collector process's memory (`session["token"]`, `nivxforge_sensor.py:1272-1281`), so a proven exit is proof no local session survives | — |
| no open enrolment attempt | `read_attempt_marker()` is closed or `None` | refuse → reconcile first |
| journal settled | `wal_checkpoint(TRUNCATE)` (`nivxforge_journal.py:651`) and the backlog counted | counts recorded in the transition record |

### 2.3 Phase sequence

| Phase | Action | On disk afterwards | Collecting? |
|---|---|---|---|
| **T0 PREPARE** | §1.3 proofs, §2.2 quiescence, record created | old identity live; record `PREPARE` | stopped, identity intact |
| **T1 FENCE** | `delivery_fence = max(journal_sequence)`; drain-first attempt under the **old** credential (default) | unchanged; fence recorded | stopped |
| **T2 ENROL→PENDING** | single-attempt enrolment with the fresh token; the new identity is published to `identity.pending.json` by the **existing** `publish_identity(record, path=…)` — an absent destination, so the no-overwrite guarantee is untouched | old identity **still live**, pending beside it | stopped, but recoverable at zero cost |
| **T3 ARCHIVE** | `identity.json` → `identity.<old_endpoint_id>.<utc>.retired.json` via `_rename_no_replace`; protected DACL re-asserted | archive + pending, **no** `identity.json` | the only uncollecting window |
| **T4 PROMOTE** | `identity.pending.json` → `identity.json` via `_rename_no_replace` (destination now genuinely absent) | new identity live, archive retained | ready |
| **T5 SETTLE** | fence disposition applied (§2.5), revocation obligation recorded and printed, record closed | record `SETTLED` | collecting after service start |

Enrolling **before** archiving is the load-bearing ordering decision: it shrinks
the uncollecting window to a single rename, and a backend failure, a refusal or
a lost response then costs **no archive and no identity**. The window between
T3 and T4 is the only interval in which the endpoint has no identity, and §2.4
makes it deterministically completable without spending a second token.

### 2.4 Recovery — keyed on observable facts only

| `identity.json` | pending | archive | record phase | Verdict and required behaviour |
|---|---|---|---|---|
| present | absent | absent | none | not a transition — ordinary `install` |
| present | absent | absent | `PREPARE`/`FENCE` | `TRANSITION_ABORTED`: nothing moved, nothing enrolled. Clear the record, report the fence as void |
| present | **present** | absent | `ENROLLED_PENDING` | **Decision point, never automatic.** `resolve-identity-transition --operator-confirmed` either promotes (verifying the pending read-back against the record) or aborts, archiving the pending as `identity.<new>.<utc>.unpromoted.json` — never deleting it — and recording the unused new credential as a revocation obligation |
| **absent** | present | present | `ARCHIVED` | the uncollecting window. `resolve-identity-transition --operator-confirmed` promotes idempotently after read-back verification: deterministic, costs no token, loses nothing. `install` itself **refuses** and prints this directive (and the directive command exists — §1 rule) |
| absent | absent | present | `ARCHIVED` | pending lost after archival → `TRANSITION_INCOMPLETE`. **THIS ENDPOINT IS NOT COLLECTING.** Recovery is a fresh `--re-enrol` with a new token; the archive is never auto-restored |
| present | absent | present | `PROMOTED` | settle idempotently: verify the live identity equals `to.endpoint_id`, then close. **Never re-publish, never re-enrol** |
| any | any | any | envelope mismatch | `TRANSITION_RECORD_TORN` — refuse everything, mutate nothing, operator action |
| absent | absent | absent | `ENROLLED_PENDING` + attempt marker `OPEN` | enrolment may have been accepted with the response lost. **Automatic retry is blocked** (`nivxforge_sensor.py:626-634`); reconcile via `m1_reconcile_enrollment` first |

**Backend authentication versus transport uncertainty** is resolved the same way
everywhere, and the distinction is explicit:

| Probe / response | Meaning | Effect |
|---|---|---|
| session opens (`/api/edr/agent/session` 200) | credential **LIVE** | retirement is deliberate; allowed |
| definite `401`/`403` with a credential verdict | credential **DEAD** | retirement is recovery; allowed |
| timeout, DNS failure, `5xx`, TLS failure, truncated body | **UNKNOWN** | **refuse** — `IDENTITY_STATE_UNKNOWN`; a transport failure is never evidence about a credential |
| enrolment request sent, response lost | **outcome unknown** | marker stays `OPEN`; no retry; reconcile |

### 2.5 Queued telemetry attribution and replay protection

This is the defect with the sharpest evidence, and it exists today:

* journal rows **do** carry per-row attribution — `endpoint_id TEXT`,
  `tenant_id TEXT` columns (`nivxforge_journal.py:106-107`, populated in
  `_row()`, `387-394`);
* but delivery posts **only** `{"payload", "source_kind", "sensor_version"}`
  with a bearer session token (`nivxforge_sensor.py:1332-1340`), and the backend
  attributes from the authenticated session —
  `source=who.endpoint_id`, `endpoint_ref=who.endpoint_id`
  (`backend/routers/edr_enrollment.py:480-490`).

**Therefore, with no fence, every row queued before an identity change is
silently re-attributed to the new endpoint on its next delivery.** The fence
closes it:

| Rule | Contract |
|---|---|
| F-1 | `delivery_fence` = the highest `journal_sequence` at T1 |
| F-2 | a row at or below the fence may be delivered **only** under a credential whose `endpoint_id` **and** `tenant_id` equal that row's own columns |
| F-3 | default is **drain-first**: deliver the fenced rows under the old credential at T1 while it is still live |
| F-4 | rows that remain are marked `ORPHANED_BY_IDENTITY_TRANSITION` and **retained** — never delivered under the new identity, never deleted, never counted as delivered. The exact count is printed and recorded |
| F-5 | a cross-tenant change may never deliver a fenced row, drain-first included — `--allow-tenant-change` makes the orphaning explicit, not permissible |
| F-6 | export of orphaned rows for manual, attributed submission is **out of scope and not implemented**; they stay owned locally |

Replay protection: `mark_accepted` is still driven by per-row backend accepts,
not by transport success (`nivxforge_sensor.py:1253-1256, 1340-1342`), so
promotion cannot resend accepted rows; the agent reads identity **only** from
`IDENTITY_FILE` (`nivxforge_sensor.py:342-344`), so an archived credential is
never loadable — **NC-22** asserts no code path reads `*.retired.json` or
`*.unpromoted.json`; and the one-time enrolment token is burned by the backend
before anything else happens (`store.py:256-262`), so the transition cannot be
replayed with the same token.

### 2.6 Credential archival, protection and revocation

| Concern | Contract |
|---|---|
| archival | the old identity is **moved, never deleted**; the archive inherits the SYSTEM+Administrators DACL and `0o600`, and the DACL is re-asserted and re-read after the rename |
| record contents | `credential_id` only; the secret is never written to the transition record, never printed, never logged |
| revocation | recorded as an OPEN obligation naming the superseded `credential_id` and the revoke route; surfaced by `status` until closed; **the agent never revokes** |
| retrospective trust | revocation is not retroactive distrust — evidence produced while trusted stays valid (`store.py:537-542`), so orphaned rows are a **delivery** problem, not an evidence-validity problem |
| archive retention | retained indefinitely by default; deletion is a separate, confirmed, ownership-gated operation and is **out of scope here** |

---

## 3 · D-3 · Phase 1 / Phase 2 boundary and test coherence

### 3.1 The contradiction, stated plainly

V2 simultaneously required (a) keeping the trunk `nivxforge_setup.py` and the
trunk `build_windows_installer.ps1` in Phase 1, and (b) importing M1's test
files in Phase 1 and treating Gate B as meaningful. Those cannot both hold:
M1's tests assert against the **entrypoint and the build script**, and the test
files hard-code their own source root —
`AGENT_DIR = Path(__file__).resolve().parents[3] / "agents" / "nivxforge-windows"`
(`test_m1_clean_install.py:26-28`, `test_p0_installer_upgrade_repair.py:52`) —
with **no environment override**. On the integration branch they would read the
trunk entrypoint and fail or error.

### 3.2 Test reachability matrix — measured, not assumed

Symbol counts are `grep -cF` against each revision's `nivxforge_setup.py` /
`build/build_windows_installer.ps1`.

| Test (M1 `388bb3d6`) | Requires | trunk `f971c765` | M1 `388bb3d6` | Outcome on an integration branch keeping the trunk entrypoint |
|---|---|---|---|---|
| `test_m1_clean_install.py::test_enterprise_commands_are_preserved` | `def recover_transaction(`, `def resolve_operation(`, `def _create_service(`, `m1.m1_service_run(raw)` | **0, 0, 0, 0** | 1, 1, 1, 1 | **FAIL** |
| `…::test_packaging_declares_every_required_module` | `nivxforge_m1` in `_REQUIRED_BUNDLED`; `nivxforge_m1.py` and `'nivxforge_m1'` in the build script | **0 / 0 / 0** | 3 / 1 / 1 | **FAIL** |
| `…::test_packaging_declares_the_win32_modules_m1_security_needs` | `_M1_REQUIRED_WIN32 = (` | **0** | 1 | **ERROR** (`IndexError` on `split`) |
| `test_p0_installer_upgrade_repair.py` — **every** test | fixture monkeypatches `VERSIONS_DIR`, `ACTIVE_FILE`, `_sc_argv`, `_running_image` | **0, 0, 0, 0** | 8, 4, 5, 8 | **ERROR** — `AttributeError` at fixture setup for the whole file |
| `test_installer_transaction.py::test_production_install_entrypoint_uses_transaction` | the trunk `install()` is a direct installer; `tx.WindowsBackend` is never reached | n/a | passes | **FAIL** |
| `test_installer_transaction.py` — engine-only tests | `nivxforge_transaction`, `nivxforge_scm_worker` only | imported in Phase 1 | — | **PASS** |
| `test_installer_transaction.py::test_no_destructive_release_probe` | `setup._image_is_released` | 2 | 2 | **PASS** |
| `test_m1_clean_install.py` — the other ~360 tests | `nivxforge_m1` + `nivxforge_sensor` only | imported in Phase 1 | — | **PASS** |
| `test_s1_2_c2_clean_install_atomicity.py` (trunk-only) | the trunk failure handler | present | absent | Phase 1 **must keep passing**; re-targeted in Phase 2 (§4) |

### 3.3 Four separate gates

Each gate names its **test source**, its **execution target**, its **baseline**
and its **expected result**. No gate may be satisfied by a skip, an `xfail`, a
weakened assertion or a relaxed marker — **a deferral is reported as a
deferral, never as a PASS.**

| Gate | Test source | Executed against | Baseline | Expected |
|---|---|---|---|---|
| **G-S · byte-identical source import** | none (static) | the integration branch tree | the §5.1 manifest | every imported file's blob hash equals its `388bb3d6` hash; every *frozen* file byte-identical; zero executions |
| **G-T · trunk runtime regression** | trunk test files at `f971c765`, unmodified | the integration branch (trunk entrypoint + M1 library blobs + the §1 adapter) | §5.3 trunk per-test manifest | identical outcome set; the expected-failure set shrunk or identical, **never substituted**; `test_s1_2_c2_clean_install_atomicity.py` green |
| **G-M · isolated M1 source verification** | M1 test files at `388bb3d6`, unmodified | an **ephemeral detached worktree at `388bb3d6`** (`git worktree add --detach`), read-only, discarded after the run | §5.4 M1 per-test manifest | the full M1 suite green **in its own tree**; proves the imported bytes behave as reviewed; proves **nothing** about the composed tree |
| **G-C · composed installer runtime acceptance** (Phase 2) | M1 **and** trunk test files, unmodified | the composed tree after the M1 entrypoint and build script land | G-T ∪ G-M | both suites green **in one tree**, the deferral list **empty**, AT-1…AT-5 (§4.4) green |

G-M is what makes Phase 1 honest: it is the only way to execute M1's tests
without modifying them and without pretending the composed tree exists. It is
also explicitly **not** acceptance of the composition.

### 3.4 Deferral register — auditable, bounded, and it must reach zero

M1's entrypoint-coupled tests are imported byte-identically in Phase 1 but are
**collection-excluded** by an explicit manifest, never by edits to the test
files:

* `agents/nivxforge-windows/.phase1-deferred` lists exactly the node ids in
  §3.2 marked FAIL or ERROR, each with a reason and the Phase 2 work item that
  clears it;
* CI consumes it as `--deselect` arguments; no `skip`, `xfail` or marker is
  added to any test file, so `git diff` against `388bb3d6` for every M1 test
  file stays **empty**;
* a gate asserts the deferral list **exactly equals** the enumerated set — an
  entry that is not in §3.2 fails the gate, and so does a §3.2 entry that is
  missing;
* **Phase 2 completes only when the file is empty and deleted.**

C-8 stands, now with the narrowed evidence of §0.1: the M1 build script
hidden-imports `nivxforge_m1`, `nivxforge_transaction` and
`nivxforge_scm_worker` and emits `payload-manifest.json` (counts 1/3/2 versus
**0/0/0** in the trunk script); those modules carry no `__main__` and no
`argparse`, so under the trunk entrypoint they are unreachable. The trunk build
script therefore stays in Phase 1, and M1's arrives in Phase 2 **with the
entrypoint that reaches it** — which is also the commit that clears the
packaging deferrals.

### 3.5 Phase boundaries

**Phase 1 — additive, inert, reversible.** Commit 1 is the workflow
`branches:` guard **alone**, touching nothing under `agents/` (the trunk
`push:` trigger has no branch filter, and Gates 5-6 create and start a real
service). Then: byte-identical import of `nivxforge_m1.py`,
`nivxforge_transaction.py`, `nivxforge_scm_worker.py`,
`build/Invoke-TransactionAcceptance.ps1`, `build/run_transaction_tests.py`,
`windows-installer-transaction-build.yml` and the three M1 test files; M1's
journal blob `bbaaaed0` unconditionally; M1's sensor blob `53a45ded` **only in
the same commit as the §1 adapter**. Lab-only origins for every
service-starting gate. Gates G-S, G-T, G-M.

**Phase 2 — composition, nothing weakened.** M1's `nivxforge_setup.py`
entrypoint and build script; the §1 modes; the §2 transition; the §4 cleanup
ladder; the uninstall hardening. The deferral register empties. Gate G-C, then
AT/UN/NC. Phase 2 may not begin until G-S, G-T and G-M are green and the §5
baselines exist.

**Neither phase** touches `backend/routers/edr.py`,
`backend/edr_plane/response.py`, `backend/routers/edr_response.py`, any
production origin, or any byte of the frozen subtree outside the composition
commit.

---

## 4 · D-4 · Cleanup, rollback and purge safety

### 4.1 What is wrong today

The trunk's handler is the right **shape** but the wrong **strength**:

* `_remove_partial_service()` (`f971c765:nivxforge_setup.py:294-306`) calls
  `sc.exe stop` then `sc.exe delete` with **no PID identified before the stop,
  no proven process exit and no `ERROR_SERVICE_DOES_NOT_EXIST` check** — it
  infers absence from `_service_exists()`;
* `_remove_partial_staging()` (`309-314`) is
  `shutil.rmtree(INSTALL_DIR, ignore_errors=True)` with **no ownership proof**,
  while `install()` reached that directory through
  `INSTALL_DIR.mkdir(parents=True, exist_ok=True)` — so a **pre-existing**
  directory at the expected path is adopted on the way in and deleted on the way
  out. `prior_state` records the **service** state only;
* the engine's uncertainty vocabulary (`MANUAL_RECOVERY: …`, `UNKNOWN` as a
  first-class answer, `nivxforge_transaction.py:214-233, 355, 491-532, 762-814`)
  has no path into that handler at all.

### 4.2 Strict precedence ladder

Evaluated **in order, before any destructive step**. The first condition that
holds decides the outcome; later conditions are never consulted, and no
condition is ever downgraded by a later success.

| # | Condition | Outcome | Message class |
|---|---|---|---|
| **0** | transaction record unreadable, or any engine verdict is `MANUAL_RECOVERY`/`UNSETTLED` | **STOP. Nothing is removed.** Preserve the record and both payloads | manual recovery, record preserved |
| **1** | a worker process is running, or its liveness is `UNKNOWN` (`worker_liveness` → `UNKNOWN` refuses by design) | **STOP.** No stop, no delete, no staging removal | refuse; worker not proven exited |
| **2** | the service is `PENDING_DELETION`, or its post-removal state is anything but `ERROR_SERVICE_DOES_NOT_EXIST` | **STOP at the service.** Report `PENDING_DELETION` **as pending** — never as removed; staging is kept because it is still referenced | honest pending state |
| **3** | an SCM operation record is unsettled, or the service did not hold still | **STOP.** Settlement precedes removal, always | manual recovery |
| **4** | staging exists but **this attempt is not proven to have created it** (no creation evidence in the ownership/attestation record for that exact path) | **KEEP IT.** Report it as present and un-owned | nothing removed; path match is not ownership |
| **5** | ownership is ambiguous — record absent, torn, or `owns()` false for the resource | **STOP.** `NOT_OWNED` | refuse |
| **6** | the target is identity, journal, cursors, outbox, queued evidence, audit records or the state directory | **NEVER REMOVED** by any rollback, under any precedence, including `--purge`'s own gate below | preserved |
| **7** | all of the above cleared, and the service this attempt registered is proven gone | remove **only this attempt's staging**, by recorded path, then verify | removed and verified |

**Rule R-1: nothing is ever deleted because its path matches an expected
installation location.** Removal requires (a) creation evidence for that exact
path recorded by this attempt, and (b) an observed safe state. A pre-existing
directory at the expected path is reported, never reclaimed.

**Rule R-2: `ignore_errors=True` is prohibited in any destructive path.** A
failed removal must be visible: `STILL_PRESENT` is reported truthfully and the
operator is told what remains.

**Rule R-3: uncertainty never escalates privilege.** `UNKNOWN` behaves exactly
as `PRESENT` — the rule M1's `clean_host_report` already enforces
(`nivxforge_m1.py:479-486`) — so no refusal can be converted into a removal by
a later, weaker probe.

### 4.3 Purge

`--purge` keeps its capability and gains its gate: elevation, `--operator-confirmed`,
proven ownership of the state directory, **and** a printed inventory of exactly
what will be destroyed (identity `endpoint_id`, journal row count, undelivered
count, orphaned-row count) before it proceeds. Precedence 0-5 apply to `--purge`
unchanged: it may not run while anything is uncertain. M1's clean-install
uninstall **has no purge, by design**, and the two commands are never aliases —
each refuses the other's layout (UN-1).

### 4.4 The five atomicity guarantees — preserved, owned, tested

| # | Guarantee | Owner after composition | Test |
|---|---|---|---|
| 1 | identity preserved after a post-enrolment failure | the composed failure handler has **no write path to the state directory**; asserted structurally, not by convention | AT-1 (re-targeted trunk test) |
| 2 | the state directory is never removed | precedence 6 | AT-2 |
| 3 | this attempt's partial staging is removed | precedence 7, plus `Engine.reconcile()` invoked **automatically** on failure rather than waiting for a later operator command | AT-3 |
| 4 | a service this attempt registered is deleted **and proved gone** | raised to M1's standard: PID before stop, proven exit, `ERROR_SERVICE_DOES_NOT_EXIST`; `PENDING_DELETION` reported honestly | AT-4 |
| 5 | truthful operator messaging | `_abort_incomplete_clean_install` retained and strengthened; the engine's bare `SystemExit` is replaced, never the reverse. Required strings preserved verbatim: `THIS ENDPOINT IS NOT COLLECTING`, `PRESERVED`, and the no-second-token statement | AT-5 |

`test_s1_2_c2_clean_install_atomicity.py` is **re-targeted, never weakened**:
its assertions are the acceptance criteria for the composed path and must pass
**before** any safeguard is touched. **If it cannot pass, the safeguards stay
and the composition stops.** Safeguard retirement remains **withdrawn**; no gate
in this design authorizes it.

Uninstall distinguishability, ownership validation, exit proof and the `--purge`
re-gate are carried forward from V2 §3.4 unchanged, now subordinate to §4.2.

---

## 5 · P-5 · Provenance and baselines

### 5.1 Exact frozen M1 manifest — `388bb3d6`, subtree `db21f422…`

| File (under `agents/nivxforge-windows/`) | Blob | In trunk `f971c765` |
|---|---|---|
| `Install-NivXForgeSensor.ps1` | `61e08b43540e94d46abda3e004b9eddd85f0b25c` | identical |
| `build/Invoke-TransactionAcceptance.ps1` | `716caca2fb77317ea9c96baf168d5c36ae15cfda` | **absent** |
| `build/build_windows_installer.ps1` | `6235038f19616923dfca74b40034439ddfe779e6` | differs (`e11c63d3…`) |
| `build/run_transaction_tests.py` | `cdc103035035ac47efd27c0dafee5cfcca3a1df3` | **absent** |
| `nivxforge_content_acquisition.py` | `43e68937d8d58c52368af5a03d284ce9e0e605f4` | identical |
| `nivxforge_delivery_counters.py` | `61f2a443253bd909354ab6237f228478ef6bec84` | identical |
| `nivxforge_exclusions.py` | `85c6ed28eed9537f3af33984d59d6142a9edb0e7` | identical |
| `nivxforge_journal.py` | `bbaaaed05ef5d95120157aa2996c8313402ea154` | differs (`6c8f0b35…`) |
| `nivxforge_m1.py` | `27e83b07f5b5282489d5d40122fbce8f0721eb54` | **absent** |
| `nivxforge_scm_worker.py` | `30cb041490ade0fc5a0646335699e42c8122ae49` | **absent** |
| `nivxforge_sensor.py` | `53a45dede74bc9ea8a224cb710f3dd0a6b6f6b53` | differs (`1ab744f3…`) |
| `nivxforge_setup.py` | `a906a7c5c17e909a84cd42c427a7237496cca7fd` | differs (`0a636bbc…`) |
| `nivxforge_transaction.py` | `bf5c0e9db12eb97c19a39afd68b4780cb0ea20db` | **absent** |
| `sysmon/nivx-b5gap1-canary-sysmon.xml` | `1806ef69569f17d388abe45a172af235f23ff60c` | identical |
| `sysmon/nivx-b5gap1-canary-sysmon.xml.b64` | `afe84234362ea5cddefde822d0711dd2a221eab0` | identical |

Fifteen files; four identical to trunk; four trunk-absent; four divergent plus
the build script. Every native job asserts **per-file blob equality against this
table** — the subtree hash alone cannot be used on an integration branch,
because the subtree necessarily differs there.

### 5.2 Build-commit separation

| Field | Meaning |
|---|---|
| `source_commit` | `388bb3d637a076f36d78fc9d1e218c878b082b9b` — the reviewed M1 lineage |
| `source_subtree` | `db21f422561f14fb4dcec91b70925f2b5291c500` |
| `integration_commit` | the integration-branch commit actually built — **never** presented as the source commit |
| `file_manifest_digest` | SHA-256 over the §5.1 table, canonically serialized |
| `trunk_base` | `f971c765` |

An artifact built on the integration branch asserts all five. **An integration
build may never claim `388bb3d6` as its build commit**, and a G3/G4 claim may
never be inferred from an integration build. A commit id proves provenance of a
tree; only the file manifest proves which bytes were compiled.

### 5.3 Trunk per-test baseline manifest

Recorded at `f971c765` on an **isolated** database, before the first Phase 1
commit. Schema per entry: `node_id`, `outcome`, `duration`, `skip_reason`,
`error_class`, `isolation_outcome` (the same test run alone), `first_failing_commit`.
Environment captured once: Python version, `pytest` version, OS, `MONGO_URL`
database name, `DB_NAME`, collection counts before and after, seed, worker count,
ordering plugin state.

Previously demonstrated failures, triaged individually:
12 × `test_34h_a_migration_control.py` — harness/ordering, **pass in isolation**;
4 × `test_p0_f13_5_detection_handoff.py` — contract drift, **fail in isolation**,
inherited by both lineages because `a8ccdb36` (2026-10-03) precedes the
2026-10-04 split. Totals recorded as `2,392 passed / 16 failed / 3 skipped`.

**Rule: the expected-failure set may only shrink, never substitute.** A pass that
replaces a different failure inside the same file is a **regression**, not a
wash. Isolated databases will make the 12 ordering failures disappear, so the
manifest must record *why* each disappeared — isolation or fix — and an
unexplained disappearance **fails the gate**.

### 5.4 M1 per-test baseline manifest — **UNMEASURED**

The only M1 number on record is `373 passed` for `test_m1_clean_install.py`
alone. **No full-suite figure exists for the M1 lineage.** Measuring
`pytest backend/tests/edr -q` at `388bb3d6`, on an isolated database, with the
§5.3 schema, is **Gate A-pre**; until it exists, Gate G-T's comparison has no
counterpart and Gate G-C has no baseline. This is a measurement gap, not an
assumption, and it is named as a gate rather than estimated.

---

## 6 · Remaining risks and owner decisions

| ID | Status |
|---|---|
| RISK-1 partial cleanup vs clean-install refusal | **RESOLVED BY PRECEDENCE** (§4.2); `clean_host_report` still refuses any non-pristine host and no cleanup may precede it |
| RISK-2 retiring the trunk safeguards | **WITHDRAWN** — retained (§4.4) |
| RISK-3 legacy layout | **RESOLVED** — identification + `UNSUPPORTED_PREDECESSOR` refusal, locked by NC-14…NC-16; note §0.1(2): the refusal arrives with the M1 entrypoint in **Phase 2** |
| RISK-4 CI touching production | **RESOLVED BY MANDATE** — lab-only origins, enforced by NC-18 |
| RISK-5 `edr_maintenance.py` dev reset | OPEN — scope/retire decision outstanding |
| RISK-6 enterprise upgrade not G3-approved | OPEN — HOLD stands; import implies no approval |
| RISK-7 Windows Actions run history **UNKNOWN** | OPEN — read-only Actions access, or T2.2 is the first real run |
| RISK-8 interactive-admin context not reproducible in CI | OPEN — accepted split (VM-only rows) |
| RISK-9 Linux `--token` argv exposure | OPEN — separate prioritized security repair, out of scope |
| RISK-10 exposed JWTs / hardcoded admin passwords | OPEN — rotation and exposure assessment outstanding |
| RISK-11 collector tenant-isolation and token-hygiene HOLDs | OPEN — unchanged |
| RISK-12 inherited `trajectory_focus` DB dependency | OPEN — tracked in the §5.3 manifest |
| RISK-13 `transfer_bundle.py` token in a query string | REGISTERED — header-borne token recommended; remediation out of scope |
| **RISK-14** `store.enroll()` leaves the **superseded credential ACTIVE** and its sessions alive (`store.py:271-307`), unlike `rotate_credential` | **NEW — REGISTERED.** Mitigated in the agent contract by §1.6 (prefer Mode R; mandatory printed + recorded revocation obligation). Backend repair is **out of scope** here and is recommended as P1 |
| **RISK-15** fenced rows orphaned by an identity change have **no attributed export path** (§2.5 F-6) | **NEW — ACCEPTED, bounded.** They are retained locally and reported; an export route is a separate, reviewed work item |

**Owner decisions requested:**

1. **Mode R as the advertised default** — change `_validate_identity`'s advice to
   name console rotation first, with token re-enrolment as the fallback. (§1.2, §1.6)
2. **RISK-14 priority** — is revoking superseded credentials inside `enroll()` a
   P1 backend repair, or does the printed-and-recorded obligation suffice for now?
3. **Fenced-row disposition** — confirm retain-and-report (F-4) as default rather
   than any form of delivery under a new identity.
4. **`resolve-identity-transition`** — confirm it is an explicit operator command
   and that `install` refuses and directs to it, rather than completing a
   transition implicitly.
5. **G-M worktree execution in CI** — confirm an ephemeral detached worktree at
   `388bb3d6` is acceptable as the isolated M1 execution target, read-only and
   discarded.

---

## 7 · Unchanged-source verification

* No tracked file was modified by this amendment:
  `git status --porcelain agents backend apps/nivxray-xdr/src .github docs` →
  **0 entries**.
* No ref was created or moved; no commit, no merge, no push, no PR.
* No workflow was triggered; no native build or Windows execution was performed.
* No database was written; no production or preview endpoint was contacted.
* No credential value was read, printed or stored. Secrets appear in this
  document only as route names and identifier fields.
* The frozen subtree `db21f422561f14fb4dcec91b70925f2b5291c500` is untouched,
  and §5.1 is a read of `388bb3d6`, not a modification of it.
* All evidence cited here is `git show` / `grep -c` against `f971c765` and
  `388bb3d6` and reads of the working tree's `backend/`; every count in §3.2 and
  §5.1 is reproducible with those commands.

---

## 8 · Decided versus unimplemented versus unverified

**Decided, with contracts (this document):** the three re-enrolment modes and
their discovery rule (§1.2); proof-not-adoption ownership and the
non-authoritative attestation (§1.3); `update_credential_in_place` and the
scope argument that preserves M1's no-overwrite invariant (§1.5); the
superseded-credential obligation (§1.6); the durable transition record, phase
order, quiescence requirements, recovery table and probe taxonomy (§2.1-§2.4);
the attribution fence F-1…F-6 and replay protection (§2.5); credential archival
and revocation handling (§2.6); the four gates, the reachability matrix and the
deferral register (§3); the cleanup precedence ladder and rules R-1…R-3 (§4.2);
purge gating (§4.3); the five guarantees with owners and tests (§4.4); the file
manifest and build-commit separation (§5.1-§5.2); the baseline manifest schema
and shrink-never-substitute rule (§5.3); RISK-14 and RISK-15.

**Unimplemented — no source-level behaviour exists for any of it:** every mode,
flag, code and record in §1 and §2 — `--re-enrol` modes, `--credential-stdin`,
`--allow-identity-change`, `--allow-tenant-change`, `update_credential_in_place`,
`reenrolment_attestation.json`, `identity_transition.json`,
`resolve-identity-transition`, the fence and the `ORPHANED_BY_IDENTITY_TRANSITION`
marking; the §4.2 precedence ladder and the uninstall/purge hardening; the
workflow guard, lab-origin and per-file blob assertions; the deferral register;
and **every test named here** — RE-1…RE-12, AT-1…AT-5, UN-1…UN-4, NC-14…NC-22,
CI-GATE-0.

**Unverified — must not be cited as evidence:** the M1 full-suite baseline is
**UNMEASURED** (§5.4) · Windows Actions **run history is UNKNOWN** · **G4 is NOT
RUN** · no portable test substitutes for a native Windows result · the
transaction engine's upgrade behaviour remains **unreviewed** (M1's G3 covers the
clean installer only) · whether the composed installer can satisfy AT-1…AT-5
remains **an open engineering question**, and if it cannot, the safeguards stay
and the composition stops · the behaviour of `enroll()` against a *live*
superseded credential is inferred from source (`store.py:271-307`,
`_active_credential`) and has **not** been exercised end-to-end.

**HOLDs reaffirmed, none removed:** Windows G4 not accepted · M1 clean-install G3
does not imply enterprise upgrade/recovery approval · collector tenant-isolation
and token-hygiene gates stand · response execution retains backend approval and
independent verification · exposed credentials still require rotation and
exposure assessment · no production activation, rollout, signing or merge is
authorized.

**Stop boundary: G1 V3 handoff. Independent Codex verification and owner
approval remain mandatory before any G2 work begins.**
