# NIVXFORGE EDR — P0 SOURCE RECONCILIATION · G1 **V2**
## Design amendment under owner decision · READ-ONLY

Supersedes `NIVXFORGE_EDR_P0_RECONCILIATION_G1.md`
(`e5fafcbc…`) in the sections named below. Corrects every finding in
`NIVXFORGE_EDR_G1_INDEPENDENT_REVIEW.md` (`16b32fb5…`, verdict **G1
BLOCKED**).

**Scope: a bounded design amendment.** No code, no merge, no commit, no CI
trigger, no deployment, no HOLD removal. **Independent Codex review and owner
approval remain mandatory before G2.**

Baselines (re-verified, unchanged): trunk `f971c765` · M1 `388bb3d6` · ancestor
`ae34056315cde90873386bb56edfcd5bd5cd19b9` · frozen subtree
`db21f422561f14fb4dcec91b70925f2b5291c500`.

---

## 0 · Correction matrix

| ID | Review finding | Amended in | Resolution class |
|---|---|---|---|
| **C-1** | `enrol()` post-condition regression breaks `--re-enrol`; no positive test exists | **§2** (re-enrolment contract), §5 Gate A2, §6 tests RE-1…RE-7 | **design decision resolved** · implementation UNIMPLEMENTED |
| **C-2** | Phase 1 would auto-trigger the push workflow | **§4.1** (CI inertness as a precondition), §5 Gate A0 | design decision resolved · UNIMPLEMENTED |
| **C-3** | Lab origin advisory; provenance asserted only by commit | **§4.2** (mandatory lab origin), §4.3 (subtree assertion) | design decision resolved · UNIMPLEMENTED |
| **C-4** | Sensor row LOW→HIGH; `install()`, `--re-enrol`, `uninstall` misclassified | **§1** (amended reconciliation rows) | **resolved — classification corrected** |
| **C-5** | RISK-2 premise false: engine has no identity/enrolment code | **§3** (atomicity contract; safeguards **retained**) | **resolved — owner decision: do not retire** |
| **C-6** | Refusal behaviours not locked as negative controls | **§3.3** + §6 NC-14…NC-18 | design decision resolved · UNIMPLEMENTED |
| **C-7** | No per-test manifest; no M1 full-suite baseline | **§5.1** (baseline manifest), §5.2 (M1 baseline) | **resolved — measurement UNMEASURED, named as a gate** |
| **C-8** | Phase 1 build script ships unreachable code | **§4.4** | **resolved — trunk build script in Phase 1** |
| **C-9** | `transfer_bundle.py` token in a query string | **§7** RISK-13 | **resolved — registered**; remediation OUT OF SCOPE |

**Resolved here = a design decision with a stated contract.** Every row marked
UNIMPLEMENTED has **no source-level behaviour yet** and **no verification**.
§8 states exactly what remains unimplemented and unverified.

---

## 1 · Amended reconciliation rows

Only the rows the review disputed are restated. All other rows of V1 §C stand.

| Component | Trunk | M1 | Required outcome | Risk | Evidence |
|---|---|---|---|---|---|
| `nivxforge_journal.py` | quarantine + backlog | same + `rebaseline_cursor`, `discard_undelivered` | **KEEP FROM M1** — claim upheld unconditionally | LOW | 47+/0−; all 8 journal entry points the installer selftest uses are unchanged |
| `nivxforge_sensor.py` — collection, cursors, integrity, policy, exclusions, heartbeat, batch degradation, transport defaults | identical / already carried | identical | **KEEP FROM M1** | LOW | no diff hunks in those functions; `attempts=2` default preserves trunk |
| `nivxforge_sensor.py` — **`enrol()` post-condition** | `IDENTITY_FILE.write_text(...)` **overwrites** | `publish_identity()` **refuses when the file exists** | **REQUIRES NEW COMPATIBILITY ADAPTER** (§2) | **HIGH until C-1 lands** | `publish_identity` is called unconditionally; trunk `setup.py:573/594` reaches it with the identity present |
| `install()` — production path | direct installer + automatic post-failure cleanup | transaction engine; `--re-enrol` refused | **INCOMPATIBLE — DESIGN DECISION REQUIRED**; resolved by §2 + §3 | **HIGH** | `setup.py:1148-1149` |
| `--re-enrol` | supported | **refused** | **PRESERVE** as an ownership-gated operation (§2) | **HIGH** | owner decision |
| `uninstall` / `--purge` | supported, but unproven removal | **refused** (`"uninstall/purge unavailable in transaction validation builds"`) | **PRESERVE** both, distinguishable (§3.4) | **HIGH** | `setup.py:1213-1218`; owner decision |
| Trunk atomicity safeguards (`_remove_partial_service`, `_remove_partial_staging`, `_abort_incomplete_clean_install`) | present, tested | absent | **KEEP FROM TRUNK — RETIREMENT WITHDRAWN** (§3) | — | `grep -ci enrol nivxforge_transaction.py` → **0** |
| Legacy service-image layout | `sensor\service\` | identified, then `UNSUPPORTED_PREDECESSOR` refusal | **KEEP FROM M1 + lock the refusal as a negative control** (§3.3) | LOW once locked | `_active_service_exe()`; engine `predecessor()` |

---

## 2 · Re-enrolment contract (owner decision 1) — C-1

**Decision: re-enrolment is preserved, as a separate ownership-gated
operation. An existing identity is never silently overwritten, and never
destroyed.**

Modelled on the pattern that already exists and was independently reviewed —
M1's `m1_reconcile_enrollment(..., operator_confirmed=False)`, which requires
**both** an explicit operator confirmation **and** a machine check (a
successful authenticated session probe) and *"neither re-enrolls nor silently
adopts"*.

### 2.1 Surface

`enrol()` keeps M1's post-condition **unchanged**: first publication only,
no-overwrite, `_rename_no_replace`. The installer never asks it to replace
anything. Replacement becomes a distinct command:

```
NivXForgeEDRSetup.exe retire-identity --operator-confirmed --reason <text>
NivXForgeEDRSetup.exe install --tenant <t> --token-stdin        # first publication
```

`install --re-enrol` is **retained as an alias** that fails with a directive
message naming `retire-identity`, so the advice already printed by
`_validate_identity` ("Re-run with --re-enrol and a fresh token") stays
truthful. **No operator path may advise a command that refuses.**

### 2.2 Authorization — all four required, fail-closed

1. elevated administrator (`_assert_admin()`);
2. `--operator-confirmed` present (never defaulted, never inferred);
3. the ownership record confirms this installation owns the state directory
   (M1 `Ownership.owns`), else `NOT_OWNED`;
4. a machine check of the **current** identity: either a successful
   authenticated session probe (credential live → retirement is deliberate) or
   a definite backend rejection (credential dead → retirement is recovery).
   **An indeterminate probe refuses** (`IDENTITY_STATE_UNKNOWN`).

### 2.3 Old/new identity handling

| Step | Contract |
|---|---|
| archive | the current `identity.json` is **moved**, never deleted, to `identity.<endpoint_id>.<utc>.retired.json` under the state directory, via the same no-overwrite rename; the archive inherits the protected DACL |
| record | an ownership-record history entry `IDENTITY_RETIRED` carrying `endpoint_id`, `credential_id`, probe outcome, operator reason and UTC |
| publish | the new identity is published by the ordinary `publish_identity()` — the destination is now genuinely absent, so **the no-overwrite guarantee is never weakened** |
| journal | journal, cursors, outbox and queued evidence are **untouched**; retirement is an identity operation, not an evidence operation |
| backend | the old credential is **not** revoked by the agent; revocation is a backend operator action (`/api/edr/endpoints/{id}/revoke`), recorded in the printed result |

### 2.4 Failure recovery

| Failure point | State | Required behaviour |
|---|---|---|
| probe indeterminate | nothing moved | refuse; nothing archived |
| archive rename fails | identity still live | refuse; endpoint keeps collecting |
| crash **after** archive, **before** publication | no `identity.json`, one archive, history says `IDENTITY_RETIRED` | next `install` sees an absent identity and a retirement record → **prints that a retirement is in progress and requires a fresh token**; it must never auto-restore the archive |
| new enrolment refused by the backend | archive present, no identity | the attempt marker rules apply unchanged: an **OPEN** marker blocks automatic retry; reconcile first |
| operator wants the old identity back | archive present | manual, ownership-gated restore with its own confirmation — **out of scope for G2-Phase-2** and explicitly not implemented |

### 2.5 Positive tests — RE-1…RE-7 (none exist today)

RE-1 first publication onto an absent destination succeeds · RE-2
`enrol()` onto an existing identity still **refuses** (the M1 invariant holds)
· RE-3 `retire-identity` without `--operator-confirmed` refuses and moves
nothing · RE-4 with confirmation **and** a live probe: archive created,
history entry written, new publication succeeds, journal byte-identical before
and after · RE-5 with a dead credential: same, with the probe outcome recorded
· RE-6 indeterminate probe refuses with `IDENTITY_STATE_UNKNOWN` · RE-7 crash
between archive and publication leaves the documented recoverable state and
the next `install` prints the retirement-in-progress message.

**RE-4 is the test the review found missing: today no test exercises a
*successful* re-enrolment on either lineage.**

---

## 3 · Atomicity and removal (owner decisions 2, 3, 4) — C-5, C-6

**Decision: the trunk's cleanup safeguards are NOT retired.** The review
established the engine cannot satisfy them: `nivxforge_transaction.py`
contains **zero** enrolment or identity code, and M1's `install()` failure path
is a bare `SystemExit`.

### 3.1 Division of responsibility

| Layer | Owns | Source |
|---|---|---|
| Transaction engine | payload staging, SCM mutation, uncertainty settlement, predecessor authentication | `nivxforge_transaction.py` |
| **Composed `install()`** | enrolment, identity, **post-failure cleanup, operator messaging** | the Phase 2 work |

The engine is the mechanism; the installer remains the guarantor.

### 3.2 The five invariants, each with its owner and its test

| # | Invariant | Satisfied by | Test |
|---|---|---|---|
| 1 | identity preserved after a post-enrolment failure | composed `install()` — the failure handler **never touches the state directory**; asserted, not assumed | AT-1 (re-targeted trunk test) |
| 2 | state directory never removed | the failure handler has no state-directory write path at all | AT-2 |
| 3 | partial staging removed | `_remove_partial_staging` **retained**, and the handler calls `Engine.reconcile()` **automatically**, not only on an operator's later command | AT-3 |
| 4 | a service this attempt registered is deleted **and proved gone** | `_remove_partial_service` **retained**, raised to M1's standard: `require_observation` + `ERROR_SERVICE_DOES_NOT_EXIST`; `PENDING_DELETION` is reported, never claimed as removed | AT-4 |
| 5 | truthful operator message | `_abort_incomplete_clean_install` **retained**; the bare `SystemExit` is replaced, never the reverse. Required strings: `THIS ENDPOINT IS NOT COLLECTING`, `NO second enrolment token`, `PRESERVED` | AT-5 |

`test_s1_2_c2_clean_install_atomicity.py` is **re-targeted, not weakened**: its
assertions are the acceptance criteria for the composed path, and it must pass
**before** any safeguard is touched. If it cannot pass, the safeguards stay and
the composition stops — that is the gate, not a preference.

### 3.3 Legacy installations — explicit refusal, never implicit migration

Upheld from source and now **locked**: `_active_service_exe()` resolves the SCM
`binPath` → `active.json` → the legacy path; the engine inventories the
registered image's directory and, when its identity is not a pinned
predecessor, refuses with `UNSUPPORTED_PREDECESSOR`, stating *"Nothing was
stopped, staged, reconfigured or activated, and identity, tenant, credentials,
journal, cursors and queued evidence are untouched."*

Negative controls **NC-14…NC-16**: an old-layout install is identified; it is
refused with that code; **nothing is mutated** (service state, `binPath`,
staging directory and state directory byte-identical before and after). **No
compatibility path is approved by this design** — refusal is the approved
outcome, and migration remains a separate, reviewed procedure.

### 3.4 Uninstall — both preserved and distinguishable

| | **Enterprise uninstall** | **M1 clean-install uninstall** |
|---|---|---|
| command | `uninstall [--purge]` | `m1-uninstall --m1-config <path>` |
| layout | `sensor\service\` or `sensor\versions\<id>\` | M1 `install_dir` |
| authority | ownership validation **added** (currently absent) | M1 `Ownership.owns(record, "service")` |
| removal proof | **raised to M1's standard**: identify the PID **before** the stop, require a proven exit, require `ERROR_SERVICE_DOES_NOT_EXIST`, report `PENDING_DELETION` honestly | already does exactly this |
| evidence | state directory **kept by default** | always preserved; nothing under it is removed |
| `--purge` | retained, **re-gated**: `--purge` additionally requires `--operator-confirmed` and prints the identity and journal it is about to destroy | **has no purge** — by design |

Today's enterprise uninstall calls `sc delete` then
`shutil.rmtree(INSTALL_DIR, ignore_errors=True)` with **no ownership check, no
exit proof and no removal verification**. Preserving the capability therefore
means preserving *and strengthening* it; the M1 refusal
(`"uninstall/purge unavailable in transaction validation builds"`) is
withdrawn for the composed installer. The two commands must never be aliases:
UN-1 asserts each refuses the other's layout.

---

## 4 · Phase 1 — additive integration, with the review's preconditions

Phase 1 remains additive and remains separable. Its purpose is to stop the
lineages drifting **without** touching the installer entrypoint.

### 4.1 CI inertness — a precondition, not an observation (C-2)

The trunk workflow's `push:` trigger carries **no `branches:` filter**, so a
commit touching `agents/nivxforge-windows/**` runs Gates 5 and 6 — which
create and start a real service. Therefore:

**P1-PRE-1.** The *first* commit of Phase 1 contains **only** the workflow
guard — a `branches:` allow-list (or the integration branch added to
`branches-ignore`) — and touches no file under `agents/`. No source import may
share a commit with, or precede, this guard.

**P1-PRE-2.** Verification before the next commit: the guard commit itself must
not have started a run (it touches the workflow file, so the path filter
matches — the guard must therefore be written so that the branch is already
excluded by the time the filter is evaluated, i.e. the allow-list excludes the
integration branch).

### 4.2 Mandatory lab-only backend (C-3)

**No CI gate may start a service configured against the production origin.**
Every service-starting gate uses `https://edr-lab.<owned-domain>`. No code
change is required: `_assert_backend` is a **deny**-list (`localhost`,
`127.0.0.1`, `::1`, `0.0.0.0`, `preview.emergentagent.com`, `.local`, dev
ports), so a lab FQDN is already accepted. Recorded asymmetry: M1's
`load_config` applies **no** production-origin deny-list (https + netloc +
`windows-default` only), so the M1 clean-install path accepts a lab origin the
enterprise path would also accept — and a preview origin that the enterprise
path refuses. CI-GATE-0 asserts that no gate's configured origin matches the
production FQDN.

### 4.3 Frozen-subtree identity assertion (C-3)

Every native CI job asserts **both**:

```
build_commit == 388bb3d637a076f36d78fc9d1e218c878b082b9b
git rev-parse HEAD:agents/nivxforge-windows == db21f422561f14fb4dcec91b70925f2b5291c500
```

A commit id does not prove which bytes were compiled; the subtree hash does.
On the integration branch the subtree necessarily differs, so the assertion
becomes **per-file blob equality** for the frozen M1 files against `388bb3d6`.

### 4.4 Build script and unreachable code (C-8)

**Phase 1 keeps the trunk's `build_windows_installer.ps1`.** M1's version
hidden-imports `nivxforge_m1`, `nivxforge_transaction`, `nivxforge_scm_worker`
and generates `payload-manifest.json`; with the trunk entrypoint those modules
are unreachable (verified: **zero** `__main__` guards, **zero** `argparse`, and
no `m1_dispatch` in the trunk entrypoint), so shipping them would place
unreachable code in a signed-artifact-to-be. M1's build script arrives in
**Phase 2**, together with the entrypoint that reaches it.

### 4.5 Phase 1 content

Import, byte-identical: `nivxforge_m1.py`, `nivxforge_transaction.py`,
`nivxforge_scm_worker.py`, `build/Invoke-TransactionAcceptance.ps1`,
`build/run_transaction_tests.py`, `windows-installer-transaction-build.yml`,
`test_m1_clean_install.py`, `test_installer_transaction.py`,
`test_p0_installer_upgrade_repair.py`, plus the additive
`acquisition_integrity.py` and `fixtures_b5_gap1_source.py` edits.
Take M1's journal blob `bbaaaed0` **unconditionally**.
Take M1's sensor blob `53a45ded` **only together with the C-1 adapter** —
§2's `retire-identity` and the directive `--re-enrol` message must land in the
same commit as the sensor, or `--re-enrol` breaks in between.
Do **not** touch `nivxforge_setup.py` (beyond the C-1 adapter),
`windows-sensor-installer.yml` (beyond P1-PRE-1) or anything in `backend/`.

### 4.6 Phase 1 must not

break any working operator path (C-1) · trigger a service-mutating workflow
(P1-PRE-1) · contact production infrastructure (§4.2) · alter any byte of the
frozen M1 implementation (§4.3) · ship unreachable code (§4.4) · touch
`routers/edr.py`, `edr_plane/response.py` or `edr_response.py`.

---

## 5 · Baselines and gates (C-7)

### 5.1 Per-test expected-failure manifest

Before the first Phase 1 commit, record at `f971c765`, on an isolated
database: a machine-readable manifest of **test id → status**, with each of
the 16 failures triaged individually (12 `test_34h_a_migration_control.py` =
harness/ordering, pass in isolation; 4 `test_p0_f13_5_detection_handoff.py` =
contract drift, fail in isolation, inherited by both lineages because
`a8ccdb36` of 2026-10-03 precedes the 2026-10-04 split).

**Rule: the expected-failure set may only shrink, never substitute.** A pass
that replaces a different failure inside the same file is a **regression**, not
a wash. Because isolated databases will make the 12 ordering failures
disappear, the manifest must record *why* each disappeared — isolation or fix —
and an unexplained disappearance fails the gate.

### 5.2 M1 full-suite baseline — **UNMEASURED**

V1 recorded `2,392 / 16 / 3` for the trunk and `373` for the M1 clean-installer
file only. **No full-suite number exists for the M1 lineage.** Measuring
`pytest backend/tests/edr -q` at `388bb3d6` on an isolated database is
**Gate A-pre** and must complete before Gate B can mean anything.

### 5.3 Gates

| Gate | Condition |
|---|---|
| **A0** | the workflow guard is in place and no service-mutating run was triggered |
| **A-pre** | the trunk manifest (§5.1) and the M1 full-suite baseline (§5.2) both exist |
| **A1** | trunk sensor, journal and delivery suites pass unchanged against M1's blobs |
| **A2** | **RE-1…RE-7 pass**, including the previously non-existent successful re-enrolment (RE-4) |
| **B** | M1's 373 + transaction + upgrade suites pass on the integration branch, compared against §5.2 |
| **C** | AT-1…AT-5 pass against the composed installer **before** any safeguard is touched |
| **D** | UN-1…UN-4 (uninstall distinguishability and proof) pass |
| **E** | full suite on isolated databases; expected-failure set shrunk or identical, never substituted |
| **F** | all negative controls NC-1…NC-18 still fail |

Phase 2 may not begin until A0–B are green. Safeguard retirement is
**withdrawn** (§3), so no gate authorizes it.

---

## 6 · Acceptance tests and negative controls

**Positive:** RE-1…RE-7 (§2.5) · AT-1…AT-5 (§3.2) · UN-1 each uninstall refuses
the other's layout · UN-2 enterprise uninstall without ownership refuses ·
UN-3 `--purge` without `--operator-confirmed` refuses · UN-4 `PENDING_DELETION`
is reported as pending, never as removed.

**Negative controls — must still FAIL:** NC-1…NC-13 from V1 §G.4 (plaintext
`--token`; secret-shaped argv; silently ignored flag; localhost/preview origin;
non-clean host; identity overwrite; token replay; unsafe or indeterminate
service descriptor; non-LocalSystem service context; `Users`-writable config;
`service_exe` outside the payload; unauthorised tenant receiving an empty
projection; a `VERIFIED` response without independent evidence) **plus**:
NC-14 old-layout install identified · NC-15 refused with
`UNSUPPORTED_PREDECESSOR` · NC-16 nothing mutated by that refusal · NC-17
`retire-identity` without confirmation or with an indeterminate probe refuses ·
NC-18 no CI gate starts a service against the production origin.

---

## 7 · Risk register — amendments

| ID | Status |
|---|---|
| RISK-1 partial cleanup vs clean-install refusal | **RESOLVED BY SEPARATION** — the safeguards operate on the *enterprise* path only; M1's `clean_host_report` continues to refuse any non-pristine host and no cleanup may run before it. NC-5 enforces this |
| RISK-2 retiring the safeguards | **WITHDRAWN** — owner decision: retained (§3) |
| RISK-3 legacy layout | **RESOLVED** — explicit identification + refusal, locked by NC-14…NC-16 (§3.3) |
| RISK-4 CI touching production | **RESOLVED BY MANDATE** (§4.2), enforced by NC-18 |
| RISK-5 `edr_maintenance.py` dev reset | OPEN — scope/retire decision outstanding |
| RISK-6 enterprise upgrade not G3-approved | OPEN — HOLD stands; Phase 1 import implies no approval |
| RISK-7 Actions run history UNKNOWN | OPEN — read-only Actions access, or T2.2 is the first real run |
| RISK-8 interactive-admin context not reproducible in CI | OPEN — accepted split (VM-only rows) |
| RISK-9 Linux `--token` argv exposure | OPEN — separate prioritized security repair, out of scope |
| RISK-10 exposed JWTs / hardcoded admin passwords | OPEN — rotation and exposure assessment outstanding |
| RISK-11 collector tenant-isolation and token-hygiene HOLDs | OPEN — unchanged |
| RISK-12 inherited `trajectory_focus` DB dependency | OPEN — fix in G2, tracked in the manifest |
| **RISK-13** `backend/transfer_bundle.py` serves bundles on `GET /api/transfer/{name}?token=…`; fail-closed and `compare_digest`, but a **token in a query string** reaches access logs and proxy telemetry | **REGISTERED (C-9)** — remediation OUT OF SCOPE here; recommend a header-borne token |

---

## 8 · Resolved design versus unverified behaviour

**Resolved as design decisions, with contracts (this document):** re-enrolment
preservation and its authorization, archival and recovery model (§2); retention
of all five atomicity safeguards and their ownership split (§3); uninstall
preservation, distinguishability and re-gating (§3.4); explicit legacy refusal
(§3.3); CI inertness, mandatory lab origin, subtree assertion and the build
script decision (§4); the baseline-manifest rule (§5.1); classification
corrections (§1); RISK-13 registration (§7).

**Unimplemented — no source-level behaviour exists:** `retire-identity` and
its archival, probe, history entry and recovery states · the directive
`--re-enrol` message · the composed `install()` failure handler and its
required strings · automatic `Engine.reconcile()` on failure · ownership
validation, exit proof and removal verification in the enterprise uninstall ·
`--purge` re-gating · the workflow guard, lab origin and subtree assertions ·
every test named here (RE-1…RE-7, AT-1…AT-5, UN-1…UN-4, NC-14…NC-18, CI-GATE-0).

**Unverified — claims that must not be treated as evidence:** the M1 full-suite
baseline is **UNMEASURED** (§5.2) · Windows Actions **run history is UNKNOWN** ·
**G4 is NOT RUN** · no portable test substitutes for a native result · the
transaction engine's upgrade behaviour remains **unreviewed** (M1's G3 covers
the clean installer only) · whether the composed installer can satisfy AT-1…AT-5
is **an open engineering question**, and if it cannot, the safeguards stay and
the composition stops.

**HOLDs reaffirmed, none removed:** Windows G4 not accepted · M1 clean-install
G3 does not imply enterprise upgrade/recovery approval · collector
tenant-isolation and token-hygiene gates stand · response execution retains
backend approval and independent verification · exposed credentials still
require rotation and exposure assessment · no production activation or rollout
is authorized.

**Unchanged state:** no tracked code was modified
(`git status --porcelain agents backend apps/nivxray-xdr/src .github docs` → 0
entries), no ref was moved by this amendment, no CI was triggered, no database
was written, no credential value was read, and the frozen subtree
`db21f422…` is untouched.

**Stop boundary: G1 V2 handoff. Independent Codex review and owner approval
remain mandatory before any G2 work.**
