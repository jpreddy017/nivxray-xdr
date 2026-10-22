# NIVXFORGE EDR — P0 SOURCE RECONCILIATION & WINDOWS CI READINESS
## G0 capability reconciliation + G1 engineering design · READ-ONLY

**Authorization honoured: G0/G1 only.** No merge, cherry-pick, rebase, commit,
push, ref change, CI trigger, installer execution, deployment, database write
or HOLD removal was performed. No G2 implementation. **G1 PASS is not declared
here** — this package exists to be reviewed independently.

---

# A · SOURCE AND PROVENANCE REPORT

## A.1 Inspection method and its limits

| Item | Value |
|---|---|
| Repository | `jpreddy017/nivxray-xdr` |
| Method | **read-only inspection of the existing object store** (`git cat-file`, `ls-tree`, `rev-list`, `diff`, `log -S`, `show`) plus read-only queries against the preview Mongo. |
| Isolated clone | **NOT established.** `/app` has **248 MB** free; a second full clone is not safe. This is stated plainly: the object store is shared with the developer workspace. No `fetch`, `reset`, `clean`, `rebase`, `cherry-pick` or branch switch was issued, and no existing worktree was altered. |
| Reproducibility | every finding below is anchored to an immutable commit/tree/blob id and can be reproduced from the published M1 snapshot bundle or from the named commits. |
| GitHub Actions history | **inaccessible** — no token. Workflow *definitions* are verified from source; workflow *execution* is **UNKNOWN**. |

## A.2 Baselines — verified, with one correction to the brief

| Brief says | Verified | Note |
|---|---|---|
| trunk `fix/p0-sensor-delivery` @ `f971c765` | branch is correct; **head has moved to `17f99d363485a6fb96ff7025f2db6c84ab31f77b`** (tree `71596320…`) | the only delta is `A memory/NIVXFORGE_EDR_CAPABILITY_INVENTORY.md` + `M memory/PRD.md` — **no code change**. `f971c765` remains the correct code baseline. |
| common ancestor `ae340563`, 2026-10-04 | **CONFIRMED** — `git merge-base f971c765 388bb3d6` = `ae34056315cde90873386bb56edfcd5bd5cd19b9`, tree `7b3eefe9…`, dated **2026-10-04** | also the merge-base of `b8020771` and HEAD |
| M1 `388bb3d6`, tree `df8eb48b…`, subtree `db21f422…` | **CONFIRMED** all three | |
| snapshot `53a965ff…` | **CONFIRMED**; all 18 exported blobs byte-identical to `388bb3d6`'s blobs | G3 covers these bytes, not an authenticated commit history — restated, not weakened |
| G4 prep `b8020771`, parent `388bb3d6`, 3 files under `agents/nivxforge-g4/` | **CONFIRMED**; `b8020771:agents/nivxforge-windows` = `db21f422…` — **the reviewed subtree is genuinely unchanged** | |
| capability inventory SHA-256 `d8e4e154…` | **CONFIRMED** byte-for-byte | |

Divergence size: **71 commits** on the trunk side, **18** on the M1 side
(19 including G4 prep), from `ae340563`.

## A.3 Repository state at the time of inspection

`git status --porcelain agents backend apps .github docs` → **0 entries**.
The worktree has 158 dirty entries in total, **all pre-existing and all
outside code**: `M rocket-p0/a3` plus untracked `rocket-e2e/`,
`rocket-evidence/` artefacts, and this assignment's own `memory/` documents.
Refs digest `cf3c3972…`; no ref belonging to another branch was touched.

---

# B · BRANCH DIVERGENCE REPORT

## B.1 The real conflict surface is four files, not a lineage

Diffing **only code paths** (`agents backend apps .github`) from the common
ancestor:

**Trunk-only additions** — `backend/routers/edr_maintenance.py`,
`backend/tests/edr/test_s1_2_c2_clean_install_atomicity.py`,
`backend/transfer_bundle.py`, `backend/server.py` (M).

**M1-only additions** — `nivxforge_m1.py`, `nivxforge_transaction.py`,
`nivxforge_scm_worker.py`, `build/Invoke-TransactionAcceptance.ps1`,
`build/run_transaction_tests.py`,
`.github/workflows/windows-installer-transaction-build.yml`,
`test_m1_clean_install.py`, `test_installer_transaction.py`,
`test_p0_installer_upgrade_repair.py`,
`backend/edr_plane/acquisition_integrity.py` (M),
`build/build_windows_installer.ps1` (M), `fixtures_b5_gap1_source.py` (M).

**Modified on both sides — the entire conflict surface:**

| File | base blob | trunk blob | M1 blob | Verdict |
|---|---|---|---|---|
| `nivxforge_journal.py` | `8c4c6da3` | `6c8f0b35` | `bbaaaed0` | **M1 is a strict superset** |
| `nivxforge_sensor.py` | `d0593501` | `1ab744f3` | `53a45ded` | **M1 is a compatible superset** |
| `nivxforge_setup.py` | `59d6c7a9` | `0a636bbc` | `a906a7c5` | **genuine divergence — compose required** |
| `.github/workflows/windows-sensor-installer.yml` | `3a9cc4ed` | `95198474` | `7b21d6de` | **genuine divergence — compose required** |
| `test_b5_gap1_pre_canary_acceptance.py` | `d3b7c14a` | `3bc7b2df` | `3bc7b2df` | **identical blobs — no conflict** |
| `test_p0_sensor_delivery_repair.py` | absent | `8540ecad` | `8540ecad` | **identical blobs — added on both sides, no conflict** |

**This is the single most important finding of the assignment.** The previous
audit's framing — "two divergent heads" — is literally true for four files,
but behaviourally the conflict reduces to **two files**: the installer and its
workflow. The sensor and journal already converged on the M1 side, and two of
the contested tests are byte-identical.

## B.2 `nivxforge_journal.py` — M1 is a strict superset

`git diff f971c765 388bb3d6` for this file: **47 insertions, 0 deletions.**
Both lineages added the *same* hunks at the *same* anchors (the
`BACKEND_ACCEPTED` / `DELIVERY_BACKLOG` states, `limits()`, `quarantine()`,
`quarantined()`). M1 additionally adds `rebaseline_cursor(channel, record_id)`
and `discard_undelivered()`, which the M1 clean-install and re-baseline paths
need. **Nothing the trunk relies on is removed or altered.**

→ **KEEP FROM M1.** Zero behavioural risk; the proof is the empty deletion set.

## B.3 `nivxforge_sensor.py` — M1 is a compatible superset

`git diff f971c765 388bb3d6`: 175 insertions, **18 deletions**, and every
deleted line is the pre-M1 *signature* of four functions, replaced by an
extended form:

| Authoritative behaviour | Lineage | Evidence |
|---|---|---|
| Event collection (`acquire`, `_query_channel`, `detect_gaps`, `_probe_source_tail`) | identical both sides | no hunk in the trunk↔M1 diff |
| Normalisation / cursor management (`_bookmarks`, `_save_bookmarks`, `_mirror_bookmarks`) | identical both sides | — |
| **Batch delivery degradation** (`BATCH_SUPPORT`, `batch_available/unavailable`, `batch_reprobe_seconds`, `_deliver_batch`, `_drain_journal`, `_drain`, `_cycle`) | **present on BOTH** | `BATCH_SUPPORT` occurs 5× in the M1 sensor; no hunk between trunk and M1 in these functions — M1 already carries the trunk's P0 delivery repair |
| Telemetry integrity (`_report_integrity`), policy sync (`_sync_policy`), exclusion enforcement (`_report_enforcement`), health (`_heartbeat`) | identical both sides | — |
| **Transport retry contract** | **M1 extends** | `_Transport.request(..., attempts: int = 2)` — *"`attempts` defaults to 2 — the reconnect-once behaviour every telemetry caller relies on. M1 enrolment, and only M1 enrolment, passes 1: a one-time token must never be replayed blindly."* The trunk's behaviour is the default |
| **Enrolment hardening** | **M1 only** | `ATTEMPT_FILENAME`, `attempt_marker_path`, `validate_enrolment_response`, `_rename_no_replace` (MoveFileExW **without** `MOVEFILE_REPLACE_EXISTING`), `publish_identity`, `open/read/close_attempt_marker`, `enrol(..., single_attempt=True)` |
| Identity / process identity | unchanged both sides | neither lineage touches `_machine_facts` |

→ **KEEP FROM M1.** The 18 deletions are additive signature changes with
backwards-compatible defaults; the acceptance requirement is to prove the
trunk's delivery tests still pass against the M1 blob (§G).

## B.4 `nivxforge_setup.py` — the one genuine divergence

`git diff f971c765 388bb3d6`: **1,127 insertions, 264 deletions.**

Trunk's unique work (vs ancestor):

1. **Clean-install atomicity** — `_remove_partial_service()`,
   `_remove_partial_staging()`, `_abort_incomplete_clean_install(enrolled)`,
   invoked from `install()`'s `except BaseException:` rollback when there is
   no prior service to restore, with its own 337-line test
   (`test_s1_2_c2_clean_install_atomicity.py`) asserting: the identity is
   preserved after a post-enrolment failure, **the state directory is never
   removed**, partial staging *is* removed, a service this attempt registered
   is deleted *and proved gone*, and the operator is told
   `THIS ENDPOINT IS NOT COLLECTING` / `NO second enrolment token` /
   `PRESERVED`.
2. **Bounded drain-mode policy** — `DRAIN_MIN_BACKLOG`,
   `DRAIN_MAX_CONSECUTIVE`, `DRAIN_WAIT_SECONDS`, `_drain_wait()`, consumed by
   `_service_class`.

Presence check across lineages:

| Symbol | trunk | M1 |
|---|---|---|
| `DRAIN_MIN_BACKLOG`, `_drain_wait` | present | **present** (shared) |
| `_service_class`, `_service_log` | present | **present** (shared) |
| `_remove_partial_service`, `_remove_partial_staging`, `_abort_incomplete_clean_install` | present | **ABSENT** |
| `m1_dispatch`, `nivxforge_m1`, `nivxforge_transaction` imports | **ABSENT** | present |

M1 replaced `install()` wholesale: *"The sole production install path: durable
transaction engine"* — `Engine(INSTALL_DIR, backend).run(payload, manifest,
prepare)`, with `recover_transaction()` and `resolve_operation()` for
uncertain SCM operations. The trunk's ad-hoc rollback helpers are the
**pre-transaction** answer to the same problem. They are therefore a
*retirement* candidate, **but only against evidence** that the transaction
engine upholds the five invariants the trunk's test asserts. That evidence
does not exist today.

M1 also changed the **on-disk layout and a public signature**:

| | trunk | M1 |
|---|---|---|
| service image | `%ProgramFiles%\NivXForge\sensor\service\NivXForgeSensor.exe` (`SERVICE_EXE`) | `…\NivXForge\sensor\versions\<id>\NivXForgeSensor.exe` (`VERSIONS_DIR`) — *"the live image is never written over, which is the P0 upgrade repair"* |
| service install | `_install_service(api, interval)` | `_install_service(api, interval, exe)` |

→ **COMPOSE BOTH**, and this is where the real design work is (§D).

## B.5 `.github/workflows/windows-sensor-installer.yml` — follows the layout change

`git diff f971c765 388bb3d6`: **489 insertions, 7 deletions.** M1 adds
`branches-ignore: ['engineering/windows-installer-transaction-recovery']` (so
service-mutating gates do not fire on that engineering branch), rewrites the
three staging/SCM gates for the versioned layout, passes the new
`_install_service` third argument, and adds two gates: *"Upgrade repair ·
mapped image, full upgrade and rollback"* and *"Upgrade repair · staging,
validation and rollback contract"* (11 steps vs the trunk's 9).

→ **COMPOSE BOTH** — mechanically derived from §B.4's outcome, not an
independent decision.

## B.6 Trunk-only backend — a correction to the previous audit

The previous inventory described `edr_maintenance.py` as "maintenance
functionality absent from M1". Verified: it is **a temporary, token-gated
development data-reset route**, a faithful port of
`SECURE_EXPORT/win-recovery-handoff/edr_dev_reset.mongosh.js`. It 404s unless
`EDR_MAINTENANCE_TOKEN` is set, requires `X-Maintenance-Token`, defaults to
`mode="dry"`, and needs `confirm="DELETE-EDR-DEV-DATA"` plus a backup
reference to write. Its only dependency is `deps.db`; it has **zero coupling**
to M1 enrolment, service identity, agent versions, response commands or the
management APIs.

→ **KEEP FROM TRUNK** (no conflict) — and see RISK-5: a destructive route
whose only gate is an environment variable is a standing risk that deserves a
scoped retirement decision, independent of this reconciliation.

## B.7 M1-only backend and build

`backend/edr_plane/acquisition_integrity.py` (+1 line) and
`fixtures_b5_gap1_source.py` (±2) are trivial and additive;
`build/build_windows_installer.ps1` gains `-PreviousPayloadManifest` and
`-PredecessorPolicy` for predecessor-pinned upgrade builds.

---

# C · RECONCILIATION MATRIX

| Component | Trunk behaviour | M1 behaviour | Required outcome | Risk | Evidence |
|---|---|---|---|---|---|
| `nivxforge_journal.py` | quarantine + backlog states | same **plus** `rebaseline_cursor`, `discard_undelivered` | **KEEP FROM M1** | LOW | 47 insertions / **0 deletions** trunk→M1 |
| Sensor: collection, normalisation, cursors, integrity, policy, exclusions, heartbeat | authoritative | **identical** | **KEEP FROM M1** (no-op) | NONE | no hunks in trunk↔M1 diff |
| Sensor: batch-delivery degradation | added here (P0 repair) | **already carried** | **KEEP FROM M1** | LOW | `BATCH_SUPPORT` ×5 in M1; no diff hunks in those functions |
| Sensor: transport retry | `for attempt in (1, 2)` | `attempts: int = 2`, enrolment passes 1 | **KEEP FROM M1** — default preserves trunk | LOW | source comment + default value |
| Sensor: enrolment hardening (attempt marker, single-attempt, response validation, no-overwrite publication) | absent | present | **KEEP FROM M1** | LOW | `_rename_no_replace` uses MoveFileExW without REPLACE_EXISTING |
| `install()` — production install path | direct installer + `except BaseException` rollback | durable transaction engine (`Engine.run` + `reconcile`) | **COMPOSE BOTH** — transaction engine as the path, trunk's five invariants as acceptance criteria | **HIGH** | §B.4 |
| `_remove_partial_service` / `_remove_partial_staging` / `_abort_incomplete_clean_install` | present, tested | absent | **RETIRE WITH EVIDENCE** — only after the transaction engine demonstrably satisfies `test_s1_2_c2_clean_install_atomicity.py`'s assertions | **HIGH** | 337-line test; M1 symbol count 0 |
| Drain-mode policy | present | **present** | **KEEP FROM M1** (no-op) | NONE | symbol counts equal |
| Service image layout | `sensor\service\` (`SERVICE_EXE`) | `sensor\versions\<id>\` (`VERSIONS_DIR`) | **KEEP FROM M1** + **REQUIRES NEW COMPATIBILITY ADAPTER** for any installed trunk endpoint | **HIGH** | workflow diff lines 367–440 |
| `_install_service` signature | `(api, interval)` | `(api, interval, exe)` | **KEEP FROM M1**; every caller (CI gates, tests) migrates together | MEDIUM | workflow diff |
| M1 clean-install path (`m1_dispatch`, `nivxforge_m1.py`) | absent | G3-APPROVED | **KEEP FROM M1, BYTE-FROZEN** — subtree must still hash `db21f422…` | LOW if frozen | §A.2 |
| `nivxforge_transaction.py`, `nivxforge_scm_worker.py` | absent | present, **not G3-approved** | **KEEP FROM M1** — and carry the HOLD: clean-install G3 ≠ enterprise upgrade approval | **HIGH** | G3 scope is the M1 clean installer |
| `edr_maintenance.py` | present (dev reset) | absent | **KEEP FROM TRUNK** | LOW (merge) / MEDIUM (standing) | §B.6 |
| `transfer_bundle.py`, `server.py` | present | absent/older | **KEEP FROM TRUNK** | LOW | trunk-only |
| `build_windows_installer.ps1` | ancestor | + predecessor pinning | **KEEP FROM M1** | LOW | additive parameters |
| `windows-sensor-installer.yml` | 9 gates, single-path layout | 11 gates, versioned layout, `branches-ignore` | **COMPOSE BOTH** | MEDIUM | §B.5 |
| `test_b5_gap1_pre_canary_acceptance.py`, `test_p0_sensor_delivery_repair.py` | — | — | **no action** — identical blobs | NONE | blob equality |
| `test_s1_2_c2_clean_install_atomicity.py` | trunk-only | — | **KEEP FROM TRUNK and RE-TARGET** at the surviving install path | **HIGH** | it is the only guard on those invariants |
| Linux sensor `--token` argv exposure | present both | present both | **OUT OF SCOPE — separate prioritized security repair** | HIGH (security) | `nivxforge-linux/nivxforge_sensor.py:1296` |

## C.1 Invariant-preservation matrix

| Invariant | Source of truth | Preserved by | Could be silently broken by |
|---|---|---|---|
| **Authentication** — session bearer per endpoint | both lineages, identical | no-op | — |
| **Tenant isolation** — `edr_scope()` narrows, never widens; raises rather than answering empty | trunk backend, untouched by M1 | no-op | adding any new route during integration that reads evidence without `edr_scope` |
| **Enrolment: one token, one attempt** | M1 sensor (`single_attempt`, attempt marker, `attempts=1`) | KEEP FROM M1 | **re-introducing the trunk's `enrol()`** — it would restore reconnect-once on a one-time token |
| **Identity never overwritten** | M1 `_rename_no_replace` | KEEP FROM M1 | any later "idempotent publish" convenience |
| **Identity preserved on failed install** | trunk atomicity test | transaction engine, **unproven** | retiring the trunk helpers before the engine is shown to do it |
| **State directory never deleted** | trunk atomicity test + M1 `m1_uninstall` | both claim it | a composed uninstall that cleans "its own" directories by path rather than by ownership record |
| **Clean-install only; no adoption** | M1 `clean_host_report` | KEEP FROM M1 | the trunk's partial-cleanup helpers making a dirty host *look* clean — **this is the one case where preserving one control disables another** (see RISK-1) |
| **Disabled-first service creation, then verify, then activate** | M1 `m1_install` | KEEP FROM M1 (frozen) | a composed `_install_service` that creates with `AUTO_START` for CI convenience |
| **Protected directories + ACL readback** | M1 | KEEP FROM M1 | writing the payload before the ACL readback to save a step |
| **LocalSystem authorization at service time** | M1 G3-B3 | KEEP FROM M1 (frozen) | any refactor of `access_context()` |
| **Installer self-identification** | M1 G3-B1 | KEEP FROM M1 (frozen) | — |
| **Payload provenance + installed-image digest** | M1 + build script | KEEP FROM M1 | the versioned-layout adapter resolving "latest by mtime" instead of by manifest id (the CI gates do exactly this — acceptable in CI, **not** in product code) |
| **Credential confidentiality (stdin only)** | M1 setup + CI assertions | KEEP FROM M1 | Linux parity work copying the argv interface |
| **Safe uninstall by ownership record** | M1 | KEEP FROM M1 | path-based cleanup |
| **Response authorization + independent verification** | trunk backend `edr_plane/response.py` | untouched | — |
| **Recovery / uncertainty boundaries** | M1 transaction engine (`resolve_operation` checks the live SCM rather than believing the operator) | KEEP FROM M1 under HOLD | treating G3 as covering it |

---

# D · G1 INTEGRATION ARCHITECTURE

## D.1 Options compared

| Criterion | **A** merge M1 → trunk | **B** transplant M1 parts onto trunk | **C** new integration branch from `ae340563`, composing both | **D** two-phase: freeze-import then compose |
|---|---|---|---|---|
| Provenance | M1 subtree survives as a parent; merge commit is auditable | **cherry-picks break the G3 byte identity chain** | ancestor is explicit and approved | both parents retained |
| Review complexity | one merge, 4 conflicted files | many small reviews, high drift risk | reviewer re-derives everything | **smallest reviewable units** |
| Risk of overwriting security fixes | real — a careless resolution of `setup.py` silently drops the trunk's atomicity helpers *or* M1's clean-install contract | **highest** | moderate | **lowest** — phase 1 cannot regress anything |
| Runtime compatibility | layout change lands in one step | partial states possible mid-sequence | same as A | layout change isolated to phase 2 |
| API/schema stability | no backend schema change in either lineage | — | — | — |
| Regression scope | whole Windows agent + CI at once | repeated | whole | phase 1 ≈ zero, phase 2 bounded |
| CI impact | workflow conflict must be resolved before anything is green | repeatedly | once | phase 1 keeps the trunk workflow intact |
| Rollback | revert the merge | hard | discard the branch | **revert either phase independently** |
| Maintenance | one lineage | lasting divergence | one lineage | one lineage |

## D.2 Recommendation — **Option D**, a two-phase integration on a new branch

**Phase 1 — FREEZE-IMPORT (additive only, zero conflict).**
Branch from the **current trunk head** (not from the ancestor: the trunk is
71 commits ahead and additive). Add, unmodified:
`nivxforge_m1.py`, `nivxforge_transaction.py`, `nivxforge_scm_worker.py`, the
three M1 test files, the two build helpers,
`windows-installer-transaction-build.yml`, and take M1's **superset** blobs
for `nivxforge_journal.py` (`bbaaaed0`) and `nivxforge_sensor.py`
(`53a45ded`). Do **not** touch `nivxforge_setup.py` or
`windows-sensor-installer.yml` in this phase.

Why this is safe: the journal has zero deletions trunk→M1, and the sensor's
only deletions are signature extensions whose defaults reproduce the trunk's
behaviour. The acceptance gate is that **the trunk's own sensor and journal
suites pass unchanged against M1's blobs**.

Phase 1 leaves one deliberate inconsistency: `nivxforge_setup.py` is still
the trunk's, so `m1_dispatch` is reachable only through `nivxforge_m1.py`
directly. That is acceptable and explicit — and it is exactly what the native
CI work in §E needs, because the M1 clean-install path is self-contained.

**Phase 2 — COMPOSE THE INSTALLER (the only real design work).**
`nivxforge_setup.py` and the shared workflow, together, in one reviewable
change:
- adopt M1's versioned layout and `_install_service(api, interval, exe)`;
- keep the trunk's atomicity invariants by **re-targeting**
  `test_s1_2_c2_clean_install_atomicity.py` at the transaction engine — and
  only retire `_remove_partial_service` / `_remove_partial_staging` /
  `_abort_incomplete_clean_install` once those assertions pass against it;
- resolve the workflow by taking M1's 11-gate version and re-adding anything
  the trunk's 9-gate version asserts that M1's does not.

**Source inputs are named exactly; no integration commit or hash is invented
here** — the branch does not exist and must not until owner approval.

## D.3 Failure modes and rollback

| Failure | Detection | Rollback |
|---|---|---|
| M1 sensor blob regresses trunk delivery behaviour | trunk sensor/journal suites in phase 1 | revert phase 1; two-file revert |
| Transaction engine does not uphold an atomicity invariant | the re-targeted trunk test fails | **stop** — keep the trunk helpers, do not retire; escalate as a design decision |
| Versioned layout breaks an installed trunk endpoint | the compatibility adapter's own test | phase 2 revert; phase 1 is unaffected |
| Workflow composition breaks a gate | first `workflow_dispatch` run on the integration branch | revert the workflow file only |
| M1 subtree byte identity lost | `git rev-parse <branch>:agents/nivxforge-windows/nivxforge_m1.py` ≠ M1's blob | reset the file from `388bb3d6` |

## D.4 Dependency order

1. Phase 1 import + trunk sensor/journal suites green.
2. M1's own 373 + transaction + upgrade suites green **on the integration branch**.
3. Native CI (§E) exercising the M1 clean-install path.
4. Phase 2 installer composition + re-targeted atomicity test.
5. Full-suite isolated-database run (§G).
6. Independent G3 re-review of the composed installer **only** (the frozen M1
   subtree keeps its existing approval).
7. G4.

---

# E · WINDOWS CI READINESS

## E.1 Workflow claims — verified from source (`f971c765` and `388bb3d6`)

| Claim | Verdict | Evidence |
|---|---|---|
| Builds the Windows executable on a native runner | **TRUE** | `runs-on: windows-latest`; `build_windows_installer.ps1 -Commit $env:GITHUB_SHA` |
| PE/header check | **TRUE** | reads bytes, asserts `0x4D 0x5A` |
| Installer CLI validation | **TRUE** | frozen `version` must report `sensor_version`, `NivXForgeSensor`, `ONEDIR_PAYLOAD`; an unknown flag must be **named**, not ignored |
| Credential-argument protection | **TRUE** | asserts the plaintext `--token` interface reports `is REMOVED`, that it names `--token-stdin`, and that a secret-*shaped* value behind an unknown flag is refused with `looks like an enrolment secret` |
| Build provenance check | **TRUE** | requires `build_commit`, `artifact_sha256`; fails on `UNOFFICIAL_BUILD` |
| Windows SCM lifecycle test | **TRUE** | "Real Windows SCM lifecycle (artifact acceptance gate)" — creates the service, proves RUNNING, stops it, proves STOPPED, and proves the service itself wrote `%ProgramData%\NivXForge\sensor\service.log` |
| Re-enrolment / recovery test | **TRUE** | "Re-enrol against a RUNNING service · stop race + rollback" |
| Upgrade repair gates | **TRUE on the M1 side only** | two extra gates |
| **Secrets required** | **NONE** — verified | `grep secrets\.` returns nothing in either version; `permissions: contents: read` |
| **Fork/PR trust risk** | **NONE** — verified | triggers are `workflow_dispatch` + `push` only; there is **no `pull_request` trigger**, so no fork-controlled code runs with repository context |
| **Has it ever run successfully?** | **UNKNOWN** | no Actions access. A definition is not a run |

Two further verified facts the previous audit did not state:

- The push trigger's path filter is `agents/nivxforge-windows/**` plus the
  workflow itself, so **phase 1 of §D.2 would trigger it automatically** on
  the integration branch. M1 already anticipated this pattern with
  `branches-ignore`; the integration branch needs the same treatment or an
  explicit decision to let the gates run.
- The SCM gate starts the real service configured against
  **`https://nivxray.nivxforge.com`** with no identity. The runner therefore
  makes **unauthenticated outbound requests to the production backend**. The
  gate's intent is to prove a failing cycle does not kill the service, so the
  failure is deliberate — but production is touched. Mitigation is available
  **without weakening the guard**: `_assert_backend` is a *deny*-list
  (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `preview.emergentagent.com`,
  `.local`, ports 8001/3000), so a dedicated lab FQDN such as
  `https://edr-lab.<owned-domain>` is already accepted and needs no code
  change. **RISK-4.**

## E.2 Testing the G3-approved M1 source on `windows-latest` without merging

Feasible, and the safest vehicle already exists in the M1 lineage:
`windows-installer-transaction-build.yml` is **`workflow_dispatch`-only**,
`permissions: contents: read`, builds predecessor and candidate, installs
nothing, and uploads artefacts. A sibling workflow for the M1 clean-install
path is the right shape: manual trigger only, no push filter, no secrets,
build + `m1-install` against a lab origin + evidence capture + guaranteed
service removal.

Prerequisites and boundaries:

| Question | Answer (verified) |
|---|---|
| Does the workflow exist on the candidate branch? | yes — `b8020771` carries both workflows, and GitHub resolves workflow files **from the ref being run**, so a `workflow_dispatch` on `engineering/m1-g4-preparation` uses that branch's definitions |
| Trigger conditions | prefer `workflow_dispatch` only; a `push` trigger on the engineering branch would fire the service-mutating gates on every publish |
| Permissions | `contents: read` suffices; artefact upload needs no extra scope |
| Secrets | genuinely unnecessary — asserted in the workflow header and verified by `grep` |
| Build dependencies | `actions/setup-python@v5` (3.11 x64) + `pip install pyinstaller pywin32` from PyPI — external downloads, so pin versions and record the resolved set |
| Administrator rights | GitHub-hosted Windows runners run as an administrator, which is why `sc.exe create/start/delete` already works in the existing gates |
| Interactive-admin install | **not available** — a runner session is a service-context, non-interactive admin. M1's installer context derives a *filtered* token from the caller; whether that resolves identically in a runner session is **UNKNOWN and must not be assumed** |
| Production contact | only as described in §E.1 — avoidable via a lab FQDN |
| Cleanup | the existing workflow already has "Remove the CI service if the gate failed"; any M1 workflow must do the same, and the runner is ephemeral |
| Artefact publication / signing | unsigned `UNSIGNED_INTERNAL_VALIDATION_BUILD`; artefacts are retained per repository policy. **Do not publish as a release** |
| Source→binary provenance | `build-info.json` carries `build_commit` + `artifact_sha256`; assert `build_commit == 388bb3d6…` and record the subtree hash in the run log |
| Failures / rerun | ephemeral runner, so a rerun is clean; no persistent state to roll back |

## E.3 G4 evidence classification

Never mark a G4 requirement PASS because a portable test passed.

| G4 requirement | Classification |
|---|---|
| Build the frozen PE from `388bb3d6` | **NATIVE CI TESTABLE** |
| PE / frozen-CLI / provenance / credential-argument contract | **NATIVE CI TESTABLE** |
| Journal selftest in the frozen binary (incl. restart process) | **NATIVE CI TESTABLE** |
| Real SCM create → start → stop → delete | **NATIVE CI TESTABLE** |
| Service-wrote-its-own-log proof | **NATIVE CI TESTABLE** |
| `GetFileAttributesW` absence/denial/reparse/race semantics (G3-B2) | **NATIVE CI TESTABLE** |
| Installer self-identification incl. onefile bootloader parent (G3-B1) | **NATIVE CI TESTABLE** |
| Protected-directory creation + ACL readback | **NATIVE CI TESTABLE** |
| Service descriptor applied and read back (`sc sdshow`) | **NATIVE CI TESTABLE** |
| Disabled-first → demand-start → auto-start ordering | **NATIVE CI TESTABLE** |
| LocalSystem `AuthzAccessCheck` at service time (G3-B3) | **NATIVE CI TESTABLE** — the service runs as LocalSystem on the runner |
| **Elevated *interactive* administrator installer context** | **REQUIRES PERSISTENT WINDOWS VM** — a runner session is not an interactive logon |
| **Reboot continuity** | **REQUIRES PERSISTENT WINDOWS VM** |
| Defender/SmartScreen behaviour on an unsigned artifact | **REQUIRES PERSISTENT WINDOWS VM** |
| Genuine enrolment | **REQUIRES ISOLATED BACKEND / TEST TENANT** (+ a ≤24 h token minted by an authorised operator) |
| Telemetry ingestion + Device Trajectory visibility | **REQUIRES ISOLATED BACKEND / TEST TENANT** |
| Safe uninstall preserving `state_dir` | **NATIVE CI TESTABLE** (filesystem), VM for the reboot interaction |
| Analyst-facing trajectory usability | **REQUIRES MANUAL AUTHORIZED OBSERVATION** |
| Multi-endpoint / fleet behaviour | **NOT SAFELY TESTABLE** in the proposed environment |
| Production-origin behaviour | **NOT SAFELY TESTABLE** — must not be attempted |

**No workflow was triggered during this assignment.**

---

# F · BOUNDED G2 EXECUTION PLAN (for approval, not execution)

Separated deliberately into source reconciliation and CI enablement.

### Track 1 — source reconciliation

| # | Step | Files | Checkpoint |
|---|---|---|---|
| T1.1 | Create the integration branch from the current trunk head | — | branch exists; `agents/nivxforge-windows` still matches the trunk |
| T1.2 | Import M1-only files **byte-identical** | `nivxforge_m1.py`, `nivxforge_transaction.py`, `nivxforge_scm_worker.py`, `build/Invoke-TransactionAcceptance.ps1`, `build/run_transaction_tests.py`, 3 test files, `windows-installer-transaction-build.yml` | each blob id equals `388bb3d6`'s |
| T1.3 | Take M1's journal + sensor blobs | `nivxforge_journal.py`, `nivxforge_sensor.py` | blobs `bbaaaed0`, `53a45ded` |
| T1.4 | Take M1's additive backend/build edits | `acquisition_integrity.py`, `fixtures_b5_gap1_source.py`, `build_windows_installer.ps1` | — |
| T1.5 | **Gate A** — trunk sensor/journal/delivery suites pass unchanged | — | green, no test edited |
| T1.6 | **Gate B** — M1's 373 + transaction + upgrade suites pass on the branch | — | green |
| T1.7 | Compose the installer | `nivxforge_setup.py` | M1 layout + `_install_service(api, interval, exe)`; `m1_dispatch` reachable |
| T1.8 | Re-target the atomicity test at the surviving path | `test_s1_2_c2_clean_install_atomicity.py` | its five assertions hold against the transaction engine |
| T1.9 | Retire the superseded helpers **only if T1.8 is green** | `nivxforge_setup.py` | otherwise **STOP** and escalate |
| T1.10 | Compose the workflow | `windows-sensor-installer.yml` | 11 gates + anything only the trunk asserted |
| T1.11 | **Gate C** — full EDR suite on isolated databases (§G) | — | no regression vs the recorded baseline |

**Ownership boundary:** the frozen M1 subtree files must not be edited in
Track 1. Any change to `nivxforge_m1.py` voids the G3 byte identity and
requires re-review.

### Track 2 — CI enablement (independent of Track 1)

| # | Step | Checkpoint |
|---|---|---|
| T2.1 | Add a `workflow_dispatch`-only M1 clean-install workflow on the **M1 branch** (no push filter, no secrets, lab origin, mandatory cleanup) | definition reviewed before any run |
| T2.2 | First manual run from `engineering/m1-g4-preparation` | build provenance asserts `build_commit == 388bb3d6…` |
| T2.3 | Add the native M1 gates from §E.3's "native CI testable" rows, one per step, each capturing evidence | each gate names its own PASS condition |
| T2.4 | Decide the CI origin question (RISK-4) before any gate starts a service | lab FQDN or an explicit accepted risk |
| T2.5 | Retain artefacts; **no release, no signing** | — |

---

# G · VERIFICATION AND ACCEPTANCE PLAN

## G.1 Suites in scope

M1 clean installer (**373**) · installer transaction · P0 installer upgrade
repair · clean-install atomicity · windows installer SCM entrypoint · sensor
journal durability, batch/integrity contract, resumability, delivery repair ·
enrolment and identity (`test_p0_a2_enrollment`,
`test_p0prod2_enrollment_hardening`, reconcile/ownership) · collector and
tenant isolation · policy and exclusion · response state machine and
authority (`test_p0a_response_authority`) · detection and trajectory
compatibility (`test_p0_f_endpoint_detection`, `test_dt2_2e_projection`) ·
relevant frontend integration tests.

## G.2 Recorded baseline and the reported failures — independently assessed

Measured on the trunk at `f971c765`: `pytest backend/tests/edr -q` →
**2,392 passed · 16 failed · 3 skipped** (230 s).

| Failure group | Count | Independent finding |
|---|---|---|
| `test_34h_a_migration_control.py` | 12 | **HARNESS.** The file passes in isolation; it fails only inside the full run. Cause is shared-Mongo state across tests, not product behaviour. |
| `test_p0_f13_5_detection_handoff.py` | 4 | **MIXED — product/test contract drift.** It fails *in isolation too*. The `paged` fixture stubs `trajectory_window.query_window` and `dir_svc.resolve`, but `routers/edr.py:1761 trajectory_focus` now also reads `_db["edr_endpoints"]` directly, and `deps.db` is unbound in that context. `git log -S` dates the product change to **`a8ccdb36`, 2026-10-03** ("trajectory/focus hostname alignment"); the test was created **2026-09-07**. Because 2026-10-03 precedes the 2026-10-04 split, **both lineages inherit it.** The user-visible consequence is that `trajectory_focus` has an unexercised database dependency — not a proven runtime defect. |

Not fixed, per the G0/G1 boundary.

## G.3 Execution requirements

- **Isolated database per run** — a dedicated `DB_NAME` per suite invocation,
  created and dropped by the harness, so the 12 order-dependent failures
  cannot recur and cannot mask a real regression.
- **Deterministic ordering** — record both a `-p no:randomly` run and a
  randomised run; a difference between them is itself a finding.
- **Reproducible fixtures** — the existing golden corpus and
  `fixtures_b5_gap1_source.py`; no live-API dependency.
- **No production contact** from any suite.

## G.4 Negative controls (must still FAIL)

1. Plaintext `--token` is refused and names `--token-stdin`.
2. A secret-shaped value behind an unknown flag is refused.
3. An unknown flag is never silently ignored.
4. `localhost` / preview origins are refused by `_assert_backend`.
5. A non-clean host is refused (`HOST_NOT_CLEAN`, naming each probe).
6. An existing identity is never overwritten (`_rename_no_replace`).
7. A one-time enrolment token is never replayed (`attempts=1`).
8. An unsafe service descriptor or an indeterminate Authz result refuses
   (`SERVICE_SD_UNSAFE`, "indeterminate").
9. A non-LocalSystem service context refuses.
10. A config writable by `Users` refuses (`CONFIG_ACL_UNSAFE`).
11. `service_exe` outside the attested payload refuses.
12. An unauthorised tenant principal receives an error, **never an empty
    projection**.
13. A response action is never `VERIFIED` without independent evidence.

## G.5 Pass/fail criteria

**PASS** requires: every suite in G.1 green on isolated databases; the
recorded baseline not regressed; all 13 negative controls still failing; the
frozen M1 subtree blob ids unchanged; and, for G4 rows, **native evidence of
the kind named in §E.3** — a portable pass never substitutes.
**FAIL** on: any invariant in §C.1 unproven; any negative control passing; any
M1 blob change; any production contact.

---

# H · OPEN DECISIONS AND RISK REGISTER

| ID | Issue | Sev | Evidence | Impact | Owner decision needed |
|---|---|---|---|---|---|
| RISK-1 | **Partial-cleanup vs clean-install-only.** The trunk's `_remove_partial_service` / `_remove_partial_staging` make a failed attempt tidy; M1 refuses any host that is not pristine. Composed naively, the cleanup could make a dirty host *look* clean to `clean_host_report` | **HIGH** | §B.4, §C.1 | the clean-install guarantee, silently | which control wins, and how the other is preserved |
| RISK-2 | **Retiring the atomicity helpers without proof.** The transaction engine is believed to supersede them; nothing demonstrates it | **HIGH** | 337-line trunk test; M1 symbol count 0 | identity loss / silent incomplete install | accept T1.8 as a hard gate |
| RISK-3 | **Versioned layout vs installed trunk endpoints.** `sensor\service\` → `sensor\versions\<id>\` | **HIGH** | workflow diff | an existing endpoint's upgrade path | adapter, or declare clean-install-only for now |
| RISK-4 | **CI contacts the production origin.** The SCM gate starts a real service against `nivxray.nivxforge.com` | MEDIUM | §E.1 | unauthenticated production traffic from runners | adopt a lab FQDN (no code change needed) or accept explicitly |
| RISK-5 | **`edr_maintenance.py` dev-reset route** gated only by an env var + header token | MEDIUM | §B.6 | destructive data loss if the var is ever set in a shared environment | scope, time-box or retire |
| RISK-6 | **Enterprise upgrade/recovery is not G3-approved.** Importing `nivxforge_transaction.py` must not be read as approval | **HIGH** | G3 scope | false confidence | keep the HOLD explicit in the integration branch README |
| RISK-7 | **Actions run history UNKNOWN.** No evidence the Windows workflow has ever succeeded | MEDIUM | §A.1 | the whole CI plan may rest on a never-green workflow | grant read-only Actions access, or treat T2.2 as the first real run |
| RISK-8 | **Interactive-admin context is not reproducible in CI** | MEDIUM | §E.2 | G3-B1/B3 installer-context behaviour stays VM-only | accept the split in §E.3 |
| RISK-9 | **Linux `--token` argv exposure** — the interface Windows CI asserts is removed | **HIGH (security)** | `nivxforge-linux/nivxforge_sensor.py:1296` | token in `/proc`, shell history and the product's own telemetry | **separate prioritized security repair — explicitly out of scope here** |
| RISK-10 | **Exposed JWTs and hardcoded admin passwords** in the repository tree | **HIGH (security)** | prior audit, unchanged | credential compromise | revocation/rotation + exposure assessment — still outstanding |
| RISK-11 | **Collector tenant-isolation and token-hygiene HOLDs** remain subject to their original gate evidence | MEDIUM | prior gates | — | unchanged by this design |
| RISK-12 | 4 inherited test/product contract failures in `trajectory_focus` | LOW | §G.2 | an unexercised DB dependency | fix in G2, not now |

**HOLDs reaffirmed:** Windows G4 **NOT RUN** and not accepted · M1 clean-install
G3 does **not** imply enterprise upgrade/recovery approval · collector
tenant-isolation and token-hygiene gates stand · response execution keeps
backend approval and independent verification · **no production activation or
rollout is authorized**.

---

# I · UNCHANGED-STATE DECLARATION

| Control | Evidence |
|---|---|
| No tracked code modified | `git status --porcelain agents backend apps .github docs` → **0 entries** |
| Worktree otherwise untouched | 158 dirty entries, all pre-existing (`M rocket-p0/a3`, untracked `rocket-e2e/`, `rocket-evidence/`) plus this assignment's `memory/` documents |
| No ref created, moved or deleted | refs digest `cf3c397280f872e2d381127ac5f522b9827bb35d566838be8c9708ee0a893620`; reflog shows only pre-existing platform commits |
| No merge, cherry-pick, rebase, reset, clean, fetch or branch switch | none issued; inspection used `cat-file`/`ls-tree`/`diff`/`log`/`rev-list`/`show` only |
| No repository object published | no push, no bundle created for this assignment |
| No CI triggered | no `gh`/API call; no workflow dispatched |
| No installer, agent or response action executed | none |
| No database write | read-only queries (`count_documents`, `aggregate`, `find_one`, `distinct`) only |
| No credential value read, printed or copied | only the *presence* and *gating* of `EDR_MAINTENANCE_TOKEN` was noted |
| M1 untouched | `388bb3d6`, tree `df8eb48b…`, subtree `db21f422…`, and `b8020771:agents/nivxforge-windows = db21f422…` all re-verified unchanged |
| Tests executed | read-only test runs against the preview database only; no suite was modified |

---

# J · FOR THE INDEPENDENT G1 REVIEWER

Every recommendation above can be re-derived from source with these commands:

```
git merge-base f971c765 388bb3d6                       # ae340563…
git diff --name-status ae340563 f971c765 -- agents backend apps .github
git diff --name-status ae340563 388bb3d6 -- agents backend apps .github
git diff --stat f971c765 388bb3d6 -- agents/nivxforge-windows/nivxforge_journal.py   # 47+/0-
git diff f971c765 388bb3d6 -- agents/nivxforge-windows/nivxforge_sensor.py          # 175+/18-
git rev-parse f971c765:backend/tests/edr/test_p0_sensor_delivery_repair.py \
              388bb3d6:backend/tests/edr/test_p0_sensor_delivery_repair.py          # equal
git show 388bb3d6:agents/nivxforge-windows/nivxforge_setup.py | grep -c _abort_incomplete_clean_install   # 0
git log -S'_ep_doc = await _db["edr_endpoints"]' -- backend/routers/edr.py          # a8ccdb36, 2026-10-03
```

The three decisions a reviewer should contest hardest: **RISK-1** (does
partial cleanup defeat clean-install-only?), **RISK-2** (is retiring the
atomicity helpers justified by anything other than belief?), and **RISK-3**
(what happens to an endpoint installed under the old layout?).

**G1 PASS is not claimed. Owner approval is required before any
implementation.**
