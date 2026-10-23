# NIVXFORGE EDR — EXECUTION DIRECTIVE · FIRST HANDOFF
## Track A source/CI readiness · Track B capability-gap inventory

Mode: verification and measurement. **No implementation, no native execution, no
CI run, no commit, no deployment, no database write.** Every number below comes
from `git`/`grep` against the named revisions or from portable `pytest` runs
recorded in §B.1. Frozen M1 subtree untouched; every HOLD preserved.

Working tree `/app` `HEAD 40779b51` on `fix/p0-sensor-delivery`; its Windows
subtree is **byte-identical** to `f971c765:agents/nivxforge-windows`
(`54fe56bdf7ae55c1ed8727a3d58f87f3743d0a33`), so trunk inspection in the tree is
baseline-faithful.

---

# TRACK A — WINDOWS INSTALLER AND SENSOR RECOVERY

## A.1 · M1 source identity — **PASS**

| Attribute | Verified value | Method |
|---|---|---|
| Commit | `388bb3d637a076f36d78fc9d1e218c878b082b9b` | `git cat-file -p` |
| Message | *"M1 G3-B3 AuthzAccessCheck result correction: a per-result ERROR_ACCESS_DENIED is a verified denial"* | " |
| Tree | `df8eb48b5719b01c936c8dec3442aeba7763a59f` | " |
| Parent | `a4e544f45772a90686d478a19a7ce80201616506` | " |
| Frozen Windows subtree | `db21f422561f14fb4dcec91b70925f2b5291c500` | `git rev-parse 388bb3d6:agents/nivxforge-windows` |
| Reachability | `engineering/m1-g3-integrated`, `engineering/m1-g4-preparation` | `git branch -a --contains` |
| Per-file manifest | **15 blobs**, published with per-file SHA-256 **and** git blob id | `NIVXFORGE_EDR_P0_3_G1_A1_PROVENANCE.json`; blob table in `…P0_RECONCILIATION_G1_V3.md` §5.1 |

Composition of the subtree, for build planning: **4 files byte-identical to
trunk**, **4 trunk-absent** (`nivxforge_m1.py` `27e83b07`,
`nivxforge_transaction.py` `bf5c0e9d`, `nivxforge_scm_worker.py` `30cb0414`,
`build/run_transaction_tests.py` `cdc10303`), **4 divergent**
(`nivxforge_sensor.py` `53a45ded`, `nivxforge_journal.py` `bbaaaed0`,
`nivxforge_setup.py` `a906a7c5`, build script `6235038f`), plus
`build/Invoke-TransactionAcceptance.ps1` `716caca2`.

**Verification limit:** this proves blob and tree identity *within this
repository clone*. It does not prove upstream ancestry, signatures or authorship.

## A.2 · Windows CI security — **FAIL (3 controls required before any gate run)**

`.github/workflows/windows-sensor-installer.yml`, 762 lines. It is the **only**
workflow that triggers on `agents/nivxforge-windows/**` (checked across all
five workflows).

### PASS

| ID | Control | Evidence |
|---|---|---|
| CI-P1 | **No secret of any kind is used.** Zero `secrets.` references; `permissions: contents: read` | `:19-20`, full-file grep |
| CI-P2 | **Service cleanup is unconditional.** `Remove the CI service if the gate failed` runs `if: always()` with `sc.exe stop` + `sc.exe delete` | `:743-750` |
| CI-P3 | **Build dependencies are pinned.** `pyinstaller==6.11.1`, `pywin32==308` in both the trunk and M1 build scripts | `build_windows_installer.ps1:47-48`; `388bb3d6:…:52-53` |
| CI-P4 | **The generated provenance stub cannot be committed.** `nivxforge_build.py` is git-ignored | `.gitignore:187` (`git check-ignore -v` confirms) |
| CI-P5 | **Negative security probes are real assertions, not comments.** Production-origin refusal, removed `--token`, secret-shaped argv, unknown-flag silence and build provenance are each asserted with a required non-zero exit | `:63-112` |

### FAIL — must be corrected before any gate is approved for execution

| ID | Finding | Evidence | Required control |
|---|---|---|---|
| **CI-F1** | **The push trigger has no branch filter.** Any push on any branch touching `agents/nivxforge-windows/**` creates and starts a real Windows service (Gates 3-4) | `:12-18` versus `:403, 531` | Add `branches:` to the push trigger **in a commit that touches nothing under `agents/`** — the guard must land first or the first import starts a service |
| **CI-F2** | **Service-starting gates are pointed at the production hostname.** Gate 3 calls `_install_service("https://nivxray.nivxforge.com", 30)` through the production code path and starts the service; Gate 4 installs with the same backend | `:417, 548, 632` | Pass a **lab FQDN**. No code change is needed: `_assert_backend` is a **deny-list** (https + not localhost/preview/dev-port), so any lab hostname passes (`nivxforge_setup.py:83-104`) |
| **CI-F3** | **The artifact has no source-provenance assertion.** `actions/checkout@v4` takes the pushed ref and the build stamps `-Commit $env:GITHUB_SHA`; nothing asserts that the Windows subtree equals the G3-reviewed blobs | `:27, 37-38` | Assert the §A.1 **per-file blob manifest** before the build. The subtree hash alone cannot be used on an integration branch, because the subtree necessarily differs there |

### Production-contact assessment — precise, and better than the trigger implies

A running unenrolled service does **not** reach production. `run()` loads the
identity and enters `_cycle` (`nivxforge_sensor.py:1370-1377`), whose first act
is `_sync_policy` → `_open_session`, which dereferences
`ident["tenant_id"]` / `ident["agent_credential"]` (`:521-525`). On an
unenrolled host that raises **`KeyError`**, which `_sync_policy`'s
`except (RuntimeError, URLError, OSError)` does **not** catch — so the cycle
fails **before any socket is opened**. Gate 4 likewise refuses on an empty
stdin token before any network call.

**But this is an accident, not a control.** The production origin is still
written into the SCM `binPath`, and the moment any identity exists on a runner
the service would begin posting to production on its first cycle. CI-F2 is
therefore a required correction even though no production contact is
demonstrated today.

### Source-contamination assessment

`build_windows_installer.ps1:69` writes `nivxforge_build.py` **into
`agents/nivxforge-windows/`** and **never removes it** (no cleanup exists
anywhere in the script). Commit risk is closed by `.gitignore:187` (CI-P4), but
the ordering consequence is real: **per-file blob verification must run before
the build**, and the only permitted post-build additions are
`nivxforge_build.py`, `dist/` and `build/work/`. A post-build re-verification
without that allowance would fail on a clean, honest build.

## A.3 · Reproducible native build readiness — **PARTIAL**

| Factor | State | Evidence |
|---|---|---|
| Build tooling pinned | **PASS** | `pyinstaller==6.11.1`, `pywin32==308` |
| Interpreter pinned | **FAIL** | `setup-python@v5` requests `python-version: '3.11'` — a floating patch level (`:30-32`) |
| Dependency integrity | **FAIL** | `pip install` without `--require-hashes`; no lockfile |
| Byte-level determinism | **NOT ACHIEVABLE as built** | PyInstaller embeds build paths and timestamps; `build-info.json` records a UTC `BUILD_TIME` by design (`:62-69`) |
| Artifact self-description | **PASS** | `SHA256SUMS.txt`, `build-info.json`, baked `build_commit` + `artifact_sha256`, asserted by the contract step |
| Signing | **BLOCKED** | `signing_status: UNSIGNED_INTERNAL_VALIDATION_BUILD` (`edr_onboarding.py:95-99`) |
| Payload pinning (M1 path) | **PASS, M1 only** | the M1 script emits `payload-manifest.json` and a pinned previous manifest (`388bb3d6:…:120-132`); the trunk script emits neither |

**Honest formulation for the gate:** the build is **repeatable** (identical
inputs produce a working, self-describing artifact) but **not
bit-reproducible**. Provenance must therefore be carried by the per-file source
manifest plus the artifact's own hashes — **not** by a claim that two builds
produce identical bytes. Pinning the interpreter to an exact patch and adding
hash-pinned dependencies are the two bounded corrections that make a build
*defensible*; neither makes it byte-identical.

## A.4 · Gate map — what is blocked until approval

| Gate | Action | Status |
|---|---|---|
| A-G1 | CI hardening commits (CI-F1 first, alone; then CI-F2, CI-F3) | **DESIGNED, not implemented** |
| A-G2 | Native build on an approved runner | **BLOCKED** — requires A-G1 |
| A-G3 | Gates 0-2 (non-service) on the built artifact | **BLOCKED** — requires A-G2 |
| A-G4 | Gates 3-4: real SCM create/start/stop/delete | **BLOCKED** — service-mutating; requires explicit gate approval and CI-F2 |
| A-G5 | Isolated-Windows acceptance: clean install, SCM operation, protected credentials, restart/uninstall, test-tenant enrolment, actual telemetry delivery | **BLOCKED** — requires a lab tenant and an approved isolated environment |

## A.5 · NOT RUN / UNKNOWN — stated, not estimated

* **G4 native Windows acceptance: NOT RUN.** No Windows host was used.
* **Actions run history: UNKNOWN.** Workflow definitions were read; whether this
  workflow has ever completed is undeterminable without authorized read-only
  Actions access. Its gates are **defined, not proven**.
* **No artifact exists.** `agents/nivxforge-windows/dist/` is absent in both
  revisions; `windows-x64-exe` reports `INCOMPLETE` → the download route 409s,
  and that route cannot serve a PE regardless (`PlainTextResponse` + utf-8
  decode, `edr_onboarding.py:242-250`).
* **Enterprise upgrade, identity migration, re-enrolment and purge remain
  BLOCKED** — unchanged by this handoff.

---

# TRACK B — REMAINING EDR PRODUCT CAPABILITIES

## B.1 · Measured test evidence (portable, non-mutating, run in this pass)

| Suite | Result |
|---|---|
| `test_phase0_windows_canonical_bridge.py` + `test_dt2_0_trajectory_contract.py` + `test_c1_canonical_event_identity.py` | **97 passed in 0.98s** |
| `test_p0a_response_authority.py` + `test_p0_f10_isolation.py` | **41 passed in 1.69s** |
| M1 installer-path suite at `388bb3d6` (recorded P0-1) | **636 passed in 25.41s** |

Portable results only. **No result here is Windows-native evidence.**
Trunk baseline from the recorded capability audit remains
`2,392 passed / 16 failed / 3 skipped`, with the 16 triaged as 12 ordering-only
(pass in isolation) and 4 contract drift (fail in isolation) — unchanged, not
re-measured here.

## B.2 · Capability inventory

| Capability | State | Source of record | Test evidence |
|---|---|---|---|
| Windows sensor — collection | **IMPLEMENTED** | `nivxforge_sensor.py` (1,439 ln): `CHANNELS = Security, System, Sysmon/Operational`; `wevtutil` paging; bookmarks | `test_b5_gap1_*`, `fixtures_windows_eventlog.py` |
| Windows sensor — durable evidence journal | **IMPLEMENTED** | `nivxforge_journal.py` — SQLite, `WAL`, `synchronous=FULL`, per-row `endpoint_id`/`tenant_id`, cursors, counters, reclaim | `test_b5_gap1_journal_durability.py` (28) |
| Windows sensor — delivery | **IMPLEMENTED** | batch `/telemetry/batch` with bounded per-row fallback; legacy `outbox.jsonl` drain retained | `test_p0_sensor_delivery_repair.py` (13), `test_c3_delivery_counters.py` |
| **Linux sensor** | **PARTIALLY IMPLEMENTED — asymmetric** | `agents/nivxforge-linux/nivxforge_sensor.py` (1,314 ln) emits `activity: PROCESS/NETWORK/FILE` directly, but has **no `nivxforge_journal.py`**: delivery is `outbox.jsonl` + `outbox.offset` only (`:52-53, 527-569`), single-row POSTs, no WAL journal, no batch route, no acquisition-integrity parity | Linux instruction contract test only (`test_w7_linux_instruction_is_unchanged_and_declared`) |
| Windows → canonical evidence | **IMPLEMENTED, COVERAGE-LIMITED** — see §B.3 | `edr_plane/windows_eventlog.py` (980 ln); `canonical_bridge.py:67,100` | 97 passed (§B.1) |
| Canonical schema (CES/CEM) | **IMPLEMENTED** | `v2/ingestion/canonical.py` — CES fields incl. `service`, `task_name`, `logon_type`, `logon_id`, `sid`, registry/DNS/network lanes, `field_provenance`, `observation_identity` | `test_c1_canonical_event_identity.py` |
| Detection / findings | **IMPLEMENTED** | `routers/edr.py:421` `/detections` (incident-keyed, case-derived); `edr_plane/findings_intake.py`, `detection_replay.py` | `test_p0_f13_5_detection_handoff.py` — **4 known failures, fail in isolation (contract drift, inherited by both lineages)** |
| Device Trajectory | **IMPLEMENTED** | `routers/edr.py:996`, `:1732` focus; `edr_plane/trajectory/*`, `trajectory_window.py`; refusals surfaced as `UNSUPPORTED` / `WINDOWS_EVENT_ID_NOT_SUPPORTED` states (`trajectory/contract.py:136, 343`) | `test_dt2_0_trajectory_contract.py`, `test_gate10_trajectory_window_fast_paths.py`, `test_trajectory_tenant_isolation.py` |
| Process tree / process identity | **IMPLEMENTED** | `routers/edr.py:719`; `edr_plane/process_identity.py`; authoritative `ProcessGuid`, explicit `PID_ONLY_NOT_AUTHORITATIVE` downgrade | included in the 97 |
| Hunting / Events Explorer | **PARTIALLY IMPLEMENTED** | server-side aggregation via payload regex signatures (`windows_eventlog.py:344-355`, `payload_event_id_regex`); `projection_class` aliases AUTH for the console | covered indirectly; no dedicated hunting-query suite found |
| Response | **IMPLEMENTED, HOLD-GATED** | `routers/edr_response.py` (8 routes), `edr_plane/response.py`, `isolation_policy.py`; backend approval + independent verification retained | **41 passed** (§B.1) |
| Enrolment / identity | **IMPLEMENTED** | `edr_plane/enrollment/store.py`, `contracts/identity.py` — deterministic `mint`, `rotate_credential` (revokes + kills sessions), `revoke_endpoint` | `test_p0_a2_enrollment.py`, `test_p0prod2_enrollment_hardening.py` |
| Tenant authority | **IMPLEMENTED** | `routers/edr_tenancy.py` — one canonical dependency, per-route scope table | `test_edr_route_tenant_authority.py` |
| Windows onboarding / downloads | **BLOCKED (P0-2/P0-3)** | advertised PS1 package cannot complete a fresh install (publishes 2 of 4 required modules); EXE unbuilt | `test_edr_onboarding_v1.py`, `test_w1_…_contract.py` |
| Enterprise upgrade / transaction engine | **BLOCKED** | `nivxforge_transaction.py`, `nivxforge_scm_worker.py` — outside M1 G3 approval, unreviewed | `test_installer_transaction.py` (M1 lineage only) |
| Identity migration / re-enrolment | **BLOCKED** | G1 V3 design exists; no source behaviour | — |

## B.3 · First bounded module — gap **verified**, candidate **re-shaped**

The directive's candidate was *Windows telemetry canonicalization*. Source
verification shows it **already exists** (980 lines, Phase 0, with an explicit
no-fabrication contract). Building another canonicalizer would violate
*one authoritative implementation per responsibility*.

**The real, measured gap is coverage alignment between two existing maps.**

| Map | Responsibility | Entries |
|---|---|---|
| `edr_plane/windows_eventlog.py::SUPPORTED` | the **ingest gate**: anything outside is refused `WINDOWS_EVENT_ID_NOT_SUPPORTED` and never becomes canonical evidence | **9** |
| `v2/ingestion/canonical.py::SYSMON_KIND` + `WINSEC_KIND` | downstream kind resolution, already written with careful semantics | **26 + 18 = 44** |

Measured delta (computed, not estimated):

* **Admitted:** sysmon `1, 3, 5, 11, 12, 13, 22`; winsec `4624, 4688`.
* **Known downstream but REFUSED at ingest — 35 classes:**
  sysmon `2, 4, 6, 7, 8, 9, 10, 14, 15, 17, 18, 19, 20, 21, 23, 24, 25, 26, 255`
  and winsec `1102, 4625, 4634, 4672, 4689, 4697, 4698, 4700, 4720, 4732, 4738,
  4776, 5140, 5145, 5156, 7045`.
* **Admitted but unknown downstream: none** — so the gate is strictly narrower
  than the classifier; there is no divergence to reconcile, only a deficit to close.

Among the refused: **4625 logon failure**, **4689 process termination**,
**4697/7045 service install**, **4698 scheduled-task create**, **1102 audit log
cleared**, **sysmon 8 remote-thread**, **10 process-access**, **23/26 file
delete**, **25 process tampering**. The sensor **collects all of them** —
whole-channel `wevtutil` queries — so today they are collected, journalled,
delivered, refused, and visible only as an `UNSUPPORTED` trajectory state.

A second, narrower finding: `CHANNEL_FAMILY` recognises only
`microsoft-windows-sysmon/operational` and `security`
(`windows_eventlog.py:339-342`), and `_provider_family` only Sysmon and
Security-Auditing (`:144-151`). The sensor also collects **System**, so every
System record — including 7045 — is refused *earlier*, at family resolution,
with no family at all. `WINSEC_KIND` already contains 7045, which means
**admitting it requires a family decision, not just a map entry**.

### Proposed module **B-1 · Windows ingest coverage alignment**

Split by whether a canonical contract has to move:

| Sub-module | Scope | Contract impact |
|---|---|---|
| **B-1a (recommended first)** | Admit the classes whose activity lanes and CES fields **already exist**: winsec `4625` (AUTHENTICATION, failed logon), `4634` (AUTHENTICATION, logoff), `4689` (PROCESS_TERMINATION), sysmon `2, 15, 23, 26` (FILE), `14` (REGISTRY) | **No new schema, no new lane.** One caveat requiring review: `NOT_SUPPORTED[AUTHENTICATION]` currently declares `authentication.session_end` unavailable (`:124`); admitting 4634 **fills a self-declared gap**, which is a contract change inside the existing module |
| **B-1b (separate, later)** | Classes needing a new activity lane or family decision: `7045`/`4697` service install, `4698`/`4700` scheduled task, sysmon `7` image load, `8` remote thread, `10` process access, `17/18` pipes, `19-21` WMI, `1102` log cleared, System-channel family admission | New lanes and a `CHANNEL_FAMILY` decision → **independent review of the canonical contract required** |

**Why B-1a qualifies as the first bounded module:** it touches no installer, no
M1 source, no enrolment, no identity, no response and no tenancy; it introduces
no sensor, schema, identity or engine; it reuses `windows_eventlog.py` and the
existing CES fields; and its effect is directly measurable — refused records
become canonical evidence that Device Trajectory, process tree and detections
already know how to consume.

**G0 inputs it still needs before any code:** per-class source-field proof from
real event XML (the `fixtures_windows_eventlog.py` corpus), a declared
`NOT_SUPPORTED` list per newly admitted class, and a decision on the
`authentication.session_end` contract change. Gap verification is complete;
**G0 scoping is not**, and B-1a is **not** authorized to start by this document.

## B.4 · Priority-ordered backlog (after B-1a)

1. **B-1b** canonical lane extension — needs contract review.
2. **Linux evidence-journal parity** — adopt the existing
   `nivxforge_journal.py` on the Linux connector rather than writing a second
   durability mechanism. (Largest single asymmetry in the inventory.)
3. **Detection-handoff contract drift** — the 4 isolation-failing tests in
   `test_p0_f13_5_detection_handoff.py`.
4. **Hunting query surface** — a dedicated suite and an explicit query
   contract; aggregation currently rides on payload regex signatures.
5. **Windows onboarding correction** — P0-3/A1, pending Codex re-review.

---

# PASS · FAIL · BLOCKED — separated

**PASS (verified in this pass):** M1 source identity and reachability (A.1) ·
CI secret hygiene, unconditional service cleanup, pinned build tooling,
ignored build stub, real negative security probes (A.2) · artifact
self-description (A.3) · 97 canonical/trajectory/identity tests · 41 response
authority/isolation tests.

**FAIL (correction required, designed only):** CI-F1 unfiltered push trigger ·
CI-F2 production hostname in service-starting gates · CI-F3 no source-provenance
assertion · floating interpreter version · unhashed build dependencies ·
Windows ingest admits 9 of 44 known classes · Linux connector has no durable
evidence journal · 4 detection-handoff tests fail in isolation.

**BLOCKED (not attempted):** native build and Gates 0-4 · G4 isolated-Windows
acceptance · artifact signing · enterprise upgrade and the transaction engine ·
identity migration, re-enrolment and purge · Windows onboarding advertisement ·
production rollout and production credential use.

**UNKNOWN:** GitHub Actions run history for the Windows workflow.

# Unchanged-state declaration

`git status --porcelain agents backend apps/nivxray-xdr/src .github docs` →
**0 entries**. No source edit, commit, merge, push, CI run, deployment, database
read or write, endpoint contact, installer execution, or credential value read
or printed. Frozen subtree `db21f422561f14fb4dcec91b70925f2b5291c500` untouched;
no HOLD removed.

**Next step requires a decision, not another document:** approve A-G1 (the three
CI hardening commits, CI-F1 first and alone) and/or authorize G0 scoping for
module B-1a.
