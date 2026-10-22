# INDEPENDENT G1 REVIEW — NIVXFORGE EDR P0 RECONCILIATION DESIGN

**Verdict: `G1 BLOCKED`**

Reviewed: `NIVXFORGE_EDR_P0_RECONCILIATION_G1.md`
(`e5fafcbc530da4c9525f041e453fd9d444b6f552c026dc73f579edb41630ca6f`).
Baselines re-verified independently: trunk `f971c765`, M1 `388bb3d6`, ancestor
`ae34056315cde90873386bb56edfcd5bd5cd19b9`, frozen subtree
`db21f422561f14fb4dcec91b70925f2b5291c500`.
Mode: READ-ONLY. No implementation, merge, CI run, deployment, source change or
HOLD removal. **Integration is not self-authorized.**

**Why BLOCKED rather than FAIL:** the baseline work, the conflict-surface
reduction and the two-phase structure are sound and reproducible. Three
material findings must be corrected before any authorization, and one of them
contradicts a risk assessment the design labels LOW. **Why not PASS:** the
design's central safety claim for Phase 1 — that the sensor is a *compatible*
superset — is **false at the call-site level**, and its Phase 2 premise is
**false at the source level**.

---

## 1 · Mandatory findings

### M-1 · The sensor superset claim does not hold at the call site — **MATERIAL**

The design's own warning ("do not equate additive diffs with proven runtime
safety") is the exact trap it falls into. The diff is additive; the
**post-condition of `enrol()` is not**.

| | trunk `1ab744f3` | M1 `53a45ded` |
|---|---|---|
| identity write | `IDENTITY_FILE.write_text(json.dumps({…}))` — **overwrites** | `publish_identity(...)` → *"refusing to publish identity: … already exists; replacement is a separate, ownership-gated operation"*, enforced by `_rename_no_replace` (MoveFileExW **without** `MOVEFILE_REPLACE_EXISTING`) |

`publish_identity` is called **unconditionally** inside `enrol()` — not gated
by `single_attempt` or `attempt_marker`. The trunk's installer calls
`sensor.enrol(api, tenant, sensor.read_enrolment_secret())`
(`nivxforge_setup.py:594`) on a path explicitly reached when
`sensor.IDENTITY_FILE.exists() and not re_enrol` is **false** — i.e. line 573
sends `--re-enrol` to `enrol()` **with the identity file still on disk**.

**Consequence:** under Phase 1 as designed (M1 sensor blob + trunk
`nivxforge_setup.py`), `install --re-enrol` fails at identity publication
instead of re-enrolling. The documented operator recovery path for *"existing
enrolment is incomplete (missing: …). Re-run with --re-enrol and a fresh
token"* (`_validate_identity`, trunk `setup.py:519-531`) becomes
**unreachable** — the installer tells the operator to do something the sensor
now refuses.

**And CI would not catch it.** Gate 6 ("Re-enrol against a RUNNING service ·
stop race + rollback") invokes `install --re-enrol` with **empty stdin**, so
`read_enrolment_secret()` refuses *before* `sensor.enrol()` runs. The gate
asserts the refusal, never the success path. The regression is latent and
untested.

→ The reconciliation matrix row "Sensor … **KEEP FROM M1** … LOW" is
**incorrect**. Risk is **HIGH** until corrected (C-1).

*Verified not broken:* every other symbol the trunk installer consumes exists
in M1's sensor with a compatible signature — `read_enrolment_secret`, `status`,
`run`, `use_state_dir`, `nvx_journal`, `refuse_secret_on_command_line`,
`_now`, `IDENTITY_FILE`, `STDIN_ONLY_NOTICE`, `STATE_DIR`, `SENSOR_VERSION`.
`enrol`'s extra parameters are keyword-only with trunk-preserving defaults,
and `_Transport.request(attempts=2)` does reproduce the trunk's
reconnect-once. The sensor imports nothing from `setup` or `m1`, so there is
no circular dependency. **The journal claim is upheld without qualification:**
47 insertions, 0 deletions, and the eight journal entry points the trunk
installer's selftest uses (`open_journal`, `commit_page`, `cursor`, `health`,
`write_integrity_snapshot`, `build_gap`, `close`, reopen) are unchanged.

### M-2 · Phase 1 **would** activate the push-triggered SCM workflow — **MATERIAL**

Confirmed from source at `f971c765`:

```yaml
on:
  workflow_dispatch:
  push:
    paths:
      - 'agents/nivxforge-windows/**'
      - '.github/workflows/windows-sensor-installer.yml'
```

There is **no `branches:` filter**. Any push to any branch touching those paths
runs the job — and Phase 1 touches exactly `agents/nivxforge-windows/**`. The
M1 lineage already recognised this and added
`branches-ignore: ['engineering/windows-installer-transaction-recovery']`;
**the integration branch is not covered by that list.**

What would then run, unreviewed and automatically: Gate 5 creates and starts a
real Windows service on the runner, and Gate 6 performs a re-enrolment race —
both against `https://nivxray.nivxforge.com`, i.e. **unauthenticated outbound
traffic to the production backend**, triggered by a source-import commit. The
design identified the path filter but recorded it as an observation; it is a
**precondition**, not an observation.

### M-3 · Importing the frozen M1 files creates **no** unsafe reachable production path — **CLEARED, with one condition**

Verified: `nivxforge_m1.py`, `nivxforge_transaction.py` and
`nivxforge_scm_worker.py` each contain **zero** `__main__` guards and **zero**
`argparse` usage. The only dispatchers are in M1's `nivxforge_setup.py`
(`m1_dispatch`, and `raw == ["--transaction-scm-worker"]` →
`nivxforge_scm_worker.entry`), and the trunk's `nivxforge_setup.py` contains
**no** `m1_dispatch` (`grep -c` = 0). PyInstaller executes only the entry
script, so hidden-imported modules are not reachable as entry points.

**Condition:** Phase 1 as designed also imports M1's
`build_windows_installer.ps1`, which adds `--hidden-import nivxforge_m1 /
nivxforge_transaction / nivxforge_scm_worker` and generates
`payload-manifest.json` via `from nivxforge_transaction import inventory`.
The artifact therefore **changes composition** while the entrypoint stays the
trunk's. That is inert but it is *not nothing*: the binary ships code the CLI
cannot reach, which weakens the "every byte is reachable and reviewed"
property. Either take the trunk's build script in Phase 1 and M1's in Phase 2,
or state the dead-code carriage explicitly in the artifact contract.

### M-4 · RISK-2 is not "needs evidence" — the premise is **false** — **MATERIAL**

The design proposes retiring `_remove_partial_service`,
`_remove_partial_staging` and `_abort_incomplete_clean_install` once the
transaction engine is shown to satisfy the five invariants of
`test_s1_2_c2_clean_install_atomicity.py`. Source says that cannot be shown:

**`nivxforge_transaction.py` contains zero enrolment or identity handling**
(`grep -ci enrol` → **0**). Enrolment happens in M1's `install()` `prepare()`
hook, *outside* the engine.

| Trunk invariant | Satisfied by the M1 path? | Evidence |
|---|---|---|
| 1. Identity preserved after a post-enrolment failure | **by omission, not by assertion** — nothing deletes it, but nothing asserts it either | engine has no identity code |
| 2. State directory never removed | **YES** — and more strongly: M1's `uninstall()` refuses outright | `setup.py:1213` *"uninstall/purge unavailable in transaction validation builds"* |
| 3. Partial staging removed | **only via operator-invoked `recover-transaction`** | `Engine.reconcile()` is called from `recover_transaction()`, not from a failing `install()` |
| 4. A service this attempt registered is deleted **and proved gone** | **only via operator-invoked settlement**; the proof requirement is strong (`require_observation`: *"absence not proved by ERROR_SERVICE_DOES_NOT_EXIST"*) | `resolve_operation` is a separate command |
| 5. Honest operator message (`THIS ENDPOINT IS NOT COLLECTING`, `NO second enrolment token`, `PRESERVED`) | **NO** | M1's `install()` failure path is `raise SystemExit(str(ex))` |

So: **1 of 5 cannot be satisfied by the engine at all, 2 only after a manual
command, 1 holds for an unrelated reason, 1 holds only incidentally.**
Retirement as proposed would remove automatic post-failure cleanup and replace
it with an operator who must know to run `recover-transaction`. That is a
**capability reduction**, not a refactor, and it needs an owner decision — not
a test re-target.

### M-5 · Two capabilities are silently lost, and the matrix does not say so — **MATERIAL**

- **`--re-enrol` is refused outright** on the M1 lineage:
  `if re_enrol: raise SystemExit("transaction recovery never re-enrolls an endpoint")`.
- **`uninstall`/`purge` is refused outright** on the M1 lineage
  (`setup.py:1213`), while the trunk's uninstall works. M1's clean-install
  path has its own `m1_uninstall`, which is a *different* operation on a
  *different* layout.

The brief requires that the integration "retains both source lines' necessary
functionality". The matrix classifies `install()` as COMPOSE BOTH but never
records that composing naively deletes two working operator capabilities.
These are **INCOMPATIBLE — DESIGN DECISION REQUIRED**, not COMPOSE.

### M-6 · RISK-3 is better than the design claims — **CLEARED**

M1 already identifies a legacy-layout installation without migrating it
silently. `_active_service_exe()`: *"the SCM is the authority … The legacy
in-place path is the last resort so an endpoint installed before this repair
still has a valid previous image to roll back to"* — resolution order is the
SCM `binPath`, then `active.json`, then `SERVICE_EXE`. The engine then
inventories the payload directory of the **registered image** and, if its
identity is not a pinned predecessor, refuses with `UNSUPPORTED_PREDECESSOR`
stating *"Nothing was stopped, staged, reconfigured or activated, and identity,
tenant, credentials, journal, cursors and queued evidence are untouched"* and
pointing at the reviewed migration procedure.

**This is the correct posture and it does not imply enterprise upgrade
approval**: an old-layout endpoint is *identified and refused*, never
auto-upgraded. Required addition: the integration must assert that refusal as
a **negative control**, so a future change cannot turn it into a silent
migration.

### M-7 · Native CI boundaries — **largely upheld, two corrections**

Verified true: `runs-on: windows-latest`; `permissions: contents: read`; **no
`secrets.` reference in either workflow**; **no `pull_request` trigger**, so no
fork-controlled code executes with repository context; PE header check; frozen
CLI contract; the `--token` removal and secret-shaped-argv refusals; build
provenance with `build_commit` + `artifact_sha256` and `UNOFFICIAL_BUILD`
rejection; real SCM create/start/stop/delete; the service-wrote-its-own-log
proof; cleanup step "Remove the CI service if the gate failed"; and, on the M1
side, the two upgrade-repair gates and the `workflow_dispatch`-only
`windows-installer-transaction-build.yml`. Workflow **execution history
remains UNKNOWN** — correctly stated.

Corrections:

1. **Lab-only origin must be mandatory, not advisory.** The design offers it as
   a mitigation for RISK-4; given M-2 it becomes a hard precondition: no gate
   may start a service against the production origin from CI. The design's
   supporting claim is confirmed — `_assert_backend` is a **deny**-list
   (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `preview.emergentagent.com`,
   `.local`, dev ports), so a lab FQDN needs **no code change**. Note the
   asymmetry the design should state plainly: M1's `load_config` applies
   **no** production-origin deny-list (https + netloc + `windows-default`
   only), so the M1 clean-install path will accept a lab or preview origin
   that the enterprise `install()` path refuses.
2. **Source provenance must be asserted, not recorded.** Asserting
   `build_commit == 388bb3d6…` is necessary but insufficient: the gate must
   also assert the **frozen subtree identity**
   `agents/nivxforge-windows == db21f422…` for the M1 files, since a commit id
   alone does not prove the reviewed bytes were the ones compiled.

### M-8 · Security invariants — **upheld, with two inherited routes to declare**

Verified that **neither lineage modifies** `backend/routers/edr.py`,
`backend/edr_plane/response.py` or `backend/routers/edr_response.py`
(`git diff --name-only` → 0 on both sides). Tenant isolation (`edr_scope()`
authority intersection), response authorization and the independent-verification
state machine are therefore **untouched by this integration**, in either phase.
Credential handling improves under M1 (stdin-only, attempt marker,
no-overwrite publication, `attempts=1`), subject to M-1.

Two trunk-only routes that Phase 1 inherits by basing on the trunk, and that
the design under-states:

- `backend/routers/edr_maintenance.py` — destructive dev reset, gated only by
  `EDR_MAINTENANCE_TOKEN` + header. Correctly fail-closed, correctly
  characterised in the design.
- `backend/transfer_bundle.py` — **not mentioned in the design's security
  analysis.** It serves source/evidence bundles on
  `GET /api/transfer/{name}?token=…`. It is fail-closed when the env var is
  unset and uses `secrets.compare_digest`, but a **token in a query string**
  appears in access logs and proxy telemetry. Add it to the register beside
  `edr_maintenance`.

### M-9 · The acceptance strategy can still hide regressions — **MATERIAL**

Two gaps:

1. **The known-failure bucket is a hiding place.** The design proposes
   isolated databases per run, which is right — but isolation will make the 12
   `test_34h_a_migration_control.py` failures *disappear*, and a disappearing
   failure looks identical to a fixed one. Worse, if post-integration runs are
   compared against "16 known failures", a new regression inside those same
   files is absorbed. Required: a per-test, per-baseline recorded manifest
   (test id → status at `f971c765`), and a rule that **the expected-failure set
   may only shrink, never substitute**.
2. **The M1 baseline was never measured.** The design records
   `2,392 / 16 / 3` for the trunk and `373 passed` for the M1 clean-installer
   file, but **no full-suite number exists for the M1 lineage**. Without it
   there is no comparable "before" for Gate B. This is an unacknowledged
   evidence gap, and Phase 1's Gate B cannot be evaluated without it.

The independent triage of the 4 `test_p0_f13_5_detection_handoff.py` failures
is **confirmed**: they fail in isolation; `routers/edr.py` `trajectory_focus`
reads `_db["edr_endpoints"]` directly while the fixture stubs only
`query_window` and `dir_svc.resolve`; `git log -S` places the product change at
`a8ccdb36` (2026-10-03) against a test created 2026-09-07; **2026-10-03
precedes the 2026-10-04 split, so both lineages inherit it.**

---

## 2 · Can Phase 1 be authorized independently of Phase 2?

**Yes in principle — no as currently specified.** Phase 1 is genuinely
separable: it is additive, it leaves the installer entrypoint untouched, the
frozen M1 modules are unreachable (M-3), and the backend security planes are
not involved (M-8). But as written it would (a) break `install --re-enrol`
with no test coverage (M-1) and (b) auto-run service-mutating CI against the
production backend (M-2).

**Phase 1 is authorizable once, and only once, C-1, C-2 and C-3 are in place.**
Phase 2 is **not** authorizable: M-4 and M-5 are owner decisions, not
engineering tasks.

---

## 3 · Required corrections

| ID | Correction | Blocks |
|---|---|---|
| **C-1** | Resolve the `enrol()` post-condition before importing M1's sensor. Either (a) keep the trunk's `--re-enrol` working by routing replacement through an explicit ownership-gated operation that the installer calls, or (b) declare `--re-enrol` withdrawn as an owner decision and make the installer say so instead of advising it. **Add a positive test for a successful re-enrol — today no test covers it.** | Phase 1 |
| **C-2** | Make Phase 1 CI-inert: add the integration branch to `branches-ignore` (or add a `branches:` allow-list) **in the same change** that imports files under `agents/nivxforge-windows/**`. | Phase 1 |
| **C-3** | Make the lab-only origin mandatory for every CI gate that starts a service, and assert the frozen subtree hash `db21f422…` in addition to `build_commit`. | Phase 1, Track 2 |
| **C-4** | Reclassify the sensor row from "KEEP FROM M1 / LOW" to "KEEP FROM M1 / **HIGH until C-1**", and the `install()`, `--re-enrol` and `uninstall` rows to **INCOMPATIBLE — DESIGN DECISION REQUIRED**. | design accuracy |
| **C-5** | Replace RISK-2's "retire with evidence" with the source finding: the engine has no identity or enrolment code, invariant 5 is unsatisfiable by it, and invariants 3–4 require an operator command. Retirement requires either equivalent logic in the composed `install()` or an accepted capability reduction. | Phase 2 |
| **C-6** | Record `test_s1_2_c2_clean_install_atomicity.py`'s refusal behaviour **and** M1's `UNSUPPORTED_PREDECESSOR` refusal as negative controls, so neither can silently become a migration. | Phase 2 |
| **C-7** | Produce the per-test expected-failure manifest at `f971c765` **and** a full-suite baseline on the M1 lineage before Gate B; expected failures may only shrink. | Gate A/B/C |
| **C-8** | Decide the Phase 1 build-script question (M-3): trunk's script in Phase 1, or an explicit dead-code declaration in the artifact contract. | Phase 1 |
| **C-9** | Add `transfer_bundle.py` to the risk register beside `edr_maintenance.py`. | design completeness |

---

## 4 · Safe future G2 boundaries

Permitted once C-1 … C-3 are satisfied **and** the owner authorizes Phase 1:

- additive import of the M1-only modules, **byte-identical**, verified by blob
  id against `388bb3d6` for every file, with
  `<branch>:agents/nivxforge-windows/nivxforge_m1.py` matching M1's blob;
- adoption of M1's journal blob `bbaaaed0` (unconditional — the claim is
  proven);
- adoption of M1's sensor blob `53a45ded` **only after** C-1;
- the CI-inertness change of C-2, in the same commit;
- a `workflow_dispatch`-only M1 clean-install workflow with a lab origin,
  mandatory service cleanup and the subtree assertion of C-3.

Explicitly **not** permitted under this review: touching
`nivxforge_setup.py` or `windows-sensor-installer.yml`; retiring any trunk
atomicity helper; changing any file inside the frozen subtree; any edit to
`routers/edr.py`, `edr_plane/response.py` or `edr_response.py`; any CI run
against the production origin; any release, signing or publication of the
artifact; any fix to the 16 trunk failures as part of the import commit (they
must be triaged separately so the baseline stays comparable).

---

## 5 · HOLDs — all reaffirmed, none removed

Windows **G4 NOT RUN** and not accepted · M1 clean-install G3 does **not**
imply enterprise upgrade/recovery approval (reinforced by M-4: the engine is
unreviewed *and* does not cover enrolment) · collector tenant-isolation and
token-hygiene gates stand on their original evidence · response execution
retains backend approval and independent verification · exposed JWTs and
hardcoded administrator credentials still require revocation/rotation and
exposure assessment · the Linux `--token` argv exposure remains a **separate
prioritized security repair**, out of scope here · **no production activation
or rollout is authorized**.

---

## 6 · Reviewer's reproduction set

```
git show f971c765:agents/nivxforge-windows/nivxforge_setup.py | sed -n '570,600p'   # line 573/594
git show 388bb3d6:agents/nivxforge-windows/nivxforge_sensor.py | sed -n '528,560p'  # publish_identity refusal
git show f971c765:.github/workflows/windows-sensor-installer.yml | sed -n '12,18p'  # no branches: filter
git show 388bb3d6:agents/nivxforge-windows/nivxforge_transaction.py | grep -ci enrol   # 0
git show 388bb3d6:agents/nivxforge-windows/nivxforge_setup.py | sed -n '1148,1150p'    # --re-enrol refused
git show 388bb3d6:agents/nivxforge-windows/nivxforge_setup.py | sed -n '1213,1218p'    # uninstall refused
git diff --name-only ae340563 388bb3d6 -- backend/routers/edr.py backend/edr_plane/response.py   # empty
```

**Unchanged-state note.** No tracked code was modified during this review:
`git status --porcelain agents backend apps/nivxray-xdr/src .github docs` → 0
entries, before and after. No merge, cherry-pick, rebase, reset, fetch or
branch switch was issued; no CI was triggered; no database was written; no
credential value was read. The branch head did advance (`17f99d36` →
`3feeb3cf`) through the **platform's own automatic commit** of the previous
turn's `memory/` documents — `git diff --name-status HEAD~1 HEAD` shows
`A memory/NIVXFORGE_EDR_P0_RECONCILIATION_G1.md`, `M memory/PRD.md` and
nothing else. No code ref was moved by this review.

**This review does not authorize integration, does not modify source and
removes no HOLD.** Owner approval is required before any G2 work, and a
re-review should address only the corrections above rather than restarting the
design.
