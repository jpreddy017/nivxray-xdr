# F1_LEGACY_V2_DEPENDENCY_REPAIR — group 1

Date: 2026-06
Branch: `engineering/f1-v2-dependency` (isolated worktree — **not merged, not pushed**)
Start: `62a2c658f638f118920aad4853c3747eeda801ec` / tree `71a64740ffa955f1a229cba57f99812f04831bc0`
Final: `04730d9d5af2c55bdb2bde728e6bfb9c8ffece1b` / tree `60e574b88caa2650a56962bd03d9fb67b1700715`

## FINAL RESULT: **PARTIAL** — group 1 complete, stopped for review

12 of 27 imports eliminated, all of them on required runtime paths, verified
against the real missing-legacy-module scenario. The remaining 15 cannot be
decided by an engineer: they are **production features implemented inside
`v2/` and mounted unconditionally in `server.py`**. Finishing them means
either migrating a 33,740-line subsystem or declaring live endpoints optional.
Per the "complete one safe group and stop" instruction, I stopped.

`test_v2_isolation` **still fails** (15 offenders). Not hidden, not skipped,
not xfailed.

---

## 1 · Root cause

Not a test defect, and not an accident of style. `v2/` was never
decommissioned: RC5 code calls into it for real capability — the canonical
event vocabulary, the live-observation bridge, the PowerShell tokenizer and
recovery, the investigation/jobs/report subsystem. The deletion-safety
contract asserts `v2/` can be removed; the code says otherwise.

The sharpest evidence is the boot path. `server.py` mounts four routers
**unconditionally** — `auto_investigate` (321), `auto_investigate_jobs` (430),
`decoded_artifacts` (436), `report_writer` (440) — and each imports `v2` at
module scope. Deleting `v2/` would break application import, not merely a
feature. Meanwhile the same file wraps the `v2.routers` include in a
try/except at line 708 with the comment *"so if `/app/backend/v2/` is deleted
the app still boots"*. **The documented intent and the wiring disagree**, and
that gap is the root cause.

Suppressing the test would have hidden exactly this.

## 2 · Inventory of all 27 imports, with decisions

### Group 1 — done · 12 imports · REFACTOR (ownership moved, no logic changed)

| File:line | Import | Decision |
|---|---|---|
| `edr_plane/file_content_acquisition.py:24` | `canonical: HASH_NOT_OBSERVED, HASH_OBSERVED` | → `telemetry.canonical` |
| `edr_plane/file_identity.py:29` | `canonical: HASH_NOT_APPLICABLE/NOT_OBSERVED/OBSERVED` | → `telemetry.canonical` |
| `edr_plane/windows_eventlog.py:910` | `canonical: SYSMON_KIND, WINSEC_KIND` | → `telemetry.canonical` |
| `edr_plane/canonical_bridge.py:510` | `case_engine.schema: COLLECTIONS` | → `telemetry.collections` |
| `edr_plane/canonical_bridge.py:511` | `telemetry_bridge: persist_live_observation` | → `telemetry.bridge` |
| `edr_trajectory/platform_seed.py:78` | `telemetry_bridge: observation_doc` | → `telemetry.bridge` |
| `edr_trajectory/prodshape.py:245` | `telemetry_bridge: observation_doc` | → `telemetry.bridge` |
| `routers/xdr_ingest.py:536` | `telemetry_bridge: link_observations_to_incident, persist_live_observation` | → `telemetry.bridge` |
| `services/decoder/powershell_constants.py:9` | `semantic.ps_ast: tokenize, Token, TOK_*` | → `services.decoder.ps_ast` |
| `engine/orchestrator.py:839` | `semantic.ps_recovery: recover_powershell_from_b64` | → `services.decoder.ps_recovery` |
| `scripts/wave_b_foundation_measure.py:28` | `canonical: HASH_OBSERVED` | → `telemetry.canonical` |
| `scripts/wave_b_foundation_measure.py:29` | `telemetry_bridge: observation_doc` | → `telemetry.bridge` |

Chosen because all five target modules are **leaves**: `canonical.py` (652
lines) and `collections.py` (87) are stdlib-only; `ps_ast.py` (747) is
stdlib-only; `ps_recovery.py` (522) already depended *downward* on
`services.decoder.*`; `bridge.py` (391) depends only on the other two. Moving
them pulls no chain and changes no behaviour — the objects are identical.

### Group 2 — not done · 15 imports · needs an owner decision

| File:line | Import | Why it is blocked |
|---|---|---|
| `routers/auto_investigate.py:674` | `v2.jobs.pipeline` | live endpoint; 708-line pipeline coupled to `v2.investigation` |
| `routers/auto_investigate_jobs.py:27,28` | `v2.jobs` (pubsub, store), `v2.jobs.pipeline` | live endpoint |
| `routers/decoded_artifacts.py:16` | `v2.decoded_artifacts` | live endpoint; also `server.py:913` index bootstrap |
| `routers/report_writer.py:18` | `v2.report_writer` | live endpoint; package, not a leaf |
| `canonical/iue/adapters/language_multi_artefact.py:10` | `v2.investigation.iu.engine` | ADR-005 adapter depends on legacy classification |
| `scripts/decode_trace_report.py:94` · `scripts/v160_baseline_metrics.py:61` | `v2.investigation.pipeline` | analysis tooling for v2 itself |
| `security_state/tests/phase2c_real_replay_runner.py:20,21,22` | `v2.investigation.{iu,cre,intent}` | phase test runners under a non-skipped `tests/` dir |
| `security_state/tests/phase5_shadow_tests.py:17,18` · `phase6b_causal_rules_tests.py:33,34` | `v2.investigation.{builder,shadow_hook}` | same |

I did **not** silently convert these to try/except, and I did **not** declare
production features optional on my own authority. Both would have produced a
green gate while changing what the platform promises.

## 3 · Files changed (10 modified, 5 moved, 1 added)

```
R  backend/v2/ingestion/canonical.py        -> backend/telemetry/canonical.py
R  backend/v2/ingestion/telemetry_bridge.py -> backend/telemetry/bridge.py
R  backend/v2/case_engine/schema.py         -> backend/telemetry/collections.py
R  backend/v2/semantic/ps_ast.py            -> backend/services/decoder/ps_ast.py
R  backend/v2/semantic/ps_recovery.py       -> backend/services/decoder/ps_recovery.py
A  backend/telemetry/__init__.py
M  backend/v2/{ingestion/canonical,ingestion/telemetry_bridge,case_engine/schema,
     semantic/ps_ast,semantic/ps_recovery}.py     (re-export shims, no logic)
M  backend/edr_plane/{canonical_bridge,file_content_acquisition,file_identity,
     windows_eventlog}.py
M  backend/edr_trajectory/{platform_seed,prodshape}.py
M  backend/engine/orchestrator.py
M  backend/routers/xdr_ingest.py
M  backend/scripts/wave_b_foundation_measure.py
M  backend/services/decoder/powershell_constants.py
```

The shims exist so the legacy tree's own 30+ importers (many using relative
`from .canonical import …`) were left untouched — rewriting 33k lines I do not
test would have been the riskier choice. They carry **no logic** and are
deleted with `v2/`. `ps_ast`'s shim re-exports `_all_children` and
`_fold_string` explicitly, because `v2/semantic/ps_behaviors.py:24` imports
those private helpers and `*` would not carry them.

## 4 · Before and after

| | Before | After |
|---|---|---|
| Dependency direction | `edr_plane`, `routers/xdr_ingest`, `engine`, `services/decoder` → `v2` | `v2` → `telemetry`, `services.decoder` |
| Deleting `v2/` | canonical vocabulary, observation bridge, PS tokenizer and recovery all vanish | all four survive; **13 affected modules import and work** |
| `v2` internal users | 30+ importers | unchanged, via shims |
| Behaviour | — | identical objects; no logic edited |

**Missing-legacy-module scenario, executed** (`v2` blocked via a `sys.meta_path`
finder, not a rename):

```
WITH v2 UNAVAILABLE — 13 imported, 0 failed
behaviour: HASH_OBSERVED True True
```

covering `telemetry.{canonical,bridge,collections}`,
`services.decoder.{ps_ast,ps_recovery,powershell_constants}`,
`edr_plane.{file_identity,file_content_acquisition,windows_eventlog,canonical_bridge}`,
`edr_trajectory.{platform_seed,prodshape}`, `engine.orchestrator`.

Normal operation is covered by the gates below, which exercise the decoder and
ingest paths with `v2` present and the shims in place.

## 5 · Test results — final commit

| Gate | Tests | Failures | Errors | Skipped | Exit |
|---|---|---|---|---|---|
| decoder | 147 | 0 | 0 | 6 | 0 |
| command | 372 | 0 | 0 | 0 | 0 |
| tenant | 104 | 0 | 0 | 0 | 0 |
| boundaries | 136 | 0 | 0 | 0 | 0 |
| response | 39 | 0 | 0 | 0 | 0 |
| **security (108 tier-one)** | 108 | **1** | 0 | 1 | **1** |
| frontend (vitest) | 420 | 0 | 0 | 0 | 0 |
| build (vite) | — | — | — | — | 0 |
| **Backend + security** | **906** | **1** | **0** | **7** | — |

- **798 backend regression tests: unchanged and passing.** The decoder gate
  matters most here — `ps_ast` and `ps_recovery` moved underneath it.
- The one security failure is `test_v2_isolation` (15 remaining offenders).
- The one skip is the pre-existing, explicit one:
  `test_the_application_env_holds_no_deploy_or_test_credential` skips because
  a checkout has no `.env`; it states the missing prerequisite rather than
  passing vacuously.
- **No new collection errors** — 0 errors throughout.
- Import origin verified in the gate log:
  `deps`, `server`, `tests._verified_session` → `/app/rocket-p0/f1/backend/…`.
- `ruff` clean on every new and moved-and-edited file. The frontend is
  byte-identical (`git diff --name-only … -- apps/nivxray-xdr frontend` → 0),
  so those gates ran from the staging worktree, which has `node_modules`.

## 6 · Architecture and portability

- No hardcoded VPS path, no cloud dependency, no credential, no new
  third-party package, no platform assumption.
- **No hidden import-path manipulation.** A `sys.modules` aliasing trick would
  have made the shims a one-liner; it was rejected as exactly the kind of
  hidden manipulation the task forbids. The shims are explicit re-exports.
- No cross-product database dependency introduced. `telemetry` is
  product-neutral by design and sits below both XDR and EDR, which suits the
  future split: EDR produces observations, XDR consumes canonical events, and
  both now share a contract that belongs to neither.
- No new abstraction layer and no duplicated implementation — the modules
  moved, they were not reimplemented.

## 7 · Remaining blockers

1. **`test_v2_isolation` fails — 15 imports, group 2.** Needs the owner to
   choose: migrate `v2.jobs` / `v2.report_writer` / `v2.decoded_artifacts` /
   `v2.investigation` into first-class packages, or formally declare those
   endpoints optional with visible failure.
2. **`server.py` mounts four v2-dependent routers unconditionally** — the
   stated deletion-safety intent is not implemented for them.
3. F2, F3, F4 untouched, as instructed.
4. `v2/` is **not** deleted. Nothing was removed before replacement behaviour
   was verified.

## 8 · Rollback

```bash
git worktree remove /app/rocket-p0/f1 --force
git branch -D engineering/f1-v2-dependency
# or keep the branch and drop the change only:
git revert 04730d9d5af2c55bdb2bde728e6bfb9c8ffece1b   # restores v2-owned paths
```

Code-only and additive-by-move; no database, artefact or deployment state is
involved. The staging package is untouched — pin `593b3e9f`, bundle
`98e4adba…fdfa`, and the staging worktree still prints "Pinned source
verified". **No re-pin, no bundle regeneration.**

> One consequence to note: these are the first F-series changes that **do**
> land inside the build context (`backend/**` is included by
> `prepare.included()`), unlike A1 and A3. Merging F1 will therefore require a
> re-pin and a fresh bundle before the next Hetzner run.

## 9 · Recommended next smallest task

**F1-b · migrate `v2/decoded_artifacts` to first-class.** It is the smallest
of the four live surfaces, it already has an index bootstrap in `server.py:913`
to move with it, and it has no investigation-pipeline coupling — so it is the
cheapest way to prove the migration pattern before touching `v2.jobs`, which
drags in `v2.investigation`. One router, one package, one gate.

---

**No merge, push, deployment, migration, staging change, bundle regeneration
or re-pin. No security control weakened. All HOLDs preserved. Release NO-GO.
Stopped after F1 group 1 — F2, F3 and F4 not started.**
