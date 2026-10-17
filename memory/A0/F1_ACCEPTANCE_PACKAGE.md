# F1 ACCEPTANCE PACKAGE — commit `d5bceb8` (read-only review)

Candidate: `d5bceb80e471ddb66a0f6119bb4e976e87afcfd3` / tree
`22e59d7bc32c46baff846c989d7409f53d2e9ba1`, branch
`engineering/f1-v2-dependency`, worktree `/app/rocket-p0/f1`.
Baseline: A3 `62a2c658f638f118920aad4853c3747eeda801ec` / tree `71a64740…`.

No code was changed for this review. Nothing was merged, deployed, re-pinned
or waived. Evidence re-generated from both trees under
`/app/rocket-evidence/{a3-compare,f1-final}/`. Probe scripts live in `/tmp`
(disposable mongod, never inside the repository).

---

## 1 · A3 versus F1 — exact comparison

### Release gates (same runner, same machine, re-run for this review)

| Gate | A3 tests/fail/err/skip | F1 tests/fail/err/skip |
|---|---|---|
| boundaries | 136 / 0 / 0 / 0 | 136 / 0 / 0 / 0 |
| command | 372 / 0 / 0 / 0 | 372 / 0 / 0 / 0 |
| decoder | 147 / 0 / 0 / 6 | 147 / 0 / 0 / 6 |
| response | 39 / 0 / 0 / 0 | 39 / 0 / 0 / 0 |
| **security (mandatory)** | **108 / 1 / 0 / 1** | **118 / 0 / 0 / 1** |
| tenant | 104 / 0 / 0 / 0 | 104 / 0 / 0 / 0 |
| **total** | **906 / 1 / 0 / 7** | **916 / 0 / 0 / 7** |
| frontend | 420 passed (25 files) | 420 passed (25 files) |
| build | vite OK | vite OK |

A3's single failure:
`tests/test_v2_isolation.py::test_rc5_source_never_imports_v2_unwrapped`.
The +10 security tests are `test_f4_tenant_bootstrap.py` (8) and
`test_f3_installation_paths.py` (2). The one skip is pre-existing in both.

### Tier-2 (live-server suites, not part of the gates)

| | A3 | F1 |
|---|---|---|
| tier-2 | **16 failed**, 88 passed, 9 skipped | **0 failed**, 104 passed, 9 skipped |

A3's 16: eight `test_human_control_requires_an_explicit_tenant[...]` and eight
`test_human_control_refuses_an_unknown_tenant[...]` across
`GET /collectors`, `/collectors/{id}`, `/connectors`, `/connectors/{cid}`,
`/data-sources`, `/outbox`, `/outbox/{rid}`, `/outbox/health`.

### Engine-touching suites (54 files, run in both trees and diffed)

38 failures pre-exist on A3; **0 new failures on F1**; `+0 / −0` difference in
the failing set. This diff — not the gates — is what caught the
`telemetry/mitre_map.py` break during the work.

### Functional suites for the migrated surfaces, run in both trees

Identical in both: **7 failed, 70 passed, 1 skipped, 8 errors**, same test
ids. The 8 errors are harness login lockout
(`429 rate_limited / locked`), the 7 failures are `test_ci_ux0_validation.py`
— both pre-existing and environment-driven, not migration effects.

---

## 2 · Do the migrated surfaces still work

### Route inventory — identical before and after

In-process probe of the built application (`/tmp/probe_routes.py`):

| | A3 | F1 |
|---|---|---|
| total routes | **969** | **969** |
| engine-owned routes | **52** | **52** |

Per promoted router, F1:

```
nivx_engine.routers.artifacts  8   cases 5   ingest 6   report 5   ingestion 4
                    validation 3   verdicts 3  ikb 2   investigation 2
                    ancestry 1   irg 1   mitre_coverage 1   parse 1   trajectory 1
routers.auto_investigate        POST /api/v2/auto-investigate
routers.auto_investigate_jobs   POST /api/v2/auto-investigate/jobs
                                GET  /api/v2/auto-investigate/jobs/{job_id}
routers.decoded_artifacts       GET  /api/v2/decoded-artifacts
                                GET  /api/v2/decoded-artifacts/{sha256}
                                GET  /api/v2/decoded-artifacts/stats/summary
routers.report_writer           POST /api/v2/report-writer/generate
                                POST /api/v2/report-writer/generate/from-model
                                POST /api/v2/report-writer/generate/markdown
```

Every engine GET answers **403** unauthenticated — no 404, no 500, i.e.
mounted and guarded, not orphaned.

### Import health

Every module in the package imports against a live database:

| | modules | imported | failed |
|---|---|---|---|
| A3 `v2` | 197 | 197 | 0 |
| F1 `nivx_engine` | 196 | 196 | 0 |

196 vs 197 is `mitre_map.py`, which moved to `backend/telemetry/`.

### Behavioural suites per surface (F1)

| Surface | Suite | Result |
|---|---|---|
| decoded artifacts + background jobs | `tests/test_xdr_analysis_ownership.py` (**in the boundaries gate**) | 28 passed |
| artifacts API | `tests/rc5/api/test_v2_artifacts.py` | 10 passed |
| report API | `tests/rc5/api/test_v2_report.py` | 7 passed, 1 skipped |
| report determinism | `tests/canonical/api/test_report_determinism.py` | 6 passed, 1 skipped |
| investigation timeline | `tests/investigation/test_timeline_builder.py` | 24 passed |

`test_xdr_analysis_ownership` is the strongest of these: job authentication
and owner isolation, websocket authority re-checks, decoded-artifact cache
integrity, tenant-scoped cache reuse, fail-closed database errors — 28 tests,
gated, green.

**UNVERIFIED:** `nivx_engine/report_writer/` (1,661 lines) and the three
`POST /api/v2/report-writer/*` routes have **no test references anywhere**.
Mounted and import-clean; behaviour unproven. Pre-existing gap, see N-4.

---

## 3 · Authoritative tenant enforcement — focused review

### What actually changed

| File | Change |
|---|---|
| `routers/collector_authz.py` | `authoritative()` → `authoritative_required()` (1 line + comment) |
| `routers/xdr_ingest.py` | same (1 line + comment) |
| `routers/xdr_rbac.py` | `authorize_tenant` reordered: AUTHORISATION before registry |
| `services/tenant_registry.py` | **docstring only — zero executable change** |

Byte-identical to A3, confirmed by `git diff --numstat`: `deps.py`,
`services/session_context.py`, `services/dashboard_lenses.py`,
`routers/edr_tenancy.py`, `routers/xdr_audit_log.py`. **No authentication
code was touched.**

### Defect being fixed

`authoritative()` resolves tenancy only when `NIVX_TENANT_REGISTRY_ENFORCE` is
set. Unset is the documented default — only
`deploy/stage1-staging/compose.yml` sets it — and unset means a missing
`X-Tenant-Id` becomes the literal tenant `"default"`. A3 evidence, verbatim:

```
AssertionError: ('GET', '/collectors') -> 200 {"collectors":[...]}
  expected 403 TENANT_REQUIRED
```

Eight reads answered 200 with no tenant resolved. On F1 all eight are
403 `TENANT_REQUIRED`.

### Cross-tenant denial

* **Unheld tenant → one opaque refusal.** Authorisation precedes the registry,
  so `TENANT_NOT_FOUND` / `TENANT_NOT_ACTIVE` are only reachable for a tenant
  the principal already holds. New test
  `test_b6_refusal_does_not_disclose_whether_an_unheld_tenant_exists` asserts
  the refusals for a *registered-but-unheld* and an *unregistered* tenant are
  byte-identical in status, code and reason — the non-enumeration property
  itself, not a code spelling.
* **Held tenant keeps the precise code**: `test_human_control_refuses_a_non_active_tenant`
  still asserts `TENANT_NOT_ACTIVE` and passes.
* **EDR plane unchanged**: `test_edr_route_tenant_authority.py` — including
  `test_unregistered_tenant_is_refused_tenant_not_found` — passes in tier-2.
  The planes disclose differently *by design*: EDR gates precise codes on the
  `tenants.read` permission (P0-FIX-2); the collector plane's admin does not
  hold it. Both verified green.
* Gated cross-tenant coverage: `test_edr_route_tenant_authority` (10 such
  tests), `test_collector_plane_auth` (8), `test_phase2_1_tenant_isolation` (3),
  `test_rbac_selected_customer` (2), `test_xdr_rc1_p1_scope_authority` (2).

### Authentication behaviour

Unchanged: every one of the 52 engine routes answers 403 without a credential;
machine-plane (`MACHINE`) collector tests pass; the 8 tier-2 login-lockout
errors prove brute-force protection is still active. New structural guard
`test_no_production_module_uses_the_flag_gated_authority` prevents regression.

---

## 4 · Have the modified security tests been weakened

90 test files differ from A3. Algorithmic classification (compare the `+`/`−`
line multisets after normalising the `v2`→`nivx_engine` token):

* **74 files — rename-only.** Identical line sets modulo the identifier.
* **16 files — semantic.** Audited individually below.

Test and assertion census (AST, both revisions):

| File | A3 tests/asserts/raises/skips/xfails | F1 |
|---|---|---|
| nivxforge/tests/test_workspace_compatibility.py | 3 / 4 / 0 / 0 / 0 | 3 / 4 / 0 / 0 / 0 |
| nivxforge/tests/test_workspace_isolation.py | 1 / 1 / 0 / 0 / 0 | 1 / 1 / 0 / 0 / 0 |
| security_state/tests/phase4c1_adversarial_tests.py | 0 / 59 / 0 / 0 / 0 | 0 / 59 / 0 / 0 / 0 |
| tests/canonical/executor/test_executor_all.py | 18 / 35 / 0 / 2 / 0 | 18 / 35 / 0 / 2 / 0 |
| tests/canonical/ssot/test_ssot_isolation.py | 3 / 3 / 0 / 0 / 0 | 3 / 3 / 0 / 0 / 0 |
| tests/test_b4b5_tenant_registry_authority.py | 30 / 62 / 7 / 0 / 0 | **32 / 66** / 7 / 0 / 0 |
| tests/test_collector_plane_auth.py | 22 / 41 / 0 / 2 / 0 | 22 / **42** / 0 / 2 / 0 |
| tests/test_phase4_wave1_observation_infra.py | 22 / 70 / 0 / 0 / 0 | 22 / 70 / 0 / 0 / 0 |
| tests/test_phase4_wave1_shadow.py | 14 / 44 / 0 / 0 / 0 | 14 / 44 / 0 / 0 / 0 |
| tests/test_v2_isolation.py | 3 / 4 / 0 / 0 / 0 | 3 / **5** / 0 / 0 / 0 |
| tests/test_v2_phase2.py | 20 / 35 / 1 / 0 / 0 | 20 / 35 / 1 / 0 / 0 |
| tests/test_workspace_certification.py | 3 / 5 / 0 / 0 / 0 | 3 / 5 / 0 / 0 / 0 |

Across **all** changed Python files: 2,189 → 2,234 assert statements
(**+45, −0**). **No `pytest.skip`, `pytest.mark.skip`, `xfail` or
`unittest.skip` was added anywhere in the candidate** — the one skip line in
the diff is a pre-existing skip whose *message* was renamed
(`python -m v2.seed` → `python -m nivx_engine.seed`).

Per-change verdict:

1. **Denylists strengthened, not relaxed.** `_WORKSPACE_MODULES` and
   `workspace_roots` are sets of modules that must NOT be imported or leaked.
   Adding `nivx_engine` keeps the engine forbidden under its new name while
   `v2` stays forbidden. Same for `test_workspace_certification`'s forbidden
   list, which gained `"from nivx_engine"`.
2. **Path anchoring strengthens four guards.** `test_phase4_wave1_shadow`,
   `test_phase4_wave1_observation_infra`, `test_executor_all` and
   `test_ssot_isolation` read `/app/backend` — on a candidate they were
   certifying the deployed pod. They now scan their own checkout. Same
   assertions, correct subject. (`test_ssot_isolation` + `test_executor_all`:
   4 failures on F1 vs 8 on A3 — the anchoring made some *pass*; the residue
   is an obsolete Phase-5.1 `git diff` scope guard, failing on both.)
3. **Two refusal-code expectations changed**, both still asserting 403 and
   both now asserting the non-disclosing code, with the reason written into
   the test. Status assertions retained; a non-enumeration assertion added.
4. **One fixture changed**: `test_b3_ingest_actor_is_never_the_client_claim`
   moved from a flag-pinned unregistered tenant to a registered ACTIVE one.
   The assertion (`pid == "system@ingest"`, `pkd == "system"`) is unchanged;
   only the tenant it names.
5. **One check genuinely removed, disclosed:** `test_v2_isolation`'s
   `test_deleting_v2_would_not_break_rc5_imports` — the simulated-deletion
   probe. It is replaced by `test_server_imports_and_exposes_rc5_surface`
   (server imports, `/api/rc5/parse` still mounted). The deletion simulation
   was removed because the engine is now a **required** dependency; keeping it
   would assert a property the architecture no longer claims. The surviving
   test 1 is strictly stronger than A3's: it forbids *every* `v2` import,
   wrapped or not, in source **and** tests, and asserts `backend/v2` does not
   exist. It was also verified with a positive control.

---

## 5 · Outstanding HOLDs, packaging gaps, unauthenticated endpoints

### Security HOLDs

| # | Item | State | Release impact |
|---|---|---|---|
| A0-9 | Kernel-enforced egress denial unproven | **BLOCKED** — Emergent cannot run it (`unshare -n` → EPERM, no Docker) | HOLD stands; needs the isolated Hetzner host |
| A0-11 | `emergentintegrations 0.2.0` unsigned, single-vendor CDN, no attestation | **CONFIRMED OPEN** — hash-pinned only | Supply-chain HOLD stands |
| A0-14 | ~563 of 601 backend test files outside the gates | **PARTIAL** — security gate 6 → 8 suites, 108 → 118 tests | Green gates do not mean a green platform |

### Packaging gaps

* **A0-12 confirmed with new evidence.** Five download routes serve files that
  are **not in git**: `backend/exports/*.pdf` (4 audit PDFs) and
  `backend/downloads/NivXRay-AIDE-Deck-fixed.pptx`. On A3 they returned 200
  **from the deployed pod's tree** even when the candidate was a different
  checkout; on F1 they honestly 404. In the container (`BACKEND_DIR ==
  /app/backend`) behaviour is unchanged. A fresh image built from git 404s on
  both — the artefacts were never shipped.
* **Candidate hygiene — see N-1.** Two machine-generated files were swept into
  commit `7c2bb3c` by `git add -A`.

### Unauthenticated endpoints (measured, both trees)

`/tmp/probe_unauth.py`: 357 parameterless GETs probed, 3 expensive paths
skipped by name.

| | A3 | F1 |
|---|---|---|
| answered 200 with no credential | **81** | **76** |
| other non-401/403 | 3 | 8 |

The open-surface *inventory is identical* (diff empty); the 81→76 delta is
exactly the five un-shipped artefacts above, and the 3→8 delta is the same
five turning into honest 404s. **This candidate opens no new surface.**

Content verified by sampling, so the classification is not guesswork:

* **Fail-closed, not a leak** — the tenant-data panels (`/api/xdr/mss/*`,
  `/api/xdr/dashboard/tiles`, `/api/incidents`, `/api/xdr/saved-views`) use
  `get_current_user_optional`, and `dashboard_lenses._scope(None)` returns the
  `{"__never_matches__": True}` sentinel, so an anonymous caller gets zeros and
  empty rows. Verified by reading `_scope`, `build_predicate` and
  `is_never_match`, and by the empty bodies in the probe. **Caveat: proven
  against an empty database and by code reading, not against populated tenant
  data.**
* **Product/IP disclosure, no customer data** — `/api/xdr/scenarios` (288 KB,
  100 scenarios), `/api/behaviors/registry` (44 behaviours),
  `/api/die/{dkp/patterns,lolbas}`, `/api/uaie/catalog`,
  `/api/xdr/vendor/_catalog` (credential *schemas*, no values),
  `/api/investigation/coverage/*` (rule efficiency).
* **Internal architecture disclosure** — `/api/audit/*.md` and `/api/deck/*`
  serve `workspace-360.md` (78 KB), `current-state-audit` (55 KB),
  `iue-architecture.md` (66 KB), investor decks (739 KB), unauthenticated.
* **Operational disclosure** — `/api/metrics` returns Prometheus exposition
  (route inventory, latencies, counters) and `/api/openapi.json` the full
  778 KB API surface, both unauthenticated.
* **Three unauthenticated 500s** (identical on A3): `/api/telemetry/frontend/recent`,
  `/api/xdr/vendor/cortex/actions`, `/api/xdr/vendor/cortex/connections`.
* **Not probed, public by design**: `POST /api/benchmark/refresh` re-runs the
  whole 120-sample corpus plus a network feed refresh with no credential —
  unauthenticated compute amplification. `BenchmarkPage.jsx` calls it
  unauthenticated, so gating it is an owner decision.

### Staging

`deploy/stage1-staging` untouched. The frozen pin still verifies from
`/app/rocket-p0/src` (`Pinned source verified`). `prepare.py --verify-only`
**refuses this candidate** — admission control working. 255 backend non-test
files inside the build context changed, so merging needs an owner-approved
re-pin and a fresh bundle. Not performed.

**RELEASE STATUS: NO-GO.**

---

## New findings — separate owner approval required, nothing changed

**N-1 · Generated artefacts committed, and the retirement ledger is keyed by
the old module path.** Commit `7c2bb3c` includes two machine-generated files:
`backend/tests/reports/phase2_batch2_perf.json` and
`backend/services/uaie/retirement/nivx_engine.investigation.rte.transformations.ps_byte_array_xor_loop.json`.
The second matters beyond hygiene: `retirement_ledger` names each record after
the **legacy module path**, so a test run after the rename minted a second
record for one retired capability. The `v2.*`-keyed original is still there,
and `list_retirement_records()` now returns **both** — an audit-trail
double-count. Options: re-key with a `supersedes` link, or keep the original
as the authoritative record and drop the new one. This is evidence provenance,
so I am not deciding it. *Impact: audit integrity, not a security boundary.*

**N-2 · Unauthenticated internal-document and metrics surface** (§5). 76 GETs,
identical on A3 — discovered by this review, not introduced. Customer data is
fail-closed; architecture documents, Prometheus metrics, detection content and
the full OpenAPI are not. *Impact: IP and reconnaissance exposure.*

**N-3 · Three unauthenticated 500s** (§5). An anonymous request reaches an
unhandled exception. *Impact: low; indicates an unguarded code path.*

**N-4 · `report_writer` has zero test coverage.** 1,661 lines and three live
`POST` routes with no test references. Migrated and import-clean, behaviour
unproven. *Impact: an untested production surface; blocks any claim that the
migration is fully behaviourally verified.*

**N-5 · `test_b4b5_tenant_registry_authority.py` is in no gate**, and 3 of its
tests fail identically on A3 and F1:
`test_edr_admin_plane_no_longer_falls_back_to_default`,
`test_edr_and_xdr_resolve_the_same_authority`,
`test_b6_cross_tenant_human_principal_is_authorized`. Cause: the harness
admin has no tenant grants in the isolated database, so the response is
`ACCESS_DENIED "not authorized for any tenant"` instead of `TENANT_REQUIRED`
— both 403 and fail-closed, so this is a fixture-provisioning gap, and F4's
bootstrap is the supported way to close it. *Impact: tenant-authority
assertions are unverified in CI until the suite is gated.*
