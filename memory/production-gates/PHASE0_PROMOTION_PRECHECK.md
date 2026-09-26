# PHASE 0 PRODUCTION PROMOTION PRECHECK — READ-ONLY

Date: 2026-06 (pod clock 2026-09-26 17:2x UTC)
Mode: **READ-ONLY**. Zero commits, zero pushes, zero deployments, zero production
database writes, zero secret access. `EDR_AUTH_PEPPER` was never read or printed.
Response authority left **FAIL-CLOSED** and untouched.

RESULT: **PHASE 0 PRODUCTION PROMOTION PRECHECK: PASS**
(PASS = the evidence is complete and consistent; it does **not** mean anything was promoted.)

---

## 1 · SOURCE STATE

| Fact | Value | How proven |
|---|---|---|
| Local branch | `feature/rc2-alignment` | `git rev-parse --abbrev-ref HEAD` |
| Local HEAD | `bea8852b` — "PHASE 0 — WINDOWS CANONICAL BRIDGE: PASS" | `git rev-parse HEAD` |
| Git remote configured in pod | **NONE** (`git remote -v` empty) | so remote HEAD is **not queryable from this pod** |
| Remote HEAD (last owner-verified) | `f7a25183` — recorded verified-pushed in §18 of `PRODUCTION_SYNC_BACKEND.md` | prior gate record, not re-verifiable here |
| Working tree | clean except **untracked** `memory/availability_probe.log` | `git status --porcelain` |
| Uncommitted Phase 0 files | **ZERO** — every Phase 0 file is committed in `bea8852b` | `git show --stat bea8852b` |
| Unpushed commits (vs last-known-pushed `f7a25183`) | **4**: `9c1e514d`, `876d6217`, `92ea4f31` (all **docs/PRD only**), `bea8852b` (**the only code commit**) | `git show --name-only` on each |

So: Phase 0 exists in authoritative local source as **one immutable commit**, and the
only code not yet on GitHub is that commit. `SOURCE SYNC = OUT OF SYNC BY 1 CODE COMMIT`
(and 3 documentation commits).

## 2 · EXACT PHASE 0 FILES CHANGED (`bea8852b`, 16 files, +3436 / −20)

Backend (code):
- `backend/edr_plane/windows_eventlog.py` **(NEW, 576 lines)**
- `backend/edr_plane/canonical_bridge.py` (+172)
- `backend/edr_plane/trajectory_window.py` (+24)
- `backend/v2/ingestion/telemetry_bridge.py` (+38)
- `backend/v2/ingestion/canonical.py` (+9)
- `backend/services/edr/telemetry_freshness.py` (+78)
- `backend/detection_content/telemetry/nivxforge_sensor_dsm.py`

Backend (tests):
- `backend/tests/edr/test_phase0_windows_canonical_bridge.py` (NEW)
- `backend/tests/edr/fixtures_windows_eventlog.py` (NEW)
- `backend/tests/edr/phase0_e2e_preview.py` (NEW, manual preview e2e harness)
- `backend/tests/edr/test_p0c_durable_findings.py` (updated)

Console:
- `apps/nivxray-xdr/src/nivxforge/components/TelemetryFreshness.jsx`

Docs:
- `memory/PRD.md`, `memory/production-gates/{P1_TENANT_BOOTSTRAP_PRECHECK,PHASE0_WINDOWS_CANONICAL_BRIDGE,STAGE_A_WINDOWS_PRODUCTION_READINESS}.md`

**No file under `backend/routers/`, `backend/edr_plane/response.py`, enrollment, RBAC,
tenant registry, or auth was touched by Phase 0.**

## 3 · PHASE 0 BACKEND CURRENTLY IN PRODUCTION

Route parity was re-measured and is **deliberately not treated as implementation parity**:

```
prod  https://nivxray.nivxforge.com/api/openapi.json  → 862 paths
prev  <preview>/api/openapi.json                     → 862 paths
only in preview: []      only in prod: []
```

Phase 0 added **zero routes**, so 862/862 tells us **nothing** about Phase 0. It also
cannot be probed via OpenAPI schema: `GET /api/edr/telemetry/freshness` has **no typed
response model**, so `investigability` never appears in either spec (verified absent in
both). And it cannot be probed functionally without an **authenticated telemetry write to
the production database**, which is forbidden in this precheck.

Therefore production Phase 0 state is established by **source lineage**, which is
unambiguous:

- production backend = Publish 100 / build `4e76891`, built from the `f345a705`→`f7a2518`
  era source (recorded in `PRODUCTION_SYNC_BACKEND.md` §17–18);
- Phase 0 commit `bea8852b` was authored **after** that publish and has **never been
  pushed or published**.

| Capability | In production now | In authoritative local source |
|---|---|---|
| `edr_plane/windows_eventlog.py` module | **ABSENT** | PRESENT |
| Sysmon 1 → PROCESS | ABSENT | PRESENT |
| Sysmon 3 → NETWORK | ABSENT | PRESENT |
| Sysmon 11 → FILE | ABSENT | PRESENT |
| Sysmon 12 → REGISTRY | ABSENT | PRESENT |
| Sysmon 13 → REGISTRY | ABSENT | PRESENT |
| Sysmon 22 → DNS | ABSENT | PRESENT |
| Security 4688 → PROCESS | ABSENT | PRESENT |
| Security 4624 → AUTHENTICATION | ABSENT | PRESENT |
| Parse-failure → `DETECTION_NOT_EVALUATED` | ABSENT (silence = console may read "evaluated and clean") | PRESENT (`canonical_bridge.py` L490/712/726) |
| Per-endpoint `investigability` (`RAW_ONLY_NOT_INVESTIGABLE`) | ABSENT | PRESENT |

Consequence, stated plainly: **if a real Windows endpoint were enrolled against production
today, its events would be stored raw and would produce no canonical evidence, no
trajectory, no detection and no finding — and the console would show it as fresh.** That is
exactly the Stage A blocker, still live in production.

## 4 · DB COMPATIBILITY

Analysed the full `bea8852b` backend diff for `db[...]`, `create_index`, `insert_*`,
`update_*` and for `os.environ`/`getenv`:

| Question | Answer | Evidence |
|---|---|---|
| DB migration required | **NO** | CES already carried `process_guid`, `registry_*`, `dns_*`, `sid`, `logon_type`; `canonical_to_ces()` was simply dropping them |
| New collection required | **NO** | writes go to existing `edr_raw_events.derivations`, `v2_shadow_observations`, `edr_finding_evaluations` |
| New index required | **NO** | new read is `_canonical_counts()` → `v2_shadow_observations` match on `connector_id` (+`tenant_id`), already served by existing index `obs_connector_ts {connector_id:1, event.ts:-1}`; also `obs_device_identity_facts` covers tenant+connector |
| Backfill required | **NO** | additive projection only; no rewrite of historical documents. Historic non-canonicalised Windows raw events would stay non-canonical unless replayed (raw bytes are retained, replay is a separate owner decision) |
| Secret change required | **NO** | zero `environ`/`getenv` additions in the diff |
| Env change required | **NO** backend. Console requires the **already-configured** per-project `NIVX_PRODUCT_SCOPE` (`xdr` / `edr`) — unchanged by Phase 0 |
| Production data touched by this precheck | **NONE** — production DB was never connected to; only read-only HTTPS GETs (`/api/health`, `/api/`, `/api/openapi.json`, static console assets) were issued |

## 5 · SECURITY REGRESSION REVIEW

Focused suites re-run locally against the preview DB (read-only w.r.t. production):

| Area | Result |
|---|---|
| AUTH REGRESSION | **NONE** — `test_sec001_002_auth_hardening.py` pass |
| TENANT REGRESSION | **NONE** — `test_phase2_1_tenant_isolation.py`, `test_d14_tenant_authority.py`, `tests/edr/test_cross_tenant.py` pass |
| RBAC REGRESSION | **NONE** — `test_edr_route_tenant_authority.py` pass (1 credential-gated live skip) |
| ENDPOINT AUTH REGRESSION | **NONE** — `tests/edr/test_p0_a2_enrollment.py`, `tests/edr/test_p0prod2_enrollment_hardening.py` pass |
| RESPONSE AUTHORITY | **FAIL-CLOSED, UNCHANGED** — `tests/edr/test_p0a_response_authority.py` pass; `edr_plane/response.py` is **not in the Phase 0 change set** |

Totals for this precheck run: **193 passed, 2 skipped** across the 9 security/isolation
suites, plus **51 passed** for `test_phase0_windows_canonical_bridge.py` +
`test_p0c_durable_findings.py`, plus **29 passed / 1 failed** for
`test_b4b5_tenant_registry_authority.py`.

### Test exceptions (3, matching the Phase 0 commit's 411/414)

1. **FAILED** `tests/test_b4b5_tenant_registry_authority.py::test_edr_and_xdr_resolve_the_same_authority` — see §6.
2. **SKIPPED** `tests/test_edr_route_tenant_authority.py:49` — `TEST_ANALYST_NIVXLIVE_PASSWORD` not supplied; the suite refuses to substitute a default password (P0-PROD-1 policy: no credential value is committed). **Intentional, policy-correct.**
3. **SKIPPED** `tests/test_sec001_002_auth_hardening.py:106` — live admin password differs from `ADMIN_PASSWORD` env var. **Intentional, policy-correct.**

## 6 · FAILING TENANT TEST — ROOT CAUSE (DIAGNOSIS ONLY, NOT FIXED)

Failure: `TypeError: _agent_tenant() missing 1 required keyword-only argument: 'oracle'`

Evidence chain:

- `backend/routers/edr_enrollment.py:67` — `def _agent_tenant(tenant_id: str, *, oracle: str) -> str:`
  The keyword-only `oracle` exists to enforce the **P0-A.2 error-oracle rule**: the agent
  surface is unauthenticated, so registry refusals must collapse into **one generic 401**
  (`ENROLLMENT_TOKEN_INVALID` / `AGENT_CREDENTIAL_INVALID`) to prevent tenant-id
  enumeration via 403-vs-401.
- Signature change introduced in commit **`1b2a2fdd`, 2026-09-26 03:47:38 UTC**
  (`git log -S"oracle: str" -- backend/routers/edr_enrollment.py`).
- The test file was last modified in commit **`0fc9be8a`, 2026-09-18 04:50:54 UTC** —
  **eight days before** the signature changed. Line 242 still calls
  `edr_enrollment._agent_tenant(ten["id"])`.
- **Stale caller inventory** (`grep -rn "_agent_tenant" backend/`): exactly **three**
  callers. `edr_enrollment.py:237` and `:322` both pass `oracle=`. The **only** caller
  missing it is `tests/test_b4b5_tenant_registry_authority.py:242`. There is **no
  production call path** that can reach the failing signature.
- Phase 0 (`bea8852b`) does **not** touch `edr_enrollment.py` or this test file — the
  failure pre-dates Phase 0 and is unrelated to it.

**Read-only proof that the invariant the test asserts is actually TRUE in production code**
(executed with `NIVX_TENANT_ENFORCEMENT=on` against an existing preview tenant, no writes):

```
enforcing: True
edr admin  _tenant()        -> nivx-live
edr agent  _agent_tenant()  -> nivx-live      (oracle="ENROLLMENT_TOKEN_INVALID")
xdr        authoritative()  -> nivx-live      (purpose="xdr.collectors")
unregistered agent tenant   -> EnrollmentError AGENT_CREDENTIAL_INVALID 401
```

EDR admin plane, EDR agent plane and XDR all resolve through the **single**
`services/tenant_registry.authoritative()` (also used by `collector_authz.py:86`,
`xdr_ingest.py:87`, `xdr_rbac.py:860`, `edr_tenancy.py:186/200`). Authority convergence
holds; an unregistered tenant is refused with the generic 401, as designed.

- Can the failing path occur in production? **NO** (no production caller omits `oracle`).
- Is tenant isolation affected? **NO** (proved above; isolation suites pass).
- CLASSIFICATION: **TEST_ONLY_HARNESS_DEBT** (P0-PROD-2-era harness drift: the hardening
  commit updated the function and not this one assertion).
- BLOCKS PROMOTION: **NO**. It is, however, a real gap in *proof coverage* — while that
  line raises `TypeError`, the suite is not actually re-verifying convergence. Recommended
  (separately authorised) one-line harness fix: pass
  `oracle="ENROLLMENT_TOKEN_INVALID"` at line 242. **Not applied.**

## 7 · CONSOLE / FRONTEND DELTA

- CONSOLE BUILD: **PASS** — `yarn build` in `apps/nivxray-xdr` → `✓ built in 4.80s`,
  exit 0, no errors. `dist/` is git-ignored, so the build changed **nothing** in source
  (`git status` still clean apart from the pre-existing untracked probe log).
- CONSOLE RUNTIME VERIFICATION: **STILL NOT DONE** — the Phase 0 chip/statement has never
  been rendered in a browser (preview console is not the Vercel artifact). The build proves
  it compiles and that the strings ship in the chunk; it does not prove presentation.
- CONSOLE DEPLOYMENT REQUIRED: **YES — both projects.** Proven by fetching the live chunks:

| Host | Live chunk | `RAW_ONLY_NOT_INVESTIGABLE` | `investigability` |
|---|---|---|---|
| `edr.nivxforge.com` | `assets/TelemetryFreshness-DntlSql7.js` | **0** | **0** |
| `xdr.nivxforge.com` | `assets/TelemetryFreshness-Bn7VDqn2.js` | **0** | **0** |
| local build | `dist/assets/TelemetryFreshness-ASk59CF2.js` | 1 | 1 |

So today both consoles still render the `[object Object]` path and have no evidence chip.
The two Vercel projects share Root Directory `apps/nivxray-xdr` and differ only by
`NIVX_PRODUCT_SCOPE`, so **both** need a redeploy of the same commit.

## 8 · EXACT PROMOTION SEQUENCE (proposed, nothing executed)

1. **Owner:** "Save to GitHub" — pushes the 4 local commits; the code payload is exactly
   `bea8852b`. Record the resulting remote commit hash.
2. **Verify source:** confirm GitHub HEAD of `feature/rc2-alignment` == `bea8852b`
   (or the platform's auto-commit whose tree contains `backend/edr_plane/windows_eventlog.py`).
3. **Owner:** republish production backend from that immutable commit
   (`NIVX_DEPLOYMENT_ENV=production`, no secret changes, no env changes).
4. **Verify backend (read-only):** route count must stay **862** (Phase 0 adds no routes);
   then the real proof — one **authorised** canonicalisation probe. This requires the
   production tenant to exist, so it happens in step 7.
5. **Owner:** Vercel redeploy **both** console projects from the same commit, **no build
   cache**; then confirm the served `TelemetryFreshness-*.js` chunk contains
   `RAW_ONLY_NOT_INVESTIGABLE` on **both** hosts.
6. **Owner authorises** the two prepared writes: organization (`kind=VENDOR`) then tenant
   (`slug=nivx-machines`, `kind=INTERNAL_VALIDATION`). Issue **once, serially** — the
   registry has **no unique index** and the audit write follows the insert, so verify
   before any retry.
7. **Owner authorises** one enrollment token + one real Windows host (Sysmon config first).
   Acceptance: raw event arrives → canonical evidence exists → endpoint reads
   `INVESTIGABLE`, not `RAW_ONLY_NOT_INVESTIGABLE` → trajectory shows the correct lane per
   event family.
8. Response authority stays **FAIL-CLOSED** throughout (P0-PROD-4 is a separate gate).

Rollback: production republish is additive and needs no data change, so rollback is a
republish of the previous build; consoles roll back by redeploying the previous Vercel
deployment. **No DB rollback exists to be needed.**

## 9 · READINESS VERDICTS

```
READY TO SAVE/PUSH PHASE0:                                  YES
READY TO PROMOTE PHASE0 BACKEND:                            YES (after push + hash verify)
READY TO PROMOTE PHASE0 CONSOLES:                           YES (both projects, no cache)
READY TO CREATE PRODUCTION ORGANIZATION/TENANT AFTER PROMOTION: YES (owner-authorised, serial)

PRODUCTION DB WRITES:            0
PRODUCTION ORGANIZATIONS CREATED:0
PRODUCTION TENANTS CREATED:      0
PRODUCTION TOKENS CREATED:       0
PRODUCTION ENDPOINTS ENROLLED:   0
PRODUCTION RESPONSE ACTIONS:     0
SECRETS READ OR CHANGED:         0 (EDR_AUTH_PEPPER never accessed)
CODE CHANGED IN THIS PRECHECK:   0
```

Two honest caveats carried forward, not buried:
1. **GitHub HEAD could not be verified from this pod** (no git remote). The "remote ==
   `f7a25183`" line is a prior-gate record, not a fresh measurement. Step 2 above exists
   precisely to close that.
2. **Production Phase 0 absence is proven by lineage + console-chunk inspection, not by a
   live backend canonicalisation probe** — such a probe requires a production write, which
   this precheck forbids.
