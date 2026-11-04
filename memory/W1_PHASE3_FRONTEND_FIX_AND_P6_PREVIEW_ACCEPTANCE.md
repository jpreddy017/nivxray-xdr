# FRONTEND CONTRACT FIX + STALE-TEST REINTERPRETATION + P6 PREVIEW A–I

Candidate/preview only. **No production republish. No production data mutation.
No W1 collector / API key / telemetry. W1 Phase 3 still paused.**
Production remains `publish 100 / build 8833215`.

---

## 1 · FRONTEND CONTRACT FIX (minimal, existing tenant context, no new UI)

| file | change |
|---|---|
| `apps/nivxray-xdr/src/lib/tenant.js` | **NEW** · `activeTenant()` / `setActiveTenant()` / `TENANT_HEADER` |
| `apps/nivxray-xdr/src/lib/api.js` | axios request interceptor attaches `X-Tenant-Id` once, for every call |
| `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | hardcoded `tenant_id=default` removed |
| `frontend/src/v2/pages/SecurityStateTab.jsx` | `inv?.tenant_id \|\| "default"` fallback removed + 3 guards |

`activeTenant()` resolves **only** from (1) `?tenant=` on the URL — the
parameter the XDR context bar already carries — then (2) `nvx_tenant` in
localStorage, the persisted operator selection. Deliberately absent:

- **no `"default"` fallback.** No selection → `null` → no header → the server
  answers `TENANT_REQUIRED`. That is the honest outcome; inventing a tenant is
  how the old console silently read another tenancy.
- **no hardcoded tenant id.** `ten_e759b7288598bd882e3dcac49d` appears nowhere
  in the frontend. The value only ever comes from the operator's selection.
- **no client-side registry check.** Whether the named tenant exists and is
  ACTIVE stays the server's decision.

The interceptor yields to a call site that already set the header, so the XDR
admin surfaces (`CollectorsBody.jsx`, `ApiKeysBody.jsx`, `collectorApi.js`)
keep their explicit per-surface tenant. `edrApi.js` is **unchanged** — one
interceptor covers all nine EDR console surfaces, so no call site can forget
the header.

`SecurityStateTab` now reports `NO_TENANT_CONTEXT` instead of querying, and
both mutating handlers (`evaluate`, `interventions/stage`) refuse without a
tenant.

**Build: `yarn build` on `apps/nivxray-xdr` → exit 0, clean.**

**Honest limit on UI validation:** the XDR/EDR SPA is Vercel-hosted, not served
by this preview (preview root serves the Workspace CRA). I therefore could NOT
drive the EDR console in a browser here. Evidence is: production-mode build
passes, and the Workspace CRA still renders (screenshot, `NivXRay XDR` login).
Browser-level EDR console validation needs a Vercel preview deploy — **not
authorized, not performed.**

**Still reported, not fixed (outside the authorized two files):**
`apps/nivxray-xdr/src/xdr/admin/collectorApi.js:77,85` — `tenantId = "default"`
as a *function* default. It is the XDR collector plane, and the interceptor
does not override an explicitly-passed header, so it remains a silent
fallback. Needs its own decision.

## 2 · STALE TESTS RE-POINTED (cross-tenant for unattributed; explicit tenant stays attributed-only)

Exactly as you directed. **The 7 legacy hosts were NOT given artificial
owners.** Verified against the substrate first: `WKS-01`, `FILE-SRV-01`,
`SRV-DC01`, `FIN-07`, `ENG-42`, `HR-11`, `WKS-07` are all
`UNATTRIBUTED_LEGACY_OBSERVATION` with `tenant_id = None`.

- **NEW** `test_legacy_corpus_still_exists_unowned_on_the_cross_tenant_path` —
  all 7 present on the cross-tenant projection, each asserted
  `UNATTRIBUTED_LEGACY_OBSERVATION`, `tenant_id is None`, authoritative
  identity, non-zero observations. Evidence narrowed, never destroyed.
- `test_endpoints_returns_seven_authoritative` — now asserts the inverse:
  under an explicit tenant **none** of the 7 may appear, and every returned
  row is `ATTRIBUTED*` with `tenant_id == <named tenant>`.
- `test_device_trajectory_by_iid`, `test_hostname_case_insensitive` ×3,
  `test_window_semantics_empty_but_identified`,
  `test_evidence_provenance_on_events` — tenant-scoped read asserted to fail
  closed; identity resolution, the 45-event count, the window dating and the
  `evidence_ref` provenance shape asserted on the cross-tenant projection.
- `test_iter107…test_evidence_outside_window` — `dev_a0267ae20737` is ENG-42;
  HTTP asserted unresolved, `EVIDENCE_OUTSIDE_WINDOW` asserted on the
  cross-tenant projection.
- `test_p0_f13_5…test_unresolvable_endpoint_fails_closed` — synthetic
  principal `a@b.c` (no `users` record) replaced with `admin@nivxray.com`, the
  same real principal every sibling test in that file uses. Assertion
  unchanged.
- `test_iteration_82…test_regression_detections_and_process_tree` — took the
  first row of a **cross-tenant** incident list and then read it under one
  tenant, so P3 correctly answered 404. Now picks an incident actually owned by
  the tenant in use, and skips honestly if the corpus has none.

**A consequence you should know about:** there is currently **no HTTP route
that returns unattributed legacy evidence**. Your R2 approval deferred the
separately-named unattributed view to a separate change, so today that evidence
is reachable only at the service layer — which is why these assertions moved
there rather than to another endpoint. Flagged for the deferred R2 item.

## 3 · HERMETIC `b4b5` FIX

`test_b3_ingest_actor_is_never_the_client_claim` now takes the **existing**
`relaxed` fixture. It asserts ACTOR authenticity, not tenancy, and drives the
deliberately-unregistered `ten_x`; its result previously depended on whether
the ambient `.env` had `NIVX_TENANT_REGISTRY_ENFORCE` set. **The assertion
itself is unchanged.** `tests/test_b4b5_tenant_registry_authority.py` →
**30 passed / 0 failed** (was 29/1).

## 4 · REGRESSION

| suite | baseline | now |
|---|---|---|
| `tests/test_edr_route_tenant_authority.py` (R4 gate) | — | **152 passed / 0 failed** |
| `tests/edr/` (30 files) | 23 failed | **22 failed · ZERO new, one baseline failure now passes** |
| tenant·RBAC·audit·response·isolation (14 files) | 48 failed+errors | **48 — identical list, 0 regression** |
| `test_b4b5_tenant_registry_authority.py` | 29/1 | **30/0** |

`comm` against the sorted baseline is empty in both directions for the core
set, and empty in the NEW direction for `tests/edr`.

## 5 · P6 · PREVIEW A–I UNDER ENFORCEMENT — ALL PASS

`enforcing = True`, 5 registered tenants (1 ARCHIVED, 4 ACTIVE, all with an
`organization_id`). Tenant used: `default` (LEGACY_ADOPTED · ACTIVE ·
`org_529e0c37d097e270d0647e101f`).

| gate | result |
|---|---|
| **A** registry authority | **PASS** · `enforcing=True`, count 5 |
| **B** tenant resolves | **PASS** · `default` ACTIVE, org present |
| **C** explicit scope | **PASS** · collectors 200, api-keys 200 |
| **D** unknown tenant | **PASS** · 403 `TENANT_NOT_FOUND` |
| **E** missing tenant | **PASS** · 403 `TENANT_REQUIRED` |
| **F** security-state | **PASS** · valid 200 + tenant echoed; unknown 403 `TENANT_NOT_FOUND` |
| **G** no implicit tenancy | **PASS** · POST collector refused `TENANT_NOT_FOUND`; tenant count **5 → 5** |
| **H** EDR control plane | **PASS** · `/edr/endpoints` 200 scoped / 403 `TENANT_REQUIRED` unscoped; `/edr/enrollment/endpoints` 403 `TENANT_REQUIRED`; `/edr/response/isolation-policy` 403 `TENANT_REQUIRED` |
| **I** actor authenticity | **PASS** · 25 rows, `X-Principal-Id: attacker@evil.test` produced **0** spoofed rows (`principals = ['system@boot']`) |

**Gate H — the production blocker — is PASS on the candidate, including the
response/write plane that was silently keyed to `"default"`.**
Zero persistent objects created: G was refused, and the R4 gate never drives a
POST/PUT with a valid tenant.

## 6 · STATUS
```
P0-P5 backend security fix        DONE (previous step)
frontend contract fix             DONE (build clean; browser validation blocked - Vercel)
stale-test reinterpretation       DONE (9 tests; no host artificially owned)
hermetic b4b5 fix                 DONE (30/0)
regression                        DONE (0 new failures anywhere)
P6 preview A-I under enforcement  ALL PASS
--- STOP · OWNER REVIEW ---
production republish              NOT ATTEMPTED
production A-I                    NOT ATTEMPTED
W1 5-event integration            STILL PAUSED
```
