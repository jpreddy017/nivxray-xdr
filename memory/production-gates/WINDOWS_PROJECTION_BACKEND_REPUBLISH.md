# BACKEND REPUBLISH — PRE-PUBLISH SAFETY GATE + ACCEPTANCE PLAN

Owner approval received (backend only). Mode so far: **READ-ONLY**. The
publish itself has **not** happened — see §3, it is an owner-only click.

## 1 · Change set being promoted

Accepted commits, in order: `86e02057` (projection) → `d03d8523` (CI gate) →
`3aadd519` (CI/test hermeticity). CI green on both push and pull_request at
HEAD `8c53c002`.

**Production-affecting code in this promotion is only `86e02057`:**

| File | Change |
|---|---|
| `backend/edr_plane/windows_eventlog.py` | +237 — `envelope_activity`, `flat_view`, `activity_projection_expr`, `activity_query_clauses`, all generated FROM the existing `SUPPORTED` table |
| `backend/routers/edr_events.py` | +48/−… — `_row` stamps the class from canonical evidence; facet aggregation and the `activity=` filter understand the Windows dialect |
| `backend/routers/edr.py` | +11 — endpoint detections / commands read the canonical class |
| `backend/edr_plane/response.py` | +15 — kill-target resolution resolves the class so a refusal is an honest identity/authority refusal; **the authority gate itself is unchanged and Windows process targeting stays unavailable by design** |

`d03d8523` and `3aadd519` touch only `.github/workflows/` and
`backend/tests/` — they cannot execute in production.

## 2 · Safety gate (re-verified now)

| Gate | Result |
|---|---|
| Frontend files touched | **NONE** (`git diff --name-only 86e02057^ 3aadd519 -- frontend/` empty) |
| `.env` / `requirements.txt` touched | **NONE** |
| New `os.environ` / `getenv` reads in production code | **NONE** (the two hits are in `tests/edr/*`) |
| DB write / index / collection / migration / backfill | **NONE** in production code (the `drop_database` / `insert_many` hits are the new test's own fixture) |
| Schema change | **NONE** — read-side projection only; `edr_raw_events` and `v2_shadow_observations` untouched |
| Collection policy / event coverage | **UNCHANGED** — `SUPPORTED` still exactly the eight authorised families: sysmon 1/3/11/12/13/22, winsec 4688/4624 |
| Response authority | **FAIL-CLOSED, UNCHANGED** — `test_p0a_response_authority.py` green in CI |
| Tenant isolation | **UNCHANGED** — `_scoped()` → `edr_scope()` untouched; CI covers cross-tenant cases |
| Module import | **PASS** — `from edr_plane import windows_eventlog` OK; `projection_class("AUTHENTICATION") == "AUTH"` |
| Preview backend on this code | **PASS** — supervisor RUNNING, `/api/health` → `{"status":"ok","service":"nivxray-api"}` |
| Endpoint sensor | **UNTOUCHED** — no file under `agents/nivxforge-windows/` in the change set |

## 3 · Production BEFORE baseline (captured read-only, pre-publish)

```
GET https://nivxray.nivxforge.com/api/health        → {"status":"ok","service":"nivxray-api"}
GET https://nivxray.nivxforge.com/api/openapi.json  → 862 paths, sha256 8c04168feebf43f0
```
Identical to the Phase 0 Stage 2 baseline, i.e. production is still running
the pre-projection build.

## 4 · Why the agent cannot press publish

Platform fact, already recorded in `PHASE0_STAGE2_BACKEND_REPUBLISH.md` §3:
**republish is strictly an owner action in the Emergent UI; the agent has no
access to the production deployment pod and cannot trigger it.** Emergent also
rebuilds the whole application rather than backend-only — acceptable here
because the change set touches **no** file under `frontend/`, so the
co-deployed frontend is a byte-level no-op, and the two Vercel consoles are
separate projects already green on this SHA.

## 5 · Acceptance plan after the click (read-only)

Run `memory/production-gates/prod_projection_verify.sh` with a console bearer
token. It prints PASS/FAIL for:

1. build identity vs the §3 baseline (openapi sha must change only if routes
   changed; health must stay ok)
2. activity facets — `PROCESS > 0` and `AUTH > 0`, and `AUTHENTICATION` must
   NOT appear unprojected
3. `activity=PROCESS` and `activity=AUTH` filters — every returned row stamped
   with that class and carrying a `canonical_event_id`
4. per-record mapping — sysmon 1 → PROCESS, winsec 4624 → AUTH (plus 3/11/12/
   13/22/4688 where present)
5. unsupported families (5379, 4798, 4648, 4672 …) — `activity: null` with a
   truthful `activity_basis`; a falsely classified gap is a FAIL
6. tenant isolation — a foreign `X-Tenant-Id` must never return an `events` key
7. Device Trajectory — `trajectory/focus` resolves the PROCESS raw id to a real
   observation with provenance, and the trajectory window returns genuine
   process evidence

The defect is CLOSED only when 2-7 all pass. Deployment success alone is not
acceptance.
