# P0 — Collector stuck in STARTING (2026-06)

## Root cause
`start_collector()` in `backend/routers/xdr_collectors.py` **only persisted a
requested state**. It called `_admin_transition(..., target="STARTING",
reason="start requested")` and returned. There was **no runtime dispatch of
any kind** — nothing was ever asked to bind a listener, so nothing could ever
move the state on. `STARTING` was a dead end by construction.

The deeper truth behind it: the NivXRay API core is a FastAPI app behind a
Kubernetes HTTPS ingress. **It cannot bind UDP/TCP 514.** A `syslog` transport
is terminated by the *separate* `apps/nivxray-xdr-collector` runtime, which is
**not deployed anywhere today**. So there was no runtime to dispatch to even in
principle, and the UI truthfully reported "start requested" forever.

### Reassurance that matters
The stuck state was **never blocking ingestion**. `xdr_ingest` writes collector
state directly (lines 599-606) and does not go through
`_ALLOWED_TRANSITIONS`, so real telemetry moves any prior state straight to
`CONNECTED`. The approved plan — the auditd forwarder posting to
`POST /api/xdr/ingest/telemetry` — **never needed the collector to "start"**.
`protocol: syslog` is metadata describing the source, not a listener the core
owns.

## Files changed — 1
`backend/routers/xdr_collectors.py` (+`urllib`/`json` imports, new
`_runtime_start()`, `start_collector()` now dispatches). No frontend change,
no state-machine change, no auth/RBAC change, no other product.

## Old → new behaviour
| | Old | New |
|---|---|---|
| Start action | writes `STARTING` / "start requested", returns | resolves `XDR_COLLECTOR_RUNTIME_URL`, POSTs `/collectors/{id}/start`, records the real outcome |
| No runtime configured | **stuck at STARTING forever** | `CONNECTION_FAILED` naming the cause and the remedy |
| Runtime unreachable | stuck at STARTING | `CONNECTION_FAILED` with the transport error |
| Runtime accepts but reports no listener | stuck at STARTING | `CONNECTION_FAILED` — an accepted start is not proof of a bound listener |
| Runtime listening | stuck at STARTING | `STARTING` · "runtime listening on `<bind>` · awaiting telemetry" — a truthful pre-connected state |
| CONNECTED | ingest-only | **unchanged** — ingest-only, evidence-gated |

`CONNECTED` was **not** touched. It still requires
`received > 0 AND parsed > 0 AND normalized > 0` and is still written only by
the ingest path. No admin action can promote to it.

## Acceptance proof (preview, throwaway tenant, all artifacts deleted)
```
collector col_cff8… protocol syslog
BEFORE                     state ADOPTED        reason "created"
START (no runtime)         state CONNECTION_FAILED
  reason: no collector runtime configured (XDR_COLLECTOR_RUNTIME_URL unset) —
          the API core cannot terminate a listening transport; deploy
          apps/nivxray-xdr-collector. HTTP ingest via
          POST /api/xdr/ingest/telemetry does not require this.
START (runtime unreachable, unit-level)  started=False
  reason: runtime unreachable at http://127.0.0.1:9/dead/collectors/col_x/start:
          URLError: [Errno 111] Connection refused

ONE real auditd event through the REAL ingest path:
  duplicates 0 · reasoned 1 · observations_created 1
  collector_state CONNECTED
  collector_state_reason "telemetry received/parsed/normalized: 1/1/1"
AFTER                      state CONNECTED
  rx/parsed/norm/err        1 / 1 / 1 / 0
  last_event_at             2026-09-10T13:21:14Z
```
So: no longer stuck, the failure is truthful and actionable, and `CONNECTED`
still arrives **only** from real telemetry.

Tenant isolation and audit history preserved — every transition still goes
through `_admin_transition`, which emits `COLLECTOR_STATE_CHANGED`; the failure
path adds `COLLECTOR_START_FAILED`.

## What the owner should expect in production
Pressing **Start** on `linux-audit-syslog-prod-1` will now return
`CONNECTION_FAILED` with the "no collector runtime configured" reason. **That
is correct and is not a regression** — it is the honest replacement for an
indefinite `STARTING`. Two valid ways forward:

1. **Approved plan, no Start needed** — point the auditd forwarder at
   `POST /api/xdr/ingest/telemetry`. The collector goes straight to
   `CONNECTED` on the first real event, exactly as proven above.
2. **Later** — deploy `apps/nivxray-xdr-collector` and set
   `XDR_COLLECTOR_RUNTIME_URL`; Start will then bind a real syslog listener.

**Not deployed.** This change is in the workspace only; production still runs
the previous backend until the owner approves a deploy.

---

## Refresh button — reproduced, and it was NOT broken (2026-06)

Instrumented the real page and counted network calls on click:

```
collector calls on initial load ......... 4
Refresh buttons found ................... 1  (visible=True enabled=True)
collector calls AFTER clicking Refresh .. 6   delta = +2
  → /api/xdr/collectors
  → /api/xdr/collectors/protocols/catalog
```

The button fires both requests correctly. It *read* as dead for two reasons:
1. **No acknowledgement** — `busy` was tracked but nothing rendered, and a
   refresh returning identical data is pixel-identical.
2. The value being re-fetched was `STARTING`, which — per the defect above —
   could never change, so Refresh legitimately changed nothing.

### Fix (1 file, `apps/nivxray-xdr/src/xdr/admin/CollectorsBody.jsx`)
- button shows `Refreshing…` and is `disabled` while in flight;
- new `loadedAt` stamp rendered as `refreshed HH:MM:SSZ`
  (`data-testid="col-last-refreshed"`), set on every completed load.

Verified in a real browser: `refreshed 13:26:42Z` → click →
`refreshed 13:26:47Z`. A no-op refresh is now evidently a refresh.

---

## BLOCKER FOUND for the next step — collector/key tenant mismatch

`xdr_ingest` enforces cross-tenant isolation (lines 406-415): every envelope's
`tenant_id` **must equal the collector's `tenant_id` on disk**, else 404 /
mismatch.

`CollectorsBody.jsx` sends **no `X-Tenant-Id`** on `api.get("/xdr/collectors")`
or `api.post("/xdr/collectors", …)` — the same defect class as the API-keys
surface. So `linux-audit-syslog-prod-1`, created through the production UI, is
bound to tenant **`default`**, while the minted ingest key is bound to
**`nivx-prod-1`**.

**Consequence:** the auditd forwarder would be rejected outright. This must be
resolved before any host work. Options for the owner:
1. Apply the same 3-line tenant-context pattern to `CollectorsBody.jsx`, then
   create the collector under `nivx-prod-1` (recommended — consistent, and
   fixes listing/start/stop/enable for every non-default tenant);
2. or mint the ingest key under tenant `default` to match the existing
   collector (works, but abandons the dedicated proof tenant).

NOT changed without approval — reporting only.

---

## QUICK-FIX DELIVERED — collector tenant context (2026-06) · NOT DEPLOYED

Scope honoured: the cosmetic refresh-feedback change was **reverted** (verified
`loadedAt` / `col-last-refreshed` absent). Only the correctness fix remains.
Backend Start fix **deferred**, not deployed. No EDR / NivXMachines /
Workspace / DNS / auth / unrelated backend change.

### Files changed — 2 (one ships, one is test-only)
| File | Ships to production? |
|---|---|
| `apps/nivxray-xdr/src/xdr/admin/CollectorsBody.jsx` | **YES** |
| `apps/nivxray-xdr/tests/adoption/test_api_keys_tenant_header.mjs` | no — test, not bundled |

`CollectorsBody.jsx`: surface-level `tenant` state + `hdrs()`; `X-Tenant-Id`
now sent on list, protocols catalog, create, start, stop, test,
enable/disable and delete; load effect re-runs on `[refresh, tenant]`; TENANT
field (`col-tenant-context`) in the hero; tenant passed to the create modal.

### Targeted tests
Regression guard extended to **both** surfaces — `11` call sites all PASS,
plus structural assertions for the enable/disable toggle (its URL embeds a
nested quote so the regex cannot reach it) and the protocols catalog read.
A real defect in the guard itself was found and fixed: the greedy `[^;]*`
window was swallowing later call sites (11 sites reported as 9), which could
have masked a missing header. Now a bounded 140-char window.

### Production frontend build
`NIVX_PRODUCT_SCOPE=xdr` guarded build → `XDR PRODUCTION BUILD GUARD · PASSED`
· API origin `https://nivxray.nivxforge.com` (4 refs) · no unauthorised origin
· scope `xdr`.

### Browser proof — every request carries the tenant header
```
GET  tenant='default'             /xdr/collectors
GET  tenant='default'             /xdr/collectors/protocols/catalog
GET  tenant='verify-tenant-9042'  /xdr/collectors
GET  tenant='verify-tenant-9042'  /xdr/collectors/protocols/catalog
POST tenant='verify-tenant-9042'  /xdr/collectors
GET  tenant='verify-tenant-9042'  /xdr/collectors      (post-create reload)
GET  tenant='verify-tenant-9042'  /xdr/collectors/protocols/catalog
requests missing the header: NONE
collector visible immediately after create: True
```

### Cross-tenant isolation + preserved behaviour (temporary objects, deleted)
```
collectors under verify-tenant-9042 .. 1  [('verify-temp-auditd','verify-tenant-9042')]
same collector visible under default . False
api key under verify-tenant-9042 ..... 1  [('verify-temp-key','verify-tenant-9042')]
same key visible under default ....... False
rotate ... new prefix nvx_d50a5250, plaintext reissued True
revoke ... {'revoked': True}
delete ... 200
cleanup .. key 200, collector 200, remaining in temp tenant: 0
```

### Delivery — ONE file to paste
| | Value |
|---|---|
| Branch | `conflict_310826_2116` (remote HEAD `957b567969d96833021a7a3f812fcc74c964093a`) |
| `ApiKeysBody.jsx` | already at `cdef74d1…d132c3` — **owner already committed it, nothing to do** |
| File to change | `apps/nivxray-xdr/src/xdr/admin/CollectorsBody.jsx` |
| Current remote hash | `1c3ae75aac2bba6e0d9b675647ed33f4ffc2404b29695255bf9b587da869df0b` |
| Replacement | `memory/xdr_frontend_patch/CollectorsBody.jsx.final` |
| **Expected new hash** | **`81ab07f059f0474fca982b0c66d1b2c5798a77066082755f8ddfd5d7d120f0fa`** |
| Size / lines | 19,730 bytes · 458 lines |
| Rollback | revert the single commit, or promote the previous Vercel deployment |

### After it is live — the owner's sequence
1. Collectors page → set `TENANT` to `nivx-prod-1` → the `default`-bound
   `linux-audit-syslog-prod-1` will NOT appear (correct) → create the collector
   under `nivx-prod-1`; optionally delete the stray one from the `default` view.
2. API Keys page → `TENANT` `nivx-prod-1` → revoke the exposed key, mint the
   replacement.
3. Both must then show the same tenant. STOP before auditd enrolment.
