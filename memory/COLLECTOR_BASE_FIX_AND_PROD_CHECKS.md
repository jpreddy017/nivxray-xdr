# COLLECTOR BASE RESOLUTION FIX + PRODUCTION BUILD GUARD
# + SIX ANONYMOUS PRODUCTION CHECKS

Scope kept exactly as authorised: `collectorApi.js` + the production-build
guard. **Cortex/vendor module NOT touched.** `VITE_XDR_COLLECTOR_URL` NOT
added. Emergent backend NOT republished. Vercel NOT promoted. **W1 HELD.**

---

## 1 · THE DIFF (2 files · +59 / −8)

### `apps/nivxray-xdr/src/xdr/admin/collectorApi.js`
```diff
-const BACKEND_URL  =
-  (typeof process !== "undefined"
-    && process.env
-    && process.env.REACT_APP_BACKEND_URL) || "";
+const BACKEND_URL  = process.env.REACT_APP_BACKEND_URL || "";
```
Vite `define` substitutes only the EXACT literal
`process.env.REACT_APP_BACKEND_URL`. With the guard in front, a production
bundle compiled to:
```js
var oe={}; const O = typeof process<"u" && oe && "https://…" || "";   // → ""
```
`process` does not exist in a browser, so the origin was never reached,
`COLLECTOR_CONFIGURED` was `false`, and the UI honestly reported
`COLLECTOR RUNTIME NOT WIRED`. `lib/api.js` has no such guard, which is why
authentication worked while the collector looked undeployed. After the fix:
```js
const se="https://nivxray.nivxforge.com", D=`${se.replace(/\/+$/,"")}/api/xdr/collector`
```

### `apps/nivxray-xdr/scripts/verify-production-build.js` — new check 6
Locates the chunk containing `collector_runtime_not_deployed` and fails the
build unless it (a) exists, (b) builds `/api/xdr/collector`, (c) carries the
expected API origin, and (d) does **not** resolve its base behind a
`typeof process` test. The failure text names the correct fix and explicitly
warns that `VITE_XDR_COLLECTOR_URL` is not it (it appends `/api/xdr` and would
404 against the landed mount).

## 2 · THE GUARD WAS PROVEN, NOT ASSUMED

```
fixed source   → XDR PRODUCTION BUILD GUARD · PASSED
                 ok · landed collector base https://nivxray.nivxforge.com/api/xdr/collector resolves
regression     → XDR PRODUCTION BUILD GUARD · FAILED   (exit 1)
re-introduced    ✗ collector chunk … resolves its base behind a `typeof process` test
                 (source restored immediately afterwards)
```
Also unchanged and still passing: no preview origin, no cross-product host,
API origin present, no unauthorised origin, product scope declared.

## 3 · SIX ANONYMOUS READ-ONLY PRODUCTION CHECKS

`https://nivxray.nivxforge.com` · GET only · no credential · no mutation ·
no collector/key/endpoint created · no telemetry sent.

| # | check | result |
|---|---|---|
| 1 | anonymous HUMAN_CONTROL endpoints refused | `/connectors` `/collectors` `/data-sources` `/outbox` `/outbox/health` → **403 `ACCESS_DENIED collectors.read / unauthenticated`** |
| 2 | previously-anonymous leaks closed | `/telemetry-health`, `/source-types` → **403** (both answered **200** on `a55ec13`) |
| 3 | ladder order · a valid tenant is not a credential | anonymous + real authoritative `ten_e759…` → **403 ACCESS_DENIED**, never a `TENANT_*` answer |
| 4 | no `default` resurrection, unknown tenant | anonymous + `default` and + unknown `ten_…` → **403 ACCESS_DENIED** (refused at AUTHENTICATION, as designed) |
| 5 | machine lane fails closed | unknown `X-XDR-API-Key` → **401 ACCESS_DENIED · principal_kind api_key · unknown-key** |
| 6 | build identity | production OpenAPI vs pod candidate: **795 paths, path-hash IDENTICAL, schema names equal, 0 schema bodies differing, 22 collector operations** |

Undeclared collector path → 404 (never served).

### Honest limits of an anonymous run
`TENANT_REQUIRED` / `TENANT_NOT_FOUND` / `TENANT_NOT_ACTIVE` and the
"no pod hostname in the body" check are now **unreachable without a
credential** — authentication comes first, so the tenant ladder and response
bodies can only be observed by an authorised principal. That is the contract
working, not a gap. They remain in the owner-side authenticated block. The
webhook-HMAC probe is a POST and was therefore **not** run against production
(no anonymous mutation probes); its behaviour is covered by the preview suite.

## 4 · WHAT IS STILL PENDING

```
push to release/xdr-w1-candidate   OWNER ACTION ("Save to Github") — no remote in this pod
vercel PREVIEW verification        after push · Integrations must load tenant-scoped
vercel PRODUCTION promotion        only after your explicit authorisation
emergent republish                 NOT NEEDED (backend unchanged by this fix)
W1                                 HELD
```
