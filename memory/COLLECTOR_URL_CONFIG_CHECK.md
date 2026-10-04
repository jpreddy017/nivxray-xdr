# READ-ONLY CONFIG CHECK — `VITE_XDR_COLLECTOR_URL`

No code, env var, DNS or deployment changed. Everything below is verified from
the deployment/runtime configuration and the compiled artifact, not inferred.

---

## 1 · COLLECTOR DEPLOYMENT MODEL

**The collector is not a separately deployed service. It is LANDED IN-PROCESS
inside the Emergent backend.**

`backend/routers/xdr_collector_landing.py::attach_collector_landing()` puts
`/app/apps/nivxray-xdr-collector` on `sys.path` and mounts the seven collector
routers into the SAME FastAPI application, under the prefix
`/api/xdr/collector`. That is why the Collector Auth P0 guard could reuse
`routers.xdr_rbac` and `services.tenant_registry` at all — same process, same
identity authority, same tenant registry.

A standalone deployment shape also exists in the repo
(`apps/nivxray-xdr-collector/main.py` + `Dockerfile`, mounted at `/api/xdr`),
but it is **deployed nowhere**, and after Collector Auth P0 its control plane
**fails closed by design** (`COLLECTOR_AUTH_UNAVAILABLE`) because standalone has
no authentication authority, RBAC store or tenant registry.

## 2 · EXACT BASE URL

```
https://nivxray.nivxforge.com/api/xdr/collector
```
Verified live (read-only GETs, no credential):
```
GET /api/xdr/collector/connectors        403 ACCESS_DENIED collectors.read / unauthenticated
GET /api/xdr/collector/collectors        403 ACCESS_DENIED
GET /api/xdr/collector/telemetry-health  403 ACCESS_DENIED
GET /api/xdr/collector/source-types      403 ACCESS_DENIED
```
Externally reachable, and now authenticated — see §6.

## 3 · HTTPS

Valid. HTTP/2 over TLS on `nivxray.nivxforge.com`; no certificate warnings on
any probe.

## 4 · MAY THE VERCEL SPA CALL IT?

Yes.
- CORS: preflight `OPTIONS /api/xdr/collector/connectors` with
  `Origin: https://xdr.nivxforge.com`, `Access-Control-Request-Headers:
  authorization,x-tenant-id` → **200**, `access-control-allow-origin: *`,
  `allow-headers: authorization,x-tenant-id`,
  `allow-methods: DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT`.
- Auth: bearer header, not cookies, so no `allow-credentials`/SameSite problem.
  `collectorApi.js` attaches the existing `nvx_token` session bearer plus
  `X-Tenant-Id`.

## 5 · PREVIEW, PRODUCTION, OR BOTH?

**NEITHER. Do not set `VITE_XDR_COLLECTOR_URL` at all, and do not invent a
value for it.**

That variable exists for ONE purpose (`collectorApi.js` lines 3-9): pointing
the SPA at a *separately deployed standalone* collector — an on-prem syslog
forwarder. It uses the legacy standalone path shape:

```js
COLLECTOR_BASE = CUSTOM_URL ? `${CUSTOM_URL}/api/xdr`               // standalone
                            : `${BACKEND_URL}/api/xdr/collector`    // landed
```

So setting `VITE_XDR_COLLECTOR_URL=https://nivxray.nivxforge.com` would build
`https://nivxray.nivxforge.com/api/xdr/connectors` — **a 404**. It would look
like a fix, deploy clean, and fail at runtime. The landed collector is reached
through the API origin you already have configured
(`XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com`, Production + Preview),
which the build script passes as `REACT_APP_NIVXRAY_API_URL` and
`vite.config.js` exposes as `process.env.REACT_APP_BACKEND_URL`.

## 6 · BONUS FINDING — COLLECTOR AUTH P0 IS LIVE IN PRODUCTION

The four routes above answered **200 anonymously** on build `a55ec13`. On the
current production build they answer `403 ACCESS_DENIED collectors.read /
unauthenticated`. The anonymous collector plane is closed in production. (The
full ten-check verification is still pending your go-ahead.)

## 7 · THE ACTUAL CAUSE OF "COLLECTOR RUNTIME NOT WIRED" — A CODE DEFECT, NOT A MISSING ENV VAR

No environment variable will fix this. Proof from the compiled production
bundle (`apps/nivxray-xdr/dist/assets/index-9wTVcqeo.js`):

```js
var oe={};
const O = typeof process<"u" && oe && "https://greeting-app-5782.preview.emergentagent.com" || "";
const D = O ? `${O.replace(/\/+$/,"")}/api/xdr/collector` : "";
const o = D ? I.create({baseURL:D,timeout:8e3}) : null;
const Ke = !!D;                      // COLLECTOR_CONFIGURED
```

Vite's `define` replaced the exact literal `process.env.REACT_APP_BACKEND_URL`
with the origin string, and replaced `process.env` with `{}` — but
`collectorApi.js` wraps the read in a defensive guard:

```js
const BACKEND_URL =
  (typeof process !== "undefined" && process.env && process.env.REACT_APP_BACKEND_URL) || "";
```

In a browser bundle `process` is undefined, so `typeof process !== "undefined"`
is **false** and the expression short-circuits **before** reaching the injected
origin. `COLLECTOR_BASE` is `""`, `COLLECTOR_CONFIGURED` is `false`, and the UI
honestly reports `COLLECTOR RUNTIME NOT WIRED`.

`lib/api.js` has no such guard (`process.env.REACT_APP_BACKEND_URL || ""`), so
the literal IS replaced — which is exactly why the SPA **authenticates fine**
while the collector panel claims nothing is wired.

Why it worked in my earlier browser verification: the pod serves the SPA via the
Vite **dev** server, where `process` is defined, so the guard passes. A
dev-only success and a production-build failure from the same source — the
divergence hid the defect until this Vercel deploy exposed it.

The same pattern exists one module over (`/api/xdr/vendor/cortex`), which will
be dead in the production bundle for the same reason:
```js
var ie={}; const P = typeof process<"u" && ie && "https://…" || "";
```

### The minimal fix (NOT APPLIED — awaiting your decision)
One line in `apps/nivxray-xdr/src/xdr/admin/collectorApi.js`: read the defined
literal directly, as `lib/api.js` already does, dropping the `typeof process`
guard. Optionally the same one-line change in the vendor/cortex module. Then:
push → Vercel redeploy → re-verify. No backend change, no env var, no republish.

## 8 · STATUS
```
collector model          landed in-process in the Emergent backend
collector base URL       https://nivxray.nivxforge.com/api/xdr/collector
https                    valid
SPA permitted            yes (CORS *, bearer header, no cookies)
VITE_XDR_COLLECTOR_URL   must remain UNSET (setting it to the API origin = 404)
root cause of NOT WIRED  frontend code defect, dev/prod divergence (§7)
changes made             NONE
W1                       HELD
```
