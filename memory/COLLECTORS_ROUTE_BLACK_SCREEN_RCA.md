# COLLECTORS ROUTE BLACK SCREEN — ROOT CAUSE + MINIMAL FIX

Preview base commit `f3fea7c4`. One file changed (+44 / −10). Backend, tenant
authority, collector authentication, env vars and Vercel settings untouched.
No production promotion. **W1 HELD.**

---

## 1 · REPRODUCED WITH THE EXCEPTION (not guessed)

Dev/preview renders the page fine, so the defect had to be reproduced in a
PRODUCTION-MODE bundle. Built `dist` with `yarn build`, served it locally with
SPA fallback, logged in, opened `/xdr/admin/collectors`, then reproduced the
production condition — a tenant that is not in the registry:

```
before:                body text length 5453   (renders)
after unknown tenant:  body text length 0      (black screen)

PAGEERROR: Minified React error #31
  args[]=object with keys {code, reason, tenant_id}
  at vl (assets/index-DVYz7P_f.js:31:6290) → P → we → Nd
console.error: Failed to load resource: the server responded with a status of 403
```
React #31 = *"Objects are not valid as a React child."* The throw happens during
render, nothing catches it, React unmounts the tree → black page, exactly as
seen on both Vercel Preview URLs.

## 2 · ROOT CAUSE — TWO LINES, ONE CHAIN

`apps/nivxray-xdr/src/xdr/admin/CollectorsBody.jsx`

```js
const [tenant, setTenant] = useState("default");            // line 54 (was)
…
setErr(e?.response?.data?.detail || e?.message || "load failed");   // line 69 (was)
…
{err && <div data-testid="col-error" …>{err}</div>}          // line 144 — renders the object
```

1. The surface hardcoded the tenant `"default"`.
2. The production registry has **no** `default` tenant (that model was
   eliminated), so `GET /xdr/collectors` answers
   `403 {code:"TENANT_NOT_FOUND", reason:…, tenant_id:"default"}`.
3. That **object** went into `err` and was rendered as a React child.
4. React #31 → unhandled → whole route unmounts → black screen.

Why the other routes are fine: `/xdr/admin/integrations` got its structured
refusal formatted during the Collector Auth P0 addendum, and
`/xdr/admin/ingest-routing` takes its scope from the verified session rather
than a tenant header, so neither ever renders a refusal object.

Why preview looked healthy: the preview registry still carries a legacy
`default` entry, so the request succeeded and the crash path was never taken.
The Vercel Previews call the PRODUCTION API, where `default` does not exist —
hence "deterministic on both Preview URLs", exactly as you observed.

## 3 · THE FIX (smallest that removes the crash and the cause)

```diff
-  const [tenant, setTenant] = useState("default");
-  const hdrs = () => ({ headers: { "X-Tenant-Id": tenant } });
+  const [tenant, setTenant] = useState(() => activeTenant() || "");
+  // No tenant selected ⇒ send no header ⇒ backend answers TENANT_REQUIRED.
+  const hdrs = () => (tenant ? { headers: { "X-Tenant-Id": tenant } } : {});
…
-      setErr(e?.response?.data?.detail || e?.message || "load failed");
+      setRows([]);
+      setErr(refusalText(e));
```
plus a local `refusalText()` (structured refusal → `CODE — reason` + a one-line
remedy) and the tenant input now writing through the existing
`setActiveTenant` contract, with placeholder `authoritative tenant` instead of
`default`.

Not done, deliberately: no Collectors redesign, no tenant-authority change, no
weakening of fail-closed behaviour, no hardcoded/default tenant introduced (one
was REMOVED), no collector-authentication change, no backend change, no error
boundary, no shared refactor.

## 4 · PROOF (production-mode bundle, browser, zero page errors)

| case | result |
|---|---|
| **no tenant selected** | page RENDERS · `TENANT_REQUIRED — no tenant named for xdr.collectors: the authoritative tenant must be presented explicitly; there is no default tenant · Name the authoritative tenant above` |
| **unknown tenant** (the exact crash trigger) | page RENDERS · `TENANT_NOT_FOUND — tenant is not registered (xdr.collectors)…` |
| **registered ACTIVE tenant** via the existing contract | loads · `col-error` count 0 · hero + roster render |
| `/xdr/admin/integrations` | still renders · tenant selector populated from the registry |
| page errors across all four | **0** |

Build + guard:
```
yarn build                        exit 0
bash scripts/vercel-build.sh      XDR PRODUCTION BUILD GUARD · PASSED
  ok · no preview origin · no cross-product host · API origin present
  ok · no unauthorised origin · product scope declared
  ok · landed collector base https://nivxray.nivxforge.com/api/xdr/collector resolves
```

## 5 · THE SAME DEFECT CLASS ELSEWHERE — REPORTED, NOT TOUCHED

`/xdr/admin/api-keys` is the next route that will black-screen in production
for the identical reason:
```
ApiKeysBody.jsx:212   const [tenant, setTenant] = useState("default");
ApiKeysBody.jsx:231   err: e?.response?.data?.detail?.reason || e?.response?.data?.detail   // object fallback
```
Additionally these render `{err}` where the value can be a structured object:
`ClosedLoopPanel`, `ContentPackLolbasBody`, `CorrelationRulesBody`,
`DataSourcesBody`, `DetectionRegistryBody`, `SecretsBody`, `UsersRolesBody`.
Whether each can actually reach the object path depends on whether its endpoint
returns a structured refusal; the tenant-scoped ones are the exposed set.

**Left untouched — outside the authorised scope.** Awaiting your call on
whether to close `ApiKeysBody` (same two-line pattern) before or after W1.

## 6 · STATUS
```
files changed          1 (CollectorsBody.jsx · +44/−10)
base commit            f3fea7c4
push to release/…      OWNER ACTION ("Save to Github") — no git remote in this pod
vercel PREVIEW         re-verify /xdr/admin/collectors after push
vercel PRODUCTION      blocked pending your authorisation
emergent backend       untouched · no republish
W1                     HELD
```
