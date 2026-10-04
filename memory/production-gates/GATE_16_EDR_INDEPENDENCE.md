# GATE 16 · NivXForge EDR INDEPENDENCE — **IN_PROGRESS** (gate live, waves remaining)

Owner architecture lock: NivXForge EDR must be a complete, independently
operable product (`edr.nivxray.com`); NivXRay XDR is a separate product
(`xdr.nivxray.com`). `/edr/*` inside the current SPA is a development
convenience and must not become permanent product coupling. **No
ordinary EDR workflow may require `/xdr/*`.**

## Audit of the current `/edr/*` implementation

Every `/xdr` reference inside `apps/nivxray-xdr/src/nivxforge/`,
classified:

| # | Site | Kind | Class | Action |
|---|------|------|-------|--------|
| 1 | `pages/EdrDetectionsPage.jsx` → `Link to="/xdr/edr/device-trajectory?device=…"` | navigation | **ILLEGAL_EDR_TO_XDR_DEPENDENCY** | **FIXED** → `/edr/device-trajectory?…` (same identifiers, EDR-native route) |
| 2 | `NivXForgeConsole.jsx` "Return to Incident" → `/xdr/incidents/{id}` | navigation | EXPLICIT_XDR_INTEGRATION | relabelled **"Return to NivXRay XDR incident ↗"** — the analyst now sees it leaves the product |
| 3 | `NivXForgeConsole.jsx` `nvf-open-in-xdr` | navigation | EXPLICIT_XDR_INTEGRATION | relabelled **"Investigate in NivXRay XDR ↗"**; already resolved through `productOrigins` so it becomes a cross-origin URL the moment XDR has its own hostname |
| 4 | `components/LinkedXdrIncidents.jsx` → `Link to={r.href}` | navigation | EXPLICIT_XDR_INTEGRATION | server-provided href, rendered under a "Linked XDR incidents" heading |
| 5 | `NivXForgeConsole.jsx` imports `@/xdr/components/XdrContextBar` | component | SHARED_COMPONENT_SAFE | the bar only renders cross-product CONTEXT when the analyst arrived from XDR |
| 6 | `@/xdr/nx/apiError`, `@/xdr/lib/pivots` (6 files) | library | SHARED_COMPONENT_SAFE | shared library ≠ product coupling (owner's rule). Should move to a neutral `shared/` path in a later wave |
| 7 | `api.get("/xdr/tenants")` (CustomerPicker) | backend | SHARED_BACKEND_SAFE | tenancy is established ONLY by the platform registry; EDR reads it, never creates it |
| 8 | `api.get("/xdr/respond/*")` (Response page: actions, health, pending approvals) | backend | SHARED_BACKEND_SAFE **with a product gap** | the response ORCHESTRATION plane is XDR-side today. The UI is EDR-native, but per the owner's boundary the endpoint response authority belongs to NivXForge — recorded as a Gate 14/16 follow-up, not silently accepted |
| 9 | `api.get("/xdr/rbac/session-context")` | backend | SHARED_BACKEND_SAFE | shared authentication/authorisation infrastructure is explicitly allowed |
| 10 | `App.jsx` route `/xdr/edr/device-trajectory` → `EdrTrajectoryRedirect` | route | EDR_NATIVE (legacy inbound) | a redirect INTO the EDR product; keep until the hostname split |

Nothing else in the EDR bundle navigates to XDR, and the EDR bundle
imports **no** XDR page or route component.

## The gate (live now)

`backend/tests/edr/test_gate16_edr_independence.py` — **5 passed**. It is
static, so it fails in CI the moment someone writes `to="/xdr/…"` inside
`src/nivxforge/`, not only when a control is clicked:

1. `test_no_undeclared_edr_to_xdr_navigation` — every `to=` / `navigate()`
   / `href=` / `location.assign` / `productHref("xdr", …)` targeting
   `/xdr` inside the EDR bundle must sit within a declared pivot in
   `ALLOWED_XDR_PIVOTS`. Anything else is an
   `ILLEGAL_EDR_TO_XDR_DEPENDENCY`.
2. `test_every_sanctioned_pivot_is_visibly_labelled` — a sanctioned pivot
   must still carry its visible label **including `↗`**, so "explicit"
   cannot decay into "silent".
3. `test_the_edr_bundle_imports_no_xdr_page_or_route_component` — XDR
   `lib`/`nx`/`components`/`hooks`/`util` may be shared; a page or route
   may not.
4. `test_every_edr_navigation_item_resolves_to_an_edr_route` — the
   product's own navigation may only address `/edr/*`.
5. `test_the_edr_product_has_its_own_login_and_entry_route` —
   independence starts at the door: `/edr/login` and `/edr` exist.

## Not yet done (this gate is NOT claimed)

* **The acceptance test the owner defined** — build/host NivXForge at its
  own origin with the XDR frontend unmounted and walk Login → Dashboard →
  Computers → Device → Events → Detections → Trajectory → Command
  Intelligence → Files/Processes → Hunt → Live Query → Policies →
  Exclusions → Response → Downloads → Audit. That cannot pass today, and
  not because of coupling: **Events, Files, Network, Hunt, Live Query,
  Forensics, Policies, Exclusions, Outbreak Control and Audit do not
  exist yet** (they are declared `NOT_IMPLEMENTED` in the EDR's own
  navigation). Independence and completeness are separate gates; this one
  cannot close before those surfaces exist.
* A build-time guard (ESLint rule / bundler resolver) in addition to the
  test, so the violation is impossible rather than merely caught.
* Moving the genuinely shared libraries out of `src/xdr/` into a neutral
  `src/shared/` so the EDR bundle has no `@/xdr` import path at all.
* Endpoint response authority moving from `/api/xdr/respond/*` to an
  EDR-owned, approval-gated response gateway (serialised work — it is a
  security authority).
