# FULL NIVXRAY XDR SPA ROUTE-HEALTH SCAN + SHARED REFUSAL CORRECTION

Base commit `f3fea7c4`. 30 files changed (+102 / −116), **2 new**.
Backend untouched · no republish · no Vercel promotion · no env-var change ·
no tenant/RBAC/authentication weakening · **W1 HELD**.

---

## 1 · ROOT CAUSE (one cause, many files — not a shared component)

Reproduced in a PRODUCTION-MODE bundle by injecting the exact response these
surfaces get in production — a structured refusal instead of a payload:

```
/xdr/admin/audit-log   body len 0     Minified React error #31 · object with keys {code, reason, tenant_id}
/xdr/admin/collectors  body len 3747  no exception  (already fixed in the previous step)
```

The shared dependency is the **refusal contract**, not a component:
`403 {"detail":{"code","reason",…}}` met a copy-pasted
`setErr(e?.response?.data?.detail || …)` and a `{err}` render. React cannot
render an object → throws during render → nothing catches it → the tree
unmounts → black page. `AuditLogBody.jsx:34` + `:104` was the same chain as
`CollectorsBody`. Integrations was immune (already formatted); ingest-routing
takes scope from the verified session and never renders a refusal object; the
MSS dashboard never reaches a tenant-scoped refusal. Preview hid all of it
because its registry still carries a legacy `default` tenant.

## 2 · THE CORRECTION

**One** helper — `src/lib/refusal.js` (`refusalText`, `refusalCode`) — not nine
implementations. Presentation only: no retry, no tenant substitution, no
`"default"`, no scope widening, no fabricated empty success, no softened
authorization. Refusal codes carry a one-line operator remedy; no credential,
token, header or stack trace is ever surfaced.

Applied to **23 object-capable render paths across 17 files** (all of
`xdr/admin/*` plus the `xdr/design/*` surfaces that render refusals), replacing
every `detail || e?.message || "…"` with `refusalText(e, "…")`. The two local
helpers written earlier (`CollectorsBody`, `IntegrationControlCenter`) were
deleted in favour of the shared one.

**`ApiKeysBody` hardcoded tenant removed** — `useState("default")` →
`useState(() => activeTenant() || "")`, header omitted when unset (so the
backend answers `TENANT_REQUIRED`), input writes through the existing
`setActiveTenant` contract, placeholder no longer says `default`. That surface
would have black-screened in production for exactly the Collectors reason.

**One** Administration route-level boundary —
`xdr/admin/AdminErrorBoundary.jsx`, wrapping the section body in
`XdrAdminPage`. Last-resort containment only: it renders
`ADMINISTRATION SURFACE FAILED TO RENDER` plus a selectable (`user-select: all`)
`<code>` block with the exception text for support tickets, resets when the
operator changes section, and **never converts a refusal into success**. Not
applied per-page, and it hides nothing.

## 3 · PHASE A — ALL 27 ADMINISTRATION SECTIONS UNDER INJECTED REFUSALS

Every `/api/xdr/**`, `/api/edr/**`, `/api/admin/**`, `/api/v2/**` call forced to
`403 {code: TENANT_NOT_FOUND, …}`:

```
overview 4677 · audit-log 3168 · secrets 3156 · content-pack-lolbas 3314
capability-hub 5344 · edr-enrollment 3310 · edr-response 3342
edr-capability-truth 3229 · detection-registry 3596 · correlation-rules 3445
engines 19228 · corpus 4531 · integrations 3639 · data-sources 3688
ingest-routing 3833 · collectors 3772 · agents 3165 · telemetry-studio 2847
telemetry-health 2909 · parsers 3046 · normalization 3039
response-policies 3123 · users-roles 3741 · api-keys 3672 · api-webhooks 3871
response-strategies 3172 · platform-health 2936
```
**27/27 rendered · 0 page errors · 0 black screens · boundary never needed**
(the boundary firing would itself have been a finding).

## 4 · PHASE B — FULL SPA ROUTE SCAN (routes enumerated from `App.jsx`)

32 static `/xdr/*` routes and 12 parameterised routes are registered. Static
routes were driven directly; nested routes were discovered by harvesting real
hrefs from the list surfaces (not invented ids). `/edr/*` is included to prove
the product-scope guard renders rather than crashes.

### FINDING — a second, unrelated black screen
```
/xdr/detections/:id   body len 0   ReferenceError: Bug is not defined
```
`XdrDetectionRuleEditorPage.jsx:294` renders `<Bug size={11} />` but `Bug` was
missing from its `lucide-react` import. Nothing to do with refusals — a genuine
undefined-identifier crash on the rule-editor route, invisible until a nested
route was actually driven. Fixed by adding `Bug` to the existing import.

I then swept **every `.jsx` in the SPA** for the same class (capitalised JSX
elements neither imported nor declared). After the fix the only hits are
destructured-prop aliases (`Icon`, `Entity`, `Tag`) and two `<Route>`/`<CASE>`
strings inside comments — no further undefined-identifier crashes anywhere.

### FINAL MATRIX — 30/30 PASS · 0 FAIL
```
PASS  /xdr/mss-dashboard 7243   /xdr/activities 3744   /xdr/incidents 844
PASS  /xdr/investigations 7828  /xdr/evidence-explorer 2715  /xdr/search 2538
PASS  /xdr/endpoints 2591       /xdr/assets/identity 2793
PASS  /xdr/assets/network 2750  /xdr/assets/attack-paths 2755
PASS  /xdr/assets/critical 2811 /xdr/intelligence/threat 9041
PASS  /xdr/intelligence/iocs 3135    /xdr/intelligence/command 2546
PASS  /xdr/intelligence/malware 3817 /xdr/intelligence/mitre 1147
PASS  /xdr/respond/playbooks 2945    /xdr/respond/automation-rules 2831
PASS  /xdr/respond/approvals 2593    /xdr/detections 3312
PASS  /xdr/kb 11518  /xdr/docs 2918  /xdr/exposure 4632  /xdr/rule-studio 10207
PASS  /xdr/admin 5232                /xdr/edr/device-trajectory 1067
PASS  /edr/response 1707 (product-scope guard renders)
PASS  /xdr/no-such-route → /xdr/mss-dashboard 7243 (catch-all, no crash)
PASS  /xdr/investigations/case_golden_cobalt_strike_36fae8f5 3354   (nested)
PASS  /xdr/detections/rule-77830359-8123-4fb2-bbc2-6b63d977b1bc 3208 (nested · was BLACK_SCREEN)

BLACK_SCREEN      0
RUNTIME_EXCEPTION 0
BROKEN_ROUTE      0
```
Redirect-only paths (`/xdr`, `/xdr/dashboard`, `/xdr/control-center`,
`/xdr/cve`, `/xdr/detect/studio`, `/xdr/intelligence/kb`) were verified in the
first pass to resolve to their targets and are represented by those targets.

**Honest note on method:** the first pass classified many routes
`EXPECTED_REFUSAL` because the persistent header chrome contains the string
`NOT CONFIGURED`. That was a weakness in my classifier, not in the pages; the
final pass classifies on *exception + rendered length*, which is why the same
routes read `PASS` above.

## 5 · BUILD / GUARD

```
yarn build                     exit 0
bash scripts/vercel-build.sh   XDR PRODUCTION BUILD GUARD · PASSED
  ok · no preview origin (126 artifacts) · no cross-product host
  ok · API origin https://nivxray.nivxforge.com · no unauthorised origin
  ok · product scope declared "xdr"
  ok · landed collector base …/api/xdr/collector resolves in the artifact
```

## 6 · FILES CHANGED (30 · 2 new)

New: `src/lib/refusal.js`, `src/xdr/admin/AdminErrorBoundary.jsx`.
Edited: `XdrAdminPage.jsx` (boundary + nonce prop), `ApiKeysBody.jsx`
(hardcoded tenant removed), `CollectorsBody.jsx` + `IntegrationControlCenter.jsx`
(local helpers deleted, shared one adopted), `XdrDetectionRuleEditorPage.jsx`
(missing `Bug` import), plus the refusal-path sweep across `AuditLogBody`,
`ClosedLoopPanel`, `ContentPackLolbasBody`, `CorrelationRulesBody`,
`DataSourcesBody`, `DetectionRegistryBody`, `EngineRoleAdminBody`,
`EnginesBody`, `FrameworkMappingsPanel`, `GoldenPipelineTrace`,
`IngestRoutingBody`, `IntegrationsBody`, `InvestigationLanes`, `PipelineStrip`,
`ResponseFabricPanel`, `ResponseStrategiesBody`, `SecretsBody`,
`UsersRolesBody`, `WebhooksBody`, `CortexOnboardingWizard`,
`ExecutiveSummaryPanel`, `GatewayNarrationPanel`, `MitreTabV2`,
`RecommendationsTabV2`, `_WizardLegacyBridge`.

No backend file, no API contract, no tenant authority, no RBAC, no
authentication, no environment variable, no Vercel setting.

## 7 · STATUS
```
acceptance          zero BLACK_SCREEN · zero RUNTIME_EXCEPTION across the tested SPA
push to release/…   OWNER ACTION ("Save to Github") — no git remote in this pod
vercel PREVIEW      re-verify after push
vercel PRODUCTION   blocked pending owner authorisation
emergent backend    untouched
W1                  HELD
```
