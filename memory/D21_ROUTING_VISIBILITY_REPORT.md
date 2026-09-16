# D21 — Routing Visibility · **PASS** (preview only · nothing deployed · no merge)

Owner decision honoured: smallest operator-visible **read-only** diagnostics
surface over the routing decisions the authenticated ingest boundary already
made. No new routing authority, no operator control over routing, no full
console.

## What the surface reads (and never recomputes)

    accepted deliveries  <-  xdr_canonical_evidence.provenance.routing
                             (the D15 decision travels with the evidence it
                              produced)
    refused deliveries   <-  xdr_ingest_routing_blocks.routing
                             (a refusal produced no evidence, so it lives in
                              its own record — that separation is the point)

Both sides are projected into ONE row shape carrying: outcome, receipt
instant + which stamp it came from, tenant, authenticated collector + how
that identity was established, declared source (raw and catalog-resolved),
the collector's server-side allowlist, the **relationship** between the two
(`IN_COLLECTOR_ALLOWLIST` / `NOT_IN_COLLECTOR_ALLOWLIST` /
`NO_DECLARATION_MADE` / `NOT_IN_CATALOG` /
`NOT_APPLICABLE_NO_AUTHENTICATED_COLLECTOR`), selected DSM, routing
authority, reason code + verbatim reason, payload shape, declared payload
format, collection method, trace id, source_event_id, and the evidence
reference — or, for a refusal, `evidence_ref: null` plus the reason there is
none. Nothing absent is back-filled from a neighbouring field; a collector
event id that never reached canonical evidence is reported as `null` with
`NOT_CARRIED_INTO_CANONICAL_EVIDENCE`, not blanked.

## FILES CHANGED
* `backend/routers/xdr_ingest_routing.py` (new · GET-only router)
* `backend/server.py` (+2 · router registration)
* `backend/tests/test_d21_routing_visibility.py` (new · 15 tests)
* `apps/nivxray-xdr/src/xdr/admin/IngestRoutingBody.jsx` (new · panel)
* `apps/nivxray-xdr/src/xdr/admin/adminMeta.js` (+1 section)
* `apps/nivxray-xdr/src/xdr/pages/XdrAdminPage.jsx` (+3 · dispatch)
* `scripts/p0_d21_routing_visibility_live_proof.py` (new · 50 live checks)

Untouched: `services/source_routing.py`, `routers/xdr_ingest.py`,
`detection_content/xdr_pipeline.py`, every Work Mode / control-plane module.

## API (read-only · `/api/xdr/ingest/routing`)
* `GET /deliveries` — last-N, newest first. Allow-listed filters only:
  `result`, `reason_code`, `collector_id`, `declared_source`,
  `selected_dsm_id`, `routing_authority`, `since`, `until`, `limit`
  (default 50, hard max 200 — `limit=9999` is a 422, never a silent widen).
* `GET /summary` — accepted/refused totals, refusals by reason code, by
  result and by collector; accepted by declared source, DSM and authority.
  Refusals are counted from the refusal record and never subtracted from
  accepted counts.
* `GET /catalog` — the declarable source catalog and refusal vocabulary,
  restated verbatim from `services.source_routing`, never redefined.

There is no POST/PUT/PATCH/DELETE on this prefix: `405` on all four,
asserted both in pytest (router method set ⊆ GET/HEAD/OPTIONS) and live.

## UI
`/xdr/admin/ingest-routing` (Administration › Ingest Routing). Counts,
tenant-scope banner, six filters, last-N table, per-row expansion showing
the collector allowlist, authority, payload shape/method, trace,
verbatim reason, refused payload keys/excerpt, and why a refusal has no
evidence. Every element carries a `data-testid`
(`xdr-ingest-routing-body`, `xdr-routing-filter-*`, `xdr-routing-row-*`,
`xdr-routing-detail-*`, `xdr-routing-tile-*`, `xdr-routing-scope`).
The footer names both source collections on screen, so an operator is never
guessing where a row came from.

## TENANT ISOLATION
Scope is derived from the **authenticated principal only** —
`deps.get_current_user` (verified JWT) →
`services.dashboard_lenses.resolve_tenant_scope`, the same authority the
incident plane already uses. `X-Tenant-Id` has no path into the Mongo filter
on this surface; `?tenant_id=` is honoured only for a cross-tenant role. A
tenant-scoped principal that asks for another tenant is answered with its
own scope **and told the request was ignored**
(`requested_tenant_id_honoured: false` + reason). The filter is built
server-side; no request-supplied filter document is ever accepted.

Proven live with two REAL tenants and two REAL analyst logins
(`analyst@default.com` / tenant `default`, `analyst@nivx-live.com` /
tenant `nivx-live`), each with its own collector, ingest key, one accepted
delivery and two refusals:

* header spoof, query spoof, and both together → own tenant only, all three
  times, in both directions
* the foreign tenant's collector id returns **0 rows**
* `/summary` pointed at the foreign tenant returns the caller's own counts,
  and the foreign collector identity appears in neither response
* cross-tenant admin is labelled `CROSS_TENANT_ROLE` and may deliberately
  scope to one tenant (labelled `requested_tenant_id_honoured: true`)
* no credential → 403; malformed token → 401

## LIVE PROOF
`scripts/p0_d21_routing_visibility_live_proof.py` — **50/50 PASS** over real
HTTP against the preview ingress. Deliveries go through the authenticated,
declared (D15) ingest route; refusals are produced genuinely
(`DECLARATION_REQUIRED` by sending no declaration,
`SOURCE_NOT_AUTHORIZED` by declaring `aws-cloudtrail` from a collector whose
allowlist is `linux-auditd` only). TEST/SYNTHETIC auditd payloads; no
production contact.

## NEGATIVE TESTS
Undeclared → refused and visible with its code; unauthorized declaration →
refused and visible with a different code; foreign-tenant read → empty;
foreign-tenant summary → own counts; unauthenticated → 403; bad token →
401; write verbs → 405; over-limit → 422; internal (non-ingest) callers are
labelled `NOT_APPLICABLE_NO_AUTHENTICATED_COLLECTOR` rather than being
dressed up as authorized collector declarations.

## REGRESSION
`253 passed` across D15–D19 + D21 suites. The known pre-existing failures are
unchanged: **12 failed / 16 passed** in `test_xdr_content_pipeline.py` +
`test_xdr_detection_consolidation.py`, the same count as the baseline. Not
touched, as instructed.

## D21: **PASS**

## Not done, deliberately
* No promotion of D11–D21 to production. Preview only, no merge.
* D20 stays **ENVIRONMENT_BLOCKED**: this pod has no auditd
  (`/var/log/audit` absent, no `auditctl`). No synthetic substitute will be
  presented as a live host.

## Recommended next capability (not another plumbing gate)
**M365 / Entra ID audit onboarding** — a real source NivX does not have at
all. It is the only remaining blocker for `DET-PS-004`, it is the lane where
real intrusions now start, and it is collectable without touching a customer
endpoint. It converts the ledger's SOURCE gap into coverage instead of
polishing instrumentation that already works.
