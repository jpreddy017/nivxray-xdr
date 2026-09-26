# W1 PHASE 3 · PRODUCTION ALIGNMENT — POST-REPUBLISH ACCEPTANCE: **PASS**

Target: `https://nivxray.nivxforge.com` · verified 2026-09-17 (UTC)
Live build (owner-reported): `8e473e4` · recorded rollback build: `5567f46`
Verification only. Nothing in production modified. No credential used.

## A · BACKEND HEALTH
| gate | expected | actual |
|---|---|---|
| GET /api/ | 200 | **200** `{"service":"NivXRay","status":"ok"}` |
| GET /api/health | 200 | **200** `{"status":"ok","service":"nivxray-api"}` |
| GET /api/zzz-not-a-route-12345 | 404 | **404** |

## B · NEW BUILD IS LIVE (vs captured baseline)
| item | pre-republish | post-republish |
|---|---|---|
| OpenAPI paths | 785 | **790** |
| /api/xdr/collectors/sources/catalog | ABSENT | **PRESENT** |
| /api/xdr/ingest/routing/catalog | ABSENT | **PRESENT** |
| /api/xdr/ingest/routing/deliveries | ABSENT | **PRESENT** |
| /api/xdr/ingest/routing/summary | ABSENT | **PRESENT** |
| /api/xdr/detections/{event_id}/citations | ABSENT | **PRESENT** |
| CanonicalEnvelope.declared_source | ABSENT | **PRESENT** |
| TelemetryReceipt.routing_blocked | ABSENT | **PRESENT** |
| sources/catalog anonymous | 404 (route absent) | **403 ACCESS_DENIED collectors.read** |

Structural equality with the accepted candidate: production 790 paths vs
candidate 790 paths, `preview_only=[]`, `prod_only=[]`, path objects hash
identical, schema name sets equal, **0 schema bodies differing**.
CONCLUSION: production has moved off the pre-D15 contract and now serves the
aligned current contract, byte-equivalent at the contract level.

## C · AUTHENTICATION / FAIL-CLOSED (no real credential used)
| gate | expected | actual |
|---|---|---|
| POST /api/xdr/ingest/telemetry, no credential | 403 | **403** `unauthenticated` |
| same with unknown `nvx_<48 hex>` + X-Tenant-Id | 401 | **401** `unknown-api-key` |
| GET /api/xdr/collectors/sources/catalog anon | 403 | **403** `collectors.read` |
| GET /api/xdr/ingest/routing/summary anon | 403 | **403** |
| GET /api/auth/me no credential | fail closed | **403** `Not authenticated` |
| POST /api/auth/login, nonexistent account | reachable + reject | **401** `Invalid credentials` |

Production auth plane is live and fail-closed. No production credential was
read, used, or exposed.

## D · W1 READINESS — CODE DEPLOYED / PRESENT (not telemetry-proven)
Deployed build = accepted code (proved contract-identical in B), therefore:
- microsoft-sysmon in `SOURCE_CATALOG` + alias `sysmon` (`services/source_routing.py:67,87`)
- Sysmon DSM present with W1 field preservation
  (`detection_content/telemetry/sysmon_dsm.py`: `OriginalFileName` kept
  separate with provenance `sysmon:EventData.OriginalFileName`,
  `ParentCommandLine`, SHA256/MD5 widths validated)
- collector `authorized_sources` enforcement + declaration-required refusals
  (D15 chain, observable as 403/401 fail-closed and the new routing endpoints)
- tenant authority enforcement (D14) — key tenant == header tenant == envelope
  tenant == collector tenant, else 403
- DCR-1 content present (`detection_content/dcr1_product_neutral.py`,
  `rule_store_binding._COLLECTED_PRODUCTS == {"linux"}` unchanged)
Candidate gates run on this code: **255 passed, 15 skipped**.

DISTINCTION HELD: the above is code deployed/present only. No real Windows
telemetry has been transmitted, accepted, routed, or evidenced. Windows is
NOT marked collected/live. W1 is NOT closed.

## E · FRONTEND CLARIFICATION (documented, nothing changed)
- `https://xdr.nivxforge.com/` responds `server: Vercel`,
  `x-vercel-id: sfo1::...`, `307 → /xdr`. It remains the **separate Vercel
  NivXRay XDR SPA**, not the Emergent deployment.
- This Emergent republish rebuilt the Emergent backend + the `/app/frontend`
  Workspace CRA app only. Leaving the Vercel SPA unchanged was **expected**;
  the visual difference vs Emergent preview is therefore correct and not a
  deployment defect. The preview UI is the Vite `apps/nivxray-xdr` tree served
  by the pod supervisor; the Vercel SPA is a separately deployed build of that
  tree from an older commit.
- `COLLECTOR RUNTIME NOT DEPLOYED` / `VITE_XDR_COLLECTOR_URL`
  (`apps/nivxray-xdr/src/xdr/admin/collectorApi.js:5,16`) refers to a
  **separately deployed collector runtime service**
  (`apps/nivxray-xdr-collector`) used by the admin Integrations panel. It is
  independent of the W1 path, which posts directly from the Windows forwarder
  over HTTPS to `POST /api/xdr/ingest/telemetry` on the core backend. That
  badge is not a blocker for W1 Phase 3.1.

## VERDICT
**PRODUCTION ALIGNMENT ACCEPTED.** No gate failed; rollback to `5567f46` is
NOT recommended. No collector, no API key, no forwarder.json, no ingest.key,
no telemetry, no bookmark movement, no `_COLLECTED_PRODUCTS` change, no Vercel
change, no second republish, no DNS/secret/database change.
B3 (machine-path audit attribution must derive from the authenticated machine
identity rather than `X-Principal-*` headers) remains separately tracked.
