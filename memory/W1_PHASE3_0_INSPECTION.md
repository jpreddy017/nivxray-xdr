# W1 PHASE 3.0 — INSPECTION ONLY (no credential, no enrollment, no transmission)

Date: 2026-06. Read-only. Nothing created, nothing changed, nothing sent.

## 1 · Authoritative ingest contract

`POST /api/xdr/ingest/telemetry` — `backend/routers/xdr_ingest.py`
- Dependency: `require_permission("collectors.enroll")` (`backend/routers/xdr_rbac.py`).
- Machine auth headers: `X-XDR-API-Key: nvx_<48 lowercase hex>` + `X-Tenant-Id`.
  Bearer JWT **and** key together => 401 `ambiguous-credentials`.
- Body: `{"envelopes":[CanonicalEnvelope,...]}` (bare list accepted).
- Required per envelope: `tenant_id`, `collector_id`, `collection_method`,
  `declared_source`, `raw`. One tenant and one collector per batch.
- Receipt (bare JSON, NOT wrapped in `data`): `accepted, parse_errors,
  normalize_errors, collector_state, collector_state_reason, duplicates,
  resumed, routing_blocked, reasoned, observations_created,
  incidents_promoted, reasoning[]`.
- Authority chain: api-key tenant == `X-Tenant-Id` == every envelope
  `tenant_id` == `xdr_collectors.tenant_id`; any mismatch => 403
  `TENANT_ISOLATION_VIOLATION`. A source-supplied `tenant_id` inside a
  JSON document is stripped and preserved only as a claim under `_nivx`.
- D15 routing: `services/source_routing.py`. Declaration required; must be in
  the collector's server-side `authorized_sources`; exactly one DSM per
  declared source (`microsoft-sysmon` -> `microsoft-sysmon` DSM); content may
  only validate. Refusal codes: DECLARATION_REQUIRED, SOURCE_NOT_AUTHORIZED,
  UNSUPPORTED_SOURCE, SOURCE_FORMAT_MISMATCH, SOURCE_DSM_UNAVAILABLE. A
  refused delivery gets no raw row, no claim, no canonical evidence, and is
  counted only in `events_routing_blocked`.
- Rate limits (`services/machine_rate_limit.py`, fixed 60 s window, fail
  closed): ip 600, key 600, tenant 1200.

## 2 · Enrollment / key issuance (existing, reused — no second mechanism)

1. `POST /api/xdr/collectors` (`collectors.create`, admin JWT)
   `{name, protocol:"rest", tls:true, authorized_sources:["microsoft-sysmon"]}`
   Tenant binding comes from `X-Tenant-Id` on the admin request. Initial state
   `ADOPTED`; only the ingest counters may move it to `CONNECTED`.
   `protocol:"rest"` is `IMPLEMENTED` in `PROTOCOL_REGISTRY`.
2. `POST /api/xdr/api-keys` (`api_keys.create`, admin JWT)
   `{name, confirm_tenant_id:<tenant>, allow_new_tenant:<bool>,
     scopes:["collectors.enroll","collectors.read"], expires_at:<ISO>}`
   Plaintext returned once; only `sha256` is stored.

## 3 · Forwarder-side configuration (not created)

`C:\ProgramData\NivXRay\config\forwarder.json`:
`ApiBaseUrl` (must start `https://`), `TenantId`, `CollectorId`,
`SourceLabel`, optional `BatchSize` (default 200).
`C:\ProgramData\NivXRay\config\ingest.key` — plain key file; the script
REFUSES to read it if Everyone / BUILTIN\Users / Authenticated Users hold ACL
entries. Bookmark advances only after a successful receipt per chunk; refused
statuses are written to `state\refused.jsonl`.

## 4 · Externally reachable ingest status (measured)

| host | TLS | /api/ | ingest no-auth | ingest bad key | contract |
|---|---|---|---|---|---|
| greeting-app-5782.preview.emergentagent.com | Google Trust WE1, valid to 2026-11-05, verify=0 | 200 | 403 unauthenticated | 401 unknown-api-key | 790 paths, `declared_source` + `routing_blocked` present |
| nivxray.nivxforge.com | Google Trust WE1, valid to 2026-12-07, verify=0 | 200 | 403 unauthenticated | 401 unknown-api-key | **785 paths, `declared_source` ABSENT, `routing_blocked` ABSENT** |
| nivxforge.com | TLS handshake failure | — | — | — | — |
| nivxmachines.com | valid | 200 (marketing API) | 404 | — | not an XDR backend |

## 5 · Blockers

- **B1 (hard).** `nivxray.nivxforge.com` runs a pre-D15 build: its
  `CanonicalEnvelope` has no `declared_source` and its receipt has no
  `routing_blocked`; `/api/xdr/collectors/sources/catalog` and
  `/api/xdr/ingest/routing/{catalog,deliveries,summary}` do not exist there.
  Declared-source authorization cannot be enforced on that host, and the W1
  Sysmon DSM field fixes and DCR-1 content are not deployed there either.
- **B2.** Production database is separate: zero collectors, zero keys.
  Minting there needs an owner-supplied short-lived admin JWT (password is
  deliberately unknown to this workspace), and the live production XDR SPA
  predates `confirm_tenant_id`, so the UI path cannot mint a key today.
- **B3 (minor, pre-existing).** `xdr_ingest._principal()` still prefers
  `X-Principal-Id`/`X-Principal-Kind` headers for AUDIT attribution on the
  machine path. Authorization and tenant authority are unaffected.

## 6 · Conclusion

The only backend that today satisfies every Phase 3 invariant is the preview
backend `https://greeting-app-5782.preview.emergentagent.com`. Production is
not eligible until the current build is deployed there (separate approval;
repo-root `vercel.json` currently refuses root deployment).

`_COLLECTED_PRODUCTS` is unchanged (`{"linux"}`). No Windows source acceptance
is claimed.
