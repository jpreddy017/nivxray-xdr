# PREVIEW COLLECTOR PROOF — VERDICT: **PASS** (2026-06)

Preview only. No production deploy, no production collector, no Vercel action.
No rule, threshold, VEEE logic or incident writer was modified. No incident was
fabricated. Harness: `scripts/preview_collector_auth_proof.py`;
machine-readable report: `test_reports/preview_collector_auth_proof.json`.

The admin JWT was used ONLY for the control plane (mint key, enroll collector,
read the queue). **Telemetry ingest was authenticated exclusively with
`X-XDR-API-Key` + `X-Tenant-Id`** — never with a JWT.

## Collector / key IDs
| Item | Value |
|---|---|
| Proof tenant | `p0f-collector-auth-proof` (throwaway) |
| Second tenant (isolation) | `p0f-collector-auth-proof-other` |
| Webhook collector | `col_20818b310f8048468077` (protocol `webhook`, ADOPTED → **CONNECTED** by real telemetry) |
| Ingest API key | `key_3280b2dad48c4f37955c` · prefix `nvx_307dcd07` · scopes `collectors.enroll, collectors.read` |
| Revoked-key control | `key_f6c2065b205549e7824c` |
| Unscoped-key control | `key_2d34ac717ef24354a343` (`alerts.read` only) |
| Other-tenant key | `key_c31e8fb213db48f19d8c` |

Storage guarantee re-verified live: stored `hash` is 64 hex chars and the
plaintext appears in **no** field of the key document.

## Auth proof matrix — 11/11 PASS (against the real ingest endpoint)
| Case | Result |
|---|---|
| valid key + matching tenant | **200 accepted** |
| no credential | 403 `unauthenticated` |
| unknown key | 401 `unknown-api-key` |
| malformed key | 401 `malformed-api-key` |
| empty key header | 401 `malformed-api-key` |
| revoked key | 403 `api-key-revoked` |
| key without `collectors.enroll` | 403 `scope-not-granted` |
| valid key + wrong tenant header | 403 `api-key-tenant-mismatch` |
| other-tenant key → this collector | 403 |
| key + admin JWT together | 401 `ambiguous-credentials` |
| key + spoofed `X-Principal-Id`/`X-Principal-Kind` | 200 — key remains the authority; spoofed headers do not elevate |

## End-to-end chain (single authenticated ingest)
Receipt: `accepted=1`, `collector_state=CONNECTED`
(`telemetry received/parsed/normalized: 1/1/1`), `reasoned=1`,
`observations_created=1`, status `REASONED`, blocker `null`.

| Stage | ID / value |
|---|---|
| trace_id | `live_81f283069f75451e` |
| raw ingest persisted | `xdr_canonical_events` `_id=6aa104d55ac416ffaa4ecab5`, verbatim line preserved |
| observation | `6aa104d65ac416ffaa4ecafe` |
| canonical evidence | `xdr_canonical_evidence` `event_id=142ec7a9-aa1e-4780-a163-6b7c5ef1115d`, dsm `cef-leef`, parser `cef-leef-parser`, normalizer `cef-leef-normalizer`, `severity_band=HIGH` |
| IUE | `iue_c7dd50e467329f87b242` |
| detection | **1 match · rule `DET-EX-001`** (existing enabled content) |
| ICE | `NO_MATCH`, 0 correlation matches |
| VEEE | **SUSPICIOUS · score 70** = `detection(+45) + iue.severity_hint(+25 HIGH)` |
| incident gate | `INCIDENT_MIN_SCORE=55` → legitimately crossed |
| incident | `inc_8c53c8ff067c4689a040` · `doc_type=xdr_incident` · tenant `p0f-collector-auth-proof` · P3 · state `new` · title "Suspicious — sig 4001 → 203.0.113.55" |
| incident provenance | full chain recorded: trace → collector `col_20818b310f8048468077` → integration `webhook-p0f-proof` → dsm/parser/normalizer → canonical_event_id → iue_id → detection_rule_id → veee |

**Exact rule matched: `DET-EX-001`.** The controlled event is the CEF
encoded-PowerShell line already used as a fixture in
`tests/edr/test_p1_10_cef_leef_dsm.py`, which asserts DET-EX-001 fires on it.
Nothing was tuned to make it match.

## Tenant isolation — PASS
- Incident `tenant_id` = proof tenant; visible to the `all_tenants` admin
  reader via `GET /api/incidents?customer=p0f-collector-auth-proof`.
- **Hidden** from `analyst@nivx-live.com` (tenant `nivx-live`): the incident is
  absent from that analyst's full queue.
- The other-tenant key cannot see the proof collector (`GET /api/xdr/collectors`
  returned 0 rows for `p0f-collector-auth-proof-other`).
- Ingest-side: cross-tenant header, cross-tenant envelope and other-tenant key
  are all refused (see matrix).

## The reported 422 — CLASSIFIED: validation-order semantics, **NOT** a defect
- A **well-formed** cross-tenant envelope → **403
  `TENANT_ISOLATION_VIOLATION`** (`header_tenant` vs `envelope_tenant` both
  reported). Isolation holds.
- The 422 appears only for a body that fails Pydantic shape validation
  (`missing field collector_id`, `collection_method`). FastAPI runs body
  validation **before** the handler, so the handler's tenant check is never
  reached for such a body.
- Either way **no cross-tenant write is possible**. Security impact: **NONE**.
  Left unfixed as instructed.

## Replay / idempotency — HONEST FINDING (pre-existing, not auth-related)
Re-sending the byte-identical envelope (same `source_event_id`) returned 200
and created a **second, distinct incident** (`inc_d75ce097dd6d4548ab8d`).

Root cause, verified in code and data: `detection_content/xdr_incident.py`
`_consolidate()` groups into an open campaign keyed on
`(tenant_id, endpoint_id)`. `_endpoint_scope(canonical)` returns **None** for
this CEF firewall event — a non-endpoint source — so consolidation is skipped
by design ("non-endpoint sources unchanged") and `endpoint_campaign` is null on
the incident. Raw ingest is intentionally append-only (audit trail).

Consequence for production: a collector using at-least-once delivery (retry
after timeout) will create **duplicate incidents for non-endpoint sources**.
This is existing pipeline behaviour, wholly independent of the new API-key
auth, and it is a real triage risk at production volume.

## Cleanup state
- **All 8** proof API keys across both proof tenants are **revoked**
  (0 remain usable) — verified in the datastore.
- **Both** proof collectors are **DISABLED** (`col_20818b310f8048468077`,
  plus `col_87b3a4f0812f445e94f6` from an earlier aborted harness run).
- Retained intentionally for owner review under tenant
  `p0f-collector-auth-proof`: 5 raw events, 5 canonical evidence docs,
  5 incidents (the extra rows are the replay probe and the aborted first run).
  Nothing outside these two throwaway tenants was written.

## Remaining blockers before production rollout
1. **P0 — replay/idempotency for non-endpoint sources.** Decide the policy
   (ingest-level dedupe on `(tenant, collector, source_event_id)`, or extend
   campaign consolidation to non-endpoint sources) *before* a retrying
   collector is pointed at production.
2. **P1 — no per-key rate limiting.** The machine path has no throttle on key
   ID / tenant / IP. A leaked key can flood ingest.
3. **P1 — key-issuance ergonomics.** `POST /api/xdr/api-keys` derives the
   tenant from the client `X-Tenant-Id` header for an `admin`-role JWT, so a
   typo mints a key for the wrong tenant. Auth is safe (the key is bound at
   verify time), but issuance deserves a confirmation step.
4. **P2 — pre-existing legacy-header test suites** (`test_xdr_api_keys.py`,
   `test_xdr_rbac_enforcement.py`) remain red and would mask a future
   regression in this area.
