# A0_REUSABLE_CAPABILITIES

Mode: READ-ONLY. Classification is based on reading the code, not on
documentation claims. "IMPLEMENTED" means the code path exists and is reachable
from a route or worker; it does **not** mean it was executed in this audit.

## 1 · NivXForge → XDR event integration

| Capability | Status | Evidence |
|---|---|---|
| Authenticated telemetry ingest | **IMPLEMENTED** | `routers/xdr_ingest.py` — `POST /api/xdr/ingest/telemetry`, the *only* path allowed to promote a collector to `CONNECTED`; forwarder authenticates with a scoped API key carrying `collectors.enroll`, enforced by `require_permission` |
| Honest state machine | **IMPLEMENTED** | same file — `CONNECTED` iff `received > 0 AND parsed > 0 AND normalized > 0`; any failure demotes to `PARSE_ERROR` / `DEGRADED`. Explicitly built so "the state machine cannot be lied to by the admin surface, a test button, or a UI toggle" |
| Idempotency | **IMPLEMENTED** | `services/ingest_idempotency.py`, tests `test_p0_ingest_idempotency.py`, `test_p0_dedupe_hardening.py` |
| Ingest provenance stamping | **IMPLEMENTED** | `services/ingest_provenance.py`; `test_d11_ingest_provenance.py` (**fails in this environment on Mongo fixtures**) |
| Raw forensic retention | **IMPLEMENTED** | `services/raw_forensic_retention.py`, contract in `memory/B4_RAW_FORENSIC_RETENTION_CONTRACT.md` |
| Source routing | **IMPLEMENTED** | `services/source_routing.py`, `routers/xdr_ingest_routing.py` |
| Sensor → EDR delivery | **IMPLEMENTED** | `agents/nivxforge-windows/nivxforge_sensor.py`, `nivxforge_delivery_counters.py`, `nivxforge_journal.py`; Linux equivalent in `agents/nivxforge-linux/` |
| **EDR→XDR via a product API** | **MISSING** | XDR reads EDR collections directly (see A0_CROSS_PRODUCT_DEPENDENCIES §1). There is no EDR-side query API |

## 2 · Third-party EDR / source connectors

| Connector | Status | Evidence |
|---|---|---|
| syslog, webhook, REST, CEF, LEEF | **IMPLEMENTED** | `routers/xdr_collectors.py:124-148` `PROTOCOL_REGISTRY` |
| Windows (EVTX/channels) | **IMPLEMENTED** | `:168`; `routers/xdr_windows.py`, `detection_content/telemetry/evtx_xml.py` |
| **`edr` protocol (third-party EDR)** | **PARTIAL — declared SCAFFOLD** | `:180` `"edr": {"implementation": "SCAFFOLD"}`. The catalogue is honest about this |
| kafka, otlp, wef, file, ndr, cloud | **PARTIAL — SCAFFOLD** | `:148-188` |
| Cortex vendor adapter (third-party XDR) | **IMPLEMENTED** | `routers/xdr_cortex_wizard.py`, `xdr_cortex_ingest_routes.py`, `detection_content/xdr_cortex_{adapter,parser,ingest,executor,promotion}.py`; startup poller `server.py:584-599` |
| Vendor registry / plug-in surface | **IMPLEMENTED** | `detection_content/xdr_vendor_registry.py` — `register_vendor`, `get_vendor_class`, `list_production_vendors`, `list_all_vendors(include_internal=)` |
| Collector framework (agent side) | **IMPLEMENTED** | `apps/nivxray-xdr-collector/framework/` — `parsers.py`, `registry.py`, `rest_poller.py`, `m365_activity.py`, `oauth2.py`, `payload_formats.py` |

**This is the strongest reuse story in the repository.** A vendor-neutral
adapter + registry pattern already exists and is already used by a real
third-party product (Cortex). Third-party EDR integration should extend this,
not introduce a parallel mechanism.

## 3 · Canonical evidence schema and provenance

| Capability | Status | Evidence |
|---|---|---|
| Canonical event store | **IMPLEMENTED** | `xdr_canonical_events`; `services/event_search.py:28`, `services/delivery_reconciliation.py:46` |
| Canonical evidence store | **IMPLEMENTED** | `xdr_canonical_evidence` |
| Observation → evidence bridge | **IMPLEMENTED** | `services/evidence_bridge.py:46,99,135` |
| Raw ↔ canonical join | **IMPLEMENTED** | documented and used: `edr_raw_events.raw_id ↔ xdr_canonical_events._id` (`evidence_bridge.py:5`) |
| Incident provenance trace | **IMPLEMENTED** | `services/incident_provenance.py:142-144` |
| Schema documentation | **IMPLEMENTED** | `BEHAVIOR_GRAPH_SCHEMA.md`, `apps/nivxray-xdr-collector/INGEST_CONTRACT.md`, `apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md` |
| **Versioned, product-neutral contract** | **MISSING** | the canonical schema is internal; no `v1` wire contract exists between products |

## 4 · Telemetry reliability

| Capability | Status | Evidence |
|---|---|---|
| Durable queue with leases | **IMPLEMENTED** | `edr_plane/processing_queue.py` (572 lines) — atomic `claim()`, `lease_until`, expired-lease reclaim so a worker crash cannot strand a job, `mark_retry` with backoff, `mark_done` |
| Collector outbox + durable delivery | **IMPLEMENTED** | `apps/nivxray-xdr-collector/framework/{outbox,durable_delivery,delivery_worker,receipts,receipt_client}.py` |
| Deduplication | **IMPLEMENTED** | `framework/dedup.py` + `services/ingest_idempotency.py` |
| Health gate / freshness | **IMPLEMENTED** | `framework/health_gate.py`, `services/edr/telemetry_freshness.py`, `services/edr/endpoint_health.py` |
| Delivery reconciliation + counters | **IMPLEMENTED** | `services/delivery_reconciliation.py`, `edr_plane/delivery_counters.py` |
| Ingestion checkpoints | **IMPLEMENTED** | `framework/acquisition_state.py` |
| **Redis / external broker** | **MISSING by design** | no Redis client anywhere; queueing is Mongo-backed. Not a gap — a deliberate simplicity choice worth preserving |

## 5 · API authentication, tenant scoping, capability discovery

| Capability | Status | Evidence |
|---|---|---|
| Scoped API keys | **IMPLEMENTED** | `routers/xdr_api_keys.py`, `routers/collector_authz.py` route classes |
| Tenant authority (XDR) | **IMPLEMENTED** | `routers/xdr_rbac.py` — `require_permission`, `verified_actor`, `_audit_scope_denial` |
| Tenant authority (EDR) | **IMPLEMENTED** | `routers/edr_tenancy.py` — `edr_tenant`, `edr_scope`, `sensor_tenant`, `_opaque_refusal` |
| Tenant-scoped endpoint predicates | **IMPLEMENTED** | `services/edr/endpoint_query.endpoint_predicate`, reused by 6 modules |
| Secrets store with tenant DEK | **IMPLEMENTED** | `routers/xdr_secrets.py` `_encrypt`/`_decrypt`; `security/secret_policy.py` refuses unkeyed values |
| Append-only signed audit chain | **IMPLEMENTED** | `routers/xdr_audit_log.py` `emit_audit`, used by XDR, EDR and webhooks |
| Capability discovery | **IMPLEMENTED** | `detection_content/xdr_capability_service.py` — `resolve_capability`, `is_available`; returns `CAPABILITY_UNAVAILABLE` / `FAILED` rather than pretending |
| Frontend capability registry | **IMPLEMENTED** | `apps/nivxray-xdr/src/xdr/capabilityRegistry.js` |
| **Per-product service identity** | **PARTIAL** | exists for the response engine only (`RESPONSE_ENGINE_SERVICE_CREDENTIAL`); no XDR↔EDR service identity |

## 6 · Approved endpoint response dispatch

| Capability | Status | Evidence |
|---|---|---|
| Thin, stateless boundary | **IMPLEMENTED** | `routers/xdr_respond_boundary.py` — "holds no response state, no registry, no approval logic" |
| Separate service identity | **IMPLEMENTED** | `_service_credential()`; analyst bearer never forwarded as engine authority; missing config → 503, bad credential → 401 |
| Approval states, pending queue | **IMPLEMENTED** | `/api/respond/pending-approvals`, engine routes under `apps/nivxray-xdr-response/routes/` |
| Vendor response adapters | **IMPLEMENTED** | `apps/nivxray-xdr-response/framework/`, gate `test_vendor_adapters.py` (39 tests green) |
| Foreign-selector rejection + audit | **IMPLEMENTED** | `_audit_response_selector_denial()` |
| Hardened runtime | **IMPLEMENTED** | non-root, read-only rootfs, `cap_drop: [ALL]`, no host ports, external `response-state` volume |
| **Real containment execution** | **MISSING by design** | simulation-only; never executed against a real endpoint |

## 7 · Reusable test assets

| Asset | Status | Evidence |
|---|---|---|
| Test corpus | **IMPLEMENTED** | 601 files in `backend/tests/` |
| Curated release gates | **PARTIAL** | `tools/rocket-validation/run.py` runs ~30 files across 7 gates; 798 tests green |
| Frontend tests | **IMPLEMENTED** | Vitest — 25 files / 420 tests green |
| Staging package tests | **IMPLEMENTED** | `deploy/stage1-staging/test_package.py` + `test_acceptance_scripts.py` — 38 green |
| Synthetic end-to-end trace | **IMPLEMENTED** | `tools/rocket_e2e/acceptance_trace.py` — 25 checks; configurable via `ROCKET_XDR_ORIGIN` |
| **Gate coverage of security suites** | **MISSING** | tenant, webhook, collector-auth and provenance suites are outside the gates |

## Bottom line

Almost everything needed for **vendor-neutral XDR** and a **standalone EDR**
already exists: ingest with idempotency and provenance, a vendor adapter
registry proven on a real third-party product, a Mongo-backed durable queue
with leases, tenant-scoped predicates, a signed audit chain, capability
discovery that admits unavailability, and a credential-separated response
service to use as the boundary template.

What is genuinely missing is narrow: **a versioned, tenant-scoped EDR query
contract** so XDR stops reading EDR collections directly, and **per-product
service identities** to authenticate it.
