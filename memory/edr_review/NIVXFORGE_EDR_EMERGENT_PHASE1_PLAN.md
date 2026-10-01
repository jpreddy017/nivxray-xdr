# NIVXFORGE EDR · EMERGENT PHASE 1 PLAN

> **Scope:** Implementation-ready plan for **EDR Sensor Enrollment + Telemetry Ingestion + Response State-Machine Extension** — backend + API contract only. **No UI implementation** during Phase 1 (UI freeze).
> **Companion:** `NIVXFORGE_EDR_EMERGENT_INTEGRATION_REVIEW.md`, `NIVXFORGE_EDR_EMERGENT_INTEGRATION_MATRIX.md`.
> **Gate:** ⛔ Not authorized to implement until owner signs off on the 8 architecture decisions (§P AD-01…AD-08) in the Review doc.

---

## Phase 1 · Deliverables (backend + API contract only)

| Deliverable | Description | Reuses (do-not-rebuild) | New |
|---|---|---|---|
| D1 | Sensor enrollment PKI + `/api/xdr/edr/enrollment/*` API | `xdr_rbac`, `xdr_audit_log`, `observability` | `edr_enrollment_tokens` coll · `edr_endpoints` coll · CA infra |
| D2 | EDR canonical envelope extension | `xdr_ingest.CanonicalEnvelope`, `xdr_events` coll, `_principal`, cross-tenant guard | 11 EDR event-type validators (`process`, `file`, `network`, `dns`, `registry`, `service`, `user_session`, `persistence`, `memory`, `system`, `security_event`) |
| D3 | EDR telemetry stream ingest route | `xdr_ingest` handler + tenant guard | new route (see §W option A recommendation) + rate-limit + batching |
| D4 | Response 7-stage extension | `apps/nivxray-xdr-response/framework/executor.py`, `xdr_response_evidence.py`, `xdr_cortex_actions.py` | `INTERVENTION_PLAN` + `ACTION_REQUESTED` states, safety-gate stub (returns `capability_available=false` until AD-07) |
| D5 | Sensor-side skeleton (agent daemon shell, no drivers yet) | none | `src/sensor/main.rs` scaffold; publish binary format; NOT installed on any real endpoint until Phase 2 |
| D6 | OpenAPI regeneration + Prometheus route templates | `observability`, `server.py.openapi_url` | new routes registered with cardinality-safe path templates |
| D7 | Acceptance-test corpus | `pytest backend/tests` | `backend/tests/edr/` folder (5 files) |

---

## Phase 1 · Components

### C1 · Sensor Enrollment PKI + REST

**New router:** `backend/routers/edr_enrollment.py`

- `POST /api/xdr/edr/enrollment/tokens` — admin creates short-lived, hashed enrollment token. Returns opaque `token_str` (Ed25519-signed). RBAC: `edr.enrollment.create`.
- `POST /api/xdr/edr/enrollment/csr` — sensor submits CSR + token; server validates token, issues X.509 cert (`CN={device_uuid}, OU={tenant_id}`, validity 90 d, KU `Digital Signature`, EKU `1.3.6.1.5.5.7.3.2`). NOT tenant-guarded by token in request body — tenant extracted from the token record server-side.
- `POST /api/xdr/edr/enrollment/rotate` — mTLS-authenticated cert-rotation endpoint (uses existing cert to sign the rotation request).
- `POST /api/xdr/edr/enrollment/revoke` — admin revokes device cert. RBAC: `edr.enrollment.revoke`. Appends to CRL.

**Mongo collections (new):**
```
edr_enrollment_tokens { _id, tenant_id, hash, expires_at, created_by, used_by_device_id?, created_at }
edr_endpoints        { _id, tenant_id, device_uuid, cert_serial, hostname, os, kernel_version,
                       sensor_version, first_seen, last_heartbeat, status ∈ {ACTIVE,STALE,REVOKED} }
edr_cert_ca_state    { _id, current_ca_serial, previous_ca_serial, ca_pem, ca_key_ref_kms, updated_at }
```

**CA implementation:** `services/edr_pki/`
- Ed25519 signing key (loaded from `EDR_CA_KEY` env — post-GA move to KMS/Vault, tracked as P0-secret backlog).
- Cert issuance uses `cryptography` (Python) — already in `requirements.txt`; no new dep.

**Existing patterns re-used:**
- `_principal(req)`, `require_permission("edr.enrollment.create")` — same as `xdr_rbac.py`.
- Audit via `emit_audit("EDR_ENROLLMENT_TOKEN_CREATED", …)`.

### C2 · EDR Canonical Envelope Extension

**Edit target:** `backend/routers/xdr_ingest.py` (add fields — must NOT remove or rename existing fields).

**New optional fields** on `CanonicalEnvelope`:
- `evidence_id: str | None` (UUID v4 — server-assigned if absent)
- `event_id: str | None` (sha256 of `device_id + timestamp + event_type + seq` — validated when supplied)
- `event_type: Literal[…11 EDR types + existing…]`
- `device_id: str | None` (must match cert subject `CN` when auth is mTLS device cert)
- `user_id: str | None`
- `process_id: str | None` (Process GUID form `{device_id}:{pid}:{epoch}`)
- `parent_process_id: str | None`
- `file_hash: str | None` (SHA-256 hex)
- `network_endpoint: str | None` ('IP:Port')
- `artifact_id: str | None`
- `provenance: dict` — required for EDR: `{collector_version, kernel_driver_hook, ingestion_gateway_timestamp}`
- `confidence: float` — 0.0…1.0, default 1.0 for sensor
- `raw_event: dict` — verbatim
- `canonical_event: dict` — typed per event_type schema

**Envelope-version negotiation:** existing collectors send `envelope_version` absent or `"1.0"`; EDR sends `"2.0.0"`. Server accepts both; validation branches by version.

**Non-negotiable invariant:** `tenant_id` is IGNORED if present in body; server-side derives from mTLS cert `OU`. Cross-tenant negative test enforces this.

### C3 · Telemetry Stream Ingest

**Route:** `POST /api/xdr/edr/telemetry/stream` (option A recommendation — extends `/api/xdr/*`; owner may pin option B in AD-01).

**Handler:** thin wrapper around existing `xdr_ingest.telemetry_batch()` — passes through the existing single-collector-per-batch guard, cross-tenant guard, and `xdr_events` writer.

**Request shape:**
```json
POST /api/xdr/edr/telemetry/stream
Content-Type: application/x-ndjson
Authorization: mTLS device cert
Body: newline-delimited JSON, one CanonicalEnvelope per line (max 100 events / batch)

HTTP 202
{ "accepted": N, "rejected": M, "reasons": {...}, "trace_id": "..." }
```

**Backpressure:** on-agent SQLite ring-buffer (documented but implemented in sensor, not backend). Server returns HTTP 429 with `Retry-After` if rate-limit exceeded (reuse `security.rate_limit`).

**Observability:**
- Prometheus counter: `nivxray_edr_telemetry_events_total{tenant, event_type, status}` — bounded label cardinality.
- Log envelope (JSON): `trace_id`, `tenant_id`, `route`, `latency_ms`, `count_accepted`, `count_rejected`.

### C4 · Response 7-Stage Extension

**Edit target:** `apps/nivxray-xdr-response/framework/executor.py` (append states — MUST NOT reorder existing).

Existing lifecycle (verified in code): `REQUESTED → APPROVED → EXECUTING → SUCCEEDED/FAILED → VERIFIED`.

Extension (backward-compatible):
- Insert **`INTERVENTION_PLAN`** between recommendation and `REQUESTED` (or as a first-class state before `REQUESTED`). Payload: aggregated actions, blast-radius estimate, policy check.
- Insert **`ACTION_REQUESTED`** as the transition after safety-gate validation (currently implicit inside `REQUESTED → EXECUTING`; make it explicit).
- **Safety-gate:** new middleware `services/edr_safety_gate/` called between `APPROVED` and `ACTION_REQUESTED`. Checks:
  - `device.is_domain_controller == False` (AD adapter data — placeholder returns `unknown` until AD adapter lands; fail-CLOSED means safety-gate BLOCKS by default).
  - `device.tags ∩ {ICU, HEALTHCARE_CRITICAL, SCADA} == ∅`.
  - `device.sensor_connectivity == 'ONLINE'`.
  - `controller_mtls_pinned == true`.
- **All real drivers stay `capability_available=false`** until Phase 4. Phase 1 only wires the safety-gate branch; existing simulated stubs continue to return `simulation_only=True`.

### C5 · Sensor Skeleton (agent binary — no drivers)

**Path:** `src/sensor/` (new top-level directory).
- `src/sensor/main.rs` — Rust binary that reads config, presents CSR, exchanges for cert, opens mTLS channel, sends a single "hello" event, exits. **No kernel driver, no telemetry collection in Phase 1.**
- `src/sensor/Cargo.toml`, `src/sensor/README.md`.
- **Build target:** Windows x86_64, Linux x86_64/arm64, macOS arm64. Phase 1 requires only Linux x86_64 to compile and enroll against the pod.
- **Signing:** unsigned dev build in Phase 1. Production signing tracked in AD-08.

### C6 · OpenAPI + Metrics Registration

- Every new route uses FastAPI dependency `Depends(require_permission("edr.…"))` so it appears in the OpenAPI security section.
- Path parameters MUST use FastAPI path templates so `observability.ObservabilityMiddleware` route templating stays cardinality-safe.
- Regenerate & verify: `curl /api/openapi.json | jq '.paths | length'` must equal `717 + N` where `N` is the count of new EDR routes.

### C7 · Test Corpus

New folder `backend/tests/edr/`:

1. `test_enrollment.py` — happy-path token → CSR → cert; token replay rejected; expired token rejected; wrong-tenant device tries to use another tenant's token → 403.
2. `test_ingest_canonical.py` — v1 envelope still ingests; v2.0.0 envelope with all 11 event_types roundtrips; missing `provenance` in v2 → 400.
3. `test_cross_tenant.py` (P0-D adversarial) — mTLS-authenticated sensor for tenant-A CANNOT write events with `tenant_id=tenant-B`; server-side wins.
4. `test_response_lifecycle_extended.py` — 7-state transitions with safety-gate `capability_available=false`; existing `_stub_ok` still returns simulation_only.
5. `test_openapi_surface.py` — every new route documented; every new label cardinality-safe; existing 195/195 tests still pass.

**Acceptance:** `pytest backend/tests -q` returns green with expected count `195 → 195 + new_edr_tests` and 1 intentional `mal-20` FN unchanged.

---

## Phase 1 · APIs (draft — subject to AD-01 & AD-02 sign-off)

```
POST   /api/xdr/edr/enrollment/tokens          — admin create token
POST   /api/xdr/edr/enrollment/csr             — sensor exchanges token+CSR for cert
POST   /api/xdr/edr/enrollment/rotate          — mTLS cert-rotation
POST   /api/xdr/edr/enrollment/revoke          — admin revoke
GET    /api/xdr/edr/endpoints                  — list (server-side tenant-scoped)
POST   /api/xdr/edr/telemetry/stream           — sensor NDJSON batch ingest (mTLS)
POST   /api/xdr/edr/heartbeat                  — sensor heartbeat (mTLS)
GET    /api/xdr/edr/registry/inventory         — introspection (replaces missing verify_*.py) — Phase 0.5 prereq
GET    /api/xdr/detection-content/inventory    — introspection (replaces missing run_content_truth_audit.py) — Phase 0.5 prereq
```

Existing routes to REUSE unchanged: `/api/response/actions`, `/api/response/execute`, `/api/artifacts/*`, `/api/v2/cases/{id}/artifacts`, `/api/xdr/ingest/telemetry`, `/api/xdr/data-sources`, `/api/xdr/collectors`, `/api/incidents`, `/api/health`, `/api/health/deep`, `/api/metrics`, `/api/openapi.json`.

---

## Phase 1 · Schemas (superset of existing `CanonicalEnvelope`)

Full 11-event schema definitions live in `05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_CANONICAL_EVIDENCE_CONTRACT.md`. Implementation must:
- validate `event_type` against the enum
- validate the `canonical_event` payload against the per-type Pydantic model
- allow `raw_event` to remain unrestricted (verbatim source)
- SHA-256 hash `raw_event` for provenance chaining
- reject records with `envelope_version="2.0.0"` if `provenance` is missing

---

## Phase 1 · Event Contracts

Each event class emits into `xdr_events` (or, if AD-M requires a new collection, into `edr_telemetry_events` — RECOMMEND continued use of `xdr_events`). Downstream consumers already exist:
- `services/canonicalizer/` → picks up new events by `event_type` (may need per-type mapper stubs — additive).
- `services/ikg/` → NO changes in Phase 1. UBAE-edge projection is Phase 3.
- Existing detection content → will begin matching against new events automatically because it evaluates the canonical shape.

---

## Phase 1 · Data Flow (drawn from live code)

```
[Sensor daemon]
  │  mTLS 1.3 (cert issued by C1)
  ▼
POST /api/xdr/edr/telemetry/stream        ← C3 (new)
  │  passes through:
  ▼
xdr_ingest.telemetry_batch()               ← REUSE (existing cross-tenant guard)
  │
  ▼
xdr_events writer                          ← REUSE
  │
  ├──► services/canonicalizer/ (event_type-branched)
  ├──► existing detection engine (content_fabric) — auto-matches
  ├──► services/ikg/ — Phase 3 (NO CHANGE Phase 1)
  └──► observability metrics + JSON log envelope
```

---

## Phase 1 · Endpoint Enrollment Sequence (mermaid-style)

```
Admin -> /tokens         : POST (RBAC edr.enrollment.create)
                            -> INSERT edr_enrollment_tokens {hash, expires_at}
                            -> emit_audit(TOKEN_CREATED)
                            -> return token_str
Sensor(installer) -> /csr : POST {token_str, csr_pem}
                            -> validate token, mark used
                            -> issue cert (CN={new device_uuid}, OU={tenant_id from token})
                            -> INSERT edr_endpoints {tenant_id, device_uuid, cert_serial, status=ACTIVE}
                            -> emit_audit(CERT_ISSUED)
                            -> return cert_pem
Sensor -> /telemetry/stream : mTLS POST NDJSON
                            -> verify cert not revoked
                            -> tenant_id = cert.OU  (SERVER-SIDE)
                            -> pass through xdr_ingest guard
                            -> INSERT xdr_events (many)
Sensor -> /heartbeat       : mTLS POST every 60 s
                            -> UPDATE edr_endpoints.last_heartbeat
                            -> if gap > 5 min → status=STALE
Admin -> /revoke           : POST device_uuid
                            -> UPDATE edr_endpoints.status=REVOKED
                            -> append cert_serial to CRL
                            -> emit_audit(CERT_REVOKED)
```

---

## Phase 1 · Health, Security, Tenancy

- **Health:** `GET /api/health/deep` remains the readiness probe; add `edr_enrollment_tokens` and `edr_endpoints` availability checks under a new `edr` field in the response.
- **Security:**
  - mTLS 1.3 termination at the ingress (existing K8s or docker-compose reverse proxy — Phase 1 must document the config once P0-J K8s chart lands; interim: nginx sidecar in docker-compose).
  - CA private key sourced from env `EDR_CA_KEY` (post-GA → KMS).
  - CSR reuse blocked (token single-use).
- **Tenancy:** P0-D adversarial test MUST pass before Phase 1 merges. If it fails, Phase 1 is BLOCKED.
- **Rate-limit:** reuse `security.rate_limit.LOGIN_LIMITER` pattern, keyed on `(device_uuid, ip)`.

---

## Phase 1 · Testing Strategy

- All existing tests (`pytest backend/tests`) MUST remain green: baseline 195/195 pass (+ 1 intentional mal-20 FN).
- New tests documented in §C7 above.
- No frontend tests (UI freeze).
- Fuzz test on `POST /api/xdr/edr/telemetry/stream` with malformed NDJSON — Phase 2 fuzz corpus can be built after Phase 1 lands.

---

## Phase 1 · Rollout / Feature Flags

- `NIVX_EDR_ENROLLMENT_ENABLED` — default `false` in prod, `true` in dev/staging.
- `NIVX_EDR_TELEMETRY_STREAM_ENABLED` — default `false` until enrollment proven.
- `NIVX_EDR_SAFETY_GATE_FAIL_MODE` — must be `CLOSED` (i.e., deny action if AD-adapter is unreachable). Alternative `OPEN` is FORBIDDEN.
- All routes registered but guarded by these flags at handler entry — flag-off returns `503 Service Unavailable` with `{"reason": "edr_disabled"}`.

---

## Phase 1 · Rollback Plan

1. Feature flags off → all Phase 1 routes return 503. Existing 195 tests still pass because they don't touch these routes.
2. Revert commit range on feature branch; `feature/rc2` unchanged.
3. Truth-contract commit `d3f7a0a…` remains the immutable snapshot for the pre-EDR state.
4. Content Fabric + decoder + reasoning suites are byte-identical (verified via `git diff --stat` — must show zero touches).

---

## Phase 1 · Success Criteria (definition of done)

| # | Criterion | Verification |
|---|---|---|
| S-1 | Sensor enrolls end-to-end via mTLS | integration test `test_enrollment.py` green |
| S-2 | 1 000 EPS ingest over 15 min | load-test script + Prometheus scrape |
| S-3 | Cross-tenant negative test passes | `test_cross_tenant.py` green |
| S-4 | Canonical envelope v1 + v2 both accepted | `test_ingest_canonical.py` green |
| S-5 | Detection surfaces on new EDR event via existing content fabric | end-to-end test in `test_ingest_canonical.py` |
| S-6 | Every new route in `openapi.json` with cardinality-safe metric labels | `test_openapi_surface.py` green |
| S-7 | 195 pre-existing tests still pass | `pytest backend/tests` green |
| S-8 | UI unchanged (git diff shows 0 changes to `frontend/**`, `apps/nivxray-xdr/**`) | `git diff --stat` |

---

## Phase 1 · What is NOT in scope

- ❌ Kernel drivers (BUILD in Phase 4).
- ❌ Live process tree streaming (BUILD in Phase 2).
- ❌ 5-lane microsecond trajectory (BUILD in Phase 2).
- ❌ Live query (BUILD in Phase 3).
- ❌ UBAE (BUILD in Phase 3).
- ❌ Sandbox runner (BUILD in Phase 4).
- ❌ Real response drivers (BUILD in Phase 4).
- ❌ Merkle-chain audit ledger extension (BUILD in Phase 4).
- ❌ Any frontend implementation (UI FREEZE).

---

## END · PHASE 1 PLAN DELIVERED (read-only · not authorized to implement)

Awaiting owner sign-off on the 8 architecture decisions (§P AD-01…AD-08 in the Review doc) and closure of Phase 0.5 prerequisites (P0-D adversarial test, missing audit scripts / introspection endpoints, path-drift reconciliation) before implementation begins.
