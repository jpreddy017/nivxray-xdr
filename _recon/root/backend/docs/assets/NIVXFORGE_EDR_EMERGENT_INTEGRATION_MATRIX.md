# NIVXFORGE EDR · EMERGENT INTEGRATION MATRIX

> Row-by-row capability matrix. Each row anchored to **runtime + code evidence** (paths verified against `feature/rc2`) — documentation claims that disagree are surfaced explicitly in the "Path Drift" column.
> **Companion:** `NIVXFORGE_EDR_EMERGENT_INTEGRATION_REVIEW.md`
> **Legend (8-state grade):** IW = Implemented+Working · IBI = Implemented but Incomplete · SMS = Stub/Mock/Scaffold · IBNW = Implemented but Not Wired · IBNPS = Implemented but Not Production-Safe · MISS = Missing · DUP = Duplicate/Fragmented · CFNT = Candidate for New Technology.

---

## Matrix

| # | Capability | Current Truth (code-verified) | Existing Code (path) | Reusable? | Integration Point | Gap | Required Work | Priority | Dependency | Acceptance Test | Path Drift vs Handoff |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **EDR Agent (Win/Linux/macOS)** | MISS → CFNT | none | n/a | new: `src/sensor/` | agent daemon, kernel hooks, TLS enrollment | build cross-platform sensor daemon (Rust preferred; Win: kernel minifilter or ETW-only fallback; Linux: eBPF `sys_enter_execve`, `LSM/security_bprm_check`; macOS: EndpointSecurity API) | P1-hard | AD-08 (signing) | sensor emits ≥ 1 000 EPS through mTLS handshake | agreed with handoff |
| 2 | **Endpoint Enrollment PKI** | MISS → CFNT | none | n/a | new: `backend/routers/edr_enrollment.py` + `edr_enrollment_tokens` coll | X.509 CA, CSR flow, cert-rotation daemon | issue certs with Subject `CN={device_uuid}, OU={tenant_id}`; validity 90 d; auto-rotate | P1-hard | AD-06 (P0-D) | admin can generate token via API, sensor exchanges it for cert, cert appears in `edr_endpoints` | new capability |
| 3 | **Telemetry Ingest (EDR canonical envelope)** | IW at `POST /api/xdr/ingest/telemetry`; EDR-specific extension MISS | `backend/routers/xdr_ingest.py` | YES (extend) | extend `SOURCE_KINDS` + `CanonicalEnvelope` | 11 EDR event types not schema-validated | add `event_type ∈ {process,file,network,dns,registry,service,user_session,persistence,memory,system,security_event}` validators | P1 | AD-01 (namespace), AD-02 (envelope) | curl ingest with valid EDR event → 202; invalid → 400 | ⚠ Code Map suggests new `/api/v2/edr/telemetry/stream` route; live pattern is `/api/xdr/ingest/telemetry` |
| 4 | **Endpoint Inventory + Health** | IW as case-projection at `GET /api/edr/endpoints`; live enrollment MISS | `backend/routers/edr.py:198-265` | partial (query pattern only) | new: `edr_endpoints` collection + persistent heartbeat | live registration API, heartbeat table | switch `edr.py` from "extract-from-cases" mode to authoritative `edr_endpoints` (keep case-projection fallback for existing incidents) | P1 | #2 | new sensor appears in `edr_endpoints`; heartbeat gap → status `STALE` after 5 min | Truth Audit acknowledges "read-only projection · endpoints extracted from saved cases" (edr.py:262) |
| 5 | **Live Process Tree** | IW (batch/case) at `GET /api/edr/process-tree`; streaming MISS | `backend/routers/edr.py:110-165`, `backend/v2/routers/ancestry.py` | YES (schema) | extend `xdr_events` writer to feed `services/ikg/` in real time | streaming pipeline from sensor `process.CREATE` → live IKG update | Phase 2 | none | #3 | sensor `process.CREATE` for PID X appears in process tree ≤ 1 s | Code Map says SCAFFOLD; Truth Audit says IMPLEMENTED. Reality = IW for case-scope, MISS for streaming |
| 6 | **5-lane Device Trajectory (microsecond)** | IW (case-scope, 1h/6h/12h/24h/3d/7d) at `GET /api/edr/device-trajectory`; microsecond streaming MISS | `backend/routers/edr.py:267-435`, `backend/v2/routers/trajectory.py` | YES (schema) | extend to live-buffer window (per-device Redis or Kafka topic per tenant) | streaming windows: 1s / 60s / 1h ring | Phase 2 | none | #3 | sensor event stream → trajectory canvas updates ≤ 1 s | agreed |
| 7 | **Live File / FIM (endpoint)** | MISS → CFNT | scaffold at `EdrReservedPages.jsx` | no | new route `POST /api/xdr/edr/telemetry/stream` (or ingested via #3) | live FIM stream + remote file-listing API | Phase 2 | none | #3 | sensor file.WRITE landing in xdr_events, queryable via `/api/xdr/events?event_type=file` | agreed |
| 8 | **Live Network / Socket Table** | MISS → CFNT | scaffold at `EdrReservedPages.jsx` | no | ingested via #3 | live socket table + endpoint DNS | Phase 2 | none | #3 | 1000 sockets/s streamed and searchable | agreed |
| 9 | **Distributed Live Query (osquery-compatible)** | SMS at `_stub_ok` | `apps/nivxray-xdr-response/framework/adapters.py:36,88-93` | no (stub) | new: `backend/routers/edr_live_query.py` + `edr_live_query_jobs` coll | fleet-dispatch coordinator, per-agent SQL execution, timeout/cancel | Phase 3 | #1, #3 | dispatch SELECT * FROM processes to 3 agents → aggregated result | agreed |
| 10 | **Forensic Triage Acquisition** | SMS at `_stub_ok` | `apps/nivxray-xdr-response/framework/adapters.py:35,83-87` | no (stub) | new: `backend/routers/edr_forensics.py` + Emergent Object Storage-backed package retention | MFT/prefetch/registry hive capture | Phase 3 | #1, Emergent Object Storage playbook | job triggers via `POST /api/xdr/edr/actions/forensics`; package appears in object storage | agreed |
| 11 | **Response Framework Core (executor, registry, audit)** | IW | `apps/nivxray-xdr-response/framework/{executor,registry,adapters,vendor_adapters}.py`, `backend/routers/xdr_response_evidence.py`, `backend/routers/xdr_cortex_actions.py`, `/api/response/*` | YES 100% | extend adapters (do not modify executor lifecycle) | 7-stage state machine (currently 5) | add STAGE 2 `INTERVENTION_PLAN` + STAGE 4 `ACTION_REQUESTED` post-safety-gate | Phase 1 | none | end-to-end: recommend → plan → approve → gate → request → execute → ack → verify | agreed |
| 12 | **Endpoint Isolation (real driver)** | SMS → CFNT | `apps/nivxray-xdr-response/framework/adapters.py:66-70`, `framework/vendor_adapters.py:217-238` (`real_vendor_call=False`) | orchestration YES; driver NO | new: `src/sensor/isolation/` | NDIS 6.x LWF (Win) / eBPF `XDP`/`tc` (Linux); safety gates | Phase 4 (P0-B) | #1, AD-07 (safety-gate data source), P0-K | isolation dispatched; sensor drops packets except mTLS:443; verifier confirms 0 non-controller outbound over 30 s | agreed |
| 13 | **Process Termination (real driver)** | SMS | same adapters file | orchestration YES; driver NO | new: `src/sensor/kill/` | `ZwTerminateProcess` (Win) / SIGKILL via BPF-LSM (Linux), recursive tree | Phase 4 (P0-B) | #1 | target PID and descendants killed; sensor emits `process.TERMINATE` events | agreed |
| 14 | **File Quarantine (real driver)** | SMS | same adapters file | orchestration YES; driver NO | new: `src/sensor/quarantine/` + `.nvxvault` container | AES-256-GCM local encryption, atomic move | Phase 4 (P0-B) | #1 | file relocated to vault, decryptable only by responder key | agreed |
| 15 | **Memory Acquisition** | MISS → CFNT | none | no | new: `src/sensor/memory/` | WinPmem-equivalent / `/proc/kcore` capture | Phase 4 | #1, retention (P0-G) | RAM dump uploaded to object storage, hashed, indexed | agreed |
| 16 | **Canonical Evidence Vault** | IW at `POST /api/artifacts/analyze`, `GET /api/v2/cases/{id}/artifacts` | `backend/routers/artifacts.py`, `backend/v2/routers/artifacts.py`, `backend/v2/investigation/rte/` | YES 100% | extend to accept EDR/Sandbox event references | none for existing pipeline | none | Phase 1 | none | existing tests remain green | ⚠ Code Map claims `/api/v2/artifacts` and `/api/v2/artifacts/:id`; live routes are `/api/artifacts/*` + `/api/v2/cases/{id}/artifacts` |
| 17 | **59-Decoder Suite** | IW; count unverifiable | `backend/decoders/` (46 top + 15 families = 61), `backend/services/decoder/base/` (7 codec families in DDO) | YES 100% | none | verification script missing | Phase 0.5: ship `verify_decoder_truth_e2e.py` OR expose `GET /api/decode/registry/inventory` | Phase 0.5 | none | script/endpoint returns count + SHA-256 catalog | ⚠ handoff claims "59 registered codecs" – runtime shows 46+15 modules & 7 DDO families; unifying number requires an inventory endpoint |
| 18 | **615 Content Fabric** | IW; count unverifiable | `backend/detection_content/` (52 py modules; 0 rule files) | YES 100% | none | verification script missing | Phase 0.5: ship `run_content_truth_audit.py` OR expose `GET /api/detection-content/inventory` returning rule-object cardinality | Phase 0.5 | none | endpoint returns rule count + rule types | ⚠ handoff says "615 active-certified"; no rule files on disk; count is registry-runtime only |
| 19 | **IUE Lanes A/B/C** | IW | `backend/routers/iue_lane_a.py`, `iue_lane_b.py`, `iue_lane_c.py` | YES 100% | feed EDR identity events | none | none | Phase 3 | #3 | existing IUE tests remain green after EDR user_session events land | agreed |
| 20 | **Correlation Engine (ICE)** | IBI | `backend/routers/correlations.py`, `backend/routers/xdr_correlation.py`, `backend/services/correlation_engine.py` | YES (extend) | none | efficacy corpus missing (P0-I) | do NOT ship EDR without P0-I gate | Phase 3 | P0-I | rule-fires-on-EDR-event test passes | agreed |
| 21 | **IKG / Attack Graph / Attack Story** | IW | `backend/services/ikg/`, `backend/routers/attack_{graph,story}.py` | YES 100% | project EDR events + UBAE anomaly edges | UBAE edge shape not defined | Phase 3 | #22 | UBAE anomaly appears as IKG edge with technique_id | agreed |
| 22 | **UBAE (behavioural baseline)** | MISS → CFNT | none | no | new: `backend/services/ubae/` | baselines per (user, logon_type); peer-group deviation; lateral-movement indicators | Phase 3 | #3, #19 | anomalous Type-2/3/10 logon appears in Entity 360 + IKG | agreed |
| 23 | **Security State FSM** | IW | `backend/routers/rc5_entities.py`, `backend/routers/rc5_diag.py`, `services/security_state/` (**NOT** `backend/security_state/contracts.py`) | YES 100% | derive intervention plans from FSM transitions | none for existing pipeline | Phase 1 (extend read-side only) | none | rc5 tests remain green | ⚠ Code Map + Handoff both cite `backend/security_state/contracts.py` — this path DOES NOT EXIST on `feature/rc2`. Real path: `routers/rc5_*` |
| 24 | **Verdict Stage-2** | IW | `backend/routers/verdict_stage2.py`, `backend/services/verdict_stage2/`, `backend/reasoning/` | YES 100% | none | none | none | Phase 1 | none | existing verdict tests remain green | agreed |
| 25 | **Approval + Ledger + Cryptographic Merkle chain** | IBI at `xdr_audit_log.py`; Merkle chain MISS | `backend/routers/xdr_audit_log.py`, `apps/nivxray-xdr-response/…executor.py` | YES (extend) | append `previous_entry_hash`, `entry_signature` to existing entries | Ed25519 signing key mgmt, chain verifier | Phase 4 | P0-C (SSO), P0-K | chain-verifier CLI validates ledger; retroactive edit detected | agreed |
| 26 | **Multi-tenant enforcement (global)** | IBI at ingest; global middleware MISS | `_principal()` pattern across routers; `xdr_ingest.py` explicit guard | YES (extend) | new: `require_tenant(req)` dependency + Mongo filter middleware | adversarial cross-tenant test | Phase 0.5 (blocks Phase 1) | P0-D | pytest: tenant-A cannot read tenant-B endpoints/events/incidents | agreed with §12 of Handoff Security Tenancy |
| 27 | **SSO / OIDC (authlib)** | MISS → CFNT | none | no | new: `backend/routers/auth_oidc.py` | authlib generic OIDC client + JIT provisioning + `OIDC_ALLOWED_DOMAINS` | Phase 0.5 (parallel prereq) | P0-C | Okta test tenant login → user auto-provisioned into `xdr_users` | agreed (from GA_BLOCKERS P0-C) |
| 28 | **Retention / Backup / Restore / Purge** | MISS → CFNT | none | no | new: TTL indexes + nightly `mongodump` runner + tenant-purge API | policy per tenant | Phase 0.5 | P0-G | tenant-A purge deletes only tenant-A rows; restore drill runs green | agreed |
| 29 | **K8s / HA / Helm chart** | MISS → CFNT | docker-compose floor at `deploy/` only | no | new: `deploy/helm/` | Mongo replica set + backend HPA + ingress + ServiceMonitor | Phase 4 | P0-J | rolling upgrade with 0 downtime for 2 min traffic burst | agreed |
| 30 | **Security scan pipeline (Trivy / Grype / ZAP / SBOM)** | MISS → CFNT | none | no | new: `.github/workflows/security_scan.yml` | scan + SBOM at every merge | Phase 0.5 (blocks Phase 4 driver ship) | P0-K | pipeline blocks merge on CVE ≥ HIGH | agreed |
| 31 | **Sandbox Runner (MicroVM/QEMU)** | MISS → CFNT | none | no | new: `apps/nivxray-xdr-sandbox/` | Firecracker + INETSim + WireGuard egress + snapshot/rollback | Phase 4 | #12, #29 | detonation completes ≤ 500 ms boot; PCAP + syscall trace committed | agreed |
| 32 | **Sandbox → Decoder handoff** | MISS | none | pipeline exists at `POST /api/decode/smart` | no | forwarding + dedup + provenance chaining | Phase 4 | #31, #17 | dropped payload forwarded and decoded; provenance chain unbroken | agreed |
| 33 | **Verification loop (30 s post-isolation)** | MISS | none | none | new: `services/verification/` scheduled job | 30 s scan of network events for target device | Phase 4 | #12 | isolation completes → `VerificationEvidence` written within 30 s | agreed |

---

## §V · Documentation-vs-Code Path Drift Ledger (six discrepancies to reconcile before Phase 1)

| # | Handoff-claimed path | Reality on `feature/rc2` | Recommended reconciliation |
|---|---|---|---|
| PD-1 | `backend/security_state/contracts.py` | DOES NOT EXIST | Handoff should reference `backend/routers/rc5_entities.py` + `services/security_state/` (existing FSM). Rename in an ADR; do not create a phantom module. |
| PD-2 | `backend/security_state/detection_bridge.py` | DOES NOT EXIST | Same as PD-1; the "detection bridge" concept lives inline in `verdict_stage2.py` + rc5 routers. |
| PD-3 | `backend/run_content_truth_audit.py` | DOES NOT EXIST | Ship it OR replace with `GET /api/detection-content/inventory` runtime endpoint. |
| PD-4 | `backend/verify_decoder_truth_e2e.py` | DOES NOT EXIST | Ship it OR replace with `GET /api/decode/registry/inventory` runtime endpoint. |
| PD-5 | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | DOES NOT EXIST | Real files: `/app/frontend/src/pages/EvidenceExplorerPage.jsx` (main SPA), and `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` (companion). Update handoff paths accordingly. |
| PD-6 | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | DOES NOT EXIST | Real files: `/app/frontend/src/v2/pages/InvestigationWorkspace.jsx`, `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx`. Update handoff paths. |

---

## §W · API-Namespace Reconciliation Options

| Option | Pattern | Pros | Cons | Recommendation |
|---|---|---|---|---|
| A | Extend `/api/xdr/*` (`/api/xdr/edr/telemetry/stream`, `/api/xdr/edr/fleet/live-query`, `/api/xdr/sandbox/detonate`) | reuses `_principal` + `xdr_ingest` cross-tenant guard; consistent with existing collectors | slightly longer URLs | ✅ RECOMMENDED |
| B | Reserve `/api/v2/edr/*` and `/api/v2/sandbox/*` | matches handoff naming | collides with existing `backend/v2/routers/*` scope; requires disambiguation | acceptable if scoped properly |
| C | New top-level `/api/edr/v2/*` / `/api/sandbox/v2/*` | isolates versioning | fragments API surface | ❌ REJECT |

---

## §X · Test Corpus for Acceptance

- `pytest backend/tests` — baseline: **195/195 pass**, 1 intentional mal-20 FN. MUST remain identical after every Phase-1 merge.
- New folders (proposed):
  - `backend/tests/edr/test_enrollment.py`
  - `backend/tests/edr/test_ingest_canonical.py`
  - `backend/tests/edr/test_cross_tenant.py` (P0-D adversarial)
  - `backend/tests/edr/test_response_lifecycle_extended.py`
  - `backend/tests/edr/test_openapi_surface.py`
- No frontend test changes in Phase 1 (UI freeze).

---

## END · MATRIX DELIVERED (read-only)
