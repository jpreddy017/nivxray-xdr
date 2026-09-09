# NIVXFORGE EDR · EMERGENT INTEGRATION REVIEW (Gate 0)

> **Mode:** READ-ONLY architecture and integration review.
> **Rule:** Runtime + code evidence AUTHORITATIVE over documentation. When the handoff package and the live NivXRay codebase disagree, this review records what the code says.
> **Package audited:** `NIVXFORGE_EDR_EMERGENT_HANDOFF_PACKAGE.zip` (SHA-256 `80fa675dc4e04e3a999c00480be4048c8e726870b75d586299961fb7a2d7e756`, 25 files, 24/24 SHA256SUMS validated).
> **NivXRay baseline pinned at:** commit `d3f7a0a000892131abc9a32ee97009338dd38d79` (immutable truth-contract) plus live-pod verification (`curl` + on-pod `find`/`grep`).
> **Companion artifacts (this deliverable):**
> - `NIVXFORGE_EDR_EMERGENT_INTEGRATION_MATRIX.md`
> - `NIVXFORGE_EDR_EMERGENT_PHASE1_PLAN.md`
> **Gate status:** ⛔ IMPLEMENTATION NOT AUTHORIZED. Zero code changes made. No git operations. UI freeze respected. Content Fabric and decoders untouched.

---

## A. Executive Summary

The handoff package proposes a **cross-platform EDR sensor + UBAE + Native Dynamic Sandbox** subsystem that plugs into an unchanged NivXRay core along an 8-stage causal pipeline (Telemetry → Canonical Evidence → IUE/ICE → IKG → Security State → Verdict → Response → Verification). The proposal is architecturally sound and correctly identifies the core "do not rebuild" list. However **four categories of misalignment** must be resolved before Phase 1 begins:

1. **Path drift in the Code-to-Capability Map.** The map (`05_INTEGRATION_CONTRACTS/NIVXFORGE_EDR_CODE_CAPABILITY_MAP.md`) references six repository paths that do not exist on the current `feature/rc2` branch. The EDR Truth Audit (`02_EDR_TRUTH/…`) is largely honest but points at some of the same non-existent paths. Emergent must NOT trust the Code Map at face value; every claim needs a live-code re-anchor before wiring.
2. **Counting claims that cannot be verified.** "615 Content Fabric objects" and "59 registered decoders" are cited as unconditional truth (Reference: [`README.md §C`], [`HANDOFF.md §2`], [`SCOPE_AND_BOUNDARIES.md §3.4/§3.8`]), backed by two executable-verification scripts (`backend/run_content_truth_audit.py`, `backend/verify_decoder_truth_e2e.py`) that **do not exist in the repository**. `backend/detection_content/` contains 52 Python infrastructure modules and 0 rule files; `backend/decoders/` contains 46 top-level codecs + 15 family decoders = 61 modules (not 59). The counts may still be true when reduced to a "content-object registry cardinality," but the truth is unverifiable until the two audit scripts are actually shipped or replaced with authoritative introspection endpoints.
3. **The proposed API namespace collides with existing routes.** The handoff standardizes on `/api/v2/*` for EDR/Sandbox (e.g., `POST /api/v2/edr/telemetry/stream`, `POST /api/v2/sandbox/detonate`, `GET /api/v2/artifacts/:id`). The live backend has:
   - Artifacts router at `/api/artifacts/*` (not `/api/v2/artifacts/*`).
   - A separate `backend/v2/routers/*` sub-tree owning `/api/v2/*` for a different concern (canonical-evidence recovery + investigation).
   - A canonical XDR ingest route at `POST /api/xdr/ingest/telemetry` — the pattern the handoff-proposed `POST /api/v2/edr/telemetry/stream` should EXTEND rather than parallel.
   Emergent must reconcile the namespace, ideally reusing `/api/xdr/ingest/telemetry` for the EDR canonical envelope so the P0-D tenant-isolation guard already coded there applies unchanged.
4. **The UI-integration map assumes standalone-app pages (`apps/nivxray-xdr/src/xdr/pages/Xdr…Page.jsx`) that do not exist in this branch.** The actual Evidence Explorer is at `/app/frontend/src/pages/EvidenceExplorerPage.jsx` (main NivXRay SPA); the investigation workspace at `/app/frontend/src/v2/pages/InvestigationWorkspace.jsx` and `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx`. Because the **UI is under an absolute freeze** per `GA_BLOCKERS.md`, all new EDR/Sandbox screens must be delivered as backend + API-contract only during Phase 1-3; frontend wiring resumes only after the UI-freeze exception is granted.

**Verdict:** ✅ Design coherent · ⚠ Documentation partially drifts from code · ⚠ API namespace overlap · ⛔ UI freeze must be reconciled before any Phase 1 UI wiring · ⛔ 6 non-existent paths must be corrected before implementation.

---

## B. Current-State Truth (recap · authoritative)

Anchored to `/app/docs/truth-contract/NIVXRAY_CURRENT_STATE_TRUTH.md` + `.json` (commit `d3f7a0a…`):

- 128 backend router modules, 717 OpenAPI paths, 792 operations. Live-verified `curl /api/health` = 200, `curl /api/metrics` returns Prometheus, `curl /api/openapi.json` = 595 KB.
- **Existing engines/routes verified alive** (subset relevant to EDR): `iue_lane_{a,b,c}.py`, `correlations.py`, `xdr_correlation.py`, `attack_graph.py`, `attack_story.py`, `verdict_stage2.py`, `reasoning/`, `detection_content/` (52 modules), `decoders/` (46+15 modules), `xdr_ingest.py` (cross-tenant guard already coded here), `xdr_cortex_actions.py`, `xdr_response_evidence.py`, `xdr_audit_log.py`, `investigations.py`, `timeline.py`, `process_tree.py`, `edr.py` (read-only projection).
- **Sprint 1 closed (P0-E/F/H):** JSON logs, Prometheus, cardinality-safe route templates, docker-compose floor, route-consistency `/api/response/*` alias.
- **Open GA blockers (unchanged since audit):** P0-A (real vendor telemetry), P0-B (real response executors), P0-C (SSO/OIDC), P0-D (multi-tenant adversarial test), P0-G (retention/backup), P0-I (detection efficacy), P0-J (HA/K8s), P0-K (pen-test).

Absolute rules still in force:
- **Honest-state / NO EVIDENCE → NO CLAIM.**
- **UI freeze.**
- **No decoder scope creep.**
- **`/app/memory/` outside git commit scope** (Save-to-GitHub only pushes `docs/*`, `backend/*`, `frontend/*`, etc.).

---

## C. Existing Capabilities (path-verified live)

| Existing capability | Verified path(s) on `feature/rc2` | Grade (8-state) |
|---|---|---|
| Auth (JWT + rate limit + force-change) | `backend/routers/auth.py` | IMPLEMENTED_AND_WORKING |
| RBAC dependency + audit log | `routers/xdr_rbac.py`, `routers/xdr_audit_log.py` | IMPLEMENTED_AND_WORKING |
| Observability (JSON logs + Prometheus + trace-id) | `observability/__init__.py` | IMPLEMENTED_AND_WORKING |
| Canonical ingest w/ cross-tenant guard | `routers/xdr_ingest.py` | IMPLEMENTED_AND_WORKING |
| Data-source catalogue (16 kinds) | `routers/xdr_data_sources.py` | IMPLEMENTED_AND_WORKING |
| Collectors framework | `apps/nivxray-xdr-collector/` (3,407 LOC) | IMPLEMENTED_BUT_NOT_WIRED (no live pollers configured) |
| Universal Decoder (DDO orchestrator + 7 codec families in `services/decoder/base/`) | `services/decoder/base/`, `services/decoder/orchestrator.py` | IMPLEMENTED_AND_WORKING |
| Legacy decoder tree (still imported by `server.py`) | `backend/decoders/` (46 top-level + 15 in `families/`) | IMPLEMENTED_AND_WORKING |
| Decode API surface | `POST /api/decode/smart`, `POST /api/decode/magic`, `POST /api/decode/candidates`, `POST /api/decode/chain/*` | IMPLEMENTED_AND_WORKING |
| Analyzers (PE + Shellcode) | `services/analyzers/{pe,shellcode}.py` | IMPLEMENTED_AND_WORKING |
| Attack Story / Attack Graph / IKG-adjacent | `services/ikg/`, `routers/attack_{graph,story}.py` | IMPLEMENTED_AND_WORKING |
| Verdict Stage-2 | `routers/verdict_stage2.py`, `services/verdict_stage2/` | IMPLEMENTED_AND_WORKING |
| Correlation | `routers/correlations.py`, `routers/xdr_correlation.py`, `services/correlation_engine.py` | IMPLEMENTED_BUT_INCOMPLETE (no efficacy corpus) |
| Rule Studio | `routers/xdr_rule_studio.py` (20 routes) | IMPLEMENTED_BUT_INCOMPLETE |
| Incident projection | `routers/incidents.py` (from `workspace_cases`) | IMPLEMENTED_AND_WORKING |
| EDR read-only projection | `routers/edr.py` (projects endpoints/detections/process-tree/trajectory from cases) | IMPLEMENTED_AND_WORKING (as projection only — NOT a live agent stream) |
| Device Trajectory (5-lane batch) | `routers/edr.py:267-435`, `backend/v2/routers/trajectory.py`, `XdrDeviceTrajectoryPage.jsx` (companion app) | IMPLEMENTED_AND_WORKING (case-batch); STREAMING = MISSING |
| Process Tree | `routers/edr.py:110-165`, `backend/v2/routers/ancestry.py`, `EdrProcessTreePage.jsx` | IMPLEMENTED_AND_WORKING (case-projection); LIVE = MISSING |
| Artifact analyzer | `routers/artifacts.py` (`/api/artifacts/*`) | IMPLEMENTED_AND_WORKING |
| v2 case artifacts | `backend/v2/routers/artifacts.py` (`/api/v2/cases/{id}/artifacts`) | IMPLEMENTED_AND_WORKING |
| Response executor app + registry | `apps/nivxray-xdr-response/framework/{executor,registry,adapters,vendor_adapters}.py` | IMPLEMENTED_BUT_NOT_WIRED (executor lifecycle real; adapters are `_stub_ok`; vendor `real_vendor_call=False`) |
| Response route alias | `/api/response/*` (Sprint 1 P0-H) | IMPLEMENTED_AND_WORKING |
| RC5 Security-State-ish FSM | `routers/rc5_entities.py`, `routers/rc5_diag.py` | IMPLEMENTED_AND_WORKING (state transitions coded; **NOT** at `backend/security_state/contracts.py` as claimed by handoff) |

---

## D. Reusable NivXRay Core (DO NOT REBUILD)

The following existing engines and their exact live paths are the mandatory reuse boundaries. Every EDR/UBAE/Sandbox capability MUST attach to these — no parallel implementations.

| Capability | Live path | Reuse verb |
|---|---|---|
| Canonical ingest + tenant guard | `backend/routers/xdr_ingest.py` (`POST /api/xdr/ingest/telemetry`, `CanonicalEnvelope`) | REUSE AS-IS · extend `SOURCE_KINDS` with EDR/Sandbox source kinds |
| Canonical-evidence recovery pipeline | `backend/services/canonical_evidence_recovery.py`, `backend/v2/investigation/rte/` | REUSE AS-IS |
| IUE Lanes A/B/C | `backend/routers/iue_lane_{a,b,c}.py` | REUSE AS-IS |
| ICE (correlation) | `backend/routers/correlations.py`, `backend/routers/xdr_correlation.py`, `backend/services/correlation_engine.py` | REUSE AS-IS |
| IKG / Attack Graph / Attack Story | `backend/services/ikg/`, `backend/routers/attack_{graph,story}.py` | REUSE AS-IS |
| Security-State FSM | `backend/routers/rc5_entities.py`, `backend/routers/rc5_diag.py` (**NOT** `backend/security_state/`) | REUSE AS-IS |
| Verdict Stage-2 | `backend/routers/verdict_stage2.py`, `backend/services/verdict_stage2/`, `backend/reasoning/` | REUSE AS-IS |
| Universal Decoder | `backend/services/decoder/*`, `backend/decoders/*` (both wired via `server.py`) | REUSE AS-IS |
| Content Fabric | `backend/detection_content/` (52 Python modules) | REUSE AS-IS |
| Analyzers | `backend/services/analyzers/{pe,shellcode}.py`, `services/uaie/`, `services/ida/` | REUSE AS-IS |
| Rule Studio | `backend/routers/xdr_rule_studio.py` | REUSE AS-IS |
| Approval + response ledger | `apps/nivxray-xdr-response/framework/{executor,registry}.py`, `backend/routers/xdr_response_evidence.py`, `backend/routers/xdr_cortex_actions.py`, `/api/response/*` alias | REUSE + EXTEND ADAPTERS |
| Audit log (tamper-evident) | `backend/routers/xdr_audit_log.py` (`emit_audit`) | REUSE AS-IS |
| Observability envelope | `backend/observability/__init__.py` (logs + metrics + trace-id + tenant-id) | REUSE AS-IS · MUST emit through same root logger + `REGISTRY` |

---

## E. EDR Capability Gap Matrix (summary — see companion Matrix doc for row-by-row)

Grades map handoff-claimed **status** ⇒ authoritative code-verified **grade**:

| Capability | Handoff status | Code-verified grade | Delta |
|---|---|---|---|
| EDR Agent (Win minifilter / Linux eBPF / macOS Endpoint Security) | MISSING | MISSING → **CANDIDATE_FOR_NEW_TECHNOLOGY** | agreed |
| Endpoint Registration / Health | PARTIAL | IMPLEMENTED_AND_WORKING as projection; **STUB** as live enrollment | agreed |
| Telemetry Ingestion (endpoint) | PARTIAL | IMPLEMENTED_AND_WORKING at `/api/xdr/ingest/telemetry`; endpoint-vendor pollers **MISSING** | agreed |
| Endpoint Detections | PARTIAL | IMPLEMENTED_AND_WORKING as read-only case projection; live-detection loop MISSING | agreed |
| Process Tree (live) | SCAFFOLD (per Code Map) / IMPLEMENTED (per Truth Audit) | IMPLEMENTED_AND_WORKING for batch/case; **live streaming MISSING** | ⚠ Code Map inconsistent with Truth Audit |
| Device Trajectory (5-lane microsecond) | PARTIAL (per Code Map) | IMPLEMENTED_AND_WORKING for case-scoped 1h/6h/12h/24h/3d/7d windows; **microsecond streaming MISSING** | agreed |
| Files / Network / DNS / Registry / Services (live endpoint monitors) | SCAFFOLD | MISSING → **CANDIDATE_FOR_NEW_TECHNOLOGY** | agreed |
| Threat Hunting (distributed fleet query) | SCAFFOLD | MISSING (Rule Studio ≠ live fleet query) | agreed |
| Forensics acquisition | SCAFFOLD | STUB_MOCK_SCAFFOLD (`endpoint_collect_forensics = _stub_ok`) | agreed |
| Live Query (osquery) | SCAFFOLD | STUB_MOCK_SCAFFOLD (`endpoint_live_query = _stub_ok`) | agreed |
| Response Framework | IMPLEMENTED | IMPLEMENTED_AND_WORKING (orchestration/idempotency/audit) | agreed |
| Endpoint Isolation | PARTIAL | STUB_MOCK_SCAFFOLD → **CANDIDATE_FOR_NEW_TECHNOLOGY**; adapter returns `simulation_only=True` | agreed |
| File Quarantine | SCAFFOLD/MOCK | STUB_MOCK_SCAFFOLD | agreed |
| Evidence Collection | PARTIAL | IMPLEMENTED_AND_WORKING (case ingestion) + `SAMPLE_ARTIFACTS` UI fallback (dishonest state — flagged) | agreed |
| Memory / Volatile Evidence | MISSING | MISSING | agreed |
| Artifact Retention 64 KB | IMPLEMENTED | IMPLEMENTED_AND_WORKING | agreed |
| Hash / Reputation Intel | PARTIAL | IMPLEMENTED_BUT_INCOMPLETE (backend routes present; XDR UI reserved) | agreed |
| Static Malware Analysis | IMPLEMENTED | IMPLEMENTED_AND_WORKING | agreed |
| Decoder Integration ("59 codecs") | IMPLEMENTED | IMPLEMENTED_AND_WORKING at 46 + 15 modules; **exact count 59 unverifiable** without `verify_decoder_truth_e2e.py` | ⚠ counting claim unverifiable |
| YARA / Content Engine ("615 objects") | IMPLEMENTED | IMPLEMENTED_AND_WORKING at 52 Python modules + `yara_engine.py`; **exact 615 count unverifiable** without `run_content_truth_audit.py` | ⚠ counting claim unverifiable |
| IKG / Investigation | IMPLEMENTED | IMPLEMENTED_AND_WORKING (services/ikg exists); UI paths in handoff drift from repo | ⚠ UI paths drift |
| Security State FSM | IMPLEMENTED | IMPLEMENTED_AND_WORKING at `routers/rc5_entities.py` (**NOT** `backend/security_state/`) | ⚠ path drift |
| Sandbox (native dynamic detonation runner) | MISSING | MISSING → **CANDIDATE_FOR_NEW_TECHNOLOGY** (P4) | agreed |

---

## F. UI/UX Gap Matrix (summary — deferred until UI-freeze exception granted)

Under absolute UI freeze per `GA_BLOCKERS.md`. Findings recorded read-only:

- The Code-to-Capability Map references `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` and `XdrInvestigationWorkspacePage.jsx` — these paths **DO NOT EXIST** on the current branch. Reality:
  - Main NivXRay SPA: `/app/frontend/src/pages/EvidenceExplorerPage.jsx` (Evidence Explorer)
  - v2 workspace: `/app/frontend/src/v2/pages/InvestigationWorkspace.jsx`
  - Companion XDR SPA: `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx`, `apps/nivxray-xdr/src/xdr/pages/XdrDeviceTrajectoryPage.jsx`, `apps/nivxray-xdr/src/nivxforge/pages/{EdrOverviewPage,EdrDetectionsPage,EdrProcessTreePage,EdrReservedPages}.jsx`, `apps/nivxray-xdr/src/nivxforge/NivXForgeConsole.jsx`, `apps/nivxray-xdr/src/nivxforge/edrApi.js`.
- The EDR Truth Audit correctly flags **`SAMPLE_ARTIFACTS`** hardcoded fallback in `XdrEvidenceExplorerPage.jsx` and hardcoded structural data in `XdrInvestigationWorkspacePage.jsx` Tabs 2/3/5/6/7/8. **These fallbacks violate honest-state.** Remediation must be included in whatever UI-freeze exception is granted for EDR rollout.
- The 37-Surface Information Architecture, Attack-Chain UX Matrix, Sandbox UI/UX Spec, and Operational Prototype HTML are UX references only. They MUST NOT be treated as evidence that any backend capability exists.
- **No UI implementation is authorized in Phase 1.** Frontend work belongs to a later phase (or the UI-freeze must be lifted for EDR-specific surfaces with explicit owner sign-off).

---

## G. Attack-Chain Gap Matrix

The 20-step chain (`Detection → Alert → Process → Parent → Device → User → Network → DNS → IOC → Dropped File → Sandbox → Dynamic Evidence → ATT&CK → IKG → Security State → Verdict → Impact → Response → Verification`) is well-mapped in the handoff. Live-verified status per transition:

| Transition | Stable identifier | Existing carrier route | Status |
|---|---|---|---|
| Detection → Alert | `alert_id` | `routers/xdr_correlation.py`, `routers/verdict_stage2.py` | IMPLEMENTED_AND_WORKING |
| Alert → Process | `process_guid = {device_id}:{pid}:{epoch}` (as proposed) | `routers/edr.py`, `backend/v2/routers/ancestry.py`, `services/ikg/` | IMPLEMENTED for case-scope · Streaming MISSING |
| Process → Parent | `parent_process_guid` | same | IMPLEMENTED for case-scope · Streaming MISSING |
| Parent → Device | `device_id` | `routers/edr.py`, `services/activity/` | IMPLEMENTED_AND_WORKING for case-scope |
| Device → User | `user_id` (AD SID / UPN / UID) | `routers/iue_lane_*.py` | IMPLEMENTED_AND_WORKING |
| User → Network / DNS | `network_flow_id`, `dns_event_id` | `routers/xdr_ingest.py`, `services/canonicalizer/` | IMPLEMENTED for schema · endpoint-sourced telemetry MISSING |
| Network → IOC | `ioc` (hash / URL / IP tuple) | `routers/ioc_intelligence.py`, `routers/threat_intel.py`, `services/die/` | IMPLEMENTED_AND_WORKING |
| IOC → Dropped File | `artifact_sha256` | `backend/v2/routers/artifacts.py`, `backend/routers/artifacts.py` | IMPLEMENTED_AND_WORKING |
| File → Sandbox | `sandbox_job_id` | — | **MISSING** (sandbox subsystem entire P4) |
| Sandbox → Dynamic Evidence | `dynamic_evidence_ids` | — | MISSING |
| DynEvidence → ATT&CK | `attck_technique_id` | `routers/mitre_heatmap.py`, `services/ikg/`, `detection_content/` | IMPLEMENTED_AND_WORKING |
| ATT&CK → IKG | `ikg_node_edge_ids` | `services/ikg/` | IMPLEMENTED_AND_WORKING |
| IKG → Security State | `security_state_version` | `routers/rc5_entities.py`, `routers/rc5_diag.py` | IMPLEMENTED_AND_WORKING |
| Security State → Verdict | `verdict_id` | `routers/verdict_stage2.py` | IMPLEMENTED_AND_WORKING |
| Verdict → Impact | `impact_assessment_id` | `services/reasoning/` | IMPLEMENTED_BUT_INCOMPLETE |
| Impact → Response | `response_action_id` | `apps/nivxray-xdr-response/framework/executor.py`, `/api/response/*` | IMPLEMENTED_AND_WORKING (orchestration) · Real drivers MISSING |
| Response → Verification | `verification_evidence_id` | `routers/xdr_response_evidence.py` | IMPLEMENTED_AND_WORKING for storage · verification loop (30 s post-isolation) MISSING |

---

## H. UBAE Integration Gap Matrix (summary)

The proposal correctly says UBAE must project identity anomaly edges into IKG rather than run a parallel analytics silo. Live baseline:

- **IUE lanes A/B/C** already resolve identity across process/user/device (existing). Extend with:
  - Behavioural baselining per user × logon-type (interactive-2 / network-3 / RDP-10) — **MISSING**
  - Peer-group deviation scoring — **MISSING**
  - Lateral-movement indicator projections onto IKG — **MISSING**
  - Progression labels `BASELINE → ANOMALY → ABUSE → COMPROMISE` — **MISSING** (RC5 FSM has cognate `AUTHORIZED_ADMIN → SUSPICIOUS_UNMANAGED → ABUSED_CAPABILITY → CONFIRMED_ATTACK` — reuse rather than parallel model).

## I. Sandbox Integration Gap Matrix (summary)

- Zero sandbox runtime exists on this branch (no MicroVM/QEMU orchestrator, no INETSim harness, no `sandbox_*` event handlers, no `/api/v2/sandbox/*` routes).
- Correctly proposed as evidence-producing only; MUST emit `sandbox_*` events into `POST /api/xdr/ingest/telemetry` under an extended `SOURCE_KINDS` entry (`sandbox_hypervisor`).
- 15 event classes and dropping-payload-forward-to-59-decoder handshake are well-scoped. Sandbox is P4 by handoff and this review concurs — do not start until EDR sensor + telemetry pipeline is proven.

## J. Response Integration Review

- Existing 5-state lifecycle (`REQUESTED → APPROVED → EXECUTING → SUCCEEDED/FAILED → VERIFIED`) is a proper subset of the proposed 7-state model. Add STAGE 2 (`INTERVENTION_PLAN`) and STAGE 4 (`ACTION_REQUESTED` — post-safety-gate dispatch) without breaking the existing DB records.
- **Safety-gate invariant is NEW.** Domain-Controller check + Healthcare-ICU tag check + controller-mTLS pin MUST be implemented before any real isolation driver ships. Without these gates, isolation MUST remain `capability_available=false`.
- Real drivers (`NetworkIsolationDriver`, `ProcessTerminationDriver`, `QuarantineVaultDriver`) are net-new (P0-B in the truth contract → now Phase 1-4 in the handoff).
- Verification loop (30 s post-isolation invariant) is NEW; must be a scheduled job that reads from the same telemetry pipeline (no parallel verifier).

## K. Multi-Tenancy / Security Review

- Server-side tenant context invariant already partially enforced at `_principal(req)` + `xdr_ingest.py`. Extend the pattern with:
  - **`require_tenant(req)`** FastAPI dependency (analogous to existing `require_permission`) — MISSING.
  - **Global Mongo filter middleware** — MISSING.
  - **Adversarial cross-tenant negative test** — MISSING (this is P0-D in the truth contract; **it MUST be closed before any EDR endpoint accepts multi-tenant sensor telemetry**).
- **Sensor PKI + mTLS**: currently no CA, no CSR/enrollment flow, no cert-rotation daemon — build in Phase 1.
- **Sandbox isolation stack**: KVM + cgroups v2 + seccomp-bpf + netns — build in Phase 4.
- **Cryptographically-sealed audit ledger with Merkle hash chain** is a superset of the existing tamper-evident `xdr_audit_log.py`. **Extend** rather than replace; append `previous_entry_hash` and `entry_signature` fields to existing entries so historical audit is not fractured.

## L. API / Contract Review

- **API namespace decision required.** Options (order of preference):
  1. **Extend `/api/xdr/*`** (recommended). New routes: `POST /api/xdr/edr/telemetry/stream`, `POST /api/xdr/edr/fleet/live-query`, `POST /api/xdr/response/actions/isolate` (already exists in a form), `POST /api/xdr/sandbox/detonate`, `GET /api/xdr/sandbox/jobs/:id/trace`. Advantage: reuses existing `_principal`/`require_permission` boundary and tenant-guarded ingest.
  2. **Reserve `/api/v2/edr/*`** and `/api/v2/sandbox/*` (as handoff proposes). Requires ensuring these do NOT collide with the existing `backend/v2/routers/*` (which handles investigation/RTE/canonical-recovery and already owns `/api/v2/*`).
  3. **Reject:** parallel `/api/edr/v2/*` route lanes — creates fragmentation.
- **Canonical envelope alignment.** The handoff's `envelope_version = 2.0.0` proposes fields (`evidence_id`, `event_id`, `provenance.collector_version`, `provenance.kernel_driver_hook`, `confidence`, `raw_event`, `canonical_event`) that are strictly a superset of the existing `CanonicalEnvelope` in `xdr_ingest.py`. RECOMMEND: extend the existing model in-place (as opt-in fields) rather than fork a new schema — preserves current collectors while allowing new EDR/Sandbox sources.
- **OpenAPI regeneration.** New EDR routes must be documented via the same `openapi.json` surface (P0-H closed). The Prometheus route-template cardinality-safety rule must be preserved (no per-`{command_id}` labels).

## M. Data Model Review

New collections required (subject to P0-D + P0-G resolution):
- `edr_endpoints` (device inventory · immutable UUID + cert subject key identifier)
- `edr_enrollment_tokens` (short-lived, hashed)
- `edr_sensor_health` (heartbeat + version + kernel driver status)
- `edr_telemetry_events` (or extend `xdr_events`; RECOMMEND the latter with `source ∈ EDR_SENSOR_{WIN,LINUX,DARWIN}, SANDBOX_HYPERVISOR`)
- `edr_live_query_jobs` (fleet dispatch)
- `edr_forensics_packages` (large payload references — MUST be object-storage-backed per handoff, per Emergent Object Storage playbook)
- `edr_isolation_ledger` (append-only Merkle-chained containment actions)
- `sandbox_jobs` (job status)
- `sandbox_evidence_events` (or extend `xdr_events` — RECOMMEND the latter)

Existing collections that must remain untouched: `workspace_cases`, `investigations`, `xdr_events`, `xdr_data_sources`, `xdr_secrets`, `xdr_audit_log`, `xdr_users/roles/groups/user_roles`.

## N. Dependency Graph (Phase order)

```
P0-D adversarial cross-tenant test (BLOCKS Phase 1 ingest)
        │
        └──► Phase 1: EDR Sensor + Telemetry (mTLS PKI, /api/xdr/edr/telemetry, canonical extension)
                  │
                  └──► Phase 2: Live Query + Trajectory streaming + Process-tree streaming + Forensics acquisition
                            │
                            └──► Phase 3: UBAE (behavioural baseline → IKG edges → rc5 FSM extension)
                                      │
                                      └──► Phase 4: Native Dynamic Sandbox (evidence-producing subsystem)

Parallel prereq (Phase 0.5): P0-C SSO/OIDC (should ship BEFORE tenant-scoped EDR consoles go live)
Parallel prereq (Phase 0.5): P0-G retention / immutable-ledger extension
Parallel prereq (Phase 0.5): P0-J K8s / Helm floor (before multi-node sensor traffic)
Cross-cutting: P0-K security-scan pipeline (before ANY real response driver merges to main)
```

## O. Risks / Conflicts

**High**
- **R-1 · Six non-existent paths in the Code Map** (see §Q). If Emergent implements against the handoff's Code Map without re-anchoring, Phase 1 code will import from nowhere and fail on first run.
- **R-2 · Unverifiable "615 + 59" counts.** Two audit scripts referenced as authoritative evidence are missing. Any acceptance-test that reads them will fail.
- **R-3 · UI freeze conflict.** The 37-surface UI map and Sandbox operational prototype cannot be implemented without a written UI-freeze exception.
- **R-4 · P0-D missing.** Without an adversarial cross-tenant test, adding endpoint-sensor multi-tenant traffic increases the blast radius of any tenant-isolation bug.

**Medium**
- **R-5 · API-namespace overlap** with existing `backend/v2/*` unless the option-1 recommendation is adopted.
- **R-6 · Sensor kernel-driver risk** (BSOD / kernel-panic) requires a hardware watchdog, CPU cap (<2 %), and rollback ring; handoff addresses this in §23 of the Handoff but must land as code-level guardrails in Phase 1.
- **R-7 · Response safety-gate coverage.** Domain-Controller detection depends on AD directory reachability which may fail — safety-gate MUST fail-closed (deny isolation if DC-status cannot be verified).

**Low**
- **R-8 · `SAMPLE_ARTIFACTS` fallback** still in `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` (referenced by Truth Audit). Not a new build blocker but violates honest-state — schedule removal.

## P. Architecture Decisions Required (owner sign-off before Phase 1)

- **AD-01 · API namespace:** confirm option-1 (extend `/api/xdr/*`) vs option-2 (reserve `/api/v2/edr/*`, `/api/v2/sandbox/*`) vs owner-directed alternative.
- **AD-02 · Canonical envelope evolution:** confirm extending existing `CanonicalEnvelope` in `xdr_ingest.py` vs shipping `envelope_version = 2.0.0` in a new module.
- **AD-03 · Security State module location:** the handoff assumes `backend/security_state/contracts.py` which does not exist. Reality: the FSM lives in `backend/routers/rc5_entities.py`. Confirm rename/refactor vs reuse-in-place. RECOMMEND reuse-in-place; do not create a phantom `security_state/` module without a plan to migrate rc5 first.
- **AD-04 · UI-freeze exception scope:** confirm whether Phase 1-3 is backend-only (recommended) or whether a limited-scope UI-freeze lift for EDR surfaces is granted.
- **AD-05 · Two missing audit scripts:** confirm plan — either ship `run_content_truth_audit.py` + `verify_decoder_truth_e2e.py` alongside Phase 0.5, OR replace them with introspection endpoints (`GET /api/detection-content/inventory`, `GET /api/decode/registry/inventory`).
- **AD-06 · P0-D adversarial test:** confirm hard prereq: no Phase-1 endpoint sensor traffic accepted until the cross-tenant negative test suite exists and passes.
- **AD-07 · Response safety-gate data source:** confirm how "is Domain Controller" and "is ICU / Healthcare" are known (AD adapter + endpoint tag registry). MUST fail closed.
- **AD-08 · Sensor kernel-driver signing:** confirm code-signing certificate provenance for Windows minifilter (Microsoft attestation vs Emergent-issued dev cert during Phase 1).

## Q. Proposed Implementation Order

**Phase 0.5 · Truth Reconciliation & Prerequisite Closure (before any EDR code)**
1. Emergent publishes the six missing paths / renamed modules in a `TRUTH_RECONCILIATION.md` addendum (see companion Matrix doc §V).
2. Emergent ships the two missing audit scripts OR the introspection endpoints.
3. Close P0-D adversarial cross-tenant test (backend-only; no UI change).
4. Land the API-namespace decision (§AD-01) and canonical-envelope decision (§AD-02) in an ADR.

**Phase 1 · EDR Sensor & Telemetry (detailed in `NIVXFORGE_EDR_EMERGENT_PHASE1_PLAN.md`)**

**Phase 2 · EDR Investigation & Analytics** — live process tree, 5-lane microsecond trajectory, distributed live query.

**Phase 3 · UBAE** — behavioural baselining, peer-group deviation, IKG-edge projection.

**Phase 4 · Native Dynamic Sandbox** — evidence-producing detonation subsystem.

## R. Phase 1 Detailed Plan

**See companion file:** `NIVXFORGE_EDR_EMERGENT_PHASE1_PLAN.md`.

## S. Acceptance Criteria (Phase 1)

1. **Sensor enrollment:** an approved installer enrolls a test endpoint via mTLS 1.3, receives an X.509 device cert, and appears in `edr_endpoints` collection with tenant_id extracted server-side from cert `OU`.
2. **Telemetry ingest ≥ 1 000 EPS** without loss over a 15-minute window through the extended `/api/xdr/edr/telemetry/stream` (or agreed namespace).
3. **Cross-tenant negative test** passes: sensor A cannot write events with tenant_B's tenant_id in the request body.
4. **Canonical Envelope roundtrip:** every ingested `process`/`file`/`network`/`dns`/`registry` event lands in `xdr_events` (or agreed collection) with `provenance.collector_version`, `provenance.kernel_driver_hook`, and `evidence_id` present and searchable.
5. **Case linkage:** at least one detection produced by an existing content-fabric rule against the ingested telemetry surfaces in the incident timeline for the sensor's tenant, with `alert_id → process_guid → device_id` chain traversable via existing routes.
6. **Observability:** every new route appears in `openapi.json`, emits Prometheus counters with cardinality-safe route templates, and logs a JSON envelope with `trace_id` + `tenant_id`.
7. **UI:** no frontend changes required in Phase 1 (backend + API-contract only). New surfaces MUST NOT appear in the SPA until the UI-freeze exception lands.
8. **Regression protection:** the pre-Phase-1 test corpus (195/195 pass; 1 intentional mal-20 FN) still passes 100 % after Phase 1 merges. Content Fabric and Decoder registries unchanged.

## T. Regression Protection Plan

- **Content Fabric freeze:** `git diff` must show zero changes to `backend/detection_content/**` (excluding `__init__.py` reformatting).
- **Decoder freeze:** `git diff` must show zero changes to `backend/decoders/**` and `backend/services/decoder/**`.
- **Reasoning freeze:** `git diff` must show zero changes to `backend/reasoning/**`, `backend/services/verdict_stage2/**`, `backend/services/ikg/**`, `backend/routers/verdict_stage2.py`, `backend/routers/rc5_entities.py`, `backend/routers/rc5_diag.py`.
- **Investigation surface freeze:** `git diff` must show zero changes to `backend/routers/investigations.py`, `backend/v2/routers/investigation.py`, `backend/v2/routers/artifacts.py` — EXCEPT purely additive fields.
- **Existing test suite green:** `pytest backend/tests` end-to-end BEFORE and AFTER every Phase-1 merge; test-count must not decrease.
- **Byte-identical parity snapshots** in `backend/tests/decoder_migration/pre_migration_snapshot*.json` must remain unchanged (SHA-256 checks).
- **Live smoke:** `curl /api/health`, `/api/metrics`, `/api/openapi.json`, `/api/response/actions`, `/api/incidents` must return 200 with identical or superset shape after every merge.
- **Rollback plan:** every Phase-1 merge lands on a dedicated feature branch; the merge-back to `feature/rc2` requires this review's acceptance-criteria matrix to be 8/8 green.

---

## END · REVIEW DELIVERED

- ✅ Read-only. No application code, tests, or configs modified.
- ✅ UI freeze respected.
- ✅ Content Fabric and decoders untouched.
- ✅ No git commit/push/tag operations attempted from the agent side.
- ✅ Runtime + code treated as authoritative over documentation.
- ✅ Six documentation-vs-code discrepancies surfaced with exact paths.
- ✅ Companion Matrix + Phase 1 Plan produced alongside.
- ⛔ Implementation NOT authorized. Awaiting owner sign-off on architecture decisions §P (AD-01 through AD-08) and Phase 1 plan.
