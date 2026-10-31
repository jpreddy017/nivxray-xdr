# NivXForge EDR · Gate 0.5 Reconciliation (Final Rollup)

> **Mode:** Read-only. No code / test / config / UI changed. No git ops. Content Fabric, decoders, and reasoning engines untouched. UI freeze maintained.
> **Companion artifacts (all in `/app/memory/edr_review/`):**
> - `NIVXRAY_CONTENT_DECODER_TRUTH_RECONCILIATION.md`
> - `NIVXFORGE_EDR_TRUTH_RECONCILIATION.md`
> - `NIVXFORGE_EDR_ARCHITECTURE_DECISIONS.md`
> - Gate 0 (already produced): `NIVXFORGE_EDR_EMERGENT_INTEGRATION_REVIEW.md`, `NIVXFORGE_EDR_EMERGENT_INTEGRATION_MATRIX.md`, `NIVXFORGE_EDR_EMERGENT_PHASE1_PLAN.md`
> **Truth-contract commit pinned:** `d3f7a0a000892131abc9a32ee97009338dd38d79` (unchanged).
> **Gate status:** ⛔ Phase 1 implementation NOT authorized. Awaiting owner sign-off on AD-01…AD-08 and closure of the Phase 0.5 prerequisites below.

---

## §1 · Truth reconciliation summary

| Claim | Classification | Action |
|---|---|---|
| 615 Content Fabric objects | UNVERIFIED | Introspection endpoint (AD-05) or explicit retraction |
| 600 active + 15 synthetic split | UNVERIFIED | Same as above |
| `run_content_truth_audit.py` | MISSING_FROM_BRANCH | AD-05 |
| `backend/detection_content/corpus/` | MISSING_FROM_BRANCH | Handoff doc correction (§2) |
| `backend/detection_content/yara_engine.py` | MISSING_FROM_BRANCH | Handoff doc correction (§2) |
| 59 decoders (module count) | VERIFIED (45 + 14 = 59) | Owner may pin this as canonical |
| "48 logical + 14 family" | VERIFIED with minor drift (real = 45 + 14) | Doc correction |
| DDO 7 codec families | VERIFIED | Pin in next truth-contract commit |
| DDO 14 signatures | VERIFIED | Pin in next truth-contract commit |
| `verify_decoder_truth_e2e.py` | MISSING_FROM_BRANCH | AD-05 |
| Truth-contract "single authoritative decoder runtime" | BRANCH_DIVERGENCE | Amend truth contract in a new pinned commit (two trees are live) |

## §2 · Six path corrections (compact ledger — full detail in path reconciliation doc)

| ID | Documented | Actual | Doc fix | Code fix |
|---|---|---|---|---|
| PD-1 | `backend/security_state/contracts.py` | `backend/routers/rc5_entities.py` | YES | NO |
| PD-2 | `backend/security_state/detection_bridge.py` | inline in `verdict_stage2.py` + rc5 routers | YES | NO |
| PD-3 | `backend/run_content_truth_audit.py` | not present | YES | YES (endpoint per AD-05) |
| PD-4 | `backend/verify_decoder_truth_e2e.py` | not present | YES | YES (endpoint per AD-05) |
| PD-5 | `apps/nivxray-xdr/src/xdr/pages/XdrEvidenceExplorerPage.jsx` | `frontend/src/pages/EvidenceExplorerPage.jsx` | YES | NO (UI freeze) |
| PD-6 | `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx` | `frontend/src/v2/pages/InvestigationWorkspace.jsx` | YES | NO (UI freeze) |

## §3 · Architecture Decisions summary — pending owner sign-off

| # | Decision | Recommendation | Sign-off |
|---|---|---|---|
| AD-01 | API namespace | Extend `/api/xdr/*` | ☐ |
| AD-02 | Canonical envelope | Extend in place | ☐ |
| AD-03 | Security-State module location | Reuse `rc5_entities.py` (no rename) | ☐ |
| AD-04 | UI-freeze scope | Phase 1 = backend + API only | ☐ |
| AD-05 | Missing audit scripts | Introspection endpoints (2 new) | ☐ |
| AD-06 | P0-D as hard prereq | HARD prereq | ☐ |
| AD-07 | Safety-gate data source | Hybrid, `FAIL_MODE=CLOSED` | ☐ |
| AD-08 | Sensor signing | Emergent dev cert now; EV cert before Phase 2 | ☐ |

## §4 · API namespace decision — recommended standard

- **Standard:** all new EDR/UBAE/Sandbox routes use `/api/xdr/{edr|sandbox|ubae}/…`.
- **Versioning:** URL segment `v` only where semver-breaking (`/api/xdr/edr/v2/telemetry/stream` reserved for future).
- **Compatibility:** existing `/api/xdr/ingest/telemetry` remains authoritative for generic collectors. EDR route wraps it (thin) so both legacy and EDR envelopes hit the same tenant-guarded writer.
- **Authentication:** mTLS 1.3 device cert for sensor endpoints; bearer JWT for admin routes. `_principal(req)` extracts tenant from cert `OU` for mTLS or JWT claim for bearer.
- **Authorization:** `require_permission("edr.<res>.<verb>")` on every admin route. Sensor endpoints protected by device-cert allow-list.
- **Tenant enforcement:** existing cross-tenant guard in `xdr_ingest.py` extended to all new routes via a new `require_tenant(req)` dependency that MUST land as part of P0-D closure.
- **Migration strategy:** none — additive routes only. Legacy routes unchanged.
- **Rollback strategy:** feature flags `NIVX_EDR_ENROLLMENT_ENABLED`, `NIVX_EDR_TELEMETRY_STREAM_ENABLED`, `NIVX_EDR_SAFETY_GATE_FAIL_MODE=CLOSED`. Flag-off = 503.

## §5 · P0-D adversarial cross-tenant security-test — design

### 5.1 Scope
Cross-tenant negative tests across: users · devices · cases · evidence · telemetry · queries · database · cache · IKG/graph · exports · response actions.

### 5.2 Actors
- **Tenant A** (`tenant_a_admin`, `tenant_a_analyst`, `tenant_a_responder`, `sensor_a_device_a1`, `sensor_a_device_a2`).
- **Tenant B** (`tenant_b_admin`, `tenant_b_analyst`, `sensor_b_device_b1`).

### 5.3 Test-ID substitution and filter manipulation vectors (all MUST return 4xx and MUST NOT return tenant-B data)

| Vector | Attempted operation by Tenant A | Expected result |
|---|---|---|
| Case ID substitution | `GET /api/incidents/{case_b_id}` | 404 (never 200) |
| Device ID substitution | `GET /api/edr/endpoints/{device_b_id}` | 404 |
| Evidence ID substitution | `GET /api/v2/cases/{case_b_id}/artifacts` | 404 |
| Telemetry write with foreign `tenant_id` in body | `POST /api/xdr/edr/telemetry/stream` with body `tenant_id=tenant_b` while auth is Tenant A sensor cert | 400 or 202-with-ignore (server strips tenant from body); MUST land in tenant A only |
| Response action against foreign device | `POST /api/response/execute {action_id:endpoint.isolate, target_device_id: device_b_id}` | 403 |
| Query-param tenant override | `GET /api/xdr/collectors?tenant_id=tenant_b` | ignored server-side; tenant A only in response |
| Header spoofing | `GET /api/xdr/collectors` with `X-Tenant-Id: tenant_b` while JWT is Tenant A | ignored; tenant A only in response |
| Cache read-through | Trigger operation X while Tenant A creates cache entry, then Tenant B tries same key | miss (namespaced by tenant) |
| IKG neighbour traversal | `GET /api/services/ikg/neighbours?node_id={tenant_b_node}` | 404 |
| Export enumeration | `GET /api/exports` — Tenant A lists exports | only tenant A rows |
| Webhook delivery cross-tenant | Tenant A creates webhook targeting Tenant B url | denied at RBAC + validated at delivery |

### 5.4 Storage-plane assertions

- Mongo `find({...})` calls MUST be intercepted by the new `require_tenant`-scoped middleware (or global driver-level filter) so that a bug in a single router does not leak.
- Any collection referenced in this test set (`workspace_cases`, `xdr_events`, `xdr_data_sources`, `xdr_collectors`, `xdr_response_evidence`, `xdr_response_executions`, `xdr_incidents`, `xdr_investigations`, `xdr_iue_understanding`, `xdr_evidence_graph_edges`, …) MUST include `tenant_id` in the effective filter.

### 5.5 Acceptance criteria

- **AC-1:** All 11 vectors above return 4xx or empty result.
- **AC-2:** Zero rows leak in any response (assert with strict deep-equality against seeded corpora).
- **AC-3:** No response action executes against a foreign device.
- **AC-4:** No log line contains a body from the other tenant.
- **AC-5:** Test suite runs green in `pytest backend/tests/edr/test_cross_tenant.py` and adds to the baseline count without regressing the existing 195/195.
- **AC-6:** Audit log shows every denial with `ACCESS_DENIED` + violating principal + vector name.
- **AC-7:** Prometheus counter `nivxray_access_denied_total{route, reason}` increments per attempted vector.

### 5.6 Implementation prerequisites (Phase 0.5 code changes required)

- `require_tenant(req)` FastAPI dependency.
- Global Mongo filter middleware (or per-collection guard). Recommended pattern: enforce at repository layer, not per route.
- Seeded fixtures for Tenant A/B (users, roles, devices, cases, evidence).
- Test file `backend/tests/edr/test_cross_tenant.py` (new).

### 5.7 Out-of-scope for the P0-D test (deferred)

- Sensor kernel driver behaviour (Phase 4).
- Sandbox tenancy (Phase 4).
- UBAE peer-group cross-tenant checks (Phase 3).

## §6 · Security / tenancy findings

- Current codebase enforces tenancy per-route via `_principal` + explicit collection filters. This is FRAGILE — a single missed filter leaks. AD-06 + §5 make the fix a hard prereq.
- `xdr_secrets` collection is Mongo-backed; secrets not in KMS/Vault (already flagged in truth contract as IMPLEMENTED_BUT_NOT_PRODUCTION_SAFE).
- Audit ledger is tamper-evident but not Merkle-chained (P4 extension per handoff).
- mTLS 1.3 termination location must be decided before Phase 1 traffic — recommend nginx sidecar in docker-compose during Phase 1, K8s ingress in Phase 4 (aligns with P0-J).

## §7 · Do-not-rebuild reconfirmation (existing NivXRay Core)

The following are IMPLEMENTED_AND_WORKING and MUST be reused. EDR / UBAE / Sandbox MUST feed them, never fork or replace them.

| Capability | Live path | Grade |
|---|---|---|
| Canonical Evidence | `backend/routers/artifacts.py` + `backend/v2/routers/artifacts.py` + `backend/v2/investigation/rte/` | IW |
| Provenance | `backend/services/canonical_evidence_recovery.py` + RTE + envelope `provenance` field | IW |
| IUE (Lanes A/B/C) | `backend/routers/iue_lane_{a,b,c}.py` | IW |
| ICE (correlation) | `backend/routers/correlations.py`, `xdr_correlation.py`, `services/correlation_engine.py` | IBI (efficacy corpus MISSING — P0-I) |
| Detection Engine + 615 Content Fabric | `backend/detection_content/` (framework verified; 615 population UNVERIFIED — see §1) | IW (framework) |
| Correlation Engine | as above | IBI |
| IKG (Incremental Knowledge Graph) | `backend/services/ikg/`, `routers/attack_graph.py`, `routers/attack_story.py` | IW |
| Security State Engine | `backend/routers/rc5_entities.py`, `rc5_diag.py` (NOT `backend/security_state/`) | IW |
| Deterministic Verdict Engine | `backend/routers/verdict_stage2.py`, `services/verdict_stage2/`, `reasoning/` | IW |
| Attack Story | `backend/routers/attack_story.py` | IW |
| MITRE ATT&CK | `backend/routers/mitre_heatmap.py`, `services/ikg/`, `detection_content/` | IW |
| Decoder / IEDDE | `backend/decoders/*` + `backend/services/decoder/*` | IW (dual tree — see §1) |
| Evidence Explorer | `frontend/src/pages/EvidenceExplorerPage.jsx` (main SPA) — UI FROZEN | IW |
| Investigation Workspace | `frontend/src/v2/pages/InvestigationWorkspace.jsx` (main SPA) — UI FROZEN | IW |
| Report Generator | `backend/routers/reports.py`, `backend/services/report/` (grep-confirmed subset) | IW |
| Response Policy | `apps/nivxray-xdr-response/framework/registry.py` | IW |
| Approval Engine | `apps/nivxray-xdr-response/framework/executor.py` | IW |
| Verification | `backend/routers/xdr_response_evidence.py` (storage side); loop MISSING (P4) | IBI |

EDR & Sandbox **feed** these — no parallel reasoning is authorized.

## §8 · Remaining blockers (Phase 0.5 must close before Phase 1)

1. **Sign-off on AD-01…AD-08.**
2. **P0-D adversarial cross-tenant test suite** — HARD prereq (AD-06).
3. **AD-05 introspection endpoints** — either `run_content_truth_audit.py` + `verify_decoder_truth_e2e.py` OR two new endpoints.
4. **Handoff-package path addendum** correcting PD-1…PD-6.
5. **Truth-contract superset commit** amending the "single authoritative decoder runtime" wording (per §1).
6. **Owner declaration of the canonical Content-Fabric cardinality** (see §5.3 of Content/Decoder reconciliation).

## §9 · Exact Phase 1 prerequisites (checklist)

- [ ] AD-01…AD-08 approved.
- [ ] P0-D test corpus written and passing.
- [ ] Introspection endpoints live.
- [ ] Handoff path addendum published.
- [ ] Truth-contract v2 commit tagged.
- [ ] UI-freeze confirmed for Phase 1 (AD-04 = A).
- [ ] Feature flags declared: `NIVX_EDR_ENROLLMENT_ENABLED`, `NIVX_EDR_TELEMETRY_STREAM_ENABLED`, `NIVX_EDR_SAFETY_GATE_FAIL_MODE=CLOSED`.
- [ ] Test-corpus baseline recorded: `pytest backend/tests -q` = 195/195 + 1 intentional mal-20 FN. This exact number MUST be preserved after every Phase 1 merge.
- [ ] Regression-freeze list acknowledged: `backend/detection_content/**`, `backend/decoders/**`, `backend/services/decoder/**`, `backend/reasoning/**`, `backend/services/verdict_stage2/**`, `backend/services/ikg/**`, `backend/routers/verdict_stage2.py`, `backend/routers/rc5_entities.py`, `backend/routers/rc5_diag.py`.

## §10 · Recommended Phase 1 starting point

Start with the **PKI + Enrollment mini-slice** (Deliverable D1 of the Phase 1 plan):

- `backend/routers/edr_enrollment.py` (new, mounted under `/api/xdr/edr/enrollment/*`).
- `services/edr_pki/` (new, Ed25519 CA, cert issuance).
- New Mongo collections `edr_enrollment_tokens`, `edr_endpoints`, `edr_cert_ca_state`.
- Tests: `test_enrollment.py` + a stub `test_cross_tenant.py` that becomes the first row of the P0-D suite.
- No sensor binary yet.
- No telemetry stream yet.

Reason to start here: **it exercises `_principal`, `require_permission`, and audit-emit in a controlled surface WITHOUT accepting any endpoint telemetry**, giving Emergent one full loop of the tenant-guarded infrastructure before real EDR traffic lands.

## §11 · Do-not rules honoured

- ✅ No production code, tests, configs, UI modified.
- ✅ No git operations (init/add/commit/push).
- ✅ Content Fabric untouched.
- ✅ Decoders untouched.
- ✅ IUE / ICE / IKG / Security State / Verdict / Attack Story / MITRE / Reasoning untouched.
- ✅ UI freeze respected.
- ✅ Runtime + code treated as authoritative over documentation.

## END · Gate 0.5 reconciliation delivered · read-only · STOP condition ACTIVE · awaiting owner review + explicit AD-01…AD-08 approval before Phase 1 kicks off
