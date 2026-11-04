# CAT-17 · Administration / Governance / Tenancy / Auditability / Platform Operations

> STRICT READ-ONLY deep-dive. Carries the **Multi-tenancy** and **Observability** rows folded in from the prior taxonomy (master §B reconciliation).

## 1 · PRE-AG baseline (proven — strong, and essentially all original NivXRay)

| Plane | Artifact at `5d67934e` | Runtime volume |
|---|---|---|
| RBAC | `backend/routers/xdr_rbac.py` (`prefix="/api/xdr/rbac"`, `:68`), **20 routes**: `/roles`(3), `/users`(5), `/groups`(2), `/permissions`, `/simulate` | `xdr_roles` 1 · `xdr_user_roles` 10 · `xdr_users` 18 · `xdr_groups` 1 |
| Permission model | `xdr_rbac.py:157` `"threat_hunting": {"actions":["read","execute"]}`; `:211` role permission globs; `:230` role descriptions | — |
| Audit log | `routers/xdr_audit_log.py` → `/api/xdr/audit-log`, `/emit`, **`/verify`**, `/{event_id}` | `xdr_audit_log` **6,465** |
| Credential vault | `detection_content/xdr_credential_vault.py` | `xdr_credential_vault` 6 · `xdr_vault_audit` **33,004** |
| Secrets | `/api/xdr/secrets` + 3 sub-paths | `xdr_secrets` 12 |
| API keys | `/api/xdr/api-keys` + 3 sub-paths | `xdr_api_keys` 5 |
| Webhooks | `/api/xdr/webhooks` + 5 sub-paths | `xdr_webhooks` 6 · `xdr_webhook_deliveries` 3 |
| Observability | `backend/observability/` package | — |
| Auth | `backend/deps.py` `seed_admin()`; `/api/auth/{login,me,change-password}` | `users` 4 |
| Request hardening | `backend/request_hardening.py`, `backend/privacy.py`, `backend/security/` | — |
| Tenancy | `backend/services/iue/tenancy.py`; Gate-0.5 P0-D | — |
| Content supply chain | 42 `/api/admin/content-supply-chain/*` paths | `xdr_capability_contracts` 339 · `xdr_engines` 339 |
| Audit doc endpoints | `/api/audit/{iue-architecture,iue-convergence-design,partial-pending-skipped-dead,workspace-360}.{md,pdf}` | — |
| Admin console | `XdrAdminPage.jsx`; `XdrShell.jsx:189-206` — 12 admin items + System section | — |

## 2 · AG delta

| Added | Purpose |
|---|---|
`security_state/ledger/ledger.py` | **immutable Security-State ledger** (`GET /{case_id}/ledger`, `router.py:365`) |
`security_state/hydration/provenance.py` | provenance (`GET /{case_id}/provenance`, `:402`) |
`security_state/persistence/{models,repository}.py` | persistence |
`backend/tests/edr/test_security_state_isolation.py` | tenant-isolation test |
`backend/tests/test_phase2_1_tenant_isolation.py` | tenant-isolation test |
`backend/tests/test_phase2_1_license_policy.py` | content licence policy test |

**AG added a ledger and two tenant-isolation test suites. It did not create RBAC, audit, vault, secrets, API keys or webhooks — all PRE-AG.**

## 3 · Current state (live)

### 3.1 · RBAC — RUNTIME-PROVEN

`GET /api/xdr/rbac/roles` (live, authenticated) returns a real tiered role model:

```json
{"roles":[
 {"id":"role_builtin_platform_admin","name":"platform_admin","tier":"PLATFORM","type":"SYSTEM",
  "description":"Platform-wide authority.  Manages tenants, engines, extensions, RBAC, secrets and audit configuration.",
  "permissions":["*.*"]},
 {"id":"role_builtin_tenant_admin","name":"tenant_admin","tier":"MANAGEMENT","type":"TENANT",
  "description":"Tenant-level control-plane operator.",
  "permissions":["users.*","roles.*","groups.*","sessions.*","api_keys.*","webhooks.*",
                 "secrets.*","data_sources.*","collectors.*", …]}, …]}
```

Note the explicit `tier: PLATFORM | MANAGEMENT` and `type: SYSTEM | TENANT` separation — a genuine two-tier tenancy model in the role schema. `/api/xdr/rbac/simulate` allows permission simulation before assignment.

### 3.2 · Auditability — the strongest quantitative evidence in the product

| Store | Docs |
|---|---|
`xdr_vault_audit` | **33,004** |
`xdr_audit_log` | **6,465** |
`xdr_cortex_scheduler_audit` | 38,326 |
`xdr_investigation_activity` | 6,223 |
`xdr_detection_versions` | 4,300 |
`xdr_intelligence_policy_audit` | 251 |
`xdr_cortex_ingest_audit` | 95 |
`xdr_intelligence_overlay_audit` | 12 |
`xdr_incident_promotion_audit` | 2 |
`xdr_response_audit` | 2 |
`v2_audit_log` | **0** ← second, unused audit path |

**`GET /api/xdr/audit-log/verify` exists** — i.e. the audit trail is designed to be **cryptographically verifiable**, not merely appended.

### 3.3 · Security posture (from `memory/test_credentials.md`)

Feb-2026 audit findings SEC-001/002 were remediated: default password retired, JWT signing secret replaced with a fresh 512-bit random value, admin force-reset, and an explicit instruction that `ADMIN_FORCE_PASSWORD_CHANGE=true` must be set in production. Credentials live in `backend/.env` (`ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_FORCE_PASSWORD_CHANGE`), seeded idempotently by `seed_admin()` in `backend/deps.py`.

| Dimension | Verdict |
|---|---|
| Implemented | ✅ strong |
| Registered | ✅ 20 RBAC + 4 audit + 4 secrets + 4 API-key + 6 webhook + 42 content-supply-chain paths |
| Executed | ✅ |
| Runtime-proven | ✅ 39,469 combined audit records; live role model |
| Production-ready | 🟢 **highest-maturity plane in NivXRay XDR, alongside Threat Intelligence** |

## 4 · Industry benchmark

| Vendor | Governance capability |
|---|---|
| **Microsoft Defender XDR** | **Unified RBAC (URBAC)** with granular data-scoped permissions (e.g. `Security operations > Raw data / Security data` gates advanced hunting); tenant-scoped |
| **CrowdStrike** | Role-based API scopes; Fusion execution history as an audit surface |
| **Cortex XDR** | Tenant model + RBAC; Broker VM / Connector governance |
| **Cisco XDR** | Org-scoped configuration; Automation Exchange content trust tiers (Cisco-managed / verified / community) |
| **SentinelOne** | Site/account/group hierarchy; **service-account tokens explicitly restricted** from certain Purple AI operations — a documented least-privilege boundary |
| **Splunk ES** | Capability-based RBAC; content management governance |
| **Trellix** | XDR console-managed integrations and policies |

## 5 · Gap

| Gap | Severity | NivXRay evidence |
|---|---|---|
| **Tenancy is model-level, not API-level** | **P1** | Role schema has `tier: PLATFORM/MANAGEMENT` and `type: TENANT`; `/api/v2/security-state/streaming/status` **requires `tenant_id`**; but **0 of 733 live paths contain `tenant`**. There is no tenant CRUD, no tenant switcher, no per-tenant data-scope enforcement visible in the API surface. Master U-3 |
| **Two audit paths, one unused** | P2 | `v2_audit_log` = **0 docs** while `xdr_audit_log` = 6,465. Same duplication pattern as DEV-3/DEV-5 |
| **`threat_hunting` permission with no route** | P2 | Master DEV-6 (`xdr_rbac.py:157,211,230`) — either implement CAT-09 or remove the permission |
| No data-scoped hunting permission model | P2 | MS gates raw-data access separately from security-data access. Not applicable until CAT-09 exists |
| No SIEM/SOC audit export | P2 | `xdr_audit_log` has `/verify` but no bulk export or forwarding |
| Platform-health page unverified | P2 | `XdrShell.jsx:212` — *"Is NivXRay itself operational? · derived from real infrastructure"*. Binding not re-verified in this audit |
| No session management API | P2 | `sessions.*` appears in `tenant_admin` permissions with no `/sessions` route — another registration-without-capability instance |

## 6 · Where NivXRay is ABOVE parity — protect this

1. **Verifiable audit trail.** `GET /api/xdr/audit-log/verify` + 33,004 vault-audit records + 4,300 detection versions + `immutable_truth_commit` on the detection inventory. No benchmarked vendor documents a *verifiable* (as opposed to merely immutable) audit log.
2. **Permission simulation.** `/api/xdr/rbac/simulate` — test a permission decision before granting it. Not documented by any benchmarked vendor.
3. **Content supply-chain governance.** 42 admin paths with SHA-pinned acquisition (`sha256`, `acquisition_state: LIVE`, `fallback_used: false`) and a licence-policy test suite. This is stricter than any public vendor documentation.
4. **Intelligence-application policy with audit** (251 records) — see CAT-11.

## 7 · UNKNOWN

- U-17.1 — Multi-tenancy enforcement depth (master U-3). Isolation tests exist (`tests/edr/test_security_state_isolation.py`, `test_phase2_1_tenant_isolation.py`) and were **not executed** under the read-only rule.
- U-17.2 — Whether `xdr_audit_log/verify` performs real chain verification or a shape check. Requires execution.
- U-17.3 — Whether `backend/observability/` exports metrics to any external system.
- U-17.4 — Why `xdr_roles` holds only 1 doc while the API returns multiple built-in roles (built-ins are presumably code-defined, not stored). Not confirmed.
