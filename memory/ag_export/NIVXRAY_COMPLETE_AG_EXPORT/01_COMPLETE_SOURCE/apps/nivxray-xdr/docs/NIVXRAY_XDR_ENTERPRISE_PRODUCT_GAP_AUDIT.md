# NivXRay XDR — Enterprise Product Surface Gap Audit

**Status:** 2026-02-10 · code-inspected · evidence-backed
**Scope:** every route + every admin section verified against `/app/apps/nivxray-xdr/**` source
**Question this audit answers:** _"Could an enterprise security team actually administer, integrate, operate, extend, tune, automate, secure, audit and maintain NivXRay XDR without needing Emergent/developers to manually modify the application?"_

**Short answer:** **NO.** The investigation/detection/response brain is production-grade. The Admin control plane is largely a read-only projection over base APIs; enterprise-critical write operations (user CRUD, RBAC, API keys, webhooks, secrets, collector enrollment, integration lifecycle) are missing.

---

## §1 · Executive Summary

| Product Layer | Grade | Evidence |
| --- | --- | --- |
| Investigation Workspace (evidence · verdict · timeline · attack story · MITRE · IKG) | **A** | 12+ live consumer panels, `WorkspaceSelectionContext`, deterministic Verdict, Recommendations composer, Investigation Completeness |
| Detection Content authoring (Sigma editor + Pattern Rules + LOLBAS pack) | **B+** | New this session; 6 pattern rules + 15 LOLBins + Sigma lifecycle |
| Engine adoption (DIE / IEDDE / IUE / UAIE / UIL / ICE / CEM / VEEE) | **A** | 38/49 rows CONNECTED, anti-hallucination CI gate |
| Response Engine (SQLite state machine + approvals + evidence sink) | **A−** | 27/27 pytest green; vendor adapters STUB |
| **Admin control plane** | **D** | 5 sections `connected:false`, Users/Roles/APIs read-only, no CRUD |
| Multi-tenancy / MSSP | **F** | Not implemented |
| Governance / Audit log | **F** | No dedicated audit surface |
| SSO / SAML / OIDC / SCIM / MFA | **F** | Not implemented |
| Content lifecycle (staging → prod promotion, signing) | **D** | Pattern & Sigma stores are local; no server-side lifecycle |
| Multi-tenant / regional / HA / DR / capacity | **F** | Not implemented |

## §2 · Current Product Surface (routes verified)

Total routes: **30** (7 EDR · 23 XDR).

### EDR routes (base MDR native app)
`/edr` · `/edr/detections` · `/edr/files` · `/edr/forensics` · `/edr/hunting` · `/edr/live-query` · `/edr/network` · `/edr/process-tree` · `/edr/response`

### XDR routes (standalone)
`/xdr` · `/xdr/incidents` · `/xdr/incidents/:id` · `/xdr/incidents/:id/domain/:domainKey` · `/xdr/endpoints` · `/xdr/endpoints/:device/trajectory` · `/xdr/detections` · `/xdr/detections/:id` · `/xdr/detect/tuning/:ruleId` · `/xdr/respond/playbooks` · `/xdr/respond/playbooks/:id` · `/xdr/respond/automation-rules` · `/xdr/respond/automation-rules/:id` · `/xdr/respond/approvals` · `/xdr/evidence/:executionId` · `/xdr/intelligence/threat` · `/xdr/intelligence/iocs` · `/xdr/intelligence/malware` · `/xdr/intelligence/command` · `/xdr/intelligence/mitre` · `/xdr/intelligence/kb` · `/xdr/admin` · `/xdr/admin/:section` (18 sections)

### Admin sections (22 total)
| Key | Kind | Backend `api` | Status |
| --- | --- | --- | --- |
| `overview` | kv | `/admin/stats` | READ_ONLY (projection) |
| `capability-hub` | capability_hub | in-tree JSON | UI_ONLY · wizard is client-side; **no persistence** |
| `detection-content` | detection_content | in-tree JSON + local store | PARTIAL · Pattern Rules writable via localStorage; no server |
| `engines` | engines | in-tree JSON | READ_ONLY |
| `corpus` | corpus | in-tree JSON | READ_ONLY |
| `integrations` | integrations | `/admin/osint/services` | PARTIAL · REST/webhook/syslog wizard shipped |
| `data-sources` | table | `collector:/data-sources` | READ_ONLY |
| `collectors` | table | `collector:/collectors` | READ_ONLY |
| `agents` | none | `null · connected:false` | NOT_PRESENT |
| `telemetry-studio` | kv | `/admin/llm-telemetry` | READ_ONLY |
| `telemetry-health` | table | `collector:/telemetry-health` | READ_ONLY |
| `parsers` | none | `null · connected:false` | NOT_PRESENT |
| `normalization` | none | `null · connected:false` | NOT_PRESENT |
| `detection-rules` | table | `/admin/models` | READ_ONLY |
| `response-policies` | none | `null · connected:false` | NOT_PRESENT |
| `users-roles` | table | `/admin/users` | READ_ONLY (screenshot confirms `admin@n… \| admin \| — \| NO`) |
| `api-webhooks` | none | `null · connected:false` | NOT_PRESENT |
| `platform-health` | kv | `/health` | READ_ONLY |

## §3 · Complete Route Inventory · CRUD reality per page

Legend: **C** = create · **R** = read · **U** = update · **D** = delete · **T** = test · **X** = execute / act.

| Route | C | R | U | D | T | X | Notes |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | --- |
| `/xdr/incidents` | · | ✅ | · | · | · | · | List only |
| `/xdr/incidents/:id` | · | ✅ | · | · | · | · | Investigation is read + analyst pivots; incident closure not exposed |
| `/xdr/detections` | ✅ | ✅ | ✅ | ✅ | ✅ | · | Local `detectionRuleStore` (LocalStorage); no server persistence |
| `/xdr/detect/tuning/:ruleId` | · | ✅ | · | · | ✅ | · | Consumes real base `/api/regression/*`, honest `INSUFFICIENT TELEMETRY` fallback |
| `/xdr/respond/playbooks` | ✅ | ✅ | ✅ | ✅ | ✅ | · | Local store; Response Engine simulate is real |
| `/xdr/respond/automation-rules` | ✅ | ✅ | ✅ | ✅ | · | · | Local store |
| `/xdr/respond/approvals` | · | ✅ | · | · | · | ✅ | Real: talks to Response Engine SQLite |
| `/xdr/intelligence/*` | · | ✅ | · | · | · | · | Base intelligence consumers; read-only |
| `/xdr/admin/*` | ← see §2 |

## §4 · Admin Gap Matrix (owner-listed audit dimensions)

For every category the audit tracked 20 acceptance questions. Summary:

| Category | UI | Backend | CRUD | Persistence | RBAC | Audit | Tenant-aware | Status |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | --- |
| Users & Roles           | ✅ list | partial | ❌ | ✅ (base) | ❌ | ❌ | ❌ | **READ_ONLY** |
| API Keys / Webhooks     | ✅ empty | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Data Sources            | ✅ list | ✅ | ❌ | ✅ (collector) | ❌ | ❌ | ❌ | **READ_ONLY** |
| Collectors              | ✅ list | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | **READ_ONLY** |
| Agents (EDR)            | ✅ shell | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Parsers / Normalization | ✅ shell | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Detection Rules         | ✅ list | ✅ (base) | partial | client-only | ❌ | ❌ | ❌ | **UI_ONLY** |
| Pattern Rules (new)     | ✅       | ❌       | ✅ (client) | localStorage | ❌ | ❌ | ❌ | **UI_ONLY** |
| Playbooks               | ✅       | ✅ (Resp) | ✅ | client-only | ❌ | ❌ | ❌ | **PARTIAL** |
| Automation Rules        | ✅       | ❌       | ✅ (client) | client-only | ❌ | ❌ | ❌ | **UI_ONLY** |
| Integrations            | ✅ wizard | ✅ (collector) | partial | ✅ | ❌ | ❌ | ❌ | **PARTIAL** |
| Response Policies       | ✅ shell | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Capability Hub (new)    | ✅ + wizard | ❌ | ❌ | in-tree JSON | ❌ | ❌ | ❌ | **UI_ONLY** |
| Detection Content (new) | ✅       | ❌       | ✅ (local) | localStorage + tree | ❌ | ❌ | ❌ | **PARTIAL** |
| Investigation Corpus (new) | ✅    | ❌       | ❌ | in-tree | ❌ | ❌ | ❌ | **READ_ONLY** |
| Engines (new)           | ✅       | ❌       | ❌ | in-tree | ❌ | ❌ | ❌ | **READ_ONLY** |
| Audit Log               | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Multi-tenant / MSSP     | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| SSO / SAML / OIDC       | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| MFA / SCIM              | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Secrets / Certificates  | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Feature Flags / Licence | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Backup / DR / HA        | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Case Management (SLA · tasks · templates · queues · merge/split) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Hunting Query Builder   | ❌       | ✅ (base) | ❌ | ❌ | ❌ | ❌ | ❌ | **BACKEND_ONLY** |
| UEBA / Risk scoring     | ❌       | partial | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Asset / Vulnerability   | ❌       | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |
| Custom Dashboards / Reports | ❌  | ❌       | ❌ | ❌ | ❌ | ❌ | ❌ | **NOT_PRESENT** |

## §5 · Identity / RBAC Gap

**Current:** `/xdr/admin/users-roles` is a read-only table backed by base `/admin/users`. No create/edit/disable/delete/reset-credentials/invite/assign-role UI or API on the XDR side.

**Missing:** Add User · Invite · Edit · Disable · Delete · Reset · Groups · Create Role · Edit Role · Delete Role · Permission Matrix · Object-level permissions · Tenant permissions · Team permissions · Service accounts · API users · Break-glass · SSO · SAML · OIDC · MFA · SCIM · Session management · Login policy · Password policy · IP allowlist · Conditional access.

## §6 · API / Webhook Gap

**Current:** `/xdr/admin/api-webhooks` is a shell (`connected:false`). Wizard from Capability Hub honestly emits `TEST CONNECTION UNAVAILABLE — control-plane API pending`.

**Missing:** Create API key · Scopes · Expiration · Rotation · Revoke · Service-account credentials · OAuth apps · Webhook create/edit/delete · Signing secret · Rotation · Retry/backoff · Delivery history · Failure handling · Test · REST config · OpenAPI · Rate limits · API audit · IP allowlist · TLS/mTLS · Proxy.

## §7 · Collector / Data Source Gap

**Current:** Both list real objects from the collector service. **No** create/edit/enroll/enable/disable/test/delete.

**Missing:** Add source · Edit · Delete · Enable/disable · Test connection · Configure creds/polling/retention/routing/parser/normalization/enrichment · Ingestion stats · Errors · Replay · Backfill · **All 14 protocol adapters** (REST/webhook/syslog exist; Kafka/S3/EventHub/PubSub/Netflow/IPFIX/STIX-TAXII/WEF/WinRM/DNS/Email/OpenTelemetry NOT_PRESENT).

## §8 · Detection Gap

**Present:** Sigma editor (client-only) · Rule Tuning Workbench with real base regression/batch/corpus consumers · 6 seed Pattern Rules · LOLBAS pack with 15 binaries.

**Missing:** Correlation Rule builder UI · Sequence rules · Threshold rules · Statistical rules · YARA · Exceptions · Suppressions · Allow/Blocklists · Rule dependencies · Scheduling · Priority · Server-side lifecycle (draft → testing → shadow → enabled → deprecated) · Regression harness UI · Coverage gap report · Server-side persistence for pattern rules.

## §9 · Threat Intelligence Gap

**Present:** IOC/Domain/URL/Hash lookup via base `/api/ioc` · MITRE heatmap · KB catalog.

**Missing:** IOC feed management (add/remove/enable/disable/schedule) · STIX/TAXII configuration · OSINT feed catalog · Feed health · Deduplication · IOC lifecycle · Allow/Blocklist authoring · Certificate/ASN/WHOIS pivots · Passive DNS · IOC-disposition write flow.

## §10 · Hunting Gap

**Present:** deterministic pivots on the Investigation Canvas.

**Missing:** Query Builder · Advanced query language surface · Saved queries · Query history · Sharing · Scheduled hunts · Templates · Query → detection/rule/case promotion.

## §11 · Investigation / Case Gap

**Present:** Incident detail workspace · Evidence-first canvas · Recommendations · Completeness · Attack Story · Response Drawer · Approvals · Evidence Ref.

**Missing:** Case create/assign/close/reopen · SLA · Tasks · Comments · Notes UI · Case templates · Merge/split · Watchers · Chain-of-custody · Report generation UI · Export · Full audit history per case.

## §12 · SOAR / Response Gap

**Present:** Playbook designer (client-only) · Response Engine simulator + approvals + evidence sink · Automation Rules editor (client-only).

**Missing:** Real vendor connector actions (CrowdStrike/Defender/SentinelOne/Cisco SEP live) · Server-side playbook persistence · Publishing/staging · Approval workflow with peers · Execution history UI (backend green tests exist but no UI browser) · Import/export · Playbook analytics.

## §13 · Integration Gap

**Present:** REST poller / Webhook receiver / Syslog receiver (all ENABLED, real). 3 catalog manifests for CrowdStrike / Defender / VirusTotal marked AVAILABLE with `adapter_status: STUB`.

**Missing:** Integration lifecycle enforcement (Install → Configure → Test → Enable → Disable → Upgrade → Remove) with backing API · Credential storage · Rotation · Health/logs/metrics per integration · Marketplace beyond the 8 seeds.

## §14 · Asset / Vulnerability Gap

**Missing entirely:** Asset inventory · Groups · Criticality · Ownership · Business context · Vulnerabilities · CVEs · Exposure · EASM · Cloud/identity/software inventory.

## §15 · Reporting Gap

**Missing entirely:** Executive/SOC/Detection/Incident/Threat/Coverage dashboards · MTTA/MTTR · Analyst productivity · Custom dashboards · Scheduled reports · PDF/CSV/JSON export.

## §16 · Governance / Audit Gap

**Missing entirely:** Immutable audit log · Configuration history · User activity · API activity · Detection/rule/playbook change history · Response action audit · Evidence access log · Login history · Export history · Retention controls.

## §17 · Multi-Tenant Gap

**Missing entirely:** Tenancy is scaffolded via JWT claims in base but XDR admin has no tenant selector, no MSSP parent/child, no tenant-scoped detection/integration/API-key/data-source management.

## §18 · Platform Operations Gap

**Present:** `/xdr/admin/platform-health` reads `/api/health`. `/xdr/admin/telemetry-health` reads real collector health.

**Missing:** Queue/database/storage health · Retention · Capacity · Performance · Rate limits · Licensing · Feature flags · Maintenance mode · Backup/restore/DR · HA · Region · Time sync · Certificate management · Secret rotation · Encryption controls.

## §19 · Content Lifecycle Gap

**Present:** In-tree Investigation Corpus (8 categories) · LOLBAS pack v1 · Pattern Rules · Extension Manifests validated by CI gate.

**Missing:** Server-side content management · Version signing / checksum · Provenance chain · Content trust store · Content testing pipeline · Content approval workflow · Staging → production promotion · Dependency solver · Compatibility matrix · Import/export UI.

## §20 · AI-Optional Gap

**Present (correctly):** No mandatory AI anywhere. Recommendations composer is deterministic. Verdict is deterministic. Pattern matches produce observations, not verdicts.

**Missing (optional, low priority):** NL query generation · Investigation summarization · Rule explanation copilot · Threat research assistant · Recommendation ranking modifier (with explainability). MUST remain optional and MUST NEVER fabricate evidence/IOC/verdict/mapping.

## §21 · Enterprise Benchmark Matrix

| Capability | NivXRay XDR | Cisco XDR | Splunk ES / SOAR | MS Defender / Sentinel | CrowdStrike Falcon | Cortex XDR / XSOAR | Elastic Sec | Google SecOps |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| User/Role CRUD           | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSO / SAML / OIDC        | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MFA / SCIM               | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| API Keys / Scopes        | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Webhook Lifecycle        | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Audit Log                | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Multi-Tenant / MSSP      | ❌ | ✅ | partial | ✅ | ✅ | ✅ | ✅ | ✅ |
| Playbook Designer        | ✅ (client) | ✅ | ✅ | ✅ | partial | ✅ | ✅ | ✅ |
| Advanced Hunting UI      | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| UEBA / Entity Risk       | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Evidence-first Verdict + Provenance | **✅ unique** | partial | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Deterministic explainability | **✅ unique** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Adopt-before-invent registry | **✅ unique** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

NivXRay XDR's moat is the **middle three rows** (evidence-first · deterministic · adopt-before-invent). The gap is enterprise operability.

## §22 · P0/P1/P2/P3/P4 Roadmap

### 🔴 P0 · Enterprise Blockers (nothing else ships until this is done)
1. **User CRUD + RBAC** — Add/Invite/Edit/Disable/Delete + Role CRUD + Permission Matrix + object-level scopes.
2. **API Key & Service-Account Lifecycle** — Create/Rotate/Revoke/Scopes + backing table + audit.
3. **Webhook Lifecycle** — Create/Test/Rotate/Delete + delivery history + retry policy + HMAC secret rotation.
4. **Immutable Audit Log** — Every admin write goes through one audit sink; UI browser at `/xdr/admin/audit`.
5. **Secrets Store** — Server-side encrypted secret storage referenced by integrations/webhooks/api-keys.
6. **Extension Control-Plane API** — `POST /api/xdr/extensions` + configure/test/enable/disable/remove. Turns the Capability Hub wizard from client-side scaffold into a real installer.
7. **Data Source CRUD** — Add/Edit/Enable/Disable/Test + credential storage via the Secrets store.
8. **Collector Enrollment** — Register/enroll/authenticate/version/upgrade/uninstall/pause/logs/metrics.

### 🟠 P1 · Core Platform Gaps
9. Detection lifecycle on server (persistence · staging → production · signing · rollback).
10. Playbook lifecycle on server + execution history UI.
11. Automation Rules server-side persistence + trigger evaluation service.
12. Integration lifecycle enforcement per §13 with live adapters (Phase C: CrowdStrike/Defender first).
13. Case management (open/assign/task/close/merge/split/comments) — full CRUD.
14. Hunting query builder + saved queries + scheduled hunts.
15. SSO/SAML/OIDC (delegate to Emergent-managed Google Auth for cloud; SAML/OIDC for enterprise).
16. MFA/SCIM.
17. Real-time selection sync across DIE/IEDDE/IUE/UAIE/Recommendations panels.

### 🟡 P2 · Important Parity
18. UEBA / entity risk scoring surfaces (base already ships risk primitives).
19. Asset inventory + criticality + ownership + software inventory.
20. Reporting: MTTA/MTTR/FP-rate/coverage dashboards; scheduled PDF/CSV export.
21. Threat-intel feed manager (add/enable/schedule/health).
22. Content marketplace expansion (Credential Access · Persistence · Lateral Movement · Ransomware chains).
23. Parsers & Normalization admin surface.

### 🟢 P3 · Advanced Capability
24. Multi-tenant / MSSP with parent/child + tenant-scoped RBAC.
25. Backup / DR / HA controls.
26. Feature-flag & licence surface.
27. Optional AI copilot (summarisation · NL hunting · rec explanation).

### 🔵 P4 · Future
28. Vulnerability / EASM / cloud posture.
29. Compliance reporting packs (NIST · ISO · SOC2 · GDPR).
30. Native mobile companion.

## §23 · Backend / API Requirements to unblock P0

Every P0 item requires the following backend endpoints (all on `/api/xdr/**` for consistency with the existing `POST /api/xdr/response-evidence` write path):

```
POST   /api/xdr/users                     · create user
GET    /api/xdr/users                     · list
GET    /api/xdr/users/{id}
PATCH  /api/xdr/users/{id}
DELETE /api/xdr/users/{id}
POST   /api/xdr/users/{id}/reset-credentials
POST   /api/xdr/users/{id}/disable
POST   /api/xdr/roles                     · role CRUD (same shape)
POST   /api/xdr/permissions/grant
POST   /api/xdr/permissions/revoke

POST   /api/xdr/api-keys                  · scopes[], expires_at
GET    /api/xdr/api-keys
POST   /api/xdr/api-keys/{id}/rotate
DELETE /api/xdr/api-keys/{id}

POST   /api/xdr/webhooks                  · secret managed server-side
GET    /api/xdr/webhooks
GET    /api/xdr/webhooks/{id}/deliveries
POST   /api/xdr/webhooks/{id}/test
POST   /api/xdr/webhooks/{id}/rotate-secret
DELETE /api/xdr/webhooks/{id}

GET    /api/xdr/audit-log                 · immutable projection
GET    /api/xdr/audit-log/{id}

POST   /api/xdr/secrets                   · encrypted at rest
GET    /api/xdr/secrets  (masked)

POST   /api/xdr/extensions                · install manifest
POST   /api/xdr/extensions/{id}/configure
POST   /api/xdr/extensions/{id}/test
POST   /api/xdr/extensions/{id}/enable
POST   /api/xdr/extensions/{id}/disable
DELETE /api/xdr/extensions/{id}

POST   /api/xdr/data-sources              · CRUD
POST   /api/xdr/data-sources/{id}/test
POST   /api/xdr/collectors/enroll
POST   /api/xdr/collectors/{id}/upgrade
POST   /api/xdr/collectors/{id}/pause
```

Every endpoint MUST:
- honour RBAC scopes,
- write to the immutable audit log,
- accept & return the tenant scope explicitly,
- reject client-supplied `tenant_id` when it does not match the authenticated principal,
- persist to server-side storage (not localStorage).

## §24 · Recommended Admin Information Architecture

```
ADMINISTRATION
│
├── PLATFORM
│   ├── Overview
│   ├── Platform Health
│   ├── Telemetry Health
│   ├── Telemetry Studio
│   └── Audit Log                             (NEW — P0)
│
├── CONTROL PLANE
│   ├── Capability Hub                        (exists; needs API)
│   ├── Extensions                            (exists; needs API)
│   ├── Data Sources                          (READ_ONLY → CRUD)
│   ├── Collectors                            (READ_ONLY → enrollment)
│   ├── Agents                                (NOT_PRESENT → build)
│   ├── Protocols                             (NEW)
│   ├── Parsers & Normalization               (NOT_PRESENT → build)
│   └── Integrations                          (PARTIAL → lifecycle)
│
├── DETECTION ENGINEERING
│   ├── Detection Rules
│   ├── Pattern Rules
│   ├── Correlation Rules                     (NEW)
│   ├── Exceptions & Suppressions             (NEW)
│   ├── Detection Content Packs
│   ├── Rule Tuning Workbench
│   └── Investigation Corpus
│
├── AUTOMATION
│   ├── Playbooks
│   ├── Automation Rules
│   ├── Approvals
│   └── Execution History                     (NEW)
│
├── IDENTITY & ACCESS                         (rebuilt)
│   ├── Users
│   ├── Roles & Permissions
│   ├── Service Accounts / API Keys
│   ├── Webhooks
│   ├── Secrets
│   ├── SSO / SAML / OIDC
│   ├── MFA / SCIM
│   └── Session Management
│
├── TENANCY / GOVERNANCE
│   ├── Tenants                               (NEW)
│   ├── Data Retention                        (NEW)
│   ├── Policies                              (NEW)
│   ├── Approvals Policy                      (NEW)
│   └── Feature Flags                         (NEW)
│
└── DEVELOPER
    ├── API Explorer                          (NEW)
    ├── OpenAPI                               (NEW)
    └── Event Stream                          (NEW)
```

## §25 · Bottom line

- NivXRay XDR's brain is genuinely strong; the enterprise control plane is not.
- **P0 must land before any more detection/response content is added.** Without user CRUD, RBAC, API keys, webhooks, secrets and audit log, a paying enterprise cannot legally onboard.
- Every new feature from now on MUST prove it passes the 20-question audit template in §4 before shipping.
- The next audit run should regenerate this document verbatim so drift is visible.
