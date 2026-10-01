# NivXRay XDR — Admin Control-Plane Spec

**Status:** 2026-02-10 · target architecture · owner-approved direction
**Scope:** the target Admin control plane every P0 item in the gap audit must satisfy

---

## 1 · Principles (non-negotiable)

1. **Every admin write goes through an authenticated, RBAC-scoped, audited API.**
   No writes from localStorage. No writes from the URL. No writes from the client
   without a server ack.
2. **Deterministic-first · AI-optional preserved.** No AI on the write path.
3. **Evidence-first invariants preserved.** SSOT / IKG / Verdict / Response
   Engine are not owned by Admin — Admin only mutates configuration, never
   evidence or verdicts.
4. **Server-side authority.** Reject any client-supplied `tenant_id`,
   `principal_id`, or `role` that does not match the authenticated principal.
5. **Immutable audit log.** Every write emits an audit record before the ack.
6. **Secrets never leave the server in cleartext.** All API keys, HMAC
   secrets, OAuth client secrets, certificates, passwords are stored
   encrypted-at-rest and returned masked (`sk_live_••••1a3f`).
7. **Reversibility.** Every write has a matching delete/rollback. Every
   config change is versioned.

## 2 · Universal envelope

Every P0 endpoint follows this envelope:

**Request headers**
- `Authorization: Bearer <access_token>`
- `X-Tenant-Id: <tenant_uuid>` (must match token claim or is rejected)
- `Idempotency-Key: <uuid>` (writes only)

**Response envelope**
```
{ "ok": true, "data": { … }, "audit_ref": "aud_2026-...", "version": 12 }
```
or
```
{ "ok": false, "error": { "code": "RBAC_DENIED", "detail": "…",
                                            "required_scopes": ["users:write"] } }
```

## 3 · Data model (minimum viable)

```
Tenant             { id, name, parent_id?, created_at, retention_days }
User               { id, tenant_id, email, display_name, disabled_at?,
                            last_login_at?, mfa_enrolled_at? }
Role               { id, tenant_id, name, description, is_builtin }
Permission         { id, action, resource, effect }   ("users:write", "detections:read", …)
RoleBinding        { user_id, role_id, scope: tenant|team|object }

ServiceAccount     { id, tenant_id, name, created_at, disabled_at? }
ApiKey             { id, tenant_id, owner_id, scopes[], expires_at?,
                            last_used_at?, revoked_at?, hashed_secret }
Webhook            { id, tenant_id, url, event_types[], secret_ref,
                            enabled, retry_policy, created_at }
WebhookDelivery    { id, webhook_id, event_id, status, attempts,
                            last_error?, sent_at }

Secret             { id, tenant_id, kind, cipher_text, iv, key_version,
                            rotated_at }
Extension          { id, tenant_id, capability_id, manifest, lifecycle,
                            config_ref, health_status, installed_at }
DataSource         { id, tenant_id, extension_id, config, enabled,
                            last_ingest_at?, health }
CollectorNode      { id, tenant_id, hostname, version, enrolled_at,
                            heartbeat_at, health, os, region }
AuditEvent         { id, tenant_id, principal_id, principal_kind,
                            action, resource_kind, resource_id,
                            before?, after?, at, ip, user_agent, sig }
```

## 4 · RBAC model (starter set of built-in roles)

| Role | Scopes |
| --- | --- |
| `platform_admin`      | `*:*` (all resources · all actions) |
| `tenant_admin`        | `*:*` inside a single tenant |
| `soc_manager`         | `incidents:*`, `playbooks:*`, `approvals:*` |
| `soc_analyst`         | `incidents:read`, `incidents:comment`, `evidence:read`, `respond:approve` |
| `detection_engineer`  | `detections:*`, `patterns:*`, `content:*` |
| `automation_engineer` | `playbooks:*`, `automation_rules:*`, `actions:*` |
| `auditor`             | `*:read`, `audit:read` (no writes anywhere) |
| `service_account`     | scoped per-key |

Every P0 endpoint declares `required_scopes`; server rejects if absent.

## 5 · Audit contract

`AuditEvent` records:
- MUST be written BEFORE the response is returned (fail-close).
- MUST be signed with a per-tenant HMAC that rotates on a schedule.
- MUST be append-only. No update path exists in the DB.
- MUST be readable at `GET /api/xdr/audit-log` with tenant + time + principal
  + action filters, no delete path, retention driven by tenant policy.
- MUST record `before` and `after` snapshots for updates so rollback is possible.

## 6 · Secrets contract

- Every secret has a `kind` ∈ `{api_key, hmac, oauth_client_secret, password,
  certificate}`.
- Cleartext appears exactly once: at creation. The response returns it, the
  server never stores it, and subsequent reads return a masked view.
- Rotation is a first-class operation that stages a new value, requires an
  explicit `confirm_rotate` call, and preserves the previous value for a
  configurable overlap window.
- All secrets are encrypted-at-rest with an envelope key stored in the
  platform KMS. `key_version` is tracked so a KMS re-key rotates all
  secrets deterministically.

## 7 · Extension control-plane state machine (canonical)

Already declared in `src/xdr/extensions/extensionContract.js`:

```
AVAILABLE → INSTALLING → INSTALLED → CONFIGURED → TESTED → ENABLED
                                                     ↕
                                                  DISABLED → REMOVING → AVAILABLE
                                                     ↕
                                                  DEPRECATED
FAILED (from INSTALLING/CONFIGURED/TESTED)
```

The API-side endpoints listed in §23 of the gap audit MUST enforce this
state machine. Illegal transitions return `409 CONFLICT` with the
`allowed_next[]` list.

## 8 · UI-side rules

Every Admin page under the new IA (§24 of the audit) MUST:
- Show real data from the API (never mock).
- Render honest empty states: "No API keys yet — create one" not "COMING SOON".
- Never render a control it cannot execute; if the endpoint 501s, disable
  the control and show why.
- Every writable control MUST show its `required_scopes`; if the current
  principal lacks them, the control is disabled with a tooltip.
- Every write MUST show the `audit_ref` in a toast on success.

## 9 · Rollout plan for P0

Order (each step is independently shippable and reversible):

1. **Audit log skeleton** (`GET /api/xdr/audit-log` + writer helper). Nothing
   else writes without emitting to it.
2. **Secrets store** (server + KMS envelope). Every subsequent P0 stores
   through it.
3. **User CRUD + RBAC** (with role bindings and `platform_admin` bootstrap
   role assigned to the seed admin).
4. **API Keys** (owner = user | service_account; hashed at rest; scopes
   validated at auth time).
5. **Webhooks** (create/test/rotate/deliveries).
6. **Extension control-plane API** (turns the existing Capability Hub
   wizard into a real installer).
7. **Data Source CRUD** on top of Extensions.
8. **Collector enrollment** on top of Data Sources.

Every step goes green with:
- pytest (`/api/xdr/**` slice)
- anti-hallucination CI gate (already extended for extension manifests)
- E2E test that boots the standalone XDR, creates an entity through the UI,
  reads back the audit event, and rotates/revokes it.

## 10 · Anti-drift guarantees

- **Route inventory** committed to `docs/NIVXRAY_XDR_ROUTE_INVENTORY.json`
  and diffed on every PR; new routes without an audit row fail CI.
- **Admin section registry** already lives in `adminMeta.js`; a lint rule
  will forbid `connected:false` sections that also have `api:null` and
  no `kind:` — that combination is a UI shell and MUST be classified
  explicitly.
- **Audit template** for every new section is a required checklist in
  the PR template: the 20-question audit from §Phase 1 of the parent
  spec.

## 11 · Explicit non-goals for this spec

- **Not a UI redesign.** The IA in §24 of the audit is the target; migrations
  can be incremental.
- **Not an AI copilot.** Optional AI belongs in a separate spec.
- **Not a competitor feature clone.** Enterprise parity does not mean UI
  mimicry — NivXRay's evidence-first / deterministic moat is preserved.

---

**Signed as target architecture: 2026-02-10**. All subsequent XDR admin
work MUST justify itself against this spec.
