# NivXForge Deployment & Enrollment Architecture

**Phase 0 · architecture + existing-contract audit + tenant-selector repair**
Status: ARCHITECTURE FOR OWNER REVIEW. Only the tenant-selector contract
repair is implemented. Nothing deployed, no tenant created, no token
minted, KUSHU and DESKTOP-A9HGFJJ untouched.

Method note: industry behaviour below is taken from PUBLIC operational
documentation only (Cisco Secure Endpoint connector deployment, Microsoft
Defender for Endpoint onboarding, Elastic Fleet/Defend enrollment,
CrowdStrike sensor provisioning, Sophos Central deployment). No
proprietary implementation or source is reproduced. Every NivXForge
statement below is cited to a file in THIS repository.

---

## 1. Current-state inventory

The audit's headline finding: **NivXForge already implements most of the
enterprise control plane, and it is better than the "generate a token"
screen suggests.** The problem is not missing authority — it is that the
authority is not surfaced as one lifecycle.

| Capability | Classification | Authority |
|---|---|---|
| Organizations | EXISTS_AND_AUTHORITATIVE | `services/tenant_registry.py::create_organization/list_organizations/set_state`, `routers/xdr_tenancy.py` (`tenants.manage`/`tenants.read`); states ACTIVE/SUSPENDED/ARCHIVED |
| Tenant registry | EXISTS_AND_AUTHORITATIVE | `tenant_registry.create_tenant/adopt_legacy/authoritative_required`; kinds INTERNAL_VALIDATION, CUSTOMER, LAB, LEGACY_ADOPTED |
| Principal authority | EXISTS_AND_AUTHORITATIVE | `services/dashboard_lenses.py::resolve_tenant_scope` + `services/platform_designation.py`; PLATFORM vs CUSTOMER, role is NOT authority |
| Tenant-scoped request authorization | EXISTS_AND_AUTHORITATIVE | `services/session_context.py::authorize_requested_tenant`, `routers/edr_tenancy.py` route classification (TENANT_SCOPED / SENSOR_SCOPED / PRODUCT_METADATA) |
| Bootstrap (enrollment) token | EXISTS_AND_AUTHORITATIVE | `edr_plane/enrollment/store.py::mint_enrollment_token/consume_enrollment_token/revoke_enrollment_token`; `enr_<urlsafe>`, digest-at-rest, single-use, TTL, atomic burn |
| Per-device runtime credential | EXISTS_AND_AUTHORITATIVE | `enrollment/store.py::enroll` → endpoint-scoped `agent_credential`; `open_session` issues a short-lived session token |
| Credential rotation / revocation | EXISTS_AND_AUTHORITATIVE | `store.py::rotate_credential`, `revoke_endpoint`; `routers/edr_enrollment.py` `/endpoints/{id}/rotate`, `/revoke`, `/tokens/{id}/revoke` |
| Endpoint identity | EXISTS_AND_AUTHORITATIVE | `enrollment/identity.py`; durable machine attributes (processor_id, machine_guid, device_iid), hostname is metadata, `AuthenticatedEndpoint` is server-derived and frozen |
| Endpoint inventory | EXISTS_AND_AUTHORITATIVE | `routers/edr_onboarding.py` `/computers`, `/computers/{endpoint_id}`; `routers/edr.py` `/endpoints` |
| Policies + versions + assignment | EXISTS_AND_AUTHORITATIVE | `edr_plane/policy/store.py`, `routers/edr_policies.py`; 11-state lifecycle in `edr_plane/policy/contracts.py` (CREATED → … → VERIFIED, plus FAILED/STALE/OUT_OF_SYNC and POLICY_UNASSIGNED) |
| Groups | EXISTS_AND_AUTHORITATIVE | `policy/store.py` `edr_groups`, `routers/edr_policies.py` groups router; `edr_endpoints.group_id`; policy resolves endpoint → group → policy |
| Group binding at bootstrap (Cisco-style) | EXISTS_AND_AUTHORITATIVE | `routers/edr_connector.py::create_deployment` binds `group_id`/`deployment_id`/`release_id` to the MINTED TOKEN server-side; `routers/edr_enrollment.py:298-311` honours it at enrol time with `placement_basis = CONNECTOR_DEPLOYMENT` |
| Installer / release catalog | EXISTS_AND_AUTHORITATIVE | `edr_plane/connector/catalog.py`, `routers/edr_connector.py` releases + artifact download with SHA-256 headers; `routers/edr_onboarding.py` `/packages` |
| Telemetry acceptance | EXISTS_AND_AUTHORITATIVE | `/api/edr/agent/telemetry`, `/telemetry/batch`; `edr_plane/delivery_counters.py`, `services/delivery_reconciliation.py`; SENT ≠ ACCEPTED is enforced |
| Sensor delivery state | EXISTS_AND_AUTHORITATIVE | `enrollment/identity.py::SensorState` — NO_SENSOR, ENROLLED_NEVER_REPORTED, REPORTING, SILENT, REVOKED |
| Acquisition integrity | EXISTS_AND_AUTHORITATIVE | `/api/edr/agent/acquisition-integrity`, `edr_plane/acquisition_integrity.py`; an acquisition gap is never benign |
| Canonical evidence | EXISTS_AND_AUTHORITATIVE | `edr_plane/canonical_bridge.py`, `xdr_canonical_evidence`, `v2_shadow_observations` |
| Rejected-sensor alarm | EXISTS_PARTIAL | `enrollment/rejection.py` records every rejection; `edr_plane/capability/inventory.py` names the alarm — no operator-facing surfaced alarm in the enrollment UI |
| Audit | EXISTS_AND_AUTHORITATIVE | `enrollment/audit.py` (TOKEN_CREATED/CONSUMED/REVOKED, ENROLLMENT_REJECTED…), `policy/store.py::_audit`, `routers/xdr_audit_log.py::emit_audit`, `routers/edr_audit.py` |
| Heartbeat | EXISTS_PARTIAL | sensor posts `/api/edr/agent/heartbeat` (`nivxforge_sensor.py:1220`), classified SENSOR_SCOPED in `edr_tenancy.py:105`; there is no consolidated readiness verdict built from it |
| Health / readiness verdict | EXISTS_PARTIAL | evidence exists in five places (sensor_state, policy state, delivery counters, acquisition integrity, journal) — nothing composes them into one READY answer |
| Deployment profile (reusable, named) | EXISTS_PARTIAL | `create_deployment` is a one-shot deployment CONTEXT, not a stored reusable profile with constraints |
| Tags | MISSING | no tag field or route on `edr_endpoints`; CrowdStrike-style grouping-by-tag has no authority |
| Set/move an endpoint's group after enrolment | MISSING | `group_id` is written only by `assign_default_placement` / `assign_deployment_placement`; no authorized route moves a computer between groups |
| Offboarding / decommission | EXISTS_PARTIAL | `revoke_endpoint` kills the credential (sensor_state REVOKED) — no uninstall instruction, no retention decision, no inventory state |
| Re-enrollment / clone handling | EXISTS_PARTIAL | `enroll` is idempotent on durable identity and preserves placement on reinstall (`edr_enrollment.py:289-295`); CLONED machines (duplicated machine_guid) have no declared policy |
| XDR data sources | EXISTS_AND_AUTHORITATIVE (as a source CRUD plane) | `routers/xdr_data_sources.py` — create/update/enable/disable/test/rotate-credential/delete, `kinds/catalog`, secrets held by `xdr_secrets`, "test is a probe, never CONNECTED" |
| XDR collectors | EXISTS_AND_AUTHORITATIVE | `routers/xdr_collectors.py` — catalog, protocols, start/stop, test, rotate-credential; `routers/xdr_collector_landing.py` ingest |
| Source normalization → evidence | EXISTS_AND_AUTHORITATIVE | `routers/xdr_ingest.py`, `xdr_ingest_routing.py`, `services/normalization/`, `services/canonicalizer/` |
| ONE unified onboarding surface | MISSING | endpoints, packages, tokens, policies, groups, deployments, data sources and collectors are 8 separate consoles with no shared lifecycle |

---

## 2. Industry-derived common pattern

Stripped of vendor vocabulary, all five products do the same six things:

1. **Bind to an authoritative customer first.** Cisco organization, Defender
   tenant, Fleet space, CrowdStrike CID, Sophos Central account.
2. **Choose a CONFIGURATION before issuing anything.** Cisco Group + Policy,
   Defender onboarding package, Fleet Agent Policy, CrowdStrike tags,
   Sophos installer type. The configuration is chosen in the console, not
   argued about on the endpoint.
3. **Issue a bounded bootstrap authority.** A group-bound connector
   package, an onboarding package, an enrollment token, a provisioning
   token. Sophos additionally treats installer POSSESSION as sensitive and
   supports expiring previously downloaded installers.
4. **Exchange bootstrap for a durable per-device identity.** Fleet is the
   clearest: after enrollment the agent receives a separate, limited
   communication API key. The bootstrap credential is never the runtime
   credential.
5. **Prove the endpoint works, separately from "the installer ran".**
   Defender has an explicit detection/onboarding validation step; Cisco
   recommends a LAB before broad rollout; Sophos recommends starting with
   a few endpoints.
6. **Keep a live health verdict** driven by policy application and
   check-in, not by installation.

Where NivXForge deliberately diverges: **Elastic enrollment tokens can
enroll many agents and persist until revoked.** NivXForge keeps
one-token-one-device-one-tenant-single-use as the interactive default.
Bulk deployment will be a SEPARATE, explicitly constrained credential —
never a weakening of this one.

---

## 3. NivXForge authoritative model

```
PLATFORM  (authority class, explicit server-side designation)
  └── ORGANIZATION            tenant_registry, ACTIVE|SUSPENDED|ARCHIVED
       └── TENANT             kind: INTERNAL_VALIDATION | CUSTOMER | LAB | LEGACY_ADOPTED
            ├── DEPLOYMENT PROFILE        (TO BUILD: named, reusable, constrained)
            │     ├── platform / OS       (exists: connector release catalog)
            │     ├── release_id          (exists)
            │     ├── group_id            (exists)
            │     ├── policy (via group)  (exists)
            │     ├── tags                (MISSING)
            │     └── enrollment constraints: TTL, max_enrollments, expiry,
            │                                  revocation  (PARTIAL: TTL only)
            ├── GROUPS  → POLICY → POLICY VERSION → config digest   (exists)
            ├── ENDPOINTS  → endpoint_id → agent_credential → observations (exists)
            └── DATA SOURCES → collector → parser → normalizer → evidence (exists)
```

No new tenancy schema is required. The gap is a **DeploymentProfile**
object and the **readiness composition** above it — both of which can be
built from records that already exist.

---

## 4. EDR enrollment lifecycle

Proposed state model, mapped onto what already produces each fact. States
in **bold** are already derivable today; the rest need composition, not
new authority.

| State | Existing source of truth |
|---|---|
| NOT_STARTED | absence of an endpoint record |
| **PACKAGE_READY** | `connector/catalog.py` artifact_state == PUBLISHED + SHA-256 |
| **BOOTSTRAP_ISSUED** | `edr_enrollment_tokens` ACTIVE (`token_state()`) |
| INSTALLING | NOT OBSERVABLE server-side. Must stay honest: the platform cannot see an installer running, so this state may only ever be reported by the operator, never asserted by the console |
| **REGISTERING** | `/api/edr/agent/enroll` in flight; rejections in `enrollment/rejection.py` |
| **ENROLLED** | `edr_endpoints` record exists, `sensor_state = ENROLLED_NEVER_REPORTED` |
| **AUTHENTICATED** | first successful `/agent/session` (credential proven, not just issued) |
| **POLICY_PENDING** | PolicyState PENDING_DELIVERY / DELIVERED |
| **POLICY_APPLIED** | PolicyState APPLIED, and VERIFIED on a later independent check-in |
| **TELEMETRY_PENDING** | `sensor_state = ENROLLED_NEVER_REPORTED` with a live session |
| **TELEMETRY_VERIFIED** | `delivery_counters` ACCEPTED > 0 for this endpoint |
| READY | composition of ALL of the above — TO BUILD |

Failure / degraded states, each already having a producer:
`TOKEN_EXPIRED`, `TOKEN_REVOKED`, `TOKEN_CONSUMED` (`token_state()`);
`REGISTRATION_REJECTED` (`rejection.py`); `TENANT_REJECTED`
(`authorize_requested_tenant` / `authoritative_required`); `AUTH_FAILED`
(session refusal); `POLICY_FAILED`, `STALE`, `OUT_OF_SYNC`
(`PolicyState`); `TELEMETRY_STALE` (`SensorState.SILENT`);
`EVIDENCE_VALIDATION_FAILED` (canonical bridge / acquisition integrity);
`ACQUISITION_GAP` (B5-GAP-1 — an acquisition gap is NEVER benign and must
not be collapsed into TELEMETRY_STALE).

**Non-collapse rule.** INSTALLED, ENROLLED, AUTHENTICATED, DELIVERING,
EVIDENCE_VERIFIED and READY are six different facts. The existing
`SensorState.ENROLLED_NEVER_REPORTED` exists precisely because an
endpoint that authenticated and then sent nothing is a visibility gap.
Nothing in the new surface may summarise it as healthy.

---

## 5. XDR source onboarding lifecycle

The same spine, using the collector plane that already exists:

```
TENANT (authorize_requested_tenant)
  → SOURCE TYPE            xdr_data_sources kinds/catalog
  → INTEGRATION PROFILE    TO BUILD (the data-source analogue of a DeploymentProfile)
  → AUTHENTICATION         xdr_secrets (secret_id only; never in the source doc)
  → CONNECTIVITY TEST      POST /{ds_id}/test — A PROBE, never a CONNECTED verdict
  → REGISTER SOURCE        xdr_data_sources + bound collector
  → INGEST TEST            xdr_collector_landing → xdr_ingest
  → PARSER VALIDATION      services/normalization
  → NORMALIZATION          services/canonicalizer
  → EVIDENCE VALIDATION    xdr_canonical_evidence
  → HEALTH                 TO BUILD (shared with EDR readiness)
  → READY
```

Source classes to converge on this one contract (catalog entries, not new
engines): NivXForge EDR, third-party EDR, firewall, IDS/IPS, proxy, VPN,
DNS, NDR, identity (AD/Entra/Okta/Duo), email (M365/Secure Email), cloud
(AWS/Azure/GCP), SIEM, syslog, WEF, CEF/LEEF, API, webhook, custom
collector. **Phase 0 defines the contract only. No integration is built.**

---

## 6. Credential lifecycle

```
MINT (console, tenant-bound, single-use, TTL)         mint_enrollment_token
  → DELIVERED ONCE in the mint response only          plaintext never stored
  → PRESENTED on STDIN ONLY (Windows)                 --token-stdin, argv refused
  → BURNED atomically                                 consume_enrollment_token
  → EXCHANGED for endpoint-scoped agent_credential    enroll()
  → SESSION tokens, short-lived                       open_session()
  → ROTATE / REVOKE                                   rotate_credential / revoke_endpoint
```

Invariants already enforced: digest-at-rest only; one generic `401` for
every refusal (expired / reused / unknown / foreign tenant are
indistinguishable to an unauthenticated caller); the token is burned
BEFORE identity is written, so a partial failure leaves it spent; every
issuance, consumption, expiry and revocation is audited; the Windows
interface refuses the secret on argv entirely
(`docs/B5_GAP_1_ENROLMENT_SECRET_STDIN.md`).

Bulk deployment, when it comes, is a **separate credential type** with
tenant binding, deployment-profile binding, expiry, max_enrollments,
revocation, rate limits and its own audit. It does not relax the
single-device token. **Not implemented in this phase.**

---

## 7. Identity lifecycle

`TENANT → ENDPOINT_ID → AGENT IDENTITY → OBSERVATIONS`, with hostname as
metadata throughout (`enrollment/identity.py`). Enrolment refuses when no
durable machine attribute is present (`NO_DURABLE_IDENTITY`), and the
Windows sensor refuses locally for the same reason before it even calls.

Declared gaps, to be answered by owner decision rather than invented:

| Case | Today | Needed |
|---|---|---|
| Reinstall | idempotent on durable identity; placement preserved | keep; state it in the UI |
| Duplicate hostname | harmless — hostname is not identity | keep |
| CLONED machine (same machine_guid, two hosts) | both resolve to ONE endpoint_id; evidence from two hosts merges silently | a detectable clone-collision signal and a declared policy. **P0 GAP** |
| Credential theft / replay | credential is endpoint-scoped | rotation exists; no automatic anomaly signal |
| Offboarding | credential revoked; evidence retained | explicit inventory state + retention decision |

---

## 8. Policy / group model

Already strong and server-authoritative: policy → version → config digest,
delivered to an AUTHENTICATED session, acknowledged, applied, and
VERIFIED only by a later independent re-report. The endpoint cannot
self-select a tenant or a policy — `fetch_policy` resolves from the
server-side endpoint record via `group_id`.

Missing: tags; a route to move an endpoint between groups; and a named
reusable profile. Nothing cosmetic should be built for these until the
authority exists.

---

## 9. Health / readiness model

A single composed verdict, computed server-side, never from heartbeat
alone:

```
READY  requires ALL of
  service running (endpoint-reported, labelled as such)
  endpoint_id established                      edr_endpoints
  credential proven by a session               open_session
  tenant binding correct                       AuthenticatedEndpoint.tenant_id
  policy VERIFIED                              PolicyState.VERIFIED
  heartbeat current                            /agent/heartbeat
  acquisition healthy                          acquisition_integrity
  journal healthy                              B5-GAP-1 local evidence journal
  telemetry ACCEPTED > 0                       delivery_counters
  canonical observation attributed to this tenant + endpoint
  no rejected-sensor alarm                     enrollment/rejection.py
  no acquisition gap
```
Anything less is named explicitly. `DEGRADED` must say WHICH clause failed.

---

## 10. Offboarding / re-enrollment model

Proposed states: `ACTIVE → REVOKED → DECOMMISSIONED → (optional)
EVIDENCE_RETAINED_ONLY`. Revocation must never delete or re-attribute
evidence; a re-enrolled machine is the same endpoint_id with a new
credential; a deliberately rebuilt machine is a NEW endpoint_id, and the
UI must make the operator choose which of the two they mean.

---

## 11. Audit model

Already present and reusable as-is: token created/consumed/revoked,
enrollment accepted/rejected, credential rotated/revoked, policy created/
version/assigned/acknowledged/applied, group created, tenant context
switched, plus the tamper-evident `xdr_audit_log`. New surfaces MUST emit
into these, not into a new log.

---

## 12. UI information architecture

```
Administration → Deployment & Enrollment
  Endpoints            inventory + per-endpoint readiness chain
  Data Sources         XDR source inventory + per-source readiness chain
  Deployment Profiles  platform, release, group, policy, tags, constraints
  Enrollment Credentials  issued / consumed / expired / revoked (metadata only)
  Policies & Groups    existing consoles, linked not duplicated
  Health               composed readiness, failing clause named
  Audit                filtered view of the existing audit authority
```

Endpoint wizard: 1 tenant → 2 platform → 3 profile (group/policy/tags) →
4 deployment method → 5 issue bootstrap (stdin instructions only) →
6 install → 7 registration verification → 8 telemetry + evidence
verification → 9 READY.

**Build order is backend-first.** No wizard step may exist whose
underlying authority does not. Steps 1, 2, 4, 5, 6, 7 are satisfiable
today; step 3 needs DeploymentProfile + tags; step 8/9 need the composed
readiness verdict.

---

## 13. Security invariants

1. Tenant resolution is server-authoritative; the browser may only REQUEST.
2. PLATFORM authority is an explicit server-side designation, never a role.
3. A PLATFORM principal must NAME the tenant for any tenant-scoped mutation.
4. A CUSTOMER principal cannot reach outside its explicit grants.
5. No default tenant, no last-used-as-authority, no hostname-derived
   tenant, no incident-derived or telemetry-derived authorization.
6. Being OFFERED a tenant is not authority over it — every request
   re-authorises.
7. Unknown, stale, SUSPENDED or ARCHIVED tenants fail closed.
8. The bootstrap secret is single-use, tenant-bound, atomically burned,
   never persisted, never logged, never on a command line.
9. The bootstrap secret never becomes the endpoint identity.
10. Evidence is attributed to the authoritative tenant + endpoint, and the
    same identity carries through telemetry, detection and response.
11. SENT ≠ ACCEPTED; an acquisition gap is never benign; READY is never
    inferred from an installer exit code or from heartbeat alone.
12. Existing Internal Validation evidence is never moved, rewritten,
    deleted or re-attributed.

---

## 14. Gap matrix

**P0**
1. ~~XDR scope contract published the evidence list as the authority list~~ —
   **REPAIRED IN THIS PHASE** (§15 / below).
2. Console-generated Windows invocation string still reads
   `-EnrollmentToken <ENROLLMENT_TOKEN>` (`routers/edr_connector.py`
   `create_deployment`), which contradicts the now-mandatory stdin-only
   contract and would teach an operator to put a secret on a command line.
   NOT CHANGED — out of this phase's approved scope, reported for decision.
3. No composed READY verdict: an endpoint can look fine while telemetry
   has never been accepted.
4. Clone collision (two hosts, one machine_guid) has no signal and no
   declared policy.
5. Linux sensor still accepts `enrol --token <secret>` on argv (separate
   P0 security debt, already recorded).

**P1**
6. DeploymentProfile does not exist as a reusable, constrained object.
7. Tags do not exist.
8. No authorized route moves an endpoint between groups.
9. Rejected-sensor alarm is recorded but not surfaced to the operator.
10. Offboarding is credential-only; no inventory/retention state.
11. Eight separate consoles instead of one Deployment & Enrollment surface.

**P2**
12. Bulk/mass deployment credential (explicitly constrained, separate type).
13. Integration profiles for the XDR source classes listed in §5.
14. Installer-possession controls in the Sophos sense (expire previously
    downloaded artifacts).
15. macOS / additional endpoint platforms.

---

## 15. Phased implementation plan

| Phase | Content | Gate |
|---|---|---|
| **0 (this phase)** | audit + this document + the additive scope-contract repair + tests | owner review |
| 0b | deploy the repair; verify the XDR selector and AdminTenantGate resolve the authorised tenant in production | owner-authorised deploy |
| 0c | create the `NivXForge Canary` LAB tenant, mint ONE token, run C0.5 on KUSHU through the real production path | owner authorisation per step |
| 1 | composed READY verdict + readiness API over existing facts (no new authority) | tests + real KUSHU endpoint |
| 2 | DeploymentProfile + tags + move-endpoint-between-groups | tests |
| 3 | unified Administration → Deployment & Enrollment surface over phases 1-2 | UI tests |
| 4 | offboarding / decommission / clone policy | owner decision on semantics first |
| 5 | XDR integration profiles onto the same lifecycle, one source class at a time | per-class evidence |
| 6 | constrained bulk deployment credential | security review |

---

## Implemented in Phase 0 — the tenant-selector contract repair

`GET /api/xdr/scope/authorized` now publishes BOTH lists:

* `tenants` — UNCHANGED, evidence-derived (`session_context.list_customers`,
  the incident-queue predicate, carrying `open_incidents` volumes).
* `authorized_tenants` — NEW, authority-derived
  (`session_context.authorized_customers`: explicit grants for a CUSTOMER
  principal, the authoritative ACTIVE registry for a PLATFORM one). This is
  the same value the EDR console already consumes, so the two consoles can
  no longer disagree.

`authorized_count` was already authority-derived and is now consistent
with the list beside it.

Frontend: `XdrScopeNavigator.jsx` offers `authorized_tenants` and uses
`tenants` only for the "N open" annotation (a tenant with no XDR incidents
now reads `no XDR incidents` instead of vanishing); `AdminTenantGate.jsx`
offers `authorized_tenants` and auto-adopts when exactly one is
authorised.

No authorization predicate was touched. Being offered a tenant still
grants nothing: `edr_tenant` → `authorize_requested_tenant` →
`authoritative_required` runs on every request, a PLATFORM principal
still gets `TENANT_REQUIRED` when it names nothing, and a SUSPENDED
tenant is still refused even though it exists.
