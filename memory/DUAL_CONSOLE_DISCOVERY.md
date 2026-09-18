# NIVXRAY XDR · DUAL-CONSOLE ARCHITECTURE — DISCOVERY REPORT

Answers items 1–5 and 10–15 of the owner directive §20. Items 6–9 are in
`CONSOLE_REFERENCE_CATALOGUES.md`.

**READ-ONLY DISCOVERY. No route, page, auth or RBAC code was changed.**
No implementation of the dual-console architecture was self-authorized.

---

## 1 · Current route / page inventory, classified

Source: `apps/nivxray-xdr/src/App.jsx` (single SPA, 74 `<Route>` entries) and
`xdr/admin/adminMeta.js` (26 admin sections under one dynamic route).

### 1a · ANALYST — belongs in the Analyst / Investigator Console (31)
| route | surface |
|---|---|
| `/xdr/mss-dashboard` | Control Center (current home) |
| `/xdr/incidents` · `/xdr/incidents/:id` · `/xdr/incidents/:id/domain/:domainKey` | incident queue + workspace |
| `/xdr/detections` · `/xdr/detections/:id` | detections |
| `/xdr/investigations` · `/xdr/investigations/:caseId` | investigations / cases |
| `/xdr/evidence-explorer` · `/xdr/evidence/:executionId` | evidence |
| `/xdr/search` | hunting / search |
| `/xdr/assets` + `/assets/identity` `/assets/network` `/assets/attack-paths` `/assets/critical` | assets |
| `/xdr/endpoints/:device` · `/xdr/endpoints/:device/trajectory` | endpoint investigation · device trajectory |
| `/xdr/intelligence/threat` `/iocs` `/command` `/malware` `/mitre` `/files/:key` | intelligence (incl. Command Intelligence) |
| `/xdr/intelligence/kb` · `/xdr/kb` · `/xdr/docs` | knowledge |
| `/xdr/respond/approvals` | response approvals (analyst-facing queue) |
| `/xdr/exposure` | exposure / CVE |
| `/edr/*` (13 routes: trajectory, detections, process-tree, campaign-story, device-trajectory, files, network, hunting, forensics, live-query, response) | separate EDR product scope — **out of dual-console scope, do not migrate** |

### 1b · ADMIN — belongs in the Administration Console (26 sections, 1 route)
`/xdr/admin` + `/xdr/admin/:section`, sections from `adminMeta.js`:
`overview · audit-log · secrets · content-pack-lolbas · capability-hub ·
edr-enrollment · edr-response · edr-capability-truth · detection-registry ·
correlation-rules · engines · corpus · integrations · data-sources ·
ingest-routing · collectors · agents · telemetry-studio · telemetry-health ·
parsers · normalization · response-policies · users-roles · api-keys ·
api-webhooks · response-strategies · platform-health`
**Finding:** the Administration Console the owner is asking for *already
exists as data and APIs* — it is 26 sections rendered through one generic
section body with a NavLink list. It has no purpose-built information
architecture, which is exactly the gap this programme addresses.

### 1c · SHARED (must work identically in both, or be duplicated deliberately)
`/login` · `XdrShell` (rail, ribbon, tenant pill, global search, theme
toggle) · `AccessProvider` (`/api/xdr/rbac/me/effective`) · `xdr/nx/` design
system · tenant selector · audit surfacing.

### 1d · MISPLACED in the current SPA
| route | problem | proposed console |
|---|---|---|
| `/xdr/data-sources` · `/xdr/data-sources/:tab` | a **second, analyst-side** data-sources page coexisting with `admin/data-sources` | ADMIN (keep an analyst read-only "contributing sources" view inside the incident, not a top-level nav item) |
| `/xdr/rule-studio` | detection authoring in the analyst rail | ADMIN → Detection Engineering |
| `/xdr/detect/tuning/:ruleId` | rule tuning in the analyst rail | ADMIN → Detection Engineering (analyst can deep-link *into* it with permission) |
| `/xdr/respond/playbooks` · `/playbooks/:id` · `/automation-rules` · `/automation-rules/:id` | automation authoring in the analyst rail | ADMIN → Automation & Response |
| `/xdr/admin/telemetry-studio` reached via `/xdr/activities` redirect | an analyst-sounding URL lands on an admin page | ADMIN; keep the redirect for compatibility |
| `Client Management` rail group | tenant administration inside the analyst rail | ADMIN → Customers / Tenants |

### 1e · DUPLICATE / redirect-only (10) — inventory before any consolidation
`/` → `HOME_PATH` · `/xdr` → mss-dashboard · `/xdr/dashboard` → mss-dashboard ·
`/xdr/control-center` → mss-dashboard · `/xdr/endpoints` → assets ·
`/xdr/cve` → exposure · `/xdr/detect/studio` → rule-studio · `/kb` → `/xdr/kb` ·
`/docs` → `/xdr/docs` · `/xdr/activities` → admin/telemetry-studio ·
`*` → `HOME_PATH`.
**Also duplicate by content, not by redirect:** `/xdr/data-sources` vs
`/xdr/admin/data-sources`; `/xdr/intelligence/kb` vs `/xdr/kb`.
**Nothing is proposed for deletion in this report.** Consolidation follows the
mandated order: inventory → compare → choose authoritative → migrate missing
capability → compatibility redirect → regression test → remove dead code.

---

## 2 · Proposed Analyst Console IA
Entry: `/login` → **Control Center** (or **My Queue** by preference).
```
CONTROL CENTER                     what needs my attention now

INCIDENTS        My Queue · All Incidents · Detections
INVESTIGATE      Investigations · Evidence · Entities
HUNTING          Hunt · Queries · Saved Hunts
INTELLIGENCE     IOC Intelligence · Command Intelligence ·
                 Malware Intelligence · MITRE ATT&CK · Knowledge
RESPONSE         Actions · Approvals · Verification
ASSETS           Devices · Users · Cloud · Applications
REPORTS

                 ── footer ──
                 ⇄ Switch to Administration Console   (only when authorized)
```
Notes: `Entities` is new as a top-level surface (today entities are reachable
only from inside an incident). `Verification` is new and is the UI home of the
`ACCEPTED ≠ EXECUTED ≠ VERIFIED` distinction. `Exposure` folds under Assets.
No administration group appears in this rail, ever — switching is an explicit,
re-authorized action.

## 3 · Proposed Administration Console IA
Entry: `/admin/login` → **Admin Overview**.
```
ADMIN OVERVIEW            is the platform configured, connected, secure, operational

CUSTOMERS / TENANTS       tenants · entitlement · tenant health

DATA & TELEMETRY          Data Sources · Collectors · Integrations ·
                          Agents / Sensors · Ingest Routing · Parsers ·
                          Normalization · Telemetry Health · Verify Ingestion ·
                          Telemetry Studio

DETECTION ENGINEERING     Rules (Rule Studio) · Detection Registry ·
                          Correlation Rules · Detection Content ·
                          Exceptions / Tuning · Coverage · Investigation Corpus

AUTOMATION & RESPONSE     Playbooks · Automation Rules · Response Policies ·
                          Response Strategies · Approval Configuration ·
                          Connectors

ACCESS MANAGEMENT         Users · Groups · Roles · Permissions · Assignments ·
                          Resource Scopes · Effective Access · Access Simulator

DEVELOPER / INTEGRATION   API Keys · Webhooks · APIs · Secrets Store

PLATFORM                  Authentication / SSO · Engines · Capability Hub ·
                          Platform Health · Audit Log · Storage / Retention ·
                          Updates · Settings

                          ⇄ Switch to Security Operations
```
Mapping: every group above is backed by an **existing** `adminMeta` section or
an existing route (§1b/§1d). `Exceptions/Tuning` = `/xdr/detect/tuning/:ruleId`.
`Rules` = `/xdr/rule-studio`. Genuinely new: `Groups`, `Permissions`,
`Assignments`, `Resource Scopes`, `Effective Access`, `Access Simulator`,
`Authentication / SSO`, `Storage / Retention`, `Updates`, `Verify Ingestion` —
all of which have backend support (§4) but no UI.

## 4 · Authentication / tenant / RBAC authority discovery
**Identity authority — one, today.** `backend/routers/auth.py`:
`POST /api/auth/login` (sliding-window rate limit keyed by
`(email, client_ip)`, 429 + `Retry-After`), `GET /api/auth/me`,
`POST /api/auth/change-password` (min 12 chars). Credentials live in the
`users` collection; `create_token(email)` issues the JWT.
**There is exactly one password store and one token issuer.**

**Authorization authority — one, today.** `backend/routers/xdr_rbac.py`
already implements a full RBAC surface:
`GET /permissions` · `GET/POST/PUT/DELETE /roles` + `/roles/{id}/clone` ·
`GET/POST/PUT/DELETE /users` · `POST/DELETE /users/{id}/roles[/{assignment}]` ·
`GET /users/{id}/effective` · `GET/POST/DELETE /groups` · `POST /simulate` ·
`GET /me/effective`.
Enforcement is a single dependency factory `require_permission(permission, *,
resource_id_header)` accepting **two mutually exclusive principals**:
a USER (verified JWT → `xdr_users` / `xdr_user_roles`) or a MACHINE
(`X-XDR-API-Key` + `X-Tenant-Id` validated against SHA-256 digests in
`xdr_api_keys`). Presenting both is rejected as ambiguous.
**Tenant authority** is carried on the same path (`X-Tenant-Id` for machines,
assignment scope for users); `resource_id_header` already provides
resource-scoped checks.
Frontend `AccessProvider` consumes `/me/effective` three-valued
(`false` denies, `true`/`null` allows) so a transient read never locks out.

**Conclusion:** the platform is *already* one identity authority + one tenant
authority + one authorization authority + one permission catalogue. Nothing in
the dual-console request requires a second one, and building one would be a
regression.

## 5 · Proposed dual-login architecture (no duplicate security authorities)
```
/login              Analyst  entry  ─┐
/admin/login        Admin    entry  ─┤→  POST /api/auth/login   (ONE endpoint,
                                     │   one user store, one token issuer,
                                     │   one rate limiter)
                                     │
                                     ├→  token gains ONE new claim:  console
                                     │   ("soc" | "admin") — the console the
                                     │   session was opened FOR, never what the
                                     │   user is allowed to do
                                     │
                                     └→  GET /api/xdr/rbac/me/effective
                                         decides what is actually permitted
```
Rules that must hold:
1. **One authentication stack.** Two entry *experiences* (different branding,
   different copy, different post-login destination) over one endpoint. No
   second password store, no second token issuer, no second rate limiter.
2. **`console` is a session *destination*, not a permission.** Admin Console
   access is gated by a new permission — proposed `console.admin.access` — and
   SOC access by `console.soc.access`, both evaluated **server-side** on every
   admin/analyst API call. A user who is an administrator does not
   automatically gain SOC response rights, and vice versa.
3. **URL knowledge grants nothing.** `/admin/*` routes render a client guard
   for UX only; every underlying endpoint already passes through
   `require_permission`. Frontend hiding is not authorization — stated as a
   test requirement, not an aspiration.
4. **Console switch re-evaluates.** `⇄ Switch to …` re-reads
   `/me/effective` and, if a separate audience claim is adopted, re-mints the
   token. It never flips a client flag.
5. **SSO-ready.** If an IdP is introduced, both entries redirect through the
   same IdP with the requested console preserved as state.
6. **Open question for owner/RBAC-1:** whether the two consoles warrant
   distinct token *audiences* (so a stolen SOC token cannot call admin APIs
   even if the account is privileged). Recommended, but it is an auth change
   and therefore belongs to the RBAC/auth lane, not to UX.

## 10 · Shared `xdr/nx/` component requirements
Already exist and are reused unchanged: `NxDataTable`, `NxFlyout`, `NxEmpty`,
`NxSeverity` family, `NxProvenanceChip`, `NxTabs`, `XdrShell`, `AccessProvider`.
Needed additions (both consoles, one implementation, no second system):
| component | purpose | consoles |
|---|---|---|
| `NxConsoleShell` | one shell parameterised by nav model + brand line, so there is never a second page shell | both |
| `NxConsoleSwitch` | authorized `⇄ Switch to …` control with re-evaluation | both |
| `NxIncidentHeader`, `NxStageRail`, `NxClaimCard`, `NxMetricDrawerCard`, `NxTechnicalDetails` | promoted from the approved UX0 prototype | analyst |
| `NxHealthState` | `HEALTHY · EVIDENCE INCOMPLETE` / `NOT CONFIGURED` / `CONNECTED` triad — `CONNECTED` only on real telemetry | admin (analyst read-only) |
| `NxEffectiveAccess` | who/what/where/why/from-which-grant explanation tree | admin |
| `NxAssignmentEditor` | group membership + role + direct grant + scope + restriction | admin |
| `NxLifecycleState` | `Requested → Approved → Dispatched → Executed → Verified → Failed` | both |
| `NxCompleteness` | Analysis Completeness — separate from confidence, never derived from it | analyst |
| `NxWizard` | connect → configure → verify → ready (Elastic onboarding pattern) | admin |
| `NxAuditTrail` | append-only who/what/when/basis | both |

## 11 · API / data gaps blocking the proposed IA
| surface | needed | today |
|---|---|---|
| Admin Overview | one aggregated platform-health rollup | 26 per-section endpoints; no rollup → compose client-side or add one read endpoint |
| Effective Access | `GET /users/{id}/effective` ✅ + **who-has-access-to-resource X** reverse query | forward only |
| Access Simulator | `POST /simulate` ✅ | exists; no UI |
| Assignments | direct grants / direct restrictions / resource scopes | roles + groups exist; grant/restriction/scope contract must be confirmed in RBAC-1 |
| Console access | `console.admin.access` / `console.soc.access` permissions | do not exist |
| Verify Ingestion | per-source last-event + counter + latency | `telemetry-health` partial |
| Tenants | tenant CRUD + entitlement | `Client Management` rail exists; contract unverified |
| Auth / SSO | IdP config | none |
| Retention / Updates | storage + version management | none |
| Incident score | numeric risk | none → `NOT AVAILABLE` (already honoured in the Wave 1 prototype) |
Rule held: **the UI adapts to backend truth; backend truth is never weakened to
fit a reference UI.**

## 12 · Migration / deep-link implications
- `/xdr/admin` and `/xdr/admin/:section` must keep working as permanent
  redirects into the new admin console. 26 section keys are live URLs today.
- Analyst deep links (`/xdr/incidents/:id`, `/xdr/endpoints/:device/trajectory`,
  `/xdr/evidence/:executionId`, `/xdr/intelligence/*`) must not move.
- Moving `rule-studio`, `detect/tuning/:ruleId`, `respond/playbooks*`,
  `respond/automation-rules*` and `data-sources` to the admin console requires
  a redirect **and** an in-analyst deep-link path for permitted analysts —
  an analyst tuning a rule from a detection must not be dead-ended.
- `/xdr/activities → /xdr/admin/telemetry-studio` is an existing analyst-looking
  URL landing on an admin page; keep the redirect, fix the naming.
- 10 existing redirect-only routes stay; nothing is deleted in this programme
  without the full consolidation sequence.
- Browser back/forward across a console switch must not strand the user on a
  surface the new session is not authorized for.

## 13 · Security risks of the dual-console change
| # | risk | mitigation |
|---|---|---|
| R1 | Two login pages become two auth stacks | ONE `/api/auth/login`; a second password store or token issuer is a hard review failure |
| R2 | Client-side console guard mistaken for authorization | every admin endpoint already behind `require_permission`; add explicit tests that an analyst token is **rejected by the API**, not merely hidden in the UI |
| R3 | "Administrator implies SOC privileges" | separate `console.*.access` permissions; no implication either way |
| R4 | Token replay across consoles | consider distinct audiences (owner decision, §5 rule 6) |
| R5 | Rate limiter bypass via the second entry | both entries must hit the same `LOGIN_LIMITER` key space |
| R6 | Tenant confusion after switching | re-resolve tenant scope on switch; never carry a stale tenant pill |
| R7 | Admin console leaking SOC evidence beyond scope | admin surfaces must not embed unscoped evidence views |
| R8 | Audit blind spot on console switch | log switch attempts (granted and denied) to the existing audit authority |
| R9 | Machine principal (`X-XDR-API-Key`) inheriting console semantics | collectors have no console; `console.*` must be user-principal only |
| R10 | Duplicate data-sources pages drifting | choose one authoritative implementation before building admin Data & Telemetry |

## 14 · Implementation-wave proposal (nothing started)
| wave | content | gate |
|---|---|---|
| **A0** | owner approval of this architecture + the two reference catalogues | **open now** |
| A1 | `NxConsoleShell` + `NxConsoleSwitch`; Analyst rail rebuilt to §2; admin surfaces removed from the analyst rail (routes kept + redirected) | A0 |
| A2 | Analyst Wave 2 from the UX0 programme (Attack Story · Timeline · Evidence · Entities · Detections · MITRE · Activity · Entity 360) | A1 + UX0 Wave 1 approval |
| B1 | `/admin/login` + Admin Overview (platform health, not SOC graphs) | A0 |
| B2 | Admin Data & Telemetry (incl. resolving the duplicate data-sources page) | B1 |
| B3 | Admin Access Management + Effective Access + Access Simulator | B1 + **RBAC-1** (grant/restriction/scope contract) |
| B4 | Detection Engineering + Automation & Response (migrated from the analyst rail) | B1 |
| B5 | Developer/Integration + Platform (SSO, retention, updates) | backend contracts |
| C | route consolidation + dead-code removal, full sequence | all above |
Cross-cutting: `console.*.access` permissions are an **auth/RBAC lane** change
and must be delivered there, not inside UX.

## 15 · Repository state
```
branch     : feature/rc2-alignment
start HEAD : 6caa3698
end   HEAD : 6caa3698      (no commit made by this discovery)
worktree   : M apps/nivxray-xdr/src/App.jsx        (earlier UX0 Wave 1, additive)
             ?? apps/nivxray-xdr/src/xdr/ux0/*     (earlier UX0 Wave 1)
             ?? memory/CI_DISCOVERY_R4_R5.md
             ?? memory/E2E_UX0_REFERENCE_CATALOGUE.md
             ?? memory/E2E_UX0_WAVE1_ACCEPTANCE.md
             ?? memory/DUAL_CONSOLE_DISCOVERY.md            (this file)
             ?? memory/CONSOLE_REFERENCE_CATALOGUES.md
             ?? memory/AUTHORITATIVE_XDR_yarn.lock          (pre-existing, unrelated)
```
No production route, page, auth or RBAC file was modified for this report.

---

## STOP
Discovery and reference design complete. **Awaiting owner architecture
approval.** No dual-console implementation self-authorized.
