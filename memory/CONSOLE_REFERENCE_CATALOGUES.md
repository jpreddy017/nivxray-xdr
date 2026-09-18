# NIVXRAY XDR · CONSOLE REFERENCE CATALOGUES (A: ANALYST · B: ADMIN)

Answers items 6–9 of the owner directive §20. Companion to
`DUAL_CONSOLE_DISCOVERY.md`.

**Reading of the formula.** "NivXRay + Cortex + Cisco + Defender + selective
Falcon / SentinelOne / Trend / Elastic" is read as *select the strongest proven
workflow per surface, normalise it through `xdr/nx/`, then add the evidence
capabilities the other products do not provide* — **not** 25% each, and not a
page-per-vendor collage. Vendor research happens at the **interaction-pattern**
level only.

**Source honesty.** `DOC` = official current product documentation.
`OWNER-SCREENSHOT` = owner-supplied capture (product build `unknown` unless
visible). `NOT-VERIFIED` = a pattern I believe exists but could not confirm
from a current official source in this pass — it is **not** adopted until
verified. No mockup is presented as a vendor console. No reference is invented.

---

# A · ANALYST / INVESTIGATOR CONSOLE CATALOGUE

| # | NivXRay surface | Primary ref | Exact screen / source | Secondary (justified) | Structure to adopt | Interaction to adopt | What to REJECT | NivX difference | API / data contract | Missing backend truth |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 | Control Center | **Cisco XDR** `DOC` docs.xdr.security.cisco.com control-center | Defender XDR home `DOC` | compact tile row + prioritised queue preview, not a marketing dashboard | tile → filtered queue | vanity counters with no drill target | tiles must cite the query that produced them | existing dashboards API | per-tile query provenance |
| A2 | Incidents queue | **Cortex XDR** `OWNER-SCREENSHOT` "Found N results" left queue | Cisco XDR status model `DOC` | compact rows: severity tile · score · assignee · state · ID+title · device/user context · updated | row → workspace; sort; filter; hover bulk-select | oversized cards | `Score → NOT AVAILABLE` (we compute none) | incidents list API | incident score |
| A3 | Incident workspace | **Cortex XDR** `OWNER-SCREENSHOT` split view | Cisco XDR tab vocabulary `DOC` for Evidence/Worklog/Report | queue ‖ detail, compact header, stat clusters, tab strip, ATT&CK strip, lifecycle rail, 4-panel grid | tab switch without losing queue; Show More → flyout | reducing to Cortex's 5 tabs | **all 10 NivX tabs survive**; Analysis Completeness | incident detail APIs | aggregated completeness |
| A4 | Attack Story | **Microsoft Defender XDR** `DOC` learn.microsoft.com investigate-incidents (Attack story: alert list ‖ graph ‖ details rail) | Cortex causality (CGO-left) `DOC` for process ancestry | 3-pane; graph centre; details rail right | node → rail updates in place; group similar nodes | edges without evidence | every edge banded OBSERVED/SUPPORTED/INFERRED/POSSIBLE/UNKNOWN | attack-graph API | edge provenance completeness |
| A5 | Timeline | **Cortex XDR** `DOC` incident timeline | Elastic Timeline `DOC` | dense time-ordered rows, field columns, filter chips | filter-in/out from any cell | prose timeline | provenance per row | canonical events API | `source_timestamp` null on raw projection |
| A6 | Evidence | **Cisco XDR** `DOC` incident Evidence tab | SentinelOne right-drawer `OWNER-SCREENSHOT` for drawer rhythm | dense table: time · type · source · entity · observed value · confidence · provenance | row → evidence flyout; raw JSON only under Technical Details | decorative citations | evidence is a first-class object, not a footnote | evidence APIs | — |
| A7 | Entities / Entity 360 | **Microsoft Defender XDR** `DOC` assets + entity pages | SentinelOne drawer tabs `OWNER-SCREENSHOT` | entity header + fact grid + tabbed drawer | inline pivot → flyout → full page | full-page navigation for every lookup | risk must cite its basis | entity 360 API | risk-score authority |
| A8 | Detections | **Cisco XDR** `DOC` Detection tab | Cortex Alerts & Insights `DOC` | table: time · detection · source · severity · verdict · ATT&CK · evidence · status | row → detection flyout; tune with permission | `Suspicious elements / Decoder chain / Indicators` as loose text | decoder status and indicators are separate concepts, separately surfaced | detections API | — |
| A9 | MITRE ATT&CK | **Cortex XDR** `OWNER-SCREENSHOT` tactic strip | Trend Vision One Observed Attack Techniques `DOC` docs.trendmicro.com | strip + matrix/list drill-down: tactic · technique · id · evidence · confidence · state | populated tactic → filtered detections/evidence | ATT&CK padding; decorative chips | technique withheld unless it can cite an artifact | mitre mapping API | tactic/confidence/evidence_ref absent today (see CI discovery §14) |
| A10 | Hunting | **Microsoft Defender XDR** `DOC` advanced hunting | Elastic Security `DOC` searchable event tables + Timeline; Trend XDR Data Explorer `DOC` | query editor + schema tree + results grid | run · column pivot → filter · save hunt | free-text-only search box | hunt results carry provenance | search API | schema browser, saved hunts |
| A11 | Intelligence (IOC) | **Cisco XDR** `DOC` Intelligence app / observable verdict + pivot menu | CrowdStrike Falcon enrichment rail `OWNER-SCREENSHOT` (report cards, Dismiss / Add to graph) | observable header + verdict + provider rows + pivot menu | pivot → investigate / block / enrich | provider majority-vote as verdict | **OSINT is an evidence contributor, never the verdict**; `NOT_APPLICABLE` / `WAITING_FOR_CANONICAL_IOC` | `osint.py` (built, unwired) | per-tenant provider keys |
| A12 | Command Intelligence | **NivXRay original** — no vendor equivalent | SentinelOne panel density `OWNER-SCREENSHOT` | Assessment · Executive Summary · Decode Status · Execution Chain · Recovered Payload · Behaviors · Indicators & Intelligence · ATT&CK · Native/LOLBAS · Impact · Evidence & Provenance · Technical Details | decode status → drill into unresolved | any vendor pattern that implies a clean decode | Analysis Completeness ≠ Confidence; canonical artifact | `/api/analyze/command` | R-4/R-5/R-7 (Lane B) |
| A13 | Response · Actions | **Cortex XDR** `DOC` + **Defender Action Center** `DOC` | — | action table with a lifecycle column | approve → dispatch → verify | one "Done" state | `Requested→Approved→Dispatched→Executed→Verified→Failed`; **ACCEPTED ≠ EXECUTED ≠ VERIFIED** | response + approvals APIs | verification evidence |
| A14 | Assets | **Cisco XDR** `DOC` assets inventory | Falcon host groups `NOT-VERIFIED` | dense inventory table + drawer | filter by type/disposition; row → entity | — | exposure folds in here | assets API | — |
| A15 | Endpoint investigation | **Cortex XDR** `DOC` causality + Forensics Highlights | Falcon host investigation `NOT-VERIFIED`; SentinelOne storyline `NOT-VERIFIED` | process/network/file/registry projections beside the chain | node select → highlights + events filter | adopting Falcon/S1 before verification | **Device Trajectory** is ours and stays | trajectory API (shadow flag) | full syscall/registry projections |
| A16 | Reports | **Cisco XDR** `DOC` Report tab | — | bounded sections: Detection · Execution · Network · ATT&CK · Indicators | expandable monospace command + Copy + View Evidence | raw key/value dump | every section cites evidence | reports API | — |

### Analyst REJECT list (with reason)
`AI narrative verdict panel` (Cisco AI analysis view `DOC`) — we will not ship a
confident narrative we cannot cite per claim. ·
`Per-analyst custom incident layouts` (Cortex XSIAM `DOC`) — customisation
before a good default multiplies the rejected problem. ·
`Dark-only default` — Cisco ships Light default; both themes first-class. ·
`Single scrollable alert view` (OpenSOAR `NOT-VERIFIED`) — valid at alert scope
inside a flyout, wrong at incident scope. ·
`Low-contrast grey-on-dark metadata` (several vendors) — legibility overrides
screenshot matching. ·
`Administration inside the analyst rail` — the whole point of this programme.

---

# B · ADMINISTRATION CONSOLE CATALOGUE

Researched **separately**. The product with the best incident workspace does
**not** automatically win an administrative surface — and it did not: Cortex
wins the workspace, **Elastic wins onboarding** and **Microsoft wins
permissions**.

| # | NivXRay admin surface | Primary ref | Exact screen / source | Secondary | Structure to adopt | Interaction to adopt | What to REJECT | NivX difference | Missing backend truth |
|---|---|---|---|---|---|---|---|---|---|
| B1 | Admin Overview | **Cisco XDR** `DOC` admin/integrations health | Elastic Fleet agent/health summary `DOC` | platform-health rollup: tenants · telemetry · collectors · sensors · integrations · ingestion · config problems · pending admin actions | any red tile → the offending object | SOC incident graphs on an admin home | `HEALTHY · EVIDENCE INCOMPLETE` is a real state | no aggregated rollup endpoint |
| B2 | Customers / Tenants | **Cortex XSIAM** `DOC` Settings → Configurations (multi-tenant) | Cisco organisation admin `DOC` | tenant table + entitlement + health | row → tenant detail; scope switch | implicit tenant switching | tenant scope is server-enforced | tenant CRUD/entitlement contract unverified |
| B3 | Data Sources | **Cisco XDR** `DOC` integrations catalogue | Elastic Integrations app `DOC` | catalogue grid + per-source health + last-event | connect → configure → **verify** | `CONNECTED` without telemetry | connectivity requires authoritative telemetry evidence | per-stream counters, computed latency |
| B4 | Collectors / Agents / Sensors | **Elastic Fleet** `DOC` elastic.co/docs/reference/fleet (agent policies, agent list, data streams, namespaces) | Cortex Broker VM `DOC` (registration token, 24h validity, right-click Configure); Falcon sensor update policies `NOT-VERIFIED` | agent table + policy object + enrolment token flow | enrol → policy assign → verify check-in | inventing an agent-policy model we do not have | W2-1 acquisition is **frozen** — admin UI must not touch it | agent policy object does not exist in NivXRay |
| B5 | Integrations / Connectors | **Cisco XDR** `DOC` | Elastic `DOC` | catalogue + configured instances + health | enable → credential → test | storing secrets in the page | existing Secrets Store is authoritative | — |
| B6 | Parsers / Normalization / Ingest Routing | **Elastic** `DOC` data streams, `@custom` pipelines, versioned ingest pipelines | Cortex XSIAM data management `DOC` | pipeline list + per-stage status + sample in/out | edit via an override, never the base | editing base pipelines in place | parser truth already surfaced (`parser_ok`) | `parser_ok`/`normalized_ok` default to `true` unmeasured (known P2 defect) |
| B7 | Detection Engineering | **Cortex XSIAM** `DOC` detection content / BIOC rules | Defender custom detections `DOC`; Elastic rules `DOC` | rule table + coverage view + exceptions | author → test against corpus → enable | enabling a rule with no corpus evidence | Investigation Corpus is ours | coverage contract |
| B8 | Automation & Response admin | **Cortex XSIAM** `DOC` + **Defender** `DOC` | — | playbook list + response policy + approval config | policy → scope → approvers | recreating the response approval authority | approval authority is untouchable by UX | — |
| B9 | **Access Management** | **Microsoft Defender XDR unified RBAC** `DOC` learn.microsoft.com (granular permission groups; separate security-data read vs response manage; data scopes) | **Cortex XSIAM** `DOC` Settings → Configurations → Access Management: RBAC **plus SBAC** scoping to assets/cases/endpoints/dataset rows; predefined roles copy-not-edit. **Trend Vision One** `DOC` fixed roles: Master Administrator · Operator · Auditor · Senior Analyst · Analyst | users · groups · roles · permissions · assignments · resource scopes as separate objects, not one blob | assign → preview effective → save; clone a built-in rather than edit it | hardcoding permission definitions in React | `Users + Groups + Roles + Direct Grants + Direct Restrictions + Resource Scope → Effective Access` | direct grants / restrictions / scope contract (RBAC-1) |
| B10 | **Effective Access** | **NivXRay original** (closest analogues: Defender permission preview `DOC`, Cortex SBAC scope view `DOC`) | — | answer table: who · what · to which resource · why · from which grant · who changed it · when · effective now | click a permission → the grant chain that produced it | showing a permission without its origin | *"No access without authority. No privilege without provenance."* | reverse query (who-can-access-resource-X) |
| B11 | Access Simulator | **Cortex XSIAM** role-permission matrix `DOC` | Defender `DOC` | pick principal + action + resource → allow/deny + reason | simulate before save | simulating with client-side rules | server `POST /simulate` already exists | UI only |
| B12 | API Keys / Webhooks / APIs | **Elastic** `DOC` API keys + Fleet API | Falcon API clients `NOT-VERIFIED` | key table: scopes · created · last used · expiry; secret shown once | create → scope → reveal once | re-displaying a secret | machine principal is `X-XDR-API-Key` + `X-Tenant-Id`, already enforced | last-used/expiry fields |
| B13 | Authentication / SSO | **Cisco XDR** `DOC` | Elastic/Cortex SSO `DOC` | IdP config + mapping + test | configure → test → enforce | a second password store | ONE identity authority (discovery §4/§5) | no IdP config at all |
| B14 | Audit | **Cisco XDR** `DOC` | Trend `DOC` | append-only table: actor · action · target · basis · time; filter + export | row → the changed object | mutable audit | audit is an authority, not a log view | — |
| B15 | Platform Health / Engines / Capability Hub | **NivXRay original** | Elastic Fleet health `DOC` | per-engine state + capability truth | drill to the failing engine | a green tick with no evidence | Capability Truth is ours | — |
| B16 | Storage / Retention / Updates | **Elastic** `DOC` data streams / ILM | Cortex `DOC` | retention policy per stream + version/update state | policy → preview impact | fabricating storage numbers | — | no contract |

### Admin REJECT list
`Right-click context menus as the primary action affordance` (Cortex Broker VM
`DOC`) — undiscoverable; use an explicit row action menu. ·
`YAML-only policy editing` (Elastic `DOC`) — keep a form with a YAML view, not
YAML alone. ·
`Fixed, uneditable built-in roles` (Trend `DOC`, Cortex `DOC`) — ADAPT: built-ins
are clone-able **and** NivXRay permits direct grants/restrictions on top, which
neither product exposes. ·
`SOC dashboards on the admin home` — different question, different home. ·
`A second navigation rail to imitate a vendor` — one permanent rail per console.

---

# Cross-vendor comparison by surface (item 8) — who wins and why

| surface | Cortex/XSIAM | Cisco XDR | Defender XDR | Falcon | SentinelOne | Trend V1 | Elastic | **NivXRay picks** |
|---|---|---|---|---|---|---|---|---|
| Shell / nav | dense, settings-heavy | **cleanest XDR-level rail** | portal-centralised | endpoint-first | endpoint-first | workbench-first | Kibana-generic | **Cisco** |
| Incidents queue | **best density** | good | good | good | good | good | table-generic | **Cortex** |
| Incident workspace | **best split view** | good tabs | good attack story | — | — | workbench | — | **Cortex** shell + **Cisco** tab vocabulary |
| Attack story / graph | causality chain | relations graph | **3-pane graph + rail** | graph | storyline `NOT-VERIFIED` | OAT `DOC` | — | **Defender**, Cortex for ancestry |
| Timeline | **dense** | good | good | good | good | good | **Timeline workspace** | **Cortex** + Elastic filter grammar |
| Evidence | artifacts | **Evidence tab** | Evidence & Response | — | Raw Data tab | Forensics `DOC` | — | **Cisco** |
| Entity 360 | key assets | assets | **best entity pages** | host detail | drawer tabs | — | — | **Defender** |
| Hunting | XQL | — | **advanced hunting** | — | — | Data Explorer `DOC` | **event tables + Timeline** | **Defender** + Elastic |
| Intelligence | — | **observable + pivot** | TI reports | **enrichment rail** | — | — | — | **Cisco** + Falcon rail |
| Response | action centre | integrated response | **Action Center** | RTR `NOT-VERIFIED` | automated response | — | connectors | **Defender** + Cortex |
| Onboarding / collectors | Broker VM | integrations | connectors | sensor policies | agent lifecycle | product connections | **Fleet — best** | **Elastic** |
| Permissions / RBAC | **SBAC scoping** | org admin | **unified RBAC granularity** | roles | sites/groups | **named role tiers** | spaces/roles | **Defender** primary + **Cortex SBAC** secondary |
| Effective access explanation | partial | — | preview | — | — | — | — | **NivXRay original** |
| Evidence provenance / completeness | — | — | — | — | — | — | — | **NivXRay original** |

**Consequence:** no single vendor wins both consoles. Cortex wins the
investigation shell; Elastic wins onboarding; Microsoft wins permissions and
entity/hunting; Cisco wins the XDR rail, evidence and intelligence pivot. The
four NivXRay differentiators (canonical evidence, provenance, Analysis
Completeness, response verification) have **no vendor primary** and are
therefore original surfaces, normalised through `xdr/nx/` so the result reads
as one product.

# Item 9 · ADOPT / ADAPT / REJECT summary
- **ADOPT (14):** Cisco rail · Cortex queue density · Cortex workspace split ·
  Defender attack-story 3-pane · Cisco evidence table · Defender entity pages ·
  Defender advanced hunting · Cisco observable pivot · Defender action centre ·
  Elastic Fleet onboarding · Elastic API-key handling · Defender unified-RBAC
  granularity · Cisco audit table · Cisco report sections.
- **ADAPT (9):** Cortex causality → narrated chain with cited edges · Cortex
  SBAC → resource scopes in our assignment model · Trend/Cortex fixed roles →
  clone-able built-ins **plus** direct grants/restrictions · Elastic YAML →
  form-with-YAML-view · Falcon enrichment rail → evidence-contributor framing ·
  SentinelOne drawer rhythm → `NxFlyout` sections · Cortex broker
  right-click → explicit row actions · Cortex 5 tabs → NivXRay 10 tabs ·
  Cortex score field → `NOT AVAILABLE`.
- **REJECT (11):** AI verdict narrative · per-analyst layouts · dark-only
  default · single-scroll incident view · low-contrast metadata · admin inside
  the analyst rail · SOC dashboards on the admin home · right-click as primary
  affordance · YAML-only policy editing · uneditable built-in roles · a second
  navigation rail.
- **NOT-VERIFIED, therefore NOT adopted this pass (5):** Falcon RTR flow ·
  Falcon host groups / sensor update policies · Falcon API clients ·
  SentinelOne storyline visualisation · OpenSOAR single-scroll guidance.
  Each needs a current official reference before it may influence a surface.

## STOP
Both catalogues delivered for owner architecture approval. No surface may be
implemented until its row above is approved and its NivXRay capability/data
mapping is locked.

---

# AMENDMENT 1 — TENANT / MULTITENANT SURFACES (owner-approved 2026-06)

Locked reference model for the tenant dimension:
**Cortex XDR/XSIAM** → Tenant Navigator, tenant-oriented context, dense SOC
workspace · **Microsoft Defender XDR** → Tenant Groups, multitenant SOC,
cross-tenant operational queues, RBAC/permissions, entity/hunting ·
**Cisco XDR / Security Cloud** → organization-first architecture, global XDR
rail, SSO/organization context · **Elastic** → collector/integration onboarding
where already validated · **NivXRay** → Canonical Evidence, Provenance,
Analysis Completeness, Negative Explainability, Effective Access provenance,
Tenant Evidence Health, Command Intelligence, Verified Response.
All adopted patterns are normalised through `xdr/nx/`. No vendor collage.

## A · ANALYST CONSOLE — new tenant surfaces

| # | NivXRay surface | Primary ref | Exact screen / source | Secondary | Structure to adopt | Interaction to adopt | REJECT | NivX difference | Contract | Missing backend truth |
|---|---|---|---|---|---|---|---|---|---|---|
| A17 | **Scope / Tenant Navigator** | **Cortex XDR** `DOC` cortex-docs "Tenant Navigator" — view and switch between authorized tenants, organised by CSP account, with Settings/notifications/help remaining global | **Defender** `DOC` learn.microsoft.com multitenant management + **Tenant Groups** (group tenants by customer / business unit / geography and change the active view) | top-bar control → panel with Search · ★ Favorites · Tenant Groups · Recently accessed | switch without re-authenticating; group changes the active view | listing a tenant because it exists; a static `ALL CUSTOMERS` label | six authoritative `basis` values drive the control; read-only + stated reason when `INHERITED_FROM_INCIDENT`; denied tenants are **named** | C1, C2 | `/scope/authorized`, `/scope/select`, groups |
| A18 | **Cross-Tenant Incident Queue** | **Microsoft Defender XDR** `DOC` multitenant case queue — adds Tenant + Tenant ID, supports tenant search/sort/filter, row preview flyouts, and moving between cases from different tenants without losing queue context | **Cortex** `OWNER-SCREENSHOT` queue density | `Priority · Customer · Incident · Verdict · Risk · Status · Device · User · MITRE · Source · Updated`; `Customer` hidden in single-tenant scope | row → split workspace without losing MDR context; tenant filter chip | a blank tenant cell; fabricated Risk | RBAC still limits visible rows; every row carries resolved tenant provenance | C4 | incident risk/score → `NOT AVAILABLE` |
| A19 | **Cross-Tenant Control Center** | **Cisco XDR** `DOC` control center | Defender multitenant home `DOC` | scope-aware tiles; per-tenant breakdown on drill | tile → cross-tenant filtered queue | one tenant's numbers presented as the whole estate | tiles cite the query and the scope that produced them | C1, C4 | per-tile provenance |
| A20 | **Tenant Evidence Health** | **Microsoft Defender XDR** `DOC` multitenant status indicator (surfaces data-loading / permission problems and identifies affected tenants) | Elastic Fleet health `DOC` | top-bar indicator → per-tenant table: Customer · Condition · Reason · Last event | click → affected tenants + exact telemetry reason | `healthy` by assumption; missing metrics as `0` | states `HEALTHY` / `HEALTHY · EVIDENCE INCOMPLETE` / `COLLECTION GAP` / `AUTHENTICATION FAILED` / `NOT CONFIGURED`; **CONNECTED only after real telemetry** | C5 | per-tenant last-event + reason |
| A21 | **Persistent tenant identity in investigation** | **NivXRay original** (no vendor makes this prominent) | Cortex header `OWNER-SCREENSHOT` | customer line above incident identity in the workspace header | always visible; mandatory when entered cross-tenant | discovering the customer only by reading a field | prevents the worst MDR error: acting on the wrong customer | — | tenant name on incident payload |
| A22 | **Tenant-confirmed response** | **NivXRay original** | Defender Action Center `DOC` | dialog: Customer · Resource · Reason · Approval | confirm → approve → dispatch, each re-validated server-side | letting a UI scope change retarget an approved action | `REQUESTED ≠ APPROVED ≠ DISPATCHED ≠ EXECUTED ≠ VERIFIED` | C8 | tenant+resource re-validation at approve **and** dispatch |

## B · ADMIN CONSOLE — tenant management becomes first class

| # | NivXRay admin surface | Primary ref | Exact screen / source | Secondary | Adopt | REJECT | NivX difference | Contract |
|---|---|---|---|---|---|---|---|---|
| B2a | **Tenants / Customers** | **Cortex Gateway** `DOC` cortex-docs — centralized administrative entry for activating/managing tenants, users, roles and user groups; XDR 5.x main/child multi-tenant structures | **Cisco Security Cloud Control** `DOC` (sign in → create organization → register products → configure user access/policies) | tenant table + lifecycle + parent/child structure | a tenant table that implies access | tenant existence is never proof of access or of telemetry | C3 |
| B2b | **Tenant Groups** | **Microsoft Defender XDR** `DOC` Tenant Groups | — | group CRUD + membership + which authorized set is in view | groups that grant access | **effective scope = requested ∩ authorized**, always | C3 |
| B2c | **Tenant Access** | **Defender** `DOC` multitenant access via Entra B2B / GDAP | Cortex CSP account org `DOC` | who may see which tenant, and from which grant | inferring access from group membership | shows the grant chain, not just the result | C6 |
| B2d | **Tenant Resource Scope** | **Cortex XSIAM SBAC** `DOC` — scope-based access control limiting access to specific assets, cases, endpoints or dataset rows | **Defender** data scopes `DOC` | scope object attached to an assignment | scope as a UI filter | scope is a server-enforced security boundary | C7 |
| B2e | **Data Isolation** | **NivXRay original** | — | per-tenant isolation statement + evidence | claiming isolation without evidence | consumes the owner-locked `EDR_TENANT_BOUNDARY`; unattributed observations stay `UNATTRIBUTED_LEGACY_OBSERVATION` and are never assigned to a customer by inference | — |
| B2f | **Entitlements** | **Cortex Gateway** `DOC` | Trend account admin `DOC` | per-tenant entitlement table | entitlement implying capability | capability truth stays authoritative | — |
| B9a | **Effective Access (flagship)** | **NivXRay original** (analogues: Defender permission preview `DOC`, Cortex SBAC scope view `DOC`) | — | grant chain: permission → group → role → permission → resource scope, + changed-by / when / audit ref / effective-now | a parallel UI-only resolver | **must consume the production resolver** (`resolve_tenant_scope` + `_resolve_user_permissions`); a simulator that can disagree with production is worse than none | C6 |
| B9b | **Access Simulator** | **Cortex XSIAM** role-permission matrix `DOC` | Defender `DOC` | `User × Console × Tenant × Resource × Action → ALLOW/DENY + chain` | a second "simulator-only" algorithm | `POST /api/xdr/rbac/simulate` already exists server-side; UI only | — |

## Amendment REJECT additions
`Separate credentials per customer` — an MDR analyst must reach 30 customers
with one identity, not 30 logins. ·
`Tenant selection before identity` — identity first, then what they may access;
Cortex, Cisco and Microsoft all resolve organization/tenant *after* identity. ·
`Static ALL CUSTOMERS label` — replaced by a real scope control driven by the
six authoritative `basis` values. ·
`Tenant groups as an access mechanism` — grouping only, never a grant. ·
`Silently shrinking a group to the authorized subset` — denials are named.
