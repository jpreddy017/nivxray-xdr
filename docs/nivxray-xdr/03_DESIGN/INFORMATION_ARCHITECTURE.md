<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **TARGET** information architecture. Live routes are **generated**:
> `08_VALIDATION/GENERATED_UI_ROUTE_INVENTORY.md`.

# INFORMATION ARCHITECTURE

Adopts `memory/NIVXRAY_ENTERPRISE_UX_GAP_ANALYSIS.md`,
`memory/COCKPIT_AUDIT_R44.md`,
`memory/LAYER2_QUEUE_REBUILD_MANDATE.md`.

## 1 · Two products, two shells

| | NivXRay XDR | NivXForge EDR |
|---|---|---|
| Route root | `/xdr/*` | `/edr/*` |
| Persona | SOC analyst, threat hunter, MSSP operator | endpoint operator, incident responder |
| Question answered | *what is happening across my estate?* | *what happened on this machine?* |

Separate logins, shells and navigation; **bidirectional
context-preserving pivots**; one authoritative backend.

## 2 · The rail — OPEN CONFLICT, must be decided by the owner

Two candidate structures exist and they are not compatible.

**A · Shipped (reference-aligned, 8 primaries)** — built and verified:
Control Center · Incidents · Investigate · Intelligence · Automate ·
Assets · Client Management · Administration.

**B · Owner mockup (15 items, 2026-09-07)** — Home · Incidents ·
Investigate · Threat Hunting · Devices · Users & Identity · Email
Security · Network · Cloud · Applications · Vulnerability · Threat
Intelligence · Automation · Reports · Administration.

### Why this is not a cosmetic choice

Structure **B** is organised by **security domain** — Email, Network,
Cloud, Applications, Users & Identity. NivXRay has real evidence in
**one** domain. Adopting B creates a rail in which the majority of
top-level items are empty by construction, permanently, until each
domain has a producer. A rail is a promise; nine of fifteen promises
would be unkeepable today.

Structure **A** is organised by **analyst function**, which is domain-
count independent: Incidents, Investigate and Intelligence are
meaningful with one source and scale to ten.

### Options
1. **A wins** — keep the 8 primaries, apply the mockup's *visual
   language* (KPI cards, detection-trend chart, donut, top techniques,
   coverage overview) to Control Center. *Recommended.*
2. **C · A + Home** — keep A as the rail, add a `Home` landing page that
   looks like the mockup, with real projections and named absences.
3. **B wins** — rebuild to 15 items; every domain without a producer
   renders `NOT_INTEGRATED` at rail level.

**Status: unresolved.** Recorded in `03_DESIGN/NAVIGATION_SPEC.md`.

## 3 · Screen-spec obligation

The tree must be sufficient for a frontend team with **no historical
context** to build the console. Every first-class screen requires:

information architecture · route · navigation position · persona · page
objective · authoritative APIs · data objects · layout hierarchy ·
columns/fields · filters · sorting · search · pagination · drawers ·
dialogs · context actions · deep links · XDR↔EDR pivots · RBAC ·
loading · empty · partial · stale · disconnected · unavailable ·
unauthorized · error · keyboard/mouse behaviour · responsive behaviour ·
acceptance tests · reference evidence where available.

**Never use fabricated values to make a screen appear populated.**

### Worked example — Incidents

```
PAGE            Incidents
PURPOSE         the SOC work queue
DATA AUTHORITY  incident SSOT (workspace_cases)
PRIMARY OBJECT  incident
TABLE           priority · title · status · detection count · assets
                users · MITRE techniques · first seen · last seen
                assignee · PROVENANCE
INTERACTIONS    filter · search · sort · open · assign · change status
                add worklog · investigate · respond
STATES          LOADING · EMPTY_REAL · NO_INTEGRATION · STALE · PARTIAL
                ERROR · UNAUTHORIZED
NEVER           hard-coded incident · synthetic operational count
                client-side severity invention
                client-side authorization decision
```

Two NivXRay-specific additions to the reference column set:
**`PROVENANCE`** must be a visible column (an analyst must be able to
tell a real incident from a seeded one), and priority must disclose that
its basis is **detection risk only** — we have no asset-value input.

## 4 · State vocabulary — mandatory

| State | Rule |
|---|---|
| `LOADING` | never an empty table |
| `EMPTY_REAL` | resolved, genuinely zero results — **must say what was searched and over what window** |
| `ENDPOINT_NOT_RESOLVED` | identifier supplied, unresolvable — explicit, never an empty table |
| `NO_INTEGRATION` | no source exists for this surface — **not** zero |
| `STALE` | data older than its freshness contract; must show age |
| `PARTIAL` | some sources answered; must name those that did not |
| `UNAVAILABLE` | capability exists but is blocked (e.g. `BLOCKED_ENVIRONMENT`) |
| `UNAUTHORIZED` | must not disclose existence |
| `ERROR` | actionable, never a blank canvas |

**The core rule: an empty result may never imply the absence of
evidence.** The reference implementation is `EndpointNotResolved.jsx`,
which reads the backend's declared state and never infers absence from an
empty list.

Known violation, tracked: an evidence surface can be truthful about its
window and still hide that evidence exists just outside it
(`WINDOW_HONESTY_GAP`, `EVIDENCE_ARCHITECTURE.md` §5).

## 5 · Pivot contract

14 live pivots audited. Requirements: carry endpoint identity in a form
the target route accepts · preserve tenant context (server-resolved,
**never** taken from the parameter) · preserve evidence context
(incident, detection, event, process) · never substitute a hostname
unnecessarily · never emit an identifier the target cannot support.

One defect was found and fixed: a case id used as a device identifier,
which could only ever render an empty canvas reading as *"this case has
no activity"*.

## 6 · Design authority conflict

`memory/NIVXRAY_VISUAL_GRAMMAR.md` (617 lines) and
`memory/VISUAL_LANGUAGE.md` (514 lines) are both adopted into
`03_DESIGN/DESIGN_SYSTEM.md` and have **never been diffed**. One must
become authoritative before further UI work.
