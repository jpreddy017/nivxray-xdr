# NIVXRAY XDR ↔ NIVXFORGE EDR · TWO-PRODUCT PARITY AUDIT
**Requested artefacts 1–8 · audited 2026-06 against the running build (no
guessing, no implementation started beyond the in-flight X1–X3 slice).**

> **PRODUCT LOCK BEING AUDITED AGAINST**
> `NivXRay XDR` = master XDR console (MSS dashboard + global XDR search +
> correlation / incident / investigation / evidence / verdict / response /
> automation), Cisco-XDR observable baseline.
> `NivXForge EDR` = standalone endpoint product (Computers · Detections ·
> Device Trajectory · **Device Trajectory · AMP ★** · Process Tree · File
> Trajectory · Network · Forensics · Live Query · Hunting · Response · EDR
> Administration), Cisco Secure Endpoint/AMP observable baseline.
> **Two products · two consoles · two direct logins · one shared platform ·
> deep bidirectional pivots.**

---

## 0 · DECISIONS LOCKED BY OWNER (2026-06)

| # | Decision | Effect |
|---|---|---|
| D-1 | **Reverse P0-F.13.3** — un-nest NivXForge EDR from the XDR shell. `/login → /xdr/*`, `/edr/login → /edr/*` | M-1 · M-2 · M-3 confirmed |
| D-2 | **`/xdr/edr/device-trajectory` stays forever** as a compatibility redirect to the canonical EDR route, preserving tenant · org · endpoint · incident · detection · evidence/event · timestamp · process_iid | no proven deep-link may break |
| D-3 | **Two logins, one auth engine** — both use `POST /api/auth/login`; unmistakable product identity per screen; authorisation and tenant resolution stay server-side; product/tenant identity is never trusted from a query parameter | N-1 · N-2 |
| D-4 | **Computers/Endpoints is owned by NivXForge EDR**; XDR keeps Assets/Device Insights which **pivots out** to EDR. No duplicate operational implementation | M-6 |
| D-5 | **FLOW 5 reported BLOCKED** — `G-16 / FLOW-5: REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED`. No fabricated DNS/network/email/identity events, ever. A real second collector is a future phase with its own runtime correlation proof | G-16 stays BLOCKED |
| D-6 | **Y1 IS ON HOLD** until the approved Cisco XDR reference captures arrive. Then: freeze baseline → inventory screens → inventory interactions/states → map to existing implementation → reuse/modify/create decisions → gap list → **then** Y1 + XDR visual/interaction conformance in ONE controlled pass | prevents designing the shell twice |
| D-7 | Parity means **100 % observable** UI/UX/interaction parity, not "inspired by". Implementation stays independent — no Cisco source, assets or branding | acceptance baseline |
| D-8 | Status vocabulary only: `REAL_RUNTIME_VERIFIED` · `END_TO_END_VALIDATED` · `IMPLEMENTED_NOT_RUNTIME_VERIFIED` · `BLOCKED` · `NOT_IMPLEMENTED`. Never inflated | reporting rule |

**Reference captures still required for Y0** (Cisco XDR): Control Center /
dashboard · Incidents list · incident workspace + tabs · Investigate ·
Assets/Device Insights · global search + results · XDR navigation · XDR
header · contextual navigation · expanded ribbon · endpoint/XDR pivots.

---

## 0 · HONEST BLOCKER, STATED FIRST

**B-1 · The approved Cisco XDR reference captures are not in this session.**
`STATUS: BLOCKED`

- For **NivXForge EDR** the reference baseline *is* established and proven:
  the AMP Device Trajectory was conformed and locked in P0-F.13.1 and
  re-proven in P0-F.13.5 / P0 Detection Attribution.
- For **NivXRay XDR** I hold only the *documented* observable model (Cisco
  XDR ribbon/Casebook, pivot menu, device-insights → Secure Endpoint
  trajectory deep-link, incident workspace tabs) plus the two screenshots
  referenced earlier in the programme — the image payloads are not
  retrievable in this session ("Image removed").
- Consequence, stated plainly: **I cannot certify "100 % observable Cisco
  XDR UI/UX parity" without the reference captures.** Any such claim would
  be exactly the kind of unearned status this programme forbids. Every XDR
  visual row in the gap matrix below is therefore capped at
  `IMPLEMENTED_NOT_RUNTIME_VERIFIED` on the *parity* axis until captures
  arrive, even where the behaviour is runtime-verified.
- **What I need**: reference captures (or a shared link) for Cisco XDR —
  Control Center/dashboard, Incidents list + incident workspace tabs,
  Investigate, Assets/Device Insights, global search results, ribbon
  expanded — and, if available, Secure Endpoint Computers + Detections
  lists to finish the EDR side beyond trajectory.

---

## 1 · CURRENT UI INVENTORY (running build)

**59 routes.** Auth: ONE shared `/login` (no product identity), always
lands on `/xdr`.

### 1.1 XDR routes (43)
`/xdr` `/xdr/dashboard` `/xdr/mss-dashboard` `/xdr/search` ★new
`/xdr/incidents` `/xdr/incidents/:id` `/xdr/incidents/:id/domain/:domainKey`
`/xdr/investigations` `/xdr/investigations/:caseId` `/xdr/evidence-explorer`
`/xdr/evidence/:executionId` `/xdr/endpoints` `/xdr/endpoints/:device`
`/xdr/endpoints/:device/trajectory` `/xdr/intelligence/{threat,iocs,command,
malware,mitre,kb}` `/xdr/intelligence/files/:key` (Fleet File Trajectory)
`/xdr/detections` `/xdr/detections/:id` `/xdr/detect/studio`
`/xdr/detect/tuning/:ruleId` `/xdr/rule-studio` `/xdr/respond/{playbooks,
playbooks/:id,automation-rules,automation-rules/:id,approvals}`
`/xdr/exposure` `/xdr/cve` `/xdr/admin` `/xdr/admin/:section`
`/xdr/assets/{identity,network,attack-paths,critical}` ★new (capability-honest)
`/xdr/kb` `/xdr/docs`

### 1.2 EDR routes (14) — **split across two namespaces**
`/edr` (overview) `/edr/detections` `/edr/process-tree`
`/edr/campaign-story` `/edr/files` `/edr/network` `/edr/hunting`
`/edr/forensics` `/edr/live-query` `/edr/response`
`/edr/device-trajectory` `/edr/trajectory` (legacy)
**`/xdr/edr/device-trajectory` ← the canonical AMP trajectory lives under
the XDR namespace.**

### 1.3 Shells / navigation
- `xdr/XdrShell.jsx` — 45 nav keys in 8 groups (WORKSPACE, COMMAND CENTER,
  OPERATIONS, INVESTIGATIONS, INTELLIGENCE, TELEMETRY, EXPOSURE,
  DETECTION ENGINEERING, RESPONSE, PLATFORM…), 9 still `disabled: true`,
  topbar search → `/xdr/search`, customer pill, theme toggle, focus mode.
- `nivxforge/NivXForgeConsole.jsx` — 12 EDR tabs — **and it renders
  `<XdrShell flush>` as its parent** (done deliberately in P0-F.13.3).
- `xdr/components/XdrContextBar.jsx` ★new — breadcrumbs + customer /
  endpoint / incident / evidence / plane chips, on every page of BOTH
  planes.

### 1.4 Proven backend surface behind the UI
`/api/xdr/search` ★new · `/api/xdr/search/capabilities` ★new ·
`/api/edr/endpoints/{id}/linked-incidents` ★new ·
`/api/edr/endpoints/{id}/trajectory` · `…/trajectory/focus` ·
`/api/edr/endpoint-detections` · `/api/edr/context` ·
`/api/xdr/rbac/session-context` · `/api/edr/wave0/capabilities`
Proofs currently green: **X1–X3 17/17 · P0-F.13.5 25/25 · Detection
Attribution 12/12 · tests/edr 330 pass** (3 pre-existing unrelated
failures in `test_p0_f4_endpoint_process_tree.py`).

---

## 2 · REFERENCE GAP MATRIX

Parity axis is capped by **B-1** for XDR rows. Status vocabulary is the
requested one.

| # | Area | Reference behaviour | Current behaviour | Gap | Root cause | Status |
|---|------|--------------------|-------------------|-----|-----------|--------|
| G-1 | **Product separation** | Two consoles, two product shells, two direct logins | ONE shell: `NivXForgeConsole` renders `XdrShell flush`; EDR tabs live inside the XDR chrome; one `/login` always landing on `/xdr` | **Products are merged** | P0-F.13.3 was explicitly built to nest EDR inside the XDR shell (approved at the time). The new lock reverses that decision | `NOT_IMPLEMENTED` |
| G-2 | **EDR product namespace** | All EDR capability under the EDR product | canonical AMP trajectory is at `/xdr/edr/device-trajectory`; the rest at `/edr/*`; a legacy `/edr/trajectory` also exists | EDR is addressed from two namespaces, one of them XDR's | incremental nesting during F.13.2/13.3 | `NOT_IMPLEMENTED` |
| G-3 | **EDR direct login** | Own login + own product identity, no XDR needed | shared `/login`, no product mark, always → `/xdr` | no EDR entry point exists | single-product assumption in `App.jsx` | `NOT_IMPLEMENTED` |
| G-4 | **File Trajectory ownership** | EDR capability | lives in XDR at `/xdr/intelligence/files/:key`, and is data-starved | wrong product + starved | built as an XDR intelligence page (P1.8) | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| G-5 | **EDR Dashboard** | Secure-Endpoint-style endpoint dashboard | `/edr` "Overview" tab exists | needs conformance review against reference | — | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| G-6 | **EDR Administration** | EDR policies/groups/exclusions/connector admin | absent from EDR nav; some equivalents under `/xdr/admin` | EDR admin belongs to the EDR product | shared admin surface | `NOT_IMPLEMENTED` |
| G-7 | **Device Trajectory · AMP** | Cisco Secure Endpoint trajectory: lanes by process ancestry, navigator, 30-day + 24-h, event select → Activity Details, deep-link straight to the event | all present and proven; detection attribution now shown on the observation | none known | — | `END_TO_END_VALIDATED` |
| G-8 | **Secondary XDR trajectory** | keep as investigation projection | kept at `/xdr/endpoints/:device/trajectory` | none | — | `REAL_RUNTIME_VERIFIED` |
| G-9 | **XDR → EDR pivot** | "Open in NivXForge EDR" carrying tenant/org/incident/endpoint/detection/evidence/timestamp/process | identifier-exact handoff proven (25/25) and incident context preserved; but it opens a *tab inside the XDR shell*, not the EDR product | pivot target is not a separate product console | G-1 | `REAL_RUNTIME_VERIFIED` (behaviour) / `NOT_IMPLEMENTED` (product separation) |
| G-10 | **EDR → XDR pivot** | "Investigate in NivXRay XDR" from detection/endpoint/hash/event/evidence | only **Linked XDR Incidents** (new, 4 incidents resolved on the fixture endpoint) + return-to-incident | no per-observable "Investigate in XDR" from the trajectory | X5 not started | `NOT_IMPLEMENTED` |
| G-11 | **Global XDR search** | XDR-level search, source/product labelled, "Open in EDR" affordance | implemented over 7 authoritative entity types, tenant-scoped, `NOT_SEARCHABLE_NO_INDEX` honest states | results are not labelled by **source product** and offer no explicit "Open in EDR" button | built before the two-product lock | `REAL_RUNTIME_VERIFIED` (search) / `NOT_IMPLEMENTED` (product labelling) |
| G-12 | **Casebook ribbon** | persistent bottom ribbon: Casebook · Inspect Observables · Live Query | absent | genuinely missing | X4 not started | `NOT_IMPLEMENTED` |
| G-13 | **Observable context actions** | right-click/hover pivot menu on every observable | `ArtifactContextMenu` exists in XDR; **not wired into the AMP trajectory or Activity Details** | missing where the analyst actually works | X5 not started | `NOT_IMPLEMENTED` |
| G-14 | **Incident workspace tabs** | Overview · Detection · Response · Evidence · Worklog · Report | 12 record tabs (executive, technical, evidence, auto_investigation, mitre, attack_story, attack_graph, report, notes, timeline, related, closure) | naming/grouping does not match the reference set | organic growth | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| G-15 | **Computers/Endpoints** | enterprise list: OS, group, policy, internal/external IP, connector id, install date, last seen, health, isolation + capability-driven actions | `XdrEndpointsPage` + details drawer + actions menu exist | column/action conformance unreviewed; lives in XDR, must be an EDR product page | G-1 | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| G-16 | **Multi-source XDR correlation** | endpoint + DNS/network/email/identity → one master incident | **only endpoint telemetry is ingested** in this build | no second domain exists to correlate | no non-endpoint collector | `BLOCKED` (data, not UI) |
| G-17 | **Light/dark parity** | both themes | dark verified in every screenshot; light unverified | light theme untested across new surfaces | never exercised | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| G-18 | **Dead controls** | none | 9 nav items still `disabled: true` (Vulnerabilities, SLA/Aging, Response placeholder, some Intelligence) | disabled ≠ capability-honest page | partially fixed for Assets in X1 | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| G-19 | **Search placeholder honesty** | — | fixed this session: no longer advertises "users" (which is `NOT_SEARCHABLE_NO_INDEX`) | none | — | `REAL_RUNTIME_VERIFIED` |
| G-20 | **Dead route from X2** | — | FILE results pointed at a non-existent `/xdr/fleet-file-trajectory`; **fixed** to `/xdr/intelligence/files/:key` and re-verified | none | my own error | `REAL_RUNTIME_VERIFIED` |

---

## 3 · EXISTING COMPONENTS TO REUSE (do not duplicate)

| Need | Reuse this | Action |
|---|---|---|
| XDR product shell | `xdr/XdrShell.jsx` | keep as the **XDR** shell; strip EDR from its nav |
| EDR product shell | `nivxforge/NivXForgeConsole.jsx` | promote to a **standalone product shell** (own chrome/topbar), stop rendering `XdrShell` |
| Login | `pages/LoginPage.jsx` + `POST /api/auth/login` | parameterise by product; add `/edr/login`; no new auth |
| Operational trajectory | `trajectory/AmpCanvas·AmpNavigator·AmpActivityPanel·AmpEventDetails·AmpComputerHeader` | untouched — proven baseline |
| Investigation trajectory | `XdrDeviceTrajectoryPage` | keep as the secondary projection |
| Observable actions | `xdr/components/ArtifactContextMenu` | **extend** and wire into AMP canvas + Activity Details |
| Endpoint list | `XdrEndpointsPage` + `EndpointDetailsDrawer` + `EndpointActionsMenu` | extend, then re-home into the EDR product |
| File trajectory | `XdrFleetFileTrajectoryPage` | connect to authoritative data, re-home into EDR |
| Incident workspace | `incidents/record/RecordTabs` | **map/rename**, never fork |
| Casebook target | incident worklog/notes API + `workspace_cases` | ribbon writes into these; **no new store** |
| Capability honesty | `xdr/capabilityRegistry.js`, `XdrReservedPage`, `XdrNotImplementedPage` | reuse for every unsupported node |
| Context | `XdrContextBar` | split into XDR- and EDR-flavoured context bars sharing one component |
| Search | `/api/xdr/search` + `XdrSearchPage` | extend with source-product labels + "Open in EDR" |

---

## 4 · REQUIRED MODIFICATIONS (no new systems)

1. **M-1 · Un-nest the products** — `NivXForgeConsole` stops rendering
   `XdrShell`; gains its own product topbar (NivXForge EDR mark, customer
   pill, theme, user menu) reusing the same primitives. Reverses P0-F.13.3
   by explicit owner instruction.
2. **M-2 · One EDR namespace** — canonical trajectory moves to
   `/edr/device-trajectory`; `/xdr/edr/device-trajectory` becomes a
   **permanent redirect** so every proven deep-link keeps working;
   `/edr/trajectory` legacy alias documented.
3. **M-3 · Two logins** — `/login` (XDR, → `/xdr`) and `/edr/login`
   (NivXForge EDR, → `/edr`), same endpoint, product identity per screen,
   `returnTo` preserved.
4. **M-4 · Product pivots** — XDR: "Open in NivXForge EDR" on incident /
   detection / endpoint / evidence rows. EDR: "Investigate in NivXRay XDR"
   on detection / endpoint / hash / event, plus the existing Linked XDR
   Incidents. Both carry tenant · org · incident · endpoint · detection ·
   evidence · timestamp · process, and the backend keeps authorising.
5. **M-5 · Search labelling** — every result gains `source_product`
   (`NIVXRAY_XDR` / `NIVXFORGE_EDR`) and the UI renders the product +
   "Open in EDR" affordance.
6. **M-6 · Re-home Computers + File Trajectory** into the EDR product;
   XDR keeps an asset view that pivots out.
7. **M-7 · Incident tabs** mapped to Overview · Detection · Response ·
   Evidence · Worklog · Report over the existing 12 tabs.
8. **M-8 · Retire the 9 disabled nav rows** into capability-honest pages.
9. **M-9 · EDR Administration** section in the EDR product for the
   endpoint-owned admin surfaces that already exist.

---

## 5 · GENUINELY MISSING (build, minimally)

- **N-1** EDR product shell chrome (topbar/product identity) — thin, reuses
  existing primitives.
- **N-2** `/edr/login` screen — parameterised copy of the existing one.
- **N-3** Bottom **Casebook ribbon** (Casebook · Inspect Observables ·
  Live Query) writing into existing incident worklog / workspace case, the
  analyst choosing the destination (incident is the default when the
  context is already an incident).
- **N-4** "Investigate in NivXRay XDR" pivot surface inside EDR.
- **N-5** `source_product` on search results.
- **N-6** EDR Administration index.
- **N-7** Light-theme conformance pass across the new surfaces.

---

## 6 · DUPLICATES THAT MUST NOT BE CREATED

No second: XDR app · navigation system · incident store or UI · evidence
store · entity graph · detection engine · trajectory renderer · telemetry
store · case/casebook store · endpoint inventory · EDR console · auth
system · capability registry · search index. **Total new backend stores in
this programme so far: zero** — `/api/xdr/search` builds no index and
`linked-incidents` only reads `workspace_cases`.

---

## 7 · IMPLEMENTATION PLAN (priority order)

| Phase | Content | Gate |
|---|---|---|
| **Y0** | Reference-capture intake for Cisco XDR (unblock B-1) | captures received |
| **Y1** | M-1 · M-2 · M-3 — product separation, one EDR namespace, two logins | FLOW 7 + FLOW 8 + all existing deep-links still resolve; 25/25 and 12/12 proofs re-run green |
| **Y2** | M-4 · M-5 · N-4 · N-5 — bidirectional product pivots + product-labelled search | FLOW 3 + FLOW 4 + FLOW 6 (cross-tenant fails closed) |
| **Y3** | N-3 · G-13 — Casebook ribbon + observable actions wired into the AMP trajectory | ribbon writes land in a real worklog/case; every action either works or states its capability |
| **Y4** | M-6 · G-15 · G-4 — Computers + File Trajectory conformed and re-homed into EDR | FLOW 2 |
| **Y5** | M-7 · G-14 — incident workspace conformance | FLOW 1 |
| **Y6** | M-8 · M-9 · N-6 · N-7 · G-17 — no dead controls, EDR admin, light/dark parity | zero-error gate |
| **Y7** | Full E2E (FLOW 1–8) + the §16 structured acceptance report | every row backed by evidence |
| **then** | resume **P0-F.13.6** → **P0-F.13.7** → **P0-F.14** (paused by owner) | — |

**G-16 stays BLOCKED throughout**: multi-source correlation cannot be
demonstrated because only endpoint telemetry is ingested. It will be
reported as blocked-by-data, never simulated.

---

## 8 · VALIDATION PLAN

Per screen: `REFERENCE → inventory → implement → visual compare →
interaction test → state-transition test → API test → tenant test →
regression test → accept`.

- **Interaction & state**: browser-driven per flow, both themes, direct and
  deep-linked entry, every empty/loading/error/selected/hover state named.
- **Security**: every pivot re-run as `analyst@nivx-live.com` against
  `default` resources and with forged `?tenant=` / `?organization_id=` —
  must fail closed (already proven for the trajectory, focus, linked
  incidents and search).
- **Regression, mandatory each phase**: `p0_f13_5_detection_handoff_proof`
  (25) · `p0_detection_attribution_proof` (12) ·
  `x1_x3_xdr_integration_proof` (17) · `tests/edr` (330) · plus a new
  `y1_product_separation_proof` asserting every historical deep-link still
  resolves after the namespace move.
- **Zero-error gate** before any PASS: console errors · runtime exceptions
  · broken routes · dead controls · wrong tenant context · fabricated data
  · missing states · visual/interaction regressions — all zero, evidenced.
- **Status vocabulary**: `REAL_RUNTIME_VERIFIED` ·
  `END_TO_END_VALIDATED` · `IMPLEMENTED_NOT_RUNTIME_VERIFIED` · `BLOCKED` ·
  `NOT_IMPLEMENTED`. Never a higher state than the evidence proves.
