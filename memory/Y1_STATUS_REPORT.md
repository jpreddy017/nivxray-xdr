# Y1 · STATUS REPORT — product separation + rail information architecture
# Y2 · appended — context-preserving product pivots (M-4 · M-5 · N-2)
# Y3.1 · appended — observable pivot menu (reference-first)

## Y3.1 · Reference verification FIRST
`docs.xdr.security.cisco.com` + Cisco DevNet material confirm the
observable pivot menu is an **object-oriented menu opened by clicking an
observable**, whose actions are grouped by verb: **deliberate**
(reputation/disposition) · **observe** (sightings) · **respond**
(enforcement) · **refer** (external references), with Casebook
"add to case" alongside. That structure — not my memory of Cisco — drove
the implementation. The pivot-menu *visual* capture is still
`REFERENCE_CAPTURE_REQUIRED`, so this is behavioural conformance, not a
pixel claim.

## Y3.1 · Delivered

| Item | What changed | Status |
|---|---|---|
| **Ownership honoured** | The EDR product's operational canvas already had an observable menu (`AmpCanvas`), and XDR already had `ArtifactContextMenu`. **Both were extended — neither was replaced or duplicated** | `REAL_RUNTIME_VERIFIED` |
| **Verb grouping** | Menus now render the reference structure: `Observe · sightings` → `Investigate · endpoint` → `Investigate · NivXRay XDR` → `Deliberate · reputation` → `Respond · enforcement` → `Refer · external` → `Utility`. Verified live in the trajectory: **7 sections**, every item present | `REAL_RUNTIME_VERIFIED` |
| **One canonical builder** | New `xdr/lib/pivots.js` owns every pivot URL (`buildSightingsPivot` · `buildFileTrajectoryPivot` · `buildProcessTreePivot` · `buildIncidentPivot`, re-exporting `buildEdrPivot`) plus `observableType()`. No call site builds its own URL | `REAL_RUNTIME_VERIFIED` |
| **New real pivots** | `Sightings across NivXRay XDR` (tenant-scoped `/xdr/search`) and **EDR → XDR** `Investigate in NivXRay XDR` (the observation's own incident when recorded, else the XDR search for its value) | `REAL_RUNTIME_VERIFIED` |
| **Dead route fixed (2nd occurrence)** | The trajectory's `Open fleet File Trajectory` pivot opened `/xdr/fleet-file-trajectory`, which **is not a route** — the SPA catch-all bounced the new tab to `/xdr`. Now `/xdr/intelligence/files/:key`; both destinations verified to render | `REAL_RUNTIME_VERIFIED` |
| **Named absence, not dead controls** | `Reputation lookup` · `Enforcement` · `External references` render as explicit unavailable rows carrying the reason (no intelligence enricher / no response driver / no relay registered). No action pretends to work | `REAL_RUNTIME_VERIFIED` |
| **Casebook item deliberately omitted** | "Add to case" is **not** shown yet: it belongs to Y3.2 and will project onto the existing `workspace_cases` / investigation model. Showing it now would have been a dead control | `NOT_IMPLEMENTED` (by design) |

## Y3.1 · Regression (owner gate)
`x1_x3_xdr_integration_proof` **22/22** · `p0_f13_5` **25/25** ·
`p0_detection_attribution` **12/12** · `tests/edr` **330 passed** (same 3
pre-existing unrelated). Zero console errors on the exercised routes.

## Y3.1 · Known gap surfaced, not hidden
Fleet File Trajectory answers honestly — *"NO OBSERVATIONS FOUND FOR THIS
KEY"* — because the substrate's `event.artefacts.file[].sha256`/name
fields are unpopulated (`G-4`, starved page). The pivot is correct; the
data is missing, and the page says so. **Y4 owns connecting it.**

## Next · Y3.2 Casebook ribbon
Must project onto the **existing** case/investigation model (owner rule):
inspect `workspace_cases` + the incident worklog/notes API first, and
build no second case engine. `G-16 / FLOW-5` remains untouched and
blocked.

---


## Y2 · Delivered

| Item | What changed | Status |
|---|---|---|
| **M-4 · XDR → EDR pivot control** | New `xdr/components/OpenInEdr.jsx` — ONE builder for the whole carried context (customer · organization · endpoint · incident · detection · raw + canonical evidence · event · process · timestamp) so it cannot drift between call sites. Wired into **XDR Assets/Endpoints rows** (14 rows, `data-testid=xdr-endpoints-open-in-edr-*`) and the **incident workspace** (`xdr-incident-open-in-edr`). Context is **carried, never granted** — EDR re-authorises everything server-side | `REAL_RUNTIME_VERIFIED` |
| **FLOW 3 end to end** | `INC000000293 → Open in NivXForge EDR → /edr/device-trajectory?device=ep_2d57cbe6f80152062109&incident_id=…` lands in the **EDR product** (`data-product=NIVXFORGE_EDR`) with the `XDR_PIVOT` banner showing INC000000293 · customer `default` · verdict suspicious · rule `EDR-LNX-002` · Return to incident | `END_TO_END_VALIDATED` |
| **M-5 · product ownership on search** | Every result now carries `source_product`; the UI renders the owning product badge and an `Open in EDR →` / `Open →` affordance. EDR-owned results address the canonical `/edr/*` namespace | `REAL_RUNTIME_VERIFIED` |
| **Backend projection (root cause, not a workaround)** | The incident record exposed `assets` as a **count map** (`hosts: 1`) and no endpoint identity, so the pivot honestly rendered *"◇ no endpoint on this record"*. Rather than scraping a hostname out of the title, `routers/incidents.py` now projects the endpoint identity the incident **itself recorded** (`endpoint_campaign.endpoint_id · hostname · device_iid · rule_ids · first/last activity`), null when the campaign recorded none | `REAL_RUNTIME_VERIFIED` |
| **Dead control removed** | `Analyst Workspace` was an `external` link to `/analyst`, which has no app — the SPA catch-all bounced the new tab back to `/xdr`. Removed; **Incidents** is the single analyst destination, matching the reference rail which has no such node | `REAL_RUNTIME_VERIFIED` |

## Y2 · Proof
`x1_x3_xdr_integration_proof.py` **22/22** (was 17; +5 Y2 items incl.
`Y2_pivot_fails_closed_for_another_customer` → a nivx-live principal
pivoting a `default` incident gets `DIRECT_EDR` /
`INCIDENT_TENANT_OUT_OF_SCOPE`). `p0_f13_5` **25/25** ·
`p0_detection_attribution` **12/12** · `tests/edr` **330 pass**.
The four incident-related failures in the wider `tests/` tree were
**verified pre-existing on a clean tree** (`git stash` comparison) and are
unrelated to the projection change.

## Y2 · Not delivered
`EDR → XDR` per-observable pivots (`Investigate in NivXRay XDR` from a
hash/process/IP inside the trajectory) still need the **observable pivot
menu capture** — `REFERENCE_CAPTURE_REQUIRED`. The product-level EDR → XDR
pivot (topbar) and Linked XDR Incidents are live.

---


Scope executed: **only the surfaces the supplied captures authorise**
(decision C). Every unseen surface stays `REFERENCE_CAPTURE_REQUIRED` and
is **not** visually accepted. Overall "Cisco XDR 100 % observable parity"
is **NOT** declared.

## A · Delivered

| Item | What changed | Status |
|---|---|---|
| **D-1 · product separation** | `NivXForgeConsole` no longer renders `XdrShell`. NivXForge EDR now has its own product console (`data-product="NIVXFORGE_EDR"`): own topbar with product mark + tagline, server-resolved customer pill, light/dark toggle, user, sign-out, and an explicit **`Investigate in NivXRay XDR`** product pivot | `REAL_RUNTIME_VERIFIED` |
| **D-2 · permanent deep-link route** | `/xdr/edr/device-trajectory` → `/edr/device-trajectory` via `EdrTrajectoryRedirect`, carrying the **entire** query string and hash. Verified live: `?device&raw_event_id&incident_id` all survived and the handoff still resolved `evt_0b5121e3924461c7#7dd36299ea` with Activity Details and rule attribution intact | `REAL_RUNTIME_VERIFIED` |
| **D-3 · two logins, one auth engine** | `/login` → NivXRay XDR · `/edr/login` → NivXForge EDR. Same `POST /api/auth/login`; each screen carries unmistakable product identity; a product login never lands the analyst in the other product (`returnTo` is honoured only when it belongs to that product) | `REAL_RUNTIME_VERIFIED` |
| **V-1/V-2/V-14 · rail correction** | The 45-item / 8-uppercase-group rail is replaced by the observed structure: **8 primary destinations with indented, expandable children** — `Control Center · Incidents · Investigate · Intelligence · Automate · Assets · Client Management · Administration`. Children are **reused by key** from the existing definitions: no route, label, icon or capability state was retyped or invented | `REAL_RUNTIME_VERIFIED` |
| **D-4 (partial)** | The cross-product `Computers → /xdr/endpoints` row added earlier was **removed** from the EDR rail rather than shipping a nav item that leaves the product. The real move is owned by Y4 | `NOT_IMPLEMENTED` (deferred, by design) |
| Search hrefs | now emit the canonical `/edr/device-trajectory` | `REAL_RUNTIME_VERIFIED` |

## B · Defects I introduced and fixed inside this pass
1. `expanded` state declared inside `useActiveKey()` instead of the
   component → **blank XDR console**. Caught by console log
   (`expanded is not defined`), fixed, re-verified.
2. `/edr/login` landed on `/xdr/incidents` because `returnTo` defaulted to
   `/xdr`. Fixed with a per-product destination guard.

## C · Regression (gate for this phase)
`x1_x3_xdr_integration_proof` **17/17** · `p0_detection_attribution_proof`
**12/12** · `p0_f13_5_detection_handoff_proof` **25/25** · `tests/edr`
**330 passed** (same 3 pre-existing, unrelated
`test_p0_f4_endpoint_process_tree.py` failures, reproduced on a clean
tree). Live UI checks: XDR login identity · EDR login identity · rail
primaries = 8 · child expand · EDR product topbar · EDR→XDR pivot ·
redirect fidelity · handoff + detection attribution unchanged.

## D · NOT delivered in Y1 (explicit)
`V-3` two-way theme parity beyond the shell toggle · `V-4` notification
bell / org line · `V-5`+`N-5` ribbon · `V-6…V-8` incident workspace ·
`V-9…V-10` Devices · `V-11` Investigate composition · `V-13` `—` empty
convention · `V-15…V-19` incidents list · `V-20`+`I-12`+`I-13` Control
Center tiles · `I-2`…`I-9` graph/table interactions · `N-1` back links ·
`N-4` Client Management children (currently mapped to existing admin
sections) — all `NOT_IMPLEMENTED` or `IMPLEMENTED_NOT_RUNTIME_VERIFIED`
per the Y0 matrices.

## E · Blocked, named
- `G-16 / FLOW-5 · REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED` — no
  DNS/network/email/identity collector exists; cross-source correlation
  will not be simulated.
- `V-10 / V-21` — `Vulnerabilities`, `Cisco Security Risk Score`,
  `Managed`, multi-vendor `Sources` and non-endpoint dashboard tiles have
  no data source. Layout parity is possible; content parity is `BLOCKED`
  and will render capability-honest states.
- Asset-value contribution to priority (`S-7`) — will read
  **"Not Available — no authoritative asset criticality source
  configured"** (decision 3A).

## F · Still `REFERENCE_CAPTURE_REQUIRED` (not visually accepted)
Detection findings · Evidence · Worklog · Report · Intelligence pages ·
Client Management · Administration · expanded ribbon / Casebook ·
observable pivot menu · standalone Global Search results.
