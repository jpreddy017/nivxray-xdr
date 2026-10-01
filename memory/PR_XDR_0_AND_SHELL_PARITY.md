# NivXRay XDR — Cisco XDR Parity Program · Working Log

Product naming is OWNER-LOCKED: **NivXRay XDR** (XDR platform) ·
**NivXForge EDR** (EDR product) · **NivXMachines** / **Workspace NivXMachines**
only when referring to those. Never shorten NivXRay XDR to "NivXRay". Never
rename NivXForge EDR. Infrastructure identifiers, DB/collection names, module
names and env vars are NOT renamed for branding.

---

## PR-XDR-0 · KILL DEAD PIVOTS — COMPLETE · VERIFIED · NOT DEPLOYED

### 1 · Files changed
| File | Change |
|---|---|
| `backend/routers/incidents.py` | line 644 label restored to `"NivXForge EDR"`; line 710 IOC `deep_link` `/threat-intel` → `/xdr/intelligence/iocs` |
| `backend/tests/canonical/incidents/test_incidents_projection.py` | pins the `NivXForge EDR` label, the new IOC deep_link, and that **no** pointer deep_link leaves `/xdr/*` or `/edr` |
| `apps/nivxray-xdr/src/xdr/components/Pivot.jsx` | rewritten: 0 external targets, `useNavigate`, honest `PIVOT_DESTINATION_NOT_AVAILABLE` rows |
| `apps/nivxray-xdr/src/xdr/XdrShell.jsx` | `openExternal()` deleted; `external` branch now fails closed (`EXTERNAL_NAVIGATION_FORBIDDEN`) |
| `apps/nivxray-xdr/src/xdr/pages/XdrMitreHeatmap.jsx` | reads `?q=` so an ATT&CK pivot preserves the technique |
| `apps/nivxray-xdr/src/xdr/pages/incidents/record/tabs/EvidenceTab.jsx` | reads the authoritative `status`/`deep_link` contract; in-product navigation |
| `apps/nivxray-xdr/src/components/incidents/tabs/InvestigationTab.jsx` | 6 dead base-app deep links → incident-record lenses (component is currently UNMOUNTED) |
| `apps/nivxray-xdr/src/components/incidents/tabs/OverviewTab.jsx` | `window.open` → in-product navigate; EDR only via `productOrigins` (UNMOUNTED) |
| NEW `apps/nivxray-xdr/tests/adoption/test_no_external_product_navigation.mjs` | 5-layer regression gate |

### 2–4 · The pivots inspected — **12**, not 13 (earlier count corrected)
| # | Old destination | New destination | Verdict |
|---|---|---|---|
| 1 | `host.base-trajectory` → `/edr/trajectory?device&incident_id` (new tab) | removed | duplicate of row 1 (`/xdr/endpoints/:device/trajectory`); EDR hand-off stays with `OpenInEdr` |
| 2 | `process.cmd` → `/analyze` | **disabled** | Command Intelligence not wired |
| 3 | `file.vt` → `/documents?q=` | **disabled** | Malware Intelligence not wired |
| 4 | `hash` → `/threat-intel?q=` | **disabled** | Intelligence not wired |
| 5 | `ip` → `/threat-intel?type=ip` | **disabled** | as above |
| 6 | `domain` → `/threat-intel?type=domain` | **disabled** | as above |
| 7 | `url` → `/threat-intel?type=url` | **disabled** | as above |
| 8 | `rule.mitre` → `/heatmap` | `/xdr/intelligence/mitre?q=<ref>` | real native page, context preserved |
| 9 | `engine.verdict` → `/edr/trajectory?incident_id` | `/xdr/incidents/:id?tab=technical&rule=` | real record lens |
| 10 | `engine.analyst` → `/analyst?case&tab=verdict` | `/xdr/investigations/:id` | real workspace |
| 11 | `engine.iue` → `/analyst?tab=iue` | **disabled** | no case-scoped IUE surface |
| 12 | `engine.artifact` → `/documents?case=` | **disabled** | Malware Intelligence not wired |

Plus a new entity pivot `/xdr/endpoints/:device` (Entity 360) and **6 more dead
links found** in `InvestigationTab` (`/history?case=`, `/analyst` ×2,
`/v2/irg/:id`, `/heatmap`, `/edr/trajectory`) → all repointed.

### 5 · Backend deep_link
`/threat-intel?incident_id=…&tenant=…` → `/xdr/intelligence/iocs?incident_id=…&tenant=…`
Verified live on 6 incidents. **Disclosed**: the only live consumer
(`EvidenceTab`) renders 6 domain cards and `ioc` is not one of them, so this
link has **no live UI consumer today**; `OverviewTab`, which does read it, is
not mounted.

### 6 · Branding verification (proved, not reverted blindly)
The `incidents.py:644` pointer **is** the NivXForge EDR product:
`domain: "edr"`, `deep_link` `/edr` → `EdrOverviewPage` (the NivXForge EDR
Console), hint *"Endpoint security console · Device Trajectory · Process Tree"*.
Label restored to **`NivXForge EDR`** and pinned by test.

### 7 · Tests
`test_no_external_product_navigation.mjs` **1862 checks PASS** ·
`test_login_branding_is_scope_aware.mjs` **51 PASS** ·
`tests/canonical/incidents/` + `test_sec001_002_auth_hardening.py`
**30 passed / 1 skipped / 1 failed** — the failure is
`test_row_projection_shape` (`assert None == 'analyst@nivxray.com'`), proven
**pre-existing** by `git stash` on a clean tree ·
`test_capability_registry_matches_base.mjs` **147 failures, pre-existing**
(identical with changes stashed).

### 8 · Build
`yarn build` **PASS**. Built chunks: `"/documents` 0 · `"/heatmap` 0 ·
`"/analyst` 0. `"/analyze` 7 and `"/threat-intel` 18 remain — all inside the
**capability-registry API path arrays**, not navigation (verified by context).
The 4 `preview.emergentagent` refs are the local `REACT_APP_BACKEND_URL`
(API base) in a local build; the production build injects the production API.

### 9 · Remaining known dead pivots (DISCLOSED, not fixed)
- `nivxforge/pages/EdrProcessTreePage.jsx:256` builds `/analyze?incident_id=` —
  a **NivXForge EDR** surface, out of PR-XDR-0 scope by owner instruction.
  Recorded as a disclosed exception in the gate.
- `xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` two generic
  `open()` helpers, and `ReportTab.jsx` (report blob) — allow-listed with
  reasons, not audited by PR-XDR-0.
- **NOT EXERCISED AT RUNTIME**: the Pivot *menu* itself. Both candidate
  incidents carry no endpoint/user identity, so `IncidentContextStrip` renders
  `NOT AVAILABLE` and no trigger; the other mount needs a selected trajectory
  event. Behaviour is covered by the static gate and by proving all five
  destinations resolve. Classified, not claimed.

### 10 · Runtime proof (preview, authenticated, single tab throughout)
`/xdr/incidents/:id?tab=evidence` cards now read **NOT CONNECTED · integration
required** instead of the previous false **SEARCHED · scope tightly bounded** ·
`/xdr/intelligence/mitre?q=T1059` → page search box holds `T1059`, survives F5 ·
`/xdr/investigations/:id` renders with the case id in the DOM ·
`/xdr/incidents/:id?tab=technical` · `/xdr/endpoints/:device/trajectory` ·
`/xdr/endpoints/:device` (Entity 360, 57,874 real observations) — every one
kept the shell mounted and opened **0** new tabs.

---

## PR-XDR-1 (partial) · CISCO-IDENTICAL SHELL — owner directive "same as Cisco XDR"

Owner overrode the earlier "no pixel-for-pixel" lock and asked for a 100% UI/UX
match with only the logo changed. Structural layer built from Cisco's **published**
system (docs verified 2026-06); pixel layer needs owner screen captures.

Delivered and verified in the browser:
- **Rail = Cisco's 8 primaries, Cisco's order**: Control Center · Incidents ·
  Investigate · Intelligence · Automate · Assets · Client Management ·
  Administration. Every NivXRay XDR capability retained as a child. Every
  `key` preserved, so no `data-testid` broke.
- **Detections moved under Incidents** and relabelled `Detections` (was
  "Detection Engineering" under Automate) — Cisco's placement.
- **Activities added under Investigate** (was "Telemetry Studio" under Control
  Center) — same route, Cisco's label and position.
- **`/xdr` → Control Center** (`/xdr/mss-dashboard`); Incidents stays at
  `/xdr/incidents`. `/xdr/dashboard` and `/xdr/control-center` alias it.
- **Light is now the default theme** (Cisco's published default; Auto/Light/Dark
  are its three options). Verified `data-nx-theme="light"` on a fresh session.
- NEW `src/xdr/lib/ciscoSemantics.js` — Cisco's published disposition set
  (`malicious/suspicious/unknown/clean`), **priority bands** ≥800 · 600–799 ·
  400–599 · ≤399 and **risk bands** 80–100 · 60–79 · 40–59 · 0–39, in one
  place so no screen can drift. Honesty rules kept: `clean` is never inferred
  from absence, and an uncomputed score returns `Not scored`, never `0`.

### Still required for a true pixel match — BLOCKED ON OWNER CAPTURES
Zero Cisco screen captures exist in this repo (every screen-level row in
`MASTER_PARITY_MATRIX.md` is `REFERENCE_CAPTURE_REQUIRED`). Without them the
following cannot be matched honestly: collapsed icon rail with hover expand ·
the persistent bottom **Ribbon** (casebook, observable search, notifications) ·
Cisco's spacing scale, type ramp, exact palette and icon geometry · per-screen
layouts for Control Center, Incidents list + drawer, Incident detail,
Detections, Investigate, Activities, Assets, Automate, Administration ·
Intelligence submenu named Judgments / Indicators / Events / Feeds.

### Freeze still held
No production deploy of collector API-key auth or ingest dedupe · no collector
enrollment · no telemetry seeding · no DNS/Vercel change · no production DB
change · NivXForge EDR not regressed.
