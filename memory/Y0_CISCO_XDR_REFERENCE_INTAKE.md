# Y0 · CISCO XDR REFERENCE INTAKE + GAP MATRICES
**Baseline frozen 2026-06 from the owner-supplied captures. Y1 NOT started.**

Reference surfaces received (5 authoritative captures + doc/manifest pack):
| Ref | Surface | Theme |
|---|---|---|
| **R1** | Investigate — New Investigation + Saved Investigations | LIGHT |
| **R2** | Incident detail — **Response** tab + playbook phases | LIGHT |
| **R3** | Assets → **Devices** inventory | LIGHT |
| **R4** | Investigation **results** — graph + timeline | DARK |
| **R5** | Incident detail — **Overview** tab (graph + Assets/Observables/Indicators) | LIGHT |

`REFERENCE_CAPTURE_REQUIRED` (never guessed): Control Center/Dashboard ·
Incidents **list** · Detection findings tab · Evidence tab · Worklog tab ·
Report tab · Intelligence · Automate · Client Management · Administration ·
**expanded ribbon / Casebook** · observable pivot menu · standalone Global
Search results.

---

## 1 · REFERENCE INVENTORY (observed, not inferred)

### 1.1 Global shell (R1·R2·R3·R5)
- **Topbar**: dark navy band, full-bleed; product mark left (`cisco XDR`);
  right cluster = help `?` · bell with **`99+`** count badge · user block
  showing **two lines (user name / org name)** · chevron. No search field in
  the topbar on these captures.
- **Left rail**: hamburger collapse; **8 flat items**, each with a `>`
  chevron when it has children:
  `Control Center · Incidents · Investigate · Intelligence · Automate ·
  Assets · Client Management · Administration`.
  Active item = left accent bar + tinted row. No group headers.
- **Ribbon**: persistent **bottom-left pill** `cisco XDR` carrying the same
  `99+` badge, above page content, present on every screen.
- **Default theme = LIGHT** for the XDR console (R4 shows dark exists for
  the investigation canvas).

### 1.2 Investigate (R1)
H1 `Investigate` · tabs `Investigation | Detection findings` · card
**New Investigation** with info icon, multiline paste box
(`Paste log entry, IP address, domain, etc`), **character counter
`0 / 2,000`** bottom-right, primary `Investigate` button in **disabled**
state · section **Saved Investigations** with its own Search input,
`23 matching results`, table `☐ | Name (link) | Description | Timestamp |
Created By | …` — empty description renders **`—`**, row overflow menu `…`.

### 1.3 Incident workspace (R2·R5)
- Back link `← Incidents`; **numeric severity pill** (`570`, `1000`) in red;
  **status dropdown** (`Open: Investigating`, `Closed: Merged`); title;
  MITRE tactic strip `Initial Access ··· +6 ··· Command and Control`;
  `Reported by <source> on <date>` · **`1 Linked Incident`** link ·
  `Unassigned` on the right; `View detailed description` toggle;
  description paragraph tagged **`AI-generated`**.
- **Tabs, exactly six**: `Overview · Detection · Response · Evidence ·
  Worklog · Report`.
- **Overview** (R5): relationship graph card with `Expand`, left vertical
  toolbar (+ · − · collapse · undo · pan · layout · hide), `Show timeline`
  + history button, disposition legend
  `Malicious · Suspicious · Common · Unknown · Clean · Asset`; below, three
  cards `N Assets · N Observables · N Indicators`, each with `View all` and
  a `TOP ACTIVE` list of typed entities + per-entity **event counts** and a
  chevron pivot.
- **Response** (R2): left phase rail `Identification · Containment ·
  Eradication · Recovery`; collapsible action rows = chevron + blue title +
  description + state badge (`✓ Complete`, `● Running`) + `Execute` + a
  secondary icon button; footer `Back` and `Go to Containment →`.

### 1.4 Assets → Devices (R3)
H1 `Devices`; three summary cards — **Source health** donut `81%` +
`Asset Inventory Sources` link · **`723 Devices`** with Types and Status
pies whose legends are **checkbox filters** · **Operating Systems** count
grid. Toolbar: Search · `Saved filters` · `Managed status` · `Filters` ·
`723 matching results` · right-aligned `Edit Labels` · `Rules` ·
`Download CSV`. Table: `☐ | Device name (link + chevron pivot) |
Vulnerabilities ⇅ | Cisco Security Risk Score (badge) | OS (icon+label) |
Sources | Last active | Type | Managed ⓘ | ⚙`. Footer:
`Rows per page 10` · `1-10 of 723` · numbered pager.

### 1.5 Investigation results (R4)
Back `← Investigate`; title = timestamp; chip `Investigation complete`;
two count chips (1 critical / 2 warning); filters `Sources` ·
`Disposition` · `My environment only` checkbox; canvas with `Full screen`,
**`31 Nodes`** badge, same left toolbar, **grouped nodes with counts**
(`Hostnames 9`, `IP Addresses 13`, `Endpoints 8`) and a focal observable
with disposition + action glyphs; legend as above; **bottom timeline** with
`Hide timeline` + history, quarterly axis (Q1…Q4 per year) and stacked
disposition bars.

---

## 2 · GAP MATRIX · VISUAL

| # | Reference | Current NivXRay XDR | Gap | Status |
|---|---|---|---|---|
| V-1 | Left rail: **8 flat items**, chevron children, no group headers | **45 items in 8 UPPERCASE groups** (WORKSPACE, COMMAND CENTER, OPERATIONS…) | information architecture is flattened-out and far denser than the reference | `NOT_IMPLEMENTED` |
| V-2 | Nav labels `Control Center · Incidents · Investigate · Intelligence · Automate · Assets · Client Management · Administration` | different vocabulary (`Workspace`, `MSS Dashboard`, `Respond`, `Exposure`, `Detection Engineering`, `Platform`) | naming + grouping | `NOT_IMPLEMENTED` |
| V-3 | **Light default**; dark only for the investigation canvas | dark-first console | default theme inverted vs reference | `NOT_IMPLEMENTED` |
| V-4 | Topbar: help · bell **with count badge** · user block **name over org** | help · theme toggle · user (email under name), **no notification bell** (removed as "no service") | bell + org-line missing; theme toggle is an addition | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| V-5 | **Bottom-left ribbon pill with badge** on every screen | absent | X4 · genuinely missing | `NOT_IMPLEMENTED` |
| V-6 | Incident header: numeric severity pill · status dropdown · tactic strip · `N Linked Incident` · assignee · `AI-generated` tag | header exists; parity of each element unverified against R2/R5 | element-level conformance | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| V-7 | **Six** incident tabs | **12** record tabs | tab set must be mapped to six | `NOT_IMPLEMENTED` |
| V-8 | Overview: 3 cards `Assets · Observables · Indicators` with `View all` + `TOP ACTIVE` + event counts | not present in this shape | missing composition | `NOT_IMPLEMENTED` |
| V-9 | Devices: 3 summary cards (donut · two pies with checkbox legends · OS grid) | endpoints page has no summary band | missing | `NOT_IMPLEMENTED` |
| V-10 | Devices table columns incl. `Vulnerabilities`, `Cisco Security Risk Score`, `Sources`, `Managed` | different columns | column parity — and several reference columns have **no data source** in this build | `BLOCKED` (data) + `NOT_IMPLEMENTED` (layout) |
| V-11 | Investigate: New Investigation paste box + `0 / 2,000` counter + Saved Investigations table | `/xdr/investigations` exists, different composition | missing paste-to-investigate surface | `NOT_IMPLEMENTED` |
| V-12 | Graph legend `Malicious · Suspicious · Common · Unknown · Clean · Asset` | our vocabulary adds `DETECTED_RULE_MATCHED`, lacks `Common`/`Clean` | disposition vocabulary differs — **evidence-driven, do not force** | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| V-13 | Empty cell renders `—` | mixed (`◇ …` phrasing) | glyph convention | `NOT_IMPLEMENTED` |

## 3 · GAP MATRIX · INTERACTION

| # | Reference | Current | Status |
|---|---|---|---|
| I-1 | Rail collapse via hamburger; children expand in place | collapse exists; EDR pages hide the rail (focus mode) | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| I-2 | Graph toolbar: zoom ± · collapse · undo · pan · layout · filter · hide | AMP canvas has its own controls; the XDR graph toolbar is not this set | `NOT_IMPLEMENTED` |
| I-3 | `Show/Hide timeline` toggling a quarterly stacked-disposition axis | not present on the XDR graph | `NOT_IMPLEMENTED` |
| I-4 | Pie/legend **checkboxes filter the table** | absent | `NOT_IMPLEMENTED` |
| I-5 | Column sort ⇅ · `⚙` column chooser · `Rows per page` · numbered pager | partial | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| I-6 | Entity chevron opens the **pivot menu** | `ArtifactContextMenu` exists in XDR, not on these rows | `NOT_IMPLEMENTED` |
| I-7 | Response: phase rail + per-action `Execute` + live state | response surfaces exist; not in this shape | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| I-8 | `Download CSV` · `Edit Labels` · `Rules` | absent | `NOT_IMPLEMENTED` (labels/rules likely `BLOCKED` — no backend) |
| I-9 | `Full screen` graph | AMP trajectory has fullscreen; XDR graph does not | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |

## 4 · GAP MATRIX · NAVIGATION

| # | Reference | Current | Status |
|---|---|---|---|
| N-1 | `← Incidents` / `← Investigate` back links | breadcrumbs (X1), no back link | `NOT_IMPLEMENTED` |
| N-2 | `N Linked Incident` from an incident | linked incidents exist EDR→XDR only | `NOT_IMPLEMENTED` |
| N-3 | Entity → pivot → source product | proven for detection → EDR trajectory | `REAL_RUNTIME_VERIFIED` (that path only) |
| N-4 | `Client Management` as a first-class node (MSSP) | customer pill + `/xdr/admin` only | `NOT_IMPLEMENTED` |
| N-5 | Ribbon reachable from every screen | absent | `NOT_IMPLEMENTED` |

## 5 · GAP MATRIX · STATE

| # | Reference | Current | Status |
|---|---|---|---|
| S-1 | Disabled primary action until input is valid (`Investigate`) | n/a | `NOT_IMPLEMENTED` |
| S-2 | Live action states `✓ Complete` / `● Running` | response verification states exist, different rendering | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| S-3 | `Investigation complete` chip + severity counters | absent | `NOT_IMPLEMENTED` |
| S-4 | `N matching results` on every table | present on some | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| S-5 | `AI-generated` provenance tag on narrative text | our narratives carry provenance differently | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| S-6 | Empty = `—`; loading/error not shown in captures | ours are explicit and honest | `REFERENCE_CAPTURE_REQUIRED` for loading/error |

---

## 6 · HONEST CONSTRAINTS ON PARITY (must be agreed, not silently broken)

1. **Reference columns with no data**: `Vulnerabilities`,
   `Cisco Security Risk Score`, `Managed`, `Sources` (multi-vendor) have no
   collector in this build. Parity of *layout* is achievable; parity of
   *content* is `BLOCKED`. They will render capability-honest states, never
   zeros that look like measurements.
2. **Multi-vendor `Sources`** (CrowdStrike, Duo, CVM in R3) is the same
   dependency as `G-16 / FLOW-5: REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED`.
3. **Disposition vocabulary**: the reference has `Common` and `Clean`; this
   platform never asserts "clean" without evidence, and it has
   `DETECTED_RULE_MATCHED` which the reference lacks. Owner decision needed
   (see report) — I will not fabricate a `Clean` verdict for parity.
4. **Light-first theme** is a real, sizeable change to a dark-first console;
   it is a Y1 workstream item, not a toggle.

## 6 · REFERENCE INTAKE · SECOND BATCH (R6·R7)

| Ref | Surface | Theme |
|---|---|---|
| **R6** | **Incidents list** + incident **preview drawer** + MITRE ATT&CK popover | DARK |
| **R7** | **Control Center / Dashboard** — multi-tab, customisable tile grid | DARK |

**Both batches together prove the same surfaces exist in LIGHT and DARK**,
so theme parity is two-way, not a light-only baseline.

### 6.1 Incidents list (R6)
- Left rail shown **expanded**: children render as an indented sub-list
  under the parent (`Automate` → Exchange · Workflows · Runs · Targets ·
  Account Keys · Variables · Triggers · Tasks · Options), plus
  `Products` and `Administration`.
- H1 `Incidents`; **four count tiles** in a row —
  `1,504 Incidents` · `8 New Incidents` · `221 Open Incidents` ·
  `1,454 …`.
- Toolbar: Search · `73 matching results` · `Filters` toggle ·
  **removable active-filter chips** (`Status: Containment Achieved ×`,
  `Status: Incident Reported ×`).
- Table: `☐ | Priority (coloured numeric badge) | Name (link) | Source |
  Created (relative, "4 Days") | Assignee (Unassigned link / initials)`.
- **Right preview drawer** on row select: priority badge · status dropdown
  · title · `Reported by <source> <n> days ago` · `Assigned` ·
  **priority-score breakdown** (composite score + sub-scores incl. asset
  value) · description blocks · MITRE tactics/techniques list ·
  primary `View Incident Detail` bottom-right.
- **MITRE ATT&CK popover** enumerating tactics `TA0043 Reconnaissance …
  TA0040 Impact` with a `View Details` link.

### 6.2 Control Center (R7)
- **Dashboard tabs** across the top (`ExploryCorp · Secure Endpoint · ETD ·
  DC Firewalls`), right-aligned `Customize` (primary) and a
  `Dashboard(s) ▾` selector plus icon buttons.
- **4-column draggable tile grid**. Every tile carries **source
  attribution** (`Private Intelligence`, `Cisco XDR Analytics — <org>`,
  `Secure Client`, `Secure Firewall`), an explicit **time-range label**
  (`Last 24 Hours`, `Last Hour`), and a per-tile `⋯` menu.
- Tile archetypes observed: list/table tile (Name · Date · Severity) ·
  heatmap bars · donut/gauge with legend counts · big-number KPI cluster ·
  stacked area chart · status table (`Active`, `Package received`) ·
  device-count chart.

### 6.3 Additional gap rows

| # | Reference | Current NivXRay XDR | Status |
|---|---|---|---|
| V-14 | Expanded rail children as indented sub-lists under 8 parents | flat 45-item list in 8 UPPERCASE groups | `NOT_IMPLEMENTED` |
| V-15 | Incidents list: four count tiles above the table | queue has no count tiles in this shape | `NOT_IMPLEMENTED` |
| V-16 | **Removable filter chips** with `×` | filter UI differs | `NOT_IMPLEMENTED` |
| V-17 | Columns `Priority (numeric badge) · Source · Created (relative) · Assignee (initials/Unassigned)` | different column set | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| V-18 | **Right preview drawer** with priority-score breakdown + `View Incident Detail` | selecting a row navigates; no preview drawer | `NOT_IMPLEMENTED` |
| V-19 | MITRE ATT&CK **popover** over the list | MITRE lives on a separate page/tab | `NOT_IMPLEMENTED` |
| V-20 | Control Center = **multi-tab, customisable, source-attributed, time-ranged tile grid** | dashboards are fixed layouts | `NOT_IMPLEMENTED` |
| V-21 | Tile source attribution names **other vendors** (Secure Client, Secure Firewall, CrowdStrike…) | single-vendor endpoint telemetry only | `BLOCKED` — same `REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED` dependency |
| I-10 | Row select → drawer (no navigation) | navigation only | `NOT_IMPLEMENTED` |
| I-11 | Chip `×` removes one filter; `Filters` toggles the panel | partial | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| I-12 | `Customize` enters tile edit/drag mode; per-tile `⋯`; per-tile time range | absent | `NOT_IMPLEMENTED` |
| I-13 | Dashboard tab switching per customer/product context | single dashboard | `NOT_IMPLEMENTED` |
| S-7 | Priority as a **numeric score with a published breakdown** (asset value contribution) | verdict/priority exist without a visible additive breakdown | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |

### 6.4 Revised Y1→Y7 anchoring
`Y1` shell conformance now also owns **V-14** (rail structure) and two-way
theme parity (**V-3**). `Y5` incident workspace gains **V-15·V-16·V-17·
V-18·V-19·I-10·I-11·S-7**. A **new `Y6b` Control Center** phase owns
**V-20·I-12·I-13** (tile framework), with **V-21** blocked on the second
telemetry domain. Tile *content* will never be padded with placeholder
numbers to fill the grid.

---

## 7 · Y0 → Y1 SEQUENCE (unchanged, now reference-anchored)

`Y0 (this doc, DONE for the 5 surfaces)` → **Y1**: product separation
(D-1…D-4) **plus** shell conformance V-1·V-2·V-3·V-4·N-1 → Y2 pivots →
Y3 ribbon/Casebook (V-5·N-5) + observable menu (I-6) → Y4 Devices/Computers
(V-9·V-10·I-4·I-5·I-8) → Y5 incident workspace (V-6·V-7·V-8·I-7) → Y6
Investigate + graph/timeline (V-11·I-2·I-3·S-1·S-3) → Y7 E2E + report.
