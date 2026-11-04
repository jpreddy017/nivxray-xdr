# NIVXFORGE EDR: TARGET UX ARCHITECTURE & AVAILABILITY TIER MATRIX
**Document ID:** `NIVXFORGE-EDR-TARGET-UX-ARCH-2026-09-05`  
**Classification:** Operational Design Contract & Target Capabilities  
**Status:** Approved Architectural Baseline  

---

## 1. Executive Summary & Design System Foundations

NivXForge EDR within NivXRay XDR delivers an evidence-first, causal, and deterministic endpoint investigation console. Rather than averaging vendor UIs, NivXForge synthesizes the highest-density operational patterns from industry leaders into a distinct NivXRay design language (*Deterministic Obsidian & Kinetic Amber*).

### 1.1 Core Epistemic & Visual Principles
1. **Evidence-First & Causal Truth**: Every displayed fact carries provenance. Unbacked claims are forbidden.
2. **Epistemic Glyph Vocabulary**:
   - `◆ EVIDENCE PRESENT` (`--nx-ep-present` / `#10B981`)
   - `◇ NO EVIDENCE` (`--nx-ep-none` / `#94A3B8`)
   - `? UNKNOWN` (`--nx-ep-unknown` / `#EAB308`)
   - `○ NOT RUN` (`--nx-ep-notrun` / `#64748B`)
   - `⊘ CAPABILITY UNAVAILABLE` (`--nx-ep-nocap` / `#F87171`)
3. **Decoupled Priority Ladder (P1–P5)**:
   - Priority and Verdict are visually decoupled from Epistemic States.
   - P1 Critical (`--nx-pri-1` / `#EF4444` red, `▰▰▰▰`), P2 High (`--nx-pri-2` / `#F97316` orange, `▰▰▰▱`), P3 Medium (`--nx-pri-3` / `#EAB308` amber, `▰▰▱▱`), P4 Low (`--nx-pri-4` / `#3B82F6` **blue**, `▰▱▱▱`), P5 Informational (`--nx-pri-5` / `#94A3B8` slate, `▱▱▱▱`).
   - **Correction applied 2026-09-05**: the priority ladder is NOT re-derivable by the design layer. It is fixed by owner mandate (P1 red / P2 orange / P3 amber / P4 **blue**) and already shipped in `/app/apps/nivxray-xdr/src/xdr/nx/nx-theme.css` lines 132–136 (light) and 213–217 (high-contrast). Any doc or component proposing `#14B8A6` teal for P4 is wrong and must be corrected against the token file.
4. **Honest Empty & Zero-State Principles**:
   - The operational runtime currently contains 0 enrolled endpoints. Zero-state is rendered as an explicit, high-clarity first-class state (`NO AUTHORITATIVE ENDPOINTS ENROLLED`), never populated with synthetic mock data.

---

## 2. Navigation Spine & Target IA Architecture

The investigation spine enforces a direct conceptual and operational flow:
$$\text{Incident} \longrightarrow \text{Endpoint Entity} \longrightarrow \text{NivXForge EDR} \longrightarrow \text{Device Trajectory}$$

### 2.1 The Resolver Flow for `/edr/trajectory`
To eliminate route dead-ends without creating a duplicate trajectory canvas:
- `/edr/trajectory` acts as an intelligent **Resolver Route**.
- When accessed with `?device=<id>` or `?device_iid=<iid>`, it resolves the authoritative `device_iid` (or hostname fallback with `INFERRED` tag) and performs an immediate client-side redirect to `/xdr/endpoints/:device/trajectory`.
- When accessed without parameters, it redirects to `/xdr/incidents` with an explicit toast: `"Select an endpoint entity from an incident record to open Device Trajectory."`

### 2.2 Device Identity Model: `device_iid` vs `hostname`
- **Authoritative Identifier**: `device_iid` (derived from IRG `v2_shadow_observations.event.device_iid` or entity graph IID).
- **Fallback Identifier**: `hostname` (used ONLY when `device_iid` is absent).
- **Visual Distinction**: Hostname-only entity badges carry an eyebrow pill labeled `INFERRED IDENTITY (NO IID)`.

---

## 3. Surface-by-Surface Availability Tier Matrix (37 Surfaces)

Every surface in the NivXForge EDR IA is explicitly assigned an Availability Tier to ensure no non-existent backend capability is falsely surfaced as operational.

| Surface ID & Name | Path | Availability Tier | Backing Engine / API State | Rendered UI Contract |
|---|---|---|---|---|
| **[1] EDR Overview** | `/edr` | `LIVE NOW` | `GET /api/edr/endpoints` + `GET /api/edr/detections` | Fleet summary projected from saved workspace cases. |
| **[2] Endpoint Fleet / Inventory** | `/xdr/endpoints` (redirects to `/xdr/incidents`) | `LIVE NOW` | `GET /api/edr/endpoints` | Projected list from `workspace_cases.ssot.investigation_object`. Renders Zero-Device state when empty. |
| **[3] Endpoint Entity 360** | `/edr/endpoints/:id/360` | `DESIGN-READY` | API Missing | Renders `⊘ CAPABILITY UNAVAILABLE · Sensor Entity 360 Engine Not Enrolled`. |
| **[4] Detections Queue** | `/edr/detections` | `LIVE NOW` | `GET /api/edr/detections?incident_id=` | Stage-2 verdict evidence projection. Read-only rule-id source. |
| **[5] Detection Detail** | `/edr/detections/:alertId` | `LIVE NOW` | Stage-2 evidence drawer | Projected evidence inspector drawer with rule rationale. |
| **[6] Incidents** | `/xdr/incidents` | `LIVE NOW` | `GET /api/incidents` | Core incident queue and investigation record. |
| **[7] Device Timeline** | `/edr/endpoints/:id/timeline` | `DESIGN-READY` | API Missing | Renders `⊘ CAPABILITY UNAVAILABLE · Device Event Log Engine Pending`. |
| **[8] Device Trajectory** | `/xdr/endpoints/:device/trajectory` | `LIVE NOW` | `GET /api/edr/device-trajectory` | 3-pane 5-lane timeline canvas. Aggregates detections + activity inventory. |
| **[9] Process Tree** | `/edr/process-tree` | `LIVE NOW` | `GET /api/edr/process-tree?incident_id=` | Root-first process ancestry tree derived from `ActivityInventory`. |
| **[10] Process Detail** | `/edr/processes/:processGuid` | `DESIGN-READY` | API Missing | Process inspection drawer stub. |
| **[11] Files & PE Artifacts** | `/edr/files` | `DESIGN-READY` | `EdrFilesPage` stub | Renders Reserved Page banner + `⊘ CAPABILITY UNAVAILABLE`. |
| **[12] File Detail** | `/edr/files/:sha256` | `DESIGN-READY` | API Missing | PE inspection layout defined in prototype. |
| **[13] Network Connections** | `/edr/network` | `DESIGN-READY` | `EdrNetworkPage` stub | Renders Reserved Page banner + `⊘ CAPABILITY UNAVAILABLE`. |
| **[14] DNS Query Activity** | `/edr/dns` | `DESIGN-READY` | API Missing | DNS activity log surface design. |
| **[15] Windows Registry** | `/edr/registry` | `DESIGN-READY` | API Missing | Registry modification surface design. |
| **[16] System Services** | `/edr/services` | `DESIGN-READY` | API Missing | Service manager surface design. |
| **[17] Users & Sessions** | `/edr/users-sessions` | `DESIGN-READY` | API Missing | User logon & session matrix design. |
| **[18] Persistence Mechanisms** | `/edr/persistence` | `DESIGN-READY` | API Missing | ASEP autostart matrix design. |
| **[19] Threat Hunting Workspace** | `/edr/hunting` | `DESIGN-READY` | `EdrHuntingPage` stub | KQL/SQL hunt workspace design. |
| **[20] Distributed Live Query** | `/edr/live-query` | `DESIGN-READY` | `EdrLiveQueryPage` stub | osquery distributed query design. |
| **[21] Forensics Artifacts & Triage** | `/edr/forensics` | `DESIGN-READY` | `EdrForensicsPage` stub | DFIR triage package collector design. |
| **[22] Memory / Volatile Evidence** | `/edr/memory` | `DESIGN-READY` | API Missing | Memory dump & unbacked segment inspector design. |
| **[23] Vulnerabilities & Exposure** | `/xdr/exposure` | `LIVE NOW` | `GET /api/xdr/cve` | Exposure and CVE tracking console. |
| **[24] Threat Intelligence & IOC Vault** | `/xdr/intelligence/threat` | `LIVE NOW` | `GET /api/threat-intel` | Threat actor dossiers and IOC match vault. |
| **[25] Response Command Center** | `/edr/response` | `DESIGN-READY` | `EdrResponsePage` stub | Central action orchestration & audit ledger design. |
| **[26] Host Isolation** | `/edr/response/isolation` | `DESIGN-READY` | API Missing | Safety-gated network isolation design. |
| **[27] Quarantine Vault** | `/edr/response/quarantine` | `DESIGN-READY` | API Missing | Encrypted file vault design. |
| **[28] Remote Response Console** | `/edr/response/terminal` | `DESIGN-READY` | API Missing | Live remote terminal design. |
| **[29] Agent / Sensor Management** | `/edr/agents` | `FUTURE` | Unimplemented | Fleet deployment & update rings. |
| **[30] Telemetry Health** | `/edr/telemetry-health` | `FUTURE` | Unimplemented | Pipeline throughput & sensor RAM/CPU metrics. |
| **[31] Detection Engineering** | `/xdr/rule-studio` | `LIVE NOW` | `GET /api/sigma` | Rule Studio for Sigma and YARA authoring. |
| **[32] Policies & Configuration** | `/edr/policies` | `FUTURE` | Unimplemented | Behavioral prevention policy manager. |
| **[33] MITRE ATT&CK Matrix Navigator**| `/xdr/intelligence/mitre` | `LIVE NOW` | `GET /api/mitre` | Interactive ATT&CK heatmaps and coverage matrix. |
| **[34] Attack Story Canvas** | `/xdr/investigations/:caseId` | `LIVE NOW` | `GET /api/attack-story` | Causal DAG investigation canvas. |
| **[35] Evidence Vault** | `/xdr/evidence-explorer` | `LIVE NOW` | `GET /api/attack-evidence` | Evidence Explorer & custody ledger. |
| **[36] Investigation Pivots** | `/xdr/incidents/:id` | `LIVE NOW` | `GET /api/evidence-inspector` | Pivot component matrix across hosts, files, IPs, processes. |
| **[37] UBAE Entity Context** | `/edr/ubae-context` | `FUTURE` | Unimplemented | Identity risk scoring & peer group anomaly baselines. |

---

## 4. Zero-Device Honest State Design

When querying `/api/edr/endpoints` or `/api/edr/device-trajectory` in an environment with no enrolled devices or zero matching cases:

```
┌─────────────────────────────────────────────────────────────────────────┐
| ⊘ NO AUTHORITATIVE ENDPOINTS ENROLLED IN TENANT SCOPE                    |
|                                                                         |
|  Reason: workspace_cases.ssot.investigation_object returned 0 host      |
|          records for the current tenant.                                |
|  Status: ◆ EVIDENCE PRESENT: 0  · ◇ NO EVIDENCE: 0  · ⊘ CAPABILITY: LIVE|
|                                                                         |
|  [ Ingest Incident Telemetry ]   [ View IRG Shadow Observations (223) ] |
└─────────────────────────────────────────────────────────────────────────┘
```
- **Never render fake host names** like `workstation-01.local` or `corp-dc-01`.
- Display exact backend reason (`no_matching_evidence`).
- Provide an operational bridge to real IRG shadow observations (`v2_shadow_observations` carries 223 device IIDs) to promote true host discovery.

---

## APPENDIX · Cisco Secure Endpoint reference notes (owner screenshots, 2026-09-05)

Captured so the detail is not lost between phases. Patterns only — no
proprietary UI is copied.

### Device Trajectory page composition (drives P1 item 3 · Entity 360)
- **Identity table, two columns**: Hostname · Operating System · Connector
  Version · Install Date · **Connector GUID** (the immutable identity — our
  `device_iid` equivalent) · Cisco Secure Client ID · Definition Version ·
  Update Server · Processor ID ‖ Group · Policy · Internal IP (multiple) ·
  External IP · Last Seen · Definitions Last Updated · Risk Score.
- **Isolation state is in the header**, not buried in a menu ("Not Isolated ⚠").
- **Two side-by-side evidence panes**: *Related Compromise Events* and
  *Vulnerabilities*, each with an explicit negative statement when empty —
  "No related compromise events observed." / "No known software vulnerabilities
  observed." This is the same discipline as our `◇ NO EVIDENCE`; adopt the
  phrasing pattern (state the observation, not a blank pane).
- **Action shelf**: Take Forensic Snapshot · View Snapshot (disabled until one
  exists) · Orbital Query · Start Isolation · Scan · Diagnose · Move to Group,
  plus Events / Diagnostics / View Changes links. Note the *disabled* View
  Snapshot — capability state is expressed by control state.
- **Header count of compromise events** ("No compromise events") sits next to
  the hostname.

### Dual-ribbon navigator (drives P1 item 4 · Timeline Scrubber)
- Row 1: continuous density sparkline across the full 30-day span.
- Row 2: day cells (JUL 17 → AUG 15) with per-day event dots — red = compromise,
  blue = search hit; unavailable days greyed.
- Row 3: 24-hour strip for the selected day with two draggable bracket handles.
- A `Filters ▾` dropdown plus `Search Device Trajectory` sit directly above.

### Process lifelines (drives the canvas rewrite, Phase 2)
- Left gutter lists each process with its artifact type tag (`svchost.exe [PE]`,
  `v32_16.0.15427.20210.cab [CAB]`) — type is part of the label.
- Each process is a **horizontal lifeline**; file/network/execution glyphs are
  anchored along its own line, so causality reads left-to-right on one row.
- A right-hand **Events** list pairs actor → target (`svchost.exe → pacjsworker.exe`,
  `services.exe → 192.168.66.210:389`), giving a scannable text mirror of the canvas.
- Group headers segment the canvas ("System", "Files & Network").

### File Trajectory (fleet-wide · new surface, Phase 3+)
- Keyed on SHA-256, with `Visibility` (earliest observation, last seen,
  observation count) and `Entry Point` (patient zero) side by side.
- `Created by` table: SHA-256 · Filename · Product · **Prevalence**.
- Collapsed `File Details` / `Network Profile` accordions.
- Trajectory row **per computer**, with a glyph legend: created · copied · moved ·
  executed · opened · scanned · advanced/tetra conviction · observed, plus
  "the file was the source of the event", red = target deemed malicious,
  green = benign.
- `Event History` table: Date · Computer · Group · Event · SHA-256 · File ·
  Product · **Disposition**.

### Artifact context menu (drives our Sandbox bridge, Phase 3)
- Right-clicking a hash yields: Disposition · Filename · Copy · Search ·
  VirusTotal score inline (`VirusTotal: (0/74) no detection`) · **File Fetch ▸**
  (with a live `Status: Able to Fetch` sub-state, then Fetch File / View in File
  Repository) · **File Analysis ▸** · File Trajectory · Outbreak Control ▸ ·
  Investigate in Threat Response.
- `File Analysis` opens a *Select a Computer to Fetch the File from* dialog:
  Filename · SHA-256 · **Choose a Computer** · **VM image for analysis** · an
  explicit sharing warning · then `Fetch and Send for Analysis`.
- The analysis pane states "There are no File Analyses to view" when empty.

**NivXRay translation**: `File Fetch` requires a live sensor we do not have →
renders `⊘ SENSOR OFFLINE — NO ACQUISITION DRIVER`. `File Analysis` maps to our
**real** static pipeline (6 analyzers + 59 decoders) and is therefore buildable
now; the VM-image selector maps to the dynamic engine and stays `DESIGN ONLY`.

### Lifeline canvas — additional detail (owner screenshots, batch 2)

**Compromise time-slice band.** The window containing the compromise is
highlighted as a **vertical translucent band spanning every lifeline**, with the
compromise glyph pinned at the top of the band. This is the "haloing" mechanism:
it scopes attention temporally across all rows at once rather than decorating a
single node. → NivXRay: drive the band from the incident's evidence timestamps;
never from a guessed window.

**Artifact type is part of the gutter label.** Every row is
`name [TYPE]`: `[PE]`, `[ZIP]`, `[GZ]`, `[TXT]`, `[Powershell]`, `[OLE2]`,
`[Link]`, `[Bin]`, `[CAB]`. Non-executable artifacts get lifelines too — a
dropped `.tmp [GZ]` or `chrome.update.lnk [Link]` is a row, not just a glyph.
The row for the artifact under investigation is **bolded** in the gutter.
→ NivXRay: we already classify artifact type in the static analyzers; reuse that
vocabulary verbatim so the gutter tag is evidence, not a guess.

**Events list is an actor → target ledger.** Two columns, left = actor,
right = target, e.g. `svchost.exe → musnotification.exe`,
`smartscreen.exe → 20.212.96.199:443`, `explorer.exe → chrome.update.lnk`,
`wscript.exe → 77.91.127.52:443`. Notable:
- Rows participating in the compromise carry an **amber leading dot**.
- `Cloud IOC` appears as an *actor* whose target is a timestamp — a
  non-process evidence source is a first-class row.
- **`unknown` appears as an actor** when the parent was not observed. This
  independently validates our `[ROOT / PARENT NOT OBSERVED]` rule — the vendor
  also refuses to invent an ancestor.

**Event Details drawer field order** (drives the P1 Process/Artifact inspector):
severity chip (`Medium`) → `Detected <filename> (<hash>)[<type>] as
<threat-name>` → `Created by <parent> (<parent-hash>)[PE_Executable] executing
as <user>` → quarantine outcome as a plain sentence ("It was moved, deleted or
already quarantined") → File full path → File size → Parent file SHA-1 → Parent
file MD5 → Parent file size → **Parent file age** → parent signer + certificate
serial + issuing CA + expiry + **trust state** ("The certificate was *trusted*
by the computer") → Parent cert MD5 / SHA-1 → Parent process id → detecting
engine ("Detected by the Tetra engines") → MITRE ATT&CK tactics block.

Two things to copy as *discipline*, not layout:
1. **Provenance of the verdict is stated** — which engine convicted it. We
   already carry this (VEEE contributor + decoder chain); surface it in the
   drawer.
2. **Missing values are named, not blanked** — the vendor prints
   `executing as Not Available` rather than an empty field. That is the same
   contract as our `◇ NO EVIDENCE`; keep the glyph but adopt the habit of
   emitting the field label even when the value is absent.

### AMP dark-mode reference notes (owner screenshots, batch 3)

Confirms the ribbon rebuild and adds detail the light-mode shots did not show.

**Navigator (matches our current build, two deltas)**
- Search field sits LEFT, `Filters ▾` RIGHT (ours has Filters/collapse on the left).
- Selected day on the 30-day ribbon is an **outlined** cell, not filled, and a
  **funnel** visually connects it down to the 24-hour ribbon. We render the
  outline; the funnel is not built.
- The whole 24-hour ribbon sits inside a **tinted selected-panel** background.
- Hour cells bordered, labels below (`0:00 1 … 24`) with the date beneath the
  left edge — ours now matches.
- Red compromise dots sit in the day cell, top-aligned; days beyond the data
  range are drawn but empty.

**Timeline gutter**
- `name [TYPE]` labels: `[PE]`, `[Link]`, and truncated hashes as names
  (`3a2f7f00…51d64508 [PE]`, `a416a722…d90c1c60 [PE]`).
- The artefact under investigation is highlighted with a **solid red row
  background** (`AnyDesk.exe`), not just bold.
- `System` is a section header row above the artefact rows.
- Sub-minute columns are labelled vertically (`11:58`, `08:53`, `09:05`) —
  vertical tick labels are how AMP survives dense clusters.
- `↩ Return to activity` link returns from a drilled state to the full activity.

**Activity Details is PROSE, not a field table**
> `anydesk.exe`, AnyDesk 0.0.0.0 (`46accaaf…5dd9c536`)[PE_Executable] was
> Executed by `explorer.exe`[common filename], Microsoft® Windows® Operating
> System 10.0.26100.8655 (`ae616daa…f43f21f9`)[PE_Executable].
> **Unknown disposition. Unknown parent disposition.**
> File full path: `c:\program files (x86)\anydesk\anydesk.exe`

Two things to adopt:
1. A generated **sentence** with inline hash/type/signer chips reads faster than
   a key/value grid for the primary fact. Our `analyst_narrative.py` already
   generates evidence-gated prose — reuse it here rather than inventing copy.
2. **"Unknown disposition. Unknown parent disposition."** — the vendor states
   the unknown explicitly as a sentence. Third independent confirmation of our
   Honest State rule (after `unknown` actors and `executing as Not Available`).

**Isolation details drawer** (for P1.4 Entity 360): `Isolated` chip, isolation
timestamp, **Unlock code**, and a vertical event timeline `Starting isolation →
Isolated` with actor (`By: Leon Cook`) and comment field. Ours must render
`⊘ RESPONSE DRIVER NOT REGISTERED` in place of all of it.

**File Trajectory search results** (P2 surface): `Computers with matching
activity` → `File Trajectory: <sha256>` → one row per host as
`HOSTNAME — N matches — OS — Manage — Device Trajectory — <group> — <policy>`,
with paging (`7 matches · 10/page`). Note **per-host match counts** and that
every row links straight into that host's Device Trajectory — that is the
fleet→host pivot we lack.
