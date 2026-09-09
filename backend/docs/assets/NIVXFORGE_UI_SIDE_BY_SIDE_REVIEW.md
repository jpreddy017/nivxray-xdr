# NIVXFORGE UI · SIDE-BY-SIDE REVIEW (Read-Only Gate)

> **Mode:** READ-ONLY. No code / tests / configs / UI changed. No git ops. No Step-3 import. UI freeze maintained.
> **Inputs:** NivXRay live pod SPA + companion XDR SPA · AG `NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html` (1,855 lines) · AG `NIVXFORGE_EDR_INFORMATION_ARCHITECTURE.md` (37-surface IA spec) · AG `NIVXFORGE_EDR_EXHAUSTIVE_UIUX_PARITY_MATRIX.md` · AG `NIVXFORGE_EDR_ATTACK_CHAIN_UX_MATRIX.md` · AG `NIVXFORGE_EDR_SANDBOX_UIUX_SPEC.md`.
> **Rule:** industry benchmarks referenced for pattern-level guidance only; no proprietary UI copied. `NO AUTHORITATIVE EVIDENCE RECORDED` semantics preserved everywhere.

---

## §1 · Executive Answer to the Guiding Question

> *"If we integrate the AG EDR/Sandbox architecture later, what should the final NivXRay XDR UI look like without creating a second competing console?"*

**One unified console, three horizontal work planes, one investigation cockpit.**

1. **Single top-level shell** — the existing companion XDR SPA (`apps/nivxray-xdr/src/xdr/XdrShell.jsx`) becomes the ONE authoritative operator console. The main NivXRay SPA (`frontend/src/pages/*`) retreats into the **research/analyst-tooling** role it currently plays best (decoder cockpit, sample library, labs, model studio). This is honest to what each surface already is.
2. **Three horizontal planes inside the XDR shell:**
   - **Detect** (Dashboard · Incidents · Detections · MITRE · Threat Intel)
   - **Investigate** (Incident Detail · Investigation Workspace · Evidence Explorer · Attack Story · Device Trajectory · Process Tree · Entity 360 · UBAE)
   - **Respond** (Approvals · Playbooks · Live Query · Forensics · Sandbox · Verification)
3. **One investigation cockpit** — the AG-side `XdrInvestigationWorkspacePage.jsx` (58,988 B, 8 tabs) supersedes the current `XdrIncidentDetailPage.jsx` when it lands, because it presents the causal 8-stage pipeline linearly. Tabs 1 (Overview) + 4 (Evidence) + Attack-Story map are the "prime" tabs; Tabs 2/3/5/6/7/8 need real data before they render (honest-state).
4. **Sandbox as an evidence tab, not a second app** — the Sandbox surfaces become tabs on the **Evidence Explorer** and on the **Incident Detail Response drawer**, not a separate top-level module. Detonation is a workflow step within investigation.
5. **UBAE integrated into Entity 360, not a separate console** — user identity, sessions, and behavioural baselines project into the same Entity 360 the endpoint uses; `BASELINE → ANOMALY → ABUSE → COMPROMISE` becomes a badge overlay on the entity card, not a new page.

**Rejected:** operating two consoles (main SPA + XDR SPA) as peer operator surfaces long-term. Analysts already report friction; two consoles doubles it. Main SPA remains a research/analyst-tooling adjunct — accessible via a "Research" tray in the XDR shell — not the primary work surface.

---

## §2 · Surface-by-Surface Comparison (24 EDR/XDR-facing surfaces)

Legend for each surface: **`AG-only`** = spec/prototype has it, POD does not · **`POD-only`** = pod has it, AG spec does not name it explicitly · **`Both`** = present on both sides · **`POD ≠ AG`** = both exist but diverge on scope.

### 2.1 · Detect plane

| # | Surface | AG (spec/prototype) | POD (companion `apps/nivxray-xdr/src/xdr/pages/`) | Diagnosis |
|---|---|---|---|---|
| 1 | XDR Dashboard | AG spec item · prototype §Executive KPIs | `XdrDashboardPage.jsx` | Both · POD authoritative; add AG's "endpoint fleet health" strip |
| 2 | MSS Dashboard (multi-tenant) | not in AG scope | `XdrMssDashboardPage.jsx` | POD-only · keep |
| 3 | Incident Queue | prototype §Incident Queue | `XdrIncidentsPage.jsx` | Both · POD authoritative |
| 4 | Detections | prototype §Detections | `XdrDetectionsPage.jsx` + `XdrDetectionRuleEditorPage.jsx` | Both · POD richer (rule editor); keep POD |
| 5 | MITRE ATT&CK Heatmap | prototype §ATT&CK | `XdrMitreHeatmap.jsx` (+ main SPA `MitreHeatmapPage.jsx`) | Both · consolidate to XDR-side |
| 6 | Threat Intel / IOC | AG-only (companion) | POD has main-SPA `ThreatIntelPage.jsx` only | POD ≠ AG · move to XDR shell |
| 7 | Threat Hunting (distributed queries) | AG-only · prototype §Hunt Builder | not on POD (only Rule Studio for content) | **AG-only** · new surface required for parity |

### 2.2 · Investigate plane

| # | Surface | AG | POD | Diagnosis |
|---|---|---|---|---|
| 8 | Incident Detail | prototype §Incident Detail (8-tab) `XdrInvestigationWorkspacePage.jsx` | `XdrIncidentDetailPage.jsx` + `XdrIncidentDomainPage.jsx` | POD ≠ AG · AG's 8-tab cockpit supersedes POD's shallow detail |
| 9 | Investigation Workspace | prototype §Investigation Workspace | `apps/nivxray-xdr/src/xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` + main `frontend/src/v2/pages/InvestigationWorkspace.jsx` | Both · rationalize into ONE workspace |
| 10 | Evidence Explorer | prototype §Evidence Explorer `XdrEvidenceExplorerPage.jsx` | main `frontend/src/pages/EvidenceExplorerPage.jsx` + `XdrEvidenceRefPage.jsx` (thin) | POD ≠ AG · main-SPA has the rich version; XDR-shell version is stub |
| 11 | Attack Story | AG-only (dedicated surface) | main `AnalystWorkspacePage.jsx` shows story panels | POD-only implicit · surface as first-class XDR tab |
| 12 | Attack Graph / Evidence Graph | AG-only surface | main-SPA has evidence-graph metrics; no dedicated XDR page | POD-only implicit · surface as first-class XDR tab |
| 13 | Device Trajectory | prototype §Trajectory | `XdrDeviceTrajectoryPage.jsx` + main `DeviceTrajectoryPage.jsx` | Both · POD authoritative for case-scope |
| 14 | Process Tree | prototype §Process Ancestry | `apps/nivxray-xdr/src/nivxforge/pages/EdrProcessTreePage.jsx` | Both · POD authoritative |
| 15 | Endpoint Inventory | prototype §Endpoint Inventory | `XdrEndpointsPage.jsx` | Both · POD authoritative (case-projection only) |
| 16 | Endpoint Entity 360 | AG-only · prototype §Entity 360 (full page) | POD has fragments across Endpoints + Device Trajectory | **AG-only** · net-new page needed |
| 17 | User / Identity Entity 360 (UBAE) | AG-only · prototype §UBAE | not on POD | **AG-only** · net-new · integrate into Entity 360 |
| 18 | Network / DNS view | AG-only | scattered in main-SPA panels | **AG-only** · required for parity |
| 19 | Files / FIM view | AG-only | not on POD | **AG-only** · required |
| 20 | Registry / Services / Persistence | AG-only | not on POD | **AG-only** · required |

### 2.3 · Respond plane

| # | Surface | AG | POD | Diagnosis |
|---|---|---|---|---|
| 21 | Approvals | AG-implicit | `XdrApprovalsPage.jsx` | Both · POD authoritative |
| 22 | Playbooks | AG-implicit | `XdrPlaybooksPage.jsx` + `XdrPlaybookDesignerPage.jsx` + `XdrAutomationRulesPage.jsx` + `XdrAutomationRuleEditorPage.jsx` | POD ≠ AG · POD is far richer; keep |
| 23 | Live Query | AG-only · prototype §Live Query | not on POD (stubbed executor only) | **AG-only** · required, must be safety-gated |
| 24 | Forensics Acquisition | AG-only · prototype §Forensics | not on POD (stubbed executor only) | **AG-only** · required |
| 25 | Sandbox Submission | AG-only · prototype §Sandbox Submit | not on POD | **AG-only** · required |
| 26 | Sandbox Interactive VM | AG-only · prototype §Sandbox Interactive | not on POD | **AG-only** · required (Phase 4 per handoff) |
| 27 | Sandbox Process/Net/File/Registry/Memory views | AG-only | not on POD | **AG-only** · required (Phase 4) |
| 28 | Verification (post-action) | AG-only · prototype §Verification | not on POD as UI (only ledger storage) | **AG-only** · required |

### 2.4 · Adjacent surfaces (research / analyst tooling — POD authoritative, keep out of primary XDR shell)

`AnalystRC5Page`, `AnalystWorkspacePage`, `AutoInvestigatePage`, `BatchTestPage`, `BenchmarkPage`, `CommandAnalyzerPage`, `ComparePage`, `CorrectionsAdminPage`, `DocsPage`, `DocumentsPage`, `HistoryPage`, `IEDDETracePage`, `KnowledgeBasePage`, `LabPage`, `LearnerPage`, `ModelStudioPage`, `MultiLayerBatteryPage`, `PlatformHealthPage`, `SampleLibraryPage`, `ThreatModelPage`, `TrainingInboxPage`, `WorkspacePage`. **These remain on the main SPA.** Access through a "Research" tray in the XDR shell.

---

## §3 · Industry benchmark pattern check (patterns only · no copy)

| Pattern | Trellix | CrowdStrike | Defender | SentinelOne | Cortex | ANY.RUN | WildFire | Joe Sandbox | AG spec | POD | Recommendation |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Single left-nav shell w/ 3 planes | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | ✓ | partial | **ADOPT** |
| Incident-Centric detail w/ tabbed evidence | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | ✓ | POD shallow | **ADOPT AG's 8-tab** |
| Attack-Story timeline | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | ✓ | partial | **ELEVATE POD implicit → explicit** |
| Interactive detonation w/ syscall trace | n/a | n/a | n/a | n/a | n/a | ✓ | ✓ | ✓ | ✓ | absent | **ADD (Phase 4)** |
| Live remote shell / RTR | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | ✓ | absent | **ADD (safety-gated)** |
| Fleet-wide hunting queries | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | ✓ | absent | **ADD (P3)** |
| Response drawer w/ safety gate | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | ✓ | partial | **HARDEN** |
| Verification-after-action loop | ✓ | ✓ | ✓ | ✓ | ✓ | n/a | n/a | n/a | ✓ | absent | **ADD** |

---

## §4 · KEEP / CHANGE / ADD / REMOVE Recommendations

### KEEP (POD is authoritative)
- Companion XDR SPA shell (`XdrShell.jsx` + `App.jsx`)
- `XdrDashboardPage`, `XdrIncidentsPage`, `XdrDetectionsPage`, `XdrEndpointsPage`, `XdrDeviceTrajectoryPage`, `XdrApprovalsPage`, `XdrPlaybooksPage`, `XdrPlaybookDesignerPage`, `XdrAutomationRulesPage`, `XdrAutomationRuleEditorPage`, `XdrRuleStudioPage`, `XdrRuleTuningPage`, `XdrDetectionRuleEditorPage`, `XdrExposurePage`, `XdrMssDashboardPage`, `XdrAdminPage`, `XdrDocsPage`, `XdrKbPage`
- Main SPA research/analyst pages — moved to a "Research" tray, not deleted
- Sample Library · Model Studio · Lab · Benchmark · Compare · MultiLayerBattery — POD-unique research tools

### CHANGE (harmonize)
- **`XdrIncidentDetailPage` + `XdrIncidentDomainPage` → replace with AG `XdrInvestigationWorkspacePage.jsx`** (8-tab causal cockpit) after Step-3 import
- **`XdrEvidenceRefPage` (thin) + main-SPA `EvidenceExplorerPage` (rich) → merge** into one XDR-shell page anchored to Evidence Explorer semantics
- **`XdrMitreHeatmap` + main-SPA `MitreHeatmapPage` → single XDR-shell page**
- **`XdrDeviceTrajectoryPage` + main-SPA `DeviceTrajectoryPage` → single XDR-shell page**
- **`EvidenceFirstInvestigationWorkspace.jsx` + main-SPA `InvestigationWorkspace.jsx` → single canonical workspace**, prefer the AG-modified companion version once Step 3 imports it
- Add the persistent **"REPRESENTATIVE / PROTOTYPE DATA"** badge and the honest-state **"NO AUTHORITATIVE EVIDENCE RECORDED"** placeholder to every empty state per AG spec §1.1

### ADD (net-new surfaces post-Step-3)
- **Endpoint Entity 360** (composite of device inventory + trajectory + process tree + files + net + registry)
- **User Entity 360 / UBAE** (identity + sessions + behavioural badge `BASELINE → ANOMALY → ABUSE → COMPROMISE`)
- **Threat Hunting** (fleet-wide live query builder, safety-gated)
- **Live Query** (osquery-style, real-time)
- **Forensics Acquisition** (MFT/prefetch/hive/memory capture jobs)
- **Sandbox Submission + Interactive VM + 5 forensic panels** (Phase 4)
- **Verification** view (30 s post-action containment loop evidence)
- **Files / Network / DNS / Registry / Services / Persistence** live views (Phase 2 telemetry)
- **Attack Story** as a first-class tab (currently implicit)

### REMOVE / RETIRE
- `XdrReservedPage.jsx` and `apps/nivxray-xdr/src/nivxforge/pages/EdrReservedPages.jsx` — placeholders that never rendered honest state. Replace with the real pages above; do not ship placeholders as production UI.

---

## §5 · Conflicts with the current UI-freeze decision

- The UI freeze locked in `GA_BLOCKERS.md` **prohibits any pod frontend edit during current phases**. This review does not violate the freeze; it only records recommendations.
- **Every CHANGE/ADD/REMOVE above is UI work.** None of it can execute until:
  1. Step 3 imports the AG frontend files (unblocks the CHANGE items where AG-authoritative already exists), AND
  2. Owner explicitly lifts the UI freeze for the affected surfaces (unblocks the ADD items).
- **Interim recommendation:** keep the pod SPA as-is until Step-3 lands. This side-by-side becomes the authoritative UI plan that Step-3 imports fulfill (partially) and Phase-2/3/4 completes.

---

## §6 · Artefacts to reference during any UI work

- **AG operational prototype** (1,855 lines HTML, 90 KB) — the closest thing to a canonical wireframe. Present in the handoff package at `04_EDR_UIUX/NIVXFORGE_EDR_SANDBOX_OPERATIONAL_PROTOTYPE.html`. Already staged on POD at `/app/memory/edr_review/emergent-handoff-package/04_EDR_UIUX/…` — **read-only reference**.
- **AG IA Spec** — 37-surface information architecture.
- **AG Parity Matrix** — surface-by-surface capability gap.
- **AG Attack-Chain UX Matrix** — 20-step causal traversal per surface.
- **AG Sandbox UI/UX Spec** — visual + safety contract.

## §7 · Do-not rules honoured

- ✅ No pod frontend edited.
- ✅ No pod backend edited.
- ✅ No tests / configs touched.
- ✅ No AG-file import.
- ✅ No conflict resolution.
- ✅ No Phase 1 kickoff.
- ✅ No proprietary UI copied — only patterns referenced.
- ✅ AG master export SHA-256 `ba06f99d…aa1f` unchanged.
- ✅ Immutable Truth v1 SHAs unchanged.

## §8 · Gate verdict

**`UI REVIEW GATE: PASS WITH CHANGES`**

Rationale for PASS: the direction is coherent (one unified XDR shell, three planes, one cockpit), the AG prototype/spec is honest about honest-state semantics, and every gap has a defensible integration path.

Rationale for WITH CHANGES: (a) `XdrReservedPage.jsx` + `EdrReservedPages.jsx` currently ship as placeholders and violate honest-state — replace with real pages OR remove pre-Phase-1; (b) two parallel investigation workspaces (`EvidenceFirstInvestigationWorkspace.jsx` and main-SPA `InvestigationWorkspace.jsx`) must be rationalized to ONE before UI-freeze lifts; (c) main-SPA Evidence Explorer is richer than the XDR-shell stub — pre-agree which one becomes the canonical page before Step-3 collides them.

**`STEP 3 MUST REMAIN UNAUTHORIZED`** — this review does not itself authorize any file movement.

## END · UI Review Gate delivered · read-only · awaiting owner decision
