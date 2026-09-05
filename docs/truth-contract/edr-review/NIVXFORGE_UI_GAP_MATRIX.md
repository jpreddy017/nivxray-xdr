# NIVXFORGE UI · GAP MATRIX (Read-Only)

> Row-by-row surface-level UI gap between the AG spec/prototype and the current NivXRay pod. Anchor to Side-By-Side Review §2. **UI freeze in force — this matrix is documentation only.**
> Legend: **POD** = present & authoritative on pod · **AG** = present in AG spec/prototype · **STUB** = placeholder only · **ABSENT** = neither side has it. Priority: **P1** (must-have for XDR operator parity) · **P2** (needed for full parity) · **P3** (nice-to-have).

| # | Surface | POD state | AG state | KEEP / CHANGE / ADD / REMOVE | Authoritative source | Priority | Notes |
|---:|---|---|---|---|---|---|---|
| 1 | XDR Dashboard | `XdrDashboardPage.jsx` (POD) | prototype §Exec KPIs | **KEEP** POD + add fleet-health strip from AG | POD | P1 | small enhancement post-Step-3 |
| 2 | MSS Dashboard | `XdrMssDashboardPage.jsx` (POD) | not in AG | **KEEP** | POD | P2 | pod-unique multi-tenant view |
| 3 | Incident Queue | `XdrIncidentsPage.jsx` (POD) | prototype §Incident Queue | **KEEP** POD | POD | P1 | already parity |
| 4 | Incident Detail | `XdrIncidentDetailPage.jsx` + `XdrIncidentDomainPage.jsx` (POD) | `XdrInvestigationWorkspacePage.jsx` (AG · 8-tab · MODIFIED_BY_AG) | **CHANGE** → replace with AG 8-tab cockpit after Step-3 | AG | P1 | biggest single UX upgrade |
| 5 | Investigation Workspace | `EvidenceFirstInvestigationWorkspace.jsx` (POD companion) + `frontend/src/v2/pages/InvestigationWorkspace.jsx` (POD main) | prototype §Investigation Workspace | **CHANGE** → rationalize to single canonical page | AG post-Step-3 | P1 | two POD copies today |
| 6 | Evidence Explorer | main-SPA `EvidenceExplorerPage.jsx` (rich · POD) + `XdrEvidenceRefPage.jsx` (STUB · POD) | `XdrEvidenceExplorerPage.jsx` (AG · 19KB) | **CHANGE** → merge POD rich version + AG page into single XDR-shell surface | POD rich + AG shell | P1 | pick canonical pre-import |
| 7 | Detections | `XdrDetectionsPage.jsx` + `XdrDetectionRuleEditorPage.jsx` (POD) | prototype §Detections | **KEEP** POD | POD | P1 | POD richer than AG spec |
| 8 | Rule Studio / Content Editor | `XdrRuleStudioPage.jsx` + `XdrRuleTuningPage.jsx` (POD) | not in AG scope | **KEEP** | POD | P1 | POD-unique |
| 9 | Attack Story (dedicated) | implicit inside main-SPA `AnalystWorkspacePage.jsx` (POD) | prototype §Attack Story | **ADD** first-class XDR tab | AG | P1 | requires XDR-side elevation |
| 10 | Attack Graph / Evidence Graph | metrics only inside main-SPA (POD) | prototype §Attack Graph | **ADD** first-class XDR page | AG | P1 | services/ikg exists but no UI |
| 11 | MITRE Heatmap | `XdrMitreHeatmap.jsx` + main `MitreHeatmapPage.jsx` (POD) | prototype §ATT&CK | **CHANGE** → consolidate to XDR-shell version | POD (XDR side) | P2 | de-dupe |
| 12 | Threat Intel / IOC | main `ThreatIntelPage.jsx` (POD) | prototype §Threat Intel | **CHANGE** → move to XDR shell | POD | P2 | out-of-shell today |
| 13 | Threat Hunting (distributed) | ABSENT | prototype §Hunt Builder | **ADD** | AG | P2 | requires Phase-3 live query |
| 14 | Device Trajectory | `XdrDeviceTrajectoryPage.jsx` + main `DeviceTrajectoryPage.jsx` (POD) | prototype §Trajectory | **CHANGE** → single XDR-shell page + microsecond stream (Phase 2) | POD | P1 | de-dupe now, extend later |
| 15 | Process Tree | `EdrProcessTreePage.jsx` (POD nivxforge) | prototype §Process Ancestry | **KEEP** + stream (Phase 2) | POD | P1 | case-scope today |
| 16 | Endpoint Inventory | `XdrEndpointsPage.jsx` (POD) | prototype §Endpoint Inventory | **KEEP** + switch from case-projection to authoritative (Phase 1) | POD | P1 | needs live enrollment data |
| 17 | Endpoint Entity 360 | fragments across pages (POD) | prototype §Entity 360 | **ADD** full page composing existing fragments | AG | P1 | high analyst value |
| 18 | User / Identity Entity 360 (UBAE) | ABSENT | prototype §UBAE | **ADD** | AG | P1 | Phase-3 UBAE dependency |
| 19 | Network / DNS view | scattered fragments (POD) | prototype §Network | **ADD** consolidated | AG | P2 | requires Phase-2 telemetry |
| 20 | Files / FIM | ABSENT | prototype §Files | **ADD** | AG | P2 | requires Phase-2 telemetry |
| 21 | Registry / Services / Persistence | ABSENT | prototype §Registry | **ADD** | AG | P2 | requires Phase-2 telemetry |
| 22 | Live Query (osquery) | ABSENT (stub executor only) | prototype §Live Query | **ADD** safety-gated | AG | P2 | Phase-3 |
| 23 | Forensics Acquisition | ABSENT (stub executor only) | prototype §Forensics | **ADD** | AG | P2 | Phase-3 · object storage |
| 24 | Approvals | `XdrApprovalsPage.jsx` (POD) | AG-implicit | **KEEP** POD | POD | P1 | already parity |
| 25 | Playbooks (list + designer) | `XdrPlaybooksPage.jsx` + `XdrPlaybookDesignerPage.jsx` (POD) | AG-implicit | **KEEP** POD | POD | P1 | POD richer than AG spec |
| 26 | Automation Rules | `XdrAutomationRulesPage.jsx` + editor (POD) | AG-implicit | **KEEP** POD | POD | P1 | POD-unique |
| 27 | Response Drawer (action gate) | inline in incident pages (POD) | prototype §Response drawer | **CHANGE** → integrate AG safety-gate UX | AG | P1 | fail-CLOSED semantics per AD-07 |
| 28 | Verification (post-action) | storage only (POD) | prototype §Verification | **ADD** UI · 30 s loop evidence | AG | P1 | requires backend verifier (Phase 4) |
| 29 | Sandbox Submission | ABSENT | prototype §Sandbox Submit | **ADD** (Phase 4) | AG | P3 | evidence-producing subsystem |
| 30 | Sandbox Interactive VM | ABSENT | prototype §Sandbox Interactive | **ADD** (Phase 4) | AG | P3 | analyst-driven detonation |
| 31 | Sandbox Process view | ABSENT | prototype §Sandbox Process | **ADD** (Phase 4) | AG | P3 | forensic panel |
| 32 | Sandbox Network view | ABSENT | prototype §Sandbox Net | **ADD** (Phase 4) | AG | P3 | forensic panel |
| 33 | Sandbox File view | ABSENT | prototype §Sandbox File | **ADD** (Phase 4) | AG | P3 | forensic panel |
| 34 | Sandbox Registry view | ABSENT | prototype §Sandbox Registry | **ADD** (Phase 4) | AG | P3 | forensic panel |
| 35 | Sandbox Memory view | ABSENT | prototype §Sandbox Memory | **ADD** (Phase 4) | AG | P3 | forensic panel |
| 36 | Exposure / Risk | `XdrExposurePage.jsx` (POD) | AG-implicit | **KEEP** POD | POD | P2 | POD-unique |
| 37 | Admin (RBAC · Users · Groups) | `XdrAdminPage.jsx` (POD) | AG-implicit | **KEEP** POD | POD | P1 | already parity |
| 38 | Docs / KB | `XdrDocsPage.jsx` + `XdrKbPage.jsx` (POD) | AG-implicit | **KEEP** POD | POD | P2 | in-app docs |
| 39 | Reserved placeholders | `XdrReservedPage.jsx` + `EdrReservedPages.jsx` (POD) | not in AG | **REMOVE** OR replace with honest empty-state | POD | P1 | violates honest-state rule |
| 40 | Research / Analyst tray | main SPA (POD, 22 pages) | not in AG scope | **KEEP** on main SPA · surface via XDR "Research" tray | POD | P2 | decoder cockpit, sample lib, labs, model studio — pod-unique research value |

## §Summary counts

| Action | Count |
|---:|---|
| **KEEP** (pod authoritative) | 15 |
| **CHANGE** (rationalize / consolidate / replace with AG) | 7 |
| **ADD** (net-new) | 17 |
| **REMOVE / RETIRE** | 1 (Reserved placeholders) |
| **Total surfaces catalogued** | **40** |

## §Do-not rules honoured

- ✅ No pod frontend / backend / tests / configs edited.
- ✅ No AG file import.
- ✅ No conflict resolution.
- ✅ No proprietary UI copied.
- ✅ UI freeze fully honoured.
- ✅ Master AG export untouched.
- ✅ Immutable Truth v1 SHAs unchanged.
- ✅ Preservation tag `preserve-pre-alignment-2026-09-05` intact.

## §Gate verdict

Reprinted here for clarity: **`UI REVIEW GATE: PASS WITH CHANGES`**. **`STEP 3 MUST REMAIN UNAUTHORIZED`**.

## END · UI Gap Matrix delivered · read-only
