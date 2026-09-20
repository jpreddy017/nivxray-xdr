# NivXRay XDR · UI migration register

GENERATED — do not hand-edit. Rebuild with
`python3 scripts/build_ui_migration_register.py`.

One design language, appropriate primitives. `MIGRATED` does NOT
mean "turned into a table": an Attack Story, an entity graph, a
timeline, a response lifecycle and an event table are different
representations of the SAME nx design language. It means the page
composes `xdr/nx/` and carries no parallel visual system.

Automatic states: `NOT_STARTED` (no nx primitive), `IN_PROGRESS`
(nx + residual ad-hoc debt), `MIGRATED` (nx, no detected debt).
`VERIFIED_PROGRAMMATICALLY` and `OWNER_VISUALLY_ACCEPTED` are
recorded by the wave notes below, not inferred from code.

| State | Routes |
| --- | --- |
| MIGRATED | 20 |
| IN_PROGRESS | 9 |
| NOT_STARTED | 35 |
| UNRESOLVED | 2 |

| Route | Page | nx adoption | Page-local CSS | Residual debt | State |
| --- | --- | --- | --- | --- | --- |
| /edr | nivxforge/pages/EdrOverviewPage.jsx | none | — | — | NOT_STARTED |
| /edr/campaign-story | nivxforge/pages/EdrCampaignStoryPage.jsx | none | — | inline dark literal | NOT_STARTED |
| /edr/detections | nivxforge/pages/EdrDetectionsPage.jsx | none | — | hand-built <table> | NOT_STARTED |
| /edr/device-trajectory | nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx | none | — | — | NOT_STARTED |
| /edr/files | nivxforge/pages/EdrReservedPages.jsx | none | — | — | NOT_STARTED |
| /edr/forensics | nivxforge/pages/EdrReservedPages.jsx | none | — | — | NOT_STARTED |
| /edr/hunting | nivxforge/pages/EdrReservedPages.jsx | none | — | — | NOT_STARTED |
| /edr/live-query | nivxforge/pages/EdrReservedPages.jsx | none | — | — | NOT_STARTED |
| /edr/login | pages/LoginPage.jsx | none | — | inline dark literal | NOT_STARTED |
| /edr/network | nivxforge/pages/EdrReservedPages.jsx | none | — | — | NOT_STARTED |
| /edr/process-tree | nivxforge/pages/EdrProcessTreePage.jsx | none | — | — | NOT_STARTED |
| /edr/response | nivxforge/pages/EdrResponsePage.jsx | none | — | — | NOT_STARTED |
| /edr/trajectory | xdr/pages/EdrTrajectoryResolver.jsx | none | — | — | NOT_STARTED |
| /login | pages/LoginPage.jsx | none | — | inline dark literal | NOT_STARTED |
| /xdr/assets/attack-paths | xdr/pages/XdrNotImplementedPage.jsx | none | — | — | NOT_STARTED |
| /xdr/assets/critical | xdr/pages/XdrNotImplementedPage.jsx | none | — | — | NOT_STARTED |
| /xdr/assets/identity | xdr/pages/XdrNotImplementedPage.jsx | none | — | — | NOT_STARTED |
| /xdr/assets/network | xdr/pages/XdrNotImplementedPage.jsx | none | — | — | NOT_STARTED |
| /xdr/detect/tuning/:ruleId | xdr/pages/XdrRuleTuningPage.jsx | none | — | — | NOT_STARTED |
| /xdr/detections/:id | xdr/pages/XdrDetectionRuleEditorPage.jsx | none | — | — | NOT_STARTED |
| /xdr/docs | xdr/pages/XdrDocsPage.jsx | none | — | — | NOT_STARTED |
| /xdr/edr/device-trajectory | nivxforge/EdrTrajectoryRedirect.jsx | none | — | — | NOT_STARTED |
| /xdr/endpoints/:device/trajectory | xdr/pages/XdrDeviceTrajectoryPage.jsx | none | — | — | NOT_STARTED |
| /xdr/evidence/:executionId | xdr/pages/XdrEvidenceRefPage.jsx | none | — | — | NOT_STARTED |
| /xdr/exposure | xdr/pages/XdrExposurePage.jsx | none | — | — | NOT_STARTED |
| /xdr/incidents/:id/domain/:domainKey | xdr/pages/XdrIncidentDomainPage.jsx | none | — | — | NOT_STARTED |
| /xdr/intelligence/command | xdr/pages/XdrCommandIntelPage.jsx | none | — | — | NOT_STARTED |
| /xdr/intelligence/files/:key | xdr/pages/XdrFleetFileTrajectoryPage.jsx | none | — | hand-built <table> | NOT_STARTED |
| /xdr/intelligence/kb | xdr/pages/XdrKbPage.jsx | none | — | — | NOT_STARTED |
| /xdr/intelligence/malware | xdr/pages/XdrMalwareIntelPage.jsx | none | — | — | NOT_STARTED |
| /xdr/kb | xdr/pages/XdrKbPage.jsx | none | — | — | NOT_STARTED |
| /xdr/respond/automation-rules/:id | xdr/pages/XdrAutomationRuleEditorPage.jsx | none | — | — | NOT_STARTED |
| /xdr/respond/playbooks/:id | xdr/pages/XdrPlaybookDesignerPage.jsx | none | — | — | NOT_STARTED |
| /xdr/rule-studio | xdr/pages/XdrRuleStudioPage.jsx | none | — | — | NOT_STARTED |
| /xdr/search/_legacy | xdr/pages/XdrSearchPage.jsx | none | — | ad-hoc <details> | NOT_STARTED |
| /xdr/_ux0-preview | xdr/ux0/Ux0PreviewPage.jsx | 4 nx primitives | ./ux0.css | page-local class system | IN_PROGRESS |
| /xdr/_ux0-preview/workspace | xdr/ux0/Ux0CortexWorkspace.jsx | 2 nx primitives | ./ux0.css, ./ux0-cortex.css | page-local class system | IN_PROGRESS |
| /xdr/clients | xdr/pages/XdrClientManagementPage.jsx | 1 nx primitives | — | page-local class system | IN_PROGRESS |
| /xdr/control-center | xdr/pages/XdrControlCenterPage.jsx | 2 nx primitives | — | page-local class system | IN_PROGRESS |
| /xdr/events | xdr/pages/XdrEventExplorerPage.jsx | 11 nx primitives | @/xdr/datasources/windows/windows.css | page-local class system | IN_PROGRESS |
| /xdr/hunting | xdr/pages/XdrHuntingPage.jsx | 5 nx primitives | — | page-local class system | IN_PROGRESS |
| /xdr/incidents | xdr/pages/XdrIncidentsCortexPage.jsx | 1 nx primitives | @/xdr/ux0/ux0.css, @/xdr/ux0/ux0-cortex.css | page-local class system | IN_PROGRESS |
| /xdr/investigations | xdr/pages/XdrInvestigationsListPage.jsx | 2 nx primitives | — | page-local class system | IN_PROGRESS |
| /xdr/mss-dashboard/_legacy | xdr/pages/XdrMssDashboardPage.jsx | 8 nx primitives | — | hand-built <table>; page-local class system | IN_PROGRESS |
| /xdr/investigations/:caseId | InvestigationRedirect | — | — | — | UNRESOLVED |
| /xdr/search | KeepQuery | — | — | — | UNRESOLVED |
| /xdr/admin | xdr/pages/XdrAdminPage.jsx | 1 nx primitives | — | — | MIGRATED |
| /xdr/admin/:section | xdr/pages/XdrAdminPage.jsx | 1 nx primitives | — | — | MIGRATED |
| /xdr/assets | xdr/assets/AssetsPage.jsx | 10 nx primitives | — | — | MIGRATED |
| /xdr/data-sources | xdr/datasources/DataSourcesPage.jsx | 6 nx primitives | — | — | MIGRATED |
| /xdr/data-sources/:tab | xdr/datasources/DataSourcesPage.jsx | 6 nx primitives | — | — | MIGRATED |
| /xdr/data-sources/windows | xdr/datasources/windows/WindowsPage.jsx | 5 nx primitives | ./windows.css | — | MIGRATED |
| /xdr/data-sources/windows/:tab | xdr/datasources/windows/WindowsPage.jsx | 5 nx primitives | ./windows.css | — | MIGRATED |
| /xdr/detections | xdr/pages/XdrDetectionsPage.jsx | 5 nx primitives | — | — | MIGRATED |
| /xdr/endpoints/:device | xdr/pages/XdrEntity360Page.jsx | 1 nx primitives | — | — | MIGRATED |
| /xdr/evidence-explorer | xdr/pages/XdrEvidenceExplorerPage.jsx | 2 nx primitives | — | — | MIGRATED |
| /xdr/incidents/:id | xdr/pages/XdrIncidentDetailPage.jsx | 19 nx primitives | ./incidents/queue-theme.css, ./incidents/record/record-theme.css | — | MIGRATED |
| /xdr/incidents/_table | xdr/pages/XdrIncidentsPage.jsx | 15 nx primitives | — | — | MIGRATED |
| /xdr/intelligence/iocs | xdr/pages/XdrIocIntelPage.jsx | 6 nx primitives | — | — | MIGRATED |
| /xdr/intelligence/mitre | xdr/pages/XdrMitreHeatmap.jsx | 4 nx primitives | — | — | MIGRATED |
| /xdr/intelligence/threat | xdr/pages/XdrThreatIntelPage.jsx | 6 nx primitives | — | — | MIGRATED |
| /xdr/investigations/:caseId/_engine | xdr/pages/XdrInvestigationWorkspacePage.jsx | 4 nx primitives | — | — | MIGRATED |
| /xdr/reports | xdr/pages/XdrReportsPage.jsx | 5 nx primitives | — | — | MIGRATED |
| /xdr/respond/approvals | xdr/pages/XdrApprovalsPage.jsx | 3 nx primitives | — | — | MIGRATED |
| /xdr/respond/automation-rules | xdr/pages/XdrAutomationRulesPage.jsx | 4 nx primitives | — | — | MIGRATED |
| /xdr/respond/playbooks | xdr/pages/XdrPlaybooksPage.jsx | 4 nx primitives | — | — | MIGRATED |
