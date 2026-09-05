# NivXRay XDR · Application-Separation Handoff (2026-08-29)

## Owner directive
Current `/xdr/*` and `/edr/*` implementation lives **inside the
existing NivXRay React SPA**.  The owner has classified this as a
**temporary Slice 1/2 implementation** that must be **extracted into a
standalone NivXRay XDR tool** in a dedicated next session.

## STOP conditions honoured this session
- ❌ No further functional changes
- ❌ No modifications to `/analyst`
- ❌ No modifications to `/edr/trajectory` (canvas untouched;
  additive context ribbon on top of page only when
  `?incident_id=` is present)
- ❌ No continuation of Slice 2/3 feature work
- ✅ Regression baseline preserved: **808 passed / 0 failed / 4 skipped**

## Files scheduled for extraction (NEXT SESSION)
Extract by **ownership**, not by folder move.  Map dependencies first.

### Owned by NivXRay XDR (extract into standalone tool)
- `frontend/src/xdr/xdr-console.css`
- `frontend/src/xdr/XdrShell.jsx`
- `frontend/src/xdr/components/IncidentQueue.jsx`
- `frontend/src/xdr/pages/XdrDashboardPage.jsx`
- `frontend/src/xdr/pages/XdrIncidentsPage.jsx`
- `frontend/src/xdr/pages/XdrIncidentDetailPage.jsx`
- `frontend/src/nivxforge/nivxforge.css`
- `frontend/src/nivxforge/NivXForgeConsole.jsx`
- `frontend/src/nivxforge/edrApi.js`
- `frontend/src/nivxforge/pages/EdrOverviewPage.jsx`
- `frontend/src/nivxforge/pages/EdrDetectionsPage.jsx`
- `frontend/src/nivxforge/pages/EdrProcessTreePage.jsx`
- `frontend/src/nivxforge/pages/EdrReservedPages.jsx`
- `frontend/src/constants/incidentTestIds.js`
- `frontend/src/lib/incidentsApi.js`
- Investigation tab widgets currently at
  `frontend/src/components/incidents/**` — **extract by ownership**;
  some helpers may legitimately belong to the base app.

### Owned by existing NivXRay (must remain)
- `frontend/src/**` for `/analyst`, Workspace, Header, etc.
- `frontend/src/pages/DeviceTrajectoryPage.jsx` (revert the top
  context ribbon or keep it as a shared additive component — decide
  in next session)

## Backend APIs consumed by the standalone XDR app
Thin adapters/projections — **no new SSOT, no duplicate engines**.

- `POST /api/auth/login`                      (existing)
- `GET  /api/incidents`                       (adapter over `workspace_cases`)
- `GET  /api/incidents/{id}`
- `PATCH /api/incidents/{id}/state`
- `PATCH /api/incidents/{id}/assignee`
- `GET  /api/incidents/{id}/summary`          (deterministic projection)
- `GET  /api/edr/detections?incident_id=…`    (projection of
    `workspace_cases.verdict_stage2.evidence[]`)
- `GET  /api/edr/process-tree?incident_id=…`  (reuses
    `services.activity.ActivityInventory` SSOT)
- `POST /api/activity/inventory`              (existing SSOT)
- Deep-links (opened in new browser tab) to existing surfaces:
    `/edr/trajectory`, `/analyze`, `/heatmap`, `/history`,
    `/threat-intel`, `/kb`, `/v2/irg/:id`

## Standalone-tool target boundary
```
NivXRay Platform
   │
   ├── Existing NivXRay Application  (unchanged, independently buildable)
   │      /analyst, /edr/trajectory, /analyze, /heatmap, engines
   │
   └── NivXRay XDR                    (new, independently buildable tool)
          consumes existing APIs
          own frontend, own build, own deploy
          NO duplicate SSOT/engines
```

## Regression status at handoff
- Backend: **808 passed / 0 failed / 4 skipped**
- Browser QA (this session):
  - `/xdr`, `/xdr/incidents`, `/xdr/incidents/:id` render correctly
  - `/edr` (NivXForge Console) renders correctly
  - `/edr/detections` renders real detections with `Detected By`
    from Stage-2 rules
  - `/edr/process-tree` renders real tree from ActivityInventory
  - `/xdr/incidents/:id` → Investigation → Summary tab renders
    the deterministic projection with all four states
    (`ok`, `no_matching_evidence`, `not_connected`, `not_available`)
  - `/analyst` and `/edr/trajectory` verified UNCHANGED

## Non-negotiables for next session
1. Start by mapping ownership before moving any file
2. Do NOT modify `/analyst`
3. Do NOT redesign `/edr/trajectory` (Cisco 95% target is a separate
   dedicated slice, later)
4. Do NOT duplicate: Workspace · Device Trajectory · Process Tree ·
   Command Intelligence · MITRE · Verdict · Evidence · SSOT
5. Preserve the 808/0/4 test baseline
6. New XDR tool must be independently buildable
7. Existing NivXRay must be independently buildable
