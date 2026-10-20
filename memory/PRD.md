# NivXForge EDR/XDR — PRD (living doc)

## Product
React + FastAPI + MongoDB EDR/XDR platform: endpoint telemetry ingestion, canonical evidence, investigation workspace (process tree, file/device trajectory, hunting), tenant-isolated.

## Status — June 2026

### Task 1 · Process Tree / Graph (DONE, awaiting owner review) — branch `feature/process-graph-falcon`, commit `2daf992e`
- Reused the EXISTING backend correlation engine (`backend/routers/edr.py :: _project_endpoint_process_tree`, identity-based `process_iid`/`parent_iid`, GHOST roots, `lineage_state`). No second correlation engine introduced; no API changes.
- New shared renderer `frontend/src/components/ProcessGraphCanvas.jsx`: premium dark Falcon-style graph, zoom/pan, directional edges, lucide process icons, suspicious highlighting, ghost/uncertain parents drawn as dashed + explicitly labelled, node detail panel (PID, user, cmdline, timestamps, evidence refs).
- `ProcessTreeTab.jsx` is the primary surface with a mode switch: "Evidence graph" (endpoint pivot, read-only `/api/edr/process-tree`) and the pre-existing IKG ancestry list (preserved untouched). `ProcessTreeView.jsx` / `ProcessTreeMini.jsx` unchanged.
- Deterministic fixtures `backend/tests/edr/test_task1_process_graph_fixtures.py` (5 tests): confirmed lineage, missing parent → ghost/unknown (never invented), PID reuse → separate identities, incomplete telemetry, empty window. `20 passed` with existing `tests/test_process_tree.py`.

### Correction (June 2026) — the EDR console is the real surface
The served preview frontend is `/app/apps/nivxray-xdr` (supervisor `directory=`), NOT `/app/frontend`. The NivXForge EDR Process Tree lives at route `/edr/process-tree` → `src/nivxforge/pages/EdrProcessTreePage.jsx`. The graph renderer was therefore ported to `src/nivxforge/components/ProcessGraphCanvas.jsx` (no Tailwind in that app — inline styles) and wired behind a Graph / Lineage-list view switch; the pre-existing list rows are untouched. Local seed: `backend/scripts/seed_task1_graph_demo.py` (device `dev_e3graph01`, host E3-GRAPH-LAB, tenant default). Verified in browser at `/edr/process-tree?endpoint_id=dev_e3graph01&hours=24`. Commit `3a3258f8`.

### Known gap (reported, not fixed)
- Local dev DB cannot render the graph end-to-end: `v2_shadow_observations` process events carry no tenant/collector linkage to `edr_endpoints`, so every endpoint pivot returns `ENDPOINT_NOT_RESOLVED`. UI screenshots therefore not captured locally; needs a resolvable seeded endpoint or live sensor telemetry.

### HOLDs (unchanged)
- EDR development reset / tenant-wide cleanup incl. KUSHU: scope approved, execution ON HOLD. `backend/routers/edr_maintenance.py` deployed, one dry run done (+602 drift reconciled).
- No production telemetry, deployment, File/Device Trajectory changes under Task 1.

## Backlog
- P0: seed a resolvable local endpoint + evidence fixture so the graph can be screenshot/QA'd; then merge review.
- P0: Task 2 — File Trajectory (not started, awaiting owner).
- P1: Device Trajectory premium pass; bounded dev-telemetry retention policy after ingestion.
- P2: fleet-placement fix publish.
