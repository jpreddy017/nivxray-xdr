## CURRENT FOCUS — Core V3 Real-Evidence Integration (E1)

Owner directive: implement the E1 ↔ E3 Device Trajectory production integration.
NO production deployment. NO endpoint actions. NO protected endpoint access.
REAL_ENDPOINT_VALIDATION is owner-set to BLOCKED_ENVIRONMENT (no authorized real
endpoint exists in this environment; KUSHU has 0 rows in all four stores).

### What changed in this phase
1. `backend/edr_trajectory/v3_presentation.py` (NEW) — pure mapping of the §d
   production evidence result into the exact E3 V3 field vocabulary. No DB read.
   Owns `encode_iid` / `decode_iid` (bijective presentation identity) and
   `apply_findings` (E1 durable findings joined on exact evidence reference).
2. `backend/routers/edr.py` — additive `out["v3"]` key on
   `GET /api/edr/endpoints/{id}/trajectory`; `before` cursor alias; focus now
   accepts `event=` alias, V3 presentation identity and `observation_id`,
   resolved through the §d authority. V1 / dt2 / e3 untouched.
3. `backend/routers/edr_trajectory_v3.py` (NEW) — production `/trajectory/hours`,
   `/trajectory/file-facts`, `/trajectory/attack`. These existed only in the
   stripped preview router before.
4. `backend/edr_trajectory/production_adapter.py` — `resolve_evidence` gained an
   optional `match` predicate and a bounded `FOCUS_PAGE_BUDGET` (8 pages). A
   capped search reports PAGE_BUDGET_REACHED, never "not found".
5. `trajectory_v3/amp/TrajectoryPage.jsx` — 4 minimal edits: read the `v3`
   contract, truthful data-source label, Actions routed to E1's durable
   response authority, server-supplied deep-link miss text.
6. `apps/nivxray-xdr/.env.development` (NEW) — `VITE_E3_DT_V3=1` for the
   integration build ONLY. Production build config untouched (verified: the
   production bundle compiles the flag to `undefined`).

### Test status
- `backend/tests/edr_trajectory/` — 108 passed, 9 skipped (31 new V3 gates).
- `backend/tests/edr/` — 2061 passed, 3 skipped, 0 failed (8 new Gate 17 gates).
- Production build `yarn build` — exit 0.
- Browser gate PENDING (this run).

### What the testing agent must verify (frontend only)
The EDR route must render the EXACT V3 surface, inside EDR, with a customer
selected, against the preview-database integration endpoint `dev_42e8c6dc74b9`.
