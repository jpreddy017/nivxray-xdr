# E1 — DT activation checklist (e3shell experience → https://edr.nivxforge.com/edr/device-trajectory on REAL data)

Work through this in order. E3 has applied **none** of it to production. Every step is E1-owned. Commit SHAs are from `feature/e3-edr-engines` (see `E3_BUNDLE_PUSH_INSTRUCTIONS.md`).

## 1. Strip preview-only code (it must never ship)
| Strip | Where / commits |
|---|---|
| Preview router mount | `backend/server.py` `_e3_dt_mount` lines (commit `64ac4107 preview-mount(e3)[E1: STRIP]`). Revert it, or keep `E3_TRAJECTORY_ROUTER` unset. |
| E1-shape preview adapter (serves `/api/edr/endpoints/*`, `/focus`, `/hours`, `/file-facts`, `/e3/preview/*` from `e3_dt_preview`) | `backend/edr_trajectory/e1_shape_preview.py` plus its `server.py` include (flag `E3_PREVIEW_E1_SHAPE`); commits `0c6d43d9`, `4812106c`, `e150e635`, `e6de40cf` |
| Preview session stubs | `GET /xdr/rbac/session-context` and `GET /edr/context` inside `e1_shape_preview.py`; `/app/.e3ui-harness/shell/auth.jsx` (injected PREVIEW_ANALYST) |
| KUSHU import route + token | `backend/edr_trajectory/kushu_import.py`, `POST /api/e3/trajectory/import`, env `E3_IMPORT_TOKEN` |
| Synthetic datasets | `prodshape.py`, `platform_seed.py`, `stale_trace.py`, `fixtures.py` (seed/reseed/seed-platforms routes) |
| **Synthetic TI / disposition / enforcement overlay** | `backend/edr_trajectory/artifacts_overlay.py` (commit `33cc6752`), collections `e3_dt_ti`, `e3_dt_dispositions`, `e3_dt_enforcement` |
| Harness | `/app/.e3ui-harness/*` (webpack shells e3shell/e3dt/e3ui) isn't in the repo. Keep `tools/e3ui/*` only as tests. |

## 2. Flags
| Flag | Prod value | Effect |
|---|---|---|
| `E3_TRAJECTORY_ROUTER` | unset | No `/api/e3/trajectory/*` |
| `E3_PREVIEW_E1_SHAPE` | unset | No preview adapter |
| `VITE_E3_DT_CONTRACT_PREVIEW` | unset | `DeviceTrajectoryEntry` renders the legacy page; the Phase 2 source switch is hidden |
| `VITE_E3_DT_V3` (**implemented by E3**, `trajectory_amp/flags.js`, commit `ebf34d39`) | `1` on staging first, then prod (tenant-gated by E1) | Set: `DeviceTrajectoryEntry` renders `trajectory_v3/DeviceTrajectoryPage` (the e3shell page) and `EdrSidebar` gets the icon-rail toggle. Unset: `EdrDeviceTrajectoryPage` unchanged and the sidebar is expanded with no toggle. |

## 3. Wire E1 endpoints to E3 modules (all under E1 auth + tenant middleware)
1. **Newest-first paging.** `GET /api/edr/endpoints/{id}/trajectory`: fix `trajectory_window.py:1463` (oldest-first `in_lane[:limit]`) and `:605` (string sort). Order by `(observed_ms DESC, event_id DESC)` from `edr_trajectory.paging`. Return `e3_preview.older_cursor`-equivalent and accept `before=` (brief §5, §9.1).
2. **Focus / event alias.** `/trajectory/focus` must accept `event_iid=`, `event=` (URL-decoded, including `%2523`) and a bare `obs_…` id as `observation_id`. Return `{state: FOCUS_RESOLVED, focus: {event_iid, window}}` (brief §9.8).
3. **Process identity + lineage.** Use `edr_trajectory.identity.process_key` / `lineage` for `process_iid`, `parent_process_iid`, causal state (PROVEN / CORRELATED / UNRESOLVED) and isolate.
4. **Hours / density / coverage.** `GET …/trajectory/hours?day=` returns 24 per-hour counts; `edr_trajectory.timeline.coverage` needs heartbeats and declared gaps (brief §9.3, §9.11). Push the aggregation down to Mongo (E1-2).
5. **File facts + prevalence.** Add a tenant-scoped `GET …/trajectory/file-facts?sha256=&path=` (first seen on device, devices seen) over the authoritative store.
6. **Approvals + status log.** Make `edr_trajectory.actions.ApprovalStore` / `StatusLog` durable: insert-only, unique `(tenant_id, idempotency_key)`, with an audit trail. Approved requests route through the hardened response boundary (§8.8, §9.2). The UI only ever shows APPROVAL_REQUESTED.
7. **TI adapter config.** Configure a real provider per `DT_I1E_TI_DESIGN.md`, then serve per-event `e3_ti[]` and `e3_disposition{state,source,at,provenance,history[]}`.
8. **Enforcement.** Serve `e3_enforcement{outcome,detail,at,source}` from response-plane evidence only.
9. **Projection additions.** Add network direction (`Initiated`) and local IP:port, DNS `QueryType`, process session (`LogonId`/`TerminalSessionId`), and detection rule metadata (`rule_id`, `rule_version`, `confidence`, `mitre[{tactic,technique,name}]`, `evidence_refs`).

## 4. Tests (in E1's real environments)
- `cd apps/nivxray-xdr && yarn install && yarn test`. Expect **≥ 207 vitest** (179 dt2 + 28 trajectory_amp) plus the timeWindow suite, all green.
- Backend: `cd backend && python -m pytest -p asyncio -o asyncio_mode=auto tests/edr_trajectory` (63), then the full E1 suite with the repo's `pytest.ini` (xdist `-n 2`), plus the new `tests/edr/test_trajectory_window_order.py`.
- `node --test tools/e3ui/fields.test.mjs tools/e3ui/labels.test.mjs tools/e3ui/attack_catalog.test.mjs` (12).
- Playwright against **E1 staging** (set `HOST`/`B`/`DEV` at the top of each file to the staging URL and a real device): `tools/e3ui/m2_interaction_test.py` (56), `ui3_shell_panel_test.py` (51), `art_details_test.py` (58), `mitre_test.py` (72), `nav_test.py` (38), `actions_search_test.py` (31). Expect differences only where staging has no TI or enforcement (see §6).
- Perf: `tools/e3ui/m2_perf_matrix.py` (100 → 50k).

## 5. Rollout and rollback
- Roll out on staging first, then to prod for 1 tenant, then all tenants, by flipping `VITE_E3_DT_V3=1` (it's a build-time flag, so it needs a rebuild + deploy).
- **Rollback:** unset `VITE_E3_DT_V3`, rebuild and deploy. `/edr/device-trajectory` renders the legacy `EdrDeviceTrajectoryPage` exactly as before. Backend changes in §3 are additive reads, so leave them in place.

## 6. Expected behaviour on day one, for data E1 can't fill yet (`docs/e3/DT_ACTIVITY_DETAILS_FIELD_COVERAGE.md`)
- None of these is a bug. Each field appears under **"Not collected for this event (N)"** with its exact reason; nothing is blank and nothing is "Clean":
  - Signer (S-8), network bytes/duration (S-9), file size (S-10), SHA-1/MD5 (S-11), protection engines (S-12).
  - File-event SHA-256 (S-3), process end (S-7).
  - Direction / local endpoint / session / DNS type (until the §3.9 projection lands).
- Disposition shows **Unknown**, and IOC shows "provider not configured", until §3.7 is live. All markers are squares.
- Action taken shows "No enforcement/response evidence recorded." until §3.8 is live.
- Navigator no-data hatch: until §3.4 heartbeats arrive, it means "0 retained observations", not "sensor offline".
- USB and system/sensor sections never appear: the sensor emits no such events today.

## 7. Production sync
The full production task, with rollback first, is in `docs/e3/E1_PRODUCTION_SYNC_BRIEF.md`. The owner backlog status is in `docs/e3/DT_OWNER_BACKLOG.md`.
