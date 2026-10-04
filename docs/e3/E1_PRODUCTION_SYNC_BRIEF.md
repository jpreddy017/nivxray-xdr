# E1 PRODUCTION SYNC BRIEF: E3 (feature/e3-edr-engines) → production NivXForge EDR

Paste this whole file into E1 as E1's task. It is self-contained. Author: the E3 agent. E3 has **not** deployed, pushed, merged or touched production, KUSHU, DESKTOP-A9HGFJJ, E1 auth/ingest/durable-ACK, Gate-4 or `processing_queue`. E1 performs all activation.

Goal: https://edr.nivxforge.com/edr/device-trajectory should behave exactly like the accepted E3 preview (`/e3shell-1ef4e879020ef615eaaa/index.html?device=…&t0=…&t1=…&event=obs_…%23…`), on E1's real data.

---
## 0. ROLLBACK FIRST (read before anything else)
- **Instant UI rollback:** unset `VITE_E3_DT_V3`, rebuild and deploy. `/edr/device-trajectory` then renders the legacy `EdrDeviceTrajectoryPage` exactly as before, and the sidebar is the expanded list with no rail toggle. **No data impact.**
- HeatMap pivot: unset `VITE_E3_ATTACK_PIVOT`, and the HeatMap is as before.
- Backend: every E3 reader is additive and read-only on evidence. Leave the readers in place, or set `E3_TRAJECTORY_ROUTER` / `E3_BEHAVIOR_ENABLED` / `E3_ML_ENABLED` / `E3_DT_VIEWMODELS_ENABLED` unset. Approval and status-log collections are insert-only side tables, and dropping them needs the owner's approval.
- Full revert: `git revert -m 1 <merge-commit>`.

## a. Scope inventory (everything E3 built, base `1800aeea` → `eab566a9` → HEAD)
| Item | Path | Status |
|---|---|---|
| Behavioral + sequence engine | `backend/edr_behavior/` | ACTIVATE AFTER E1 WIRING (canonical_bridge hook, flag `E3_BEHAVIOR_ENABLED`, index migration) |
| ML foundation | `backend/edr_ml/` | DESIGN-ONLY / TESTING (flag `E3_ML_ENABLED` stays OFF) |
| Investigation view models (causal + TI contracts) | `backend/edr_investigation/` | ACTIVATE AFTER E1 WIRING (`E3_DT_VIEWMODELS_ENABLED`, TI broker) |
| DT contracts: paging, identity, lineage, timeline/coverage, TI states, actions | `backend/edr_trajectory/{contracts,paging,identity,lineage,timeline,ti,providers,actions,service,attack,disposition}.py` | ACTIVATE AFTER E1 WIRING (§d) |
| DT preview plumbing | `backend/edr_trajectory/{preview_mount,e1_shape_preview,kushu_import,fixtures,prodshape,platform_seed,stale_trace,artifacts_overlay}.py`, `api.py` `/seed` | PREVIEW-ONLY (STRIP, §b) |
| Device Trajectory V3 UI | `apps/nivxray-xdr/src/nivxforge/trajectory_v3/**` | ACTIVATE NOW behind `VITE_E3_DT_V3` once §d.1–3 are wired |
| Sidebar icon rail | `apps/nivxray-xdr/src/nivxforge/EdrSidebar.jsx`, `NivXForgeConsole.jsx`, `nivxforge.css` | ACTIVATE NOW (with `VITE_E3_DT_V3`; OFF = expanded list, no toggle) |
| Activity panel / Activity Details / artifacts / Actions menu | `trajectory_v3/amp/{Activity,Artifacts,fields,labels,Menu,Header}.jsx` | ACTIVATE NOW (with `VITE_E3_DT_V3`) |
| Contract-preview AMP page (older) | `nivxforge/trajectory_amp/**` | PREVIEW-ONLY (`VITE_E3_DT_CONTRACT_PREVIEW` stays unset) |
| MITRE catalogue v19.2 + HeatMap pivot | `backend/mitre_catalogue/`, `services/mitre_catalogue/`, `xdr/mitre/*`, `XdrMitreHeatmap.jsx` (commit `182a780a`) | Catalogue: ACTIVATE NOW (E1 REVIEW). Pivot: ACTIVATE AFTER review (`VITE_E3_ATTACK_PIVOT`) |
| Mutating actions / approvals | `edr_trajectory/actions.py` | ACTIVATE AFTER E1 WIRING. They stay **APPROVAL_REQUESTED** until E1 wires its hardened response boundary |
| KUSHU import tool | `tools/` export script + `kushu_import.py` | PREVIEW-ONLY (STRIP the route and token) |
| DT time model fix | `trajectory/dt2/timeWindow.mjs` | ACTIVATE NOW (unflagged bug fix, brief §2) |
| Docs | `docs/e3/*` | Reference |

## b. Merge plan
- Source: `origin/feature/e3-edr-engines` after the owner pushes the bundle (tip in `E3_BUNDLE_PUSH_INSTRUCTIONS.md`). Target: E1's production branch (`feature/rc2-alignment`).
- Create `integrate/e3-into-rc2` from the **current** target and run `git merge --no-ff origin/feature/e3-edr-engines`. No rebase, no squash, no force-push. This keeps one revertible merge commit.
- Expected conflicts are only in files E3 modified:
  - `apps/nivxray-xdr/src/App.jsx` (route → `DeviceTrajectoryEntry`)
  - `nivxforge/NivXForgeConsole.jsx` + `nivxforge.css` (sidebar)
  - `backend/server.py` (two flag-gated preview mounts, which are STRIPPED)
  - `xdr/pages/XdrMitreHeatmap.jsx`, `xdr/mitre/attackNameIndex.generated.js`
  - `backend/mitre_catalogue/*`, `services/mitre_catalogue/service.py`, `tests/test_mitre_catalogue.py`
  - plus the eab566a9-era files listed in `E1_INTEGRATION_AND_DEPLOY_BRIEF.md` §1.
  Check them with `comm -12` (brief §1).
- **STRIP (must never ship):**
  | Strip | Commits / files |
  |---|---|
  | Preview router mount in `server.py` (`E3_TRAJECTORY_ROUTER`, `E3_CLONE_BACKEND`) | `64ac4107` |
  | E1-shape preview adapter (`/api/edr/endpoints/*` from `e3_dt_preview`, `/focus`, `/hours`, `/file-facts`, `/attack`, `/mitre/catalogue/coverage`, `/e3/preview/*`) | `edr_trajectory/e1_shape_preview.py`; `0c6d43d9`, `4812106c`, `e150e635`, `e6de40cf`, `5ed595bd`, `c1a0f243`, preview parts of `4f0079cc` |
  | Preview session stubs `GET /xdr/rbac/session-context`, `GET /edr/context` | inside `e1_shape_preview.py`; harness `shell/auth.jsx` |
  | KUSHU import route + **preview-only token** `E3_IMPORT_TOKEN` (env name only; no value is in the repo or bundle) | `kushu_import.py`, `POST /api/e3/trajectory/import`, `/imports*` |
  | Synthetic datasets + seeders | `fixtures.py`, `prodshape.py`, `platform_seed.py`, `stale_trace.py`, `api.py` `POST /seed` |
  | Synthetic TI / disposition / enforcement overlays | `artifacts_overlay.py` (`33cc6752`); collections `e3_dt_ti`, `e3_dt_dispositions`, `e3_dt_enforcement`, `e3_dt_preview*` |
  | Harness + static shells | `/app/.e3ui-harness/*` (not in the repo); `frontend/public/e3shell-*`, `e3dt-*`, `e3ui-*`, `e3dl-*` (not in the repo) |
  | Preview `.env` flags | `E3_TRAJECTORY_ROUTER`, `E3_PREVIEW_E1_SHAPE`, `E3_CLONE_BACKEND`, `E3_PREVIEW_DB`, `E3_PREVIEW_EXPORT`, `E3_PREVIEW_AUTO_RESEED`, `E3_IMPORT_TOKEN`: none set in production |

## c. Flags
| Flag | Effect | Production value |
|---|---|---|
| `VITE_E3_DT_V3` (build time) | `/edr/device-trajectory` renders `trajectory_v3/DeviceTrajectoryPage` and turns on the sidebar icon rail. OFF = legacy page + expanded sidebar | Staging `1` → owner tenant → all (see §g) |
| `VITE_E3_ATTACK_PIVOT` (build time) | HeatMap ⇄ DT pivot + DT context banner | `1` after E1 review of `182a780a` |
| `VITE_E3_DT_CONTRACT_PREVIEW` | Older contract-preview source switch | unset |
| `E3_TRAJECTORY_ROUTER`, `E3_PREVIEW_E1_SHAPE` | Preview-only routers | unset (and stripped) |
| `E3_BEHAVIOR_ENABLED` | Behavior engine hook | unset until §a wiring + canary |
| `E3_ML_ENABLED` | ML signals | unset |
| `E3_DT_VIEWMODELS_ENABLED` | `dt2.views` additive keys | unset until wired |

Because `VITE_*` flags are build-time, **per-tenant** rollout needs a tenant check. E1 should gate `DeviceTrajectoryEntry` with `E3_DT_V3 && tenantAllowed(session.tenant_id)` using its own tenant-flag service. Do not use a client-side allow-list.

## d. Wiring: E1 endpoint → E3 module (all under E1 auth + tenant middleware)
1. **Newest-first cursor paging** replaces the oldest-2,500/500 retrieval. `GET /api/edr/endpoints/{id}/trajectory`: fix `trajectory_window.py:1463` (`in_lane[:limit]`). Order by `(observed_ms DESC, event_id DESC)` via `edr_trajectory.paging`, return rows ascending plus `e3_preview.older_cursor`, and accept `before=`. Tests: `tests/edr/test_trajectory_window_order.py`.
2. **Timestamp-as-text sort fix:** `trajectory_window.py:605` `sort("event.ts", -1)` sorts strings. Sort on a parsed instant (`observed_ms`).
3. **Deep link / focus resolver:** `GET …/trajectory/focus` accepts `event_iid=`, `event=` (URL-decoded once, including `%23` and the double-encoded `%2523`) and a bare `obs_…` as `observation_id`. It walks history newest-first across pages until found and returns `{state: FOCUS_RESOLVED|NOT_FOUND, focus: {event_iid, observed_at, window}}`. The UI then sets `?device=&event=&t0=&t1=`, with one history entry.
4. **Process identity + lineage:** `edr_trajectory.identity.process_key` / `lineage` produce `process_iid`, `parent_process_iid`, causal state PROVEN / CORRELATED / UNRESOLVED, and isolate.
5. **Hours, density, coverage:** `GET …/trajectory/hours?day=` returns 24 counts. `timeline.coverage` needs heartbeats and declared gaps. Aggregate in Mongo.
6. **File facts + prevalence:** `GET …/trajectory/file-facts?sha256=&path=` returns first seen on the device and the number of devices seen (tenant-scoped).
7. **MITRE:** from E1's own attribution (`findings.attck`, `event.mitre`, `mitre_basis`) via `edr_trajectory.attack.annotate_row` / `device_summary`. Serve `e3_attack` per row and `GET …/trajectory/attack`. One catalogue, v19.2 (`docs/e3/DT_MITRE_ATTRIBUTION_INVENTORY.md`).
8. **Approvals + status log:** make `actions.ApprovalStore` / `StatusLog` durable. They are insert-only and tenant-scoped, with a unique `(tenant_id, idempotency_key)` and an audit trail. Actions: `ADD_HASH_TO_BLOCKLIST, BLOCK_APPLICATION, QUARANTINE_FILE, ISOLATE_DEVICE, STOP_ISOLATION, RUN_SCAN, FORENSIC_SNAPSHOT, DIAGNOSE_SENSOR, MOVE_TO_GROUP`. **Every one stays APPROVAL_REQUESTED** until E1 wires the hardened response boundary. The UI never shows EXECUTED without response-plane evidence.
9. **TI adapter:** `none_configured` (UI: "provider not configured") until E1 switches on the live providers with an authority trace (`DT_I1E_TI_DESIGN.md`). Disposition is `Unknown` until then. Only signature / hash-reputation evidence yields Malicious.
10. **Enforcement:** `e3_enforcement{outcome, reason, detail, at, source}` comes only from response-plane evidence.
11. **Isolation chip:** `computer.isolation{state}` (ISOLATED / NOT_ISOLATED / PENDING_START) comes from the sensor. Absent means "Isolation not reported".

## e. Data
- Read-only on the evidence stores. **No migration rewrites evidence.**
- New side collections, created by E1 migrations:
  - approvals (unique `tenant_id+idempotency_key`)
  - status log (insert-only, `tenant_id+subject+recorded_at`)
  - `e3_behavior_detections` (`edr_behavior.store.INDEXES`)
- Read indexes on the trajectory store:
  - `(tenant_id, endpoint_id, observed_ms -1, event_id -1)` for paging/focus
  - `(tenant_id, file_sha256)` for prevalence
- Canonical-store authority remains E1's decision.

## f. Tests E1 must run before go-live
- `cd apps/nivxray-xdr && yarn install && yarn test`. Expect ≥ 207 vitest (179 dt2 + 28 trajectory_amp) in E1's real yarn env.
- `cd backend && python -m pytest -p asyncio -o asyncio_mode=auto tests/edr_trajectory` (63 in E3), plus `tests/edr_behavior tests/edr_ml tests/edr_investigation`, plus the full E1 suite including **Gate-4** (`tests/edr -m 'slow or not slow'`).
- `node --test tools/e3ui/{fields,labels,attack_catalog}.test.mjs` (12).
- Playwright against **E1 STAGING** with real KUSHU data. Set `HOST`/`B`/`DEV` at the top of each file:
  - `art_details_test.py` (58), `m2_interaction_test.py` (56), `ui3_shell_panel_test.py` (51), `mitre_test.py` (72), `nav_test.py` (38), `actions_search_test.py` (31), `m2_perf_matrix.py`.
  - Deep-link cases on `dev_8b90e7c9a70d`, including `obs_2e29e40ee2dc#c133a4ab50` (as `%23` and `%2523`).
- Build both apps with the flags OFF and confirm legacy responses are byte-identical. Then build with `VITE_E3_DT_V3=1`.

## g. Staged rollout + post-deploy verification
1. Staging: merge, strip, wire, run §f with the flags OFF, then ON.
2. Production with `VITE_E3_DT_V3=1` + the tenant gate for the **owner's tenant only** (`ten_e759b7288598bd882e3dcac49d`).
3. Verify on https://edr.nivxforge.com/edr/device-trajectory. Owner sign-off:
   - [ ] The newest KUSHU events are visible (not the oldest page).
   - [ ] A deep link `?device=&event=obs_…%23…` opens Activity Details for that event.
   - [ ] Detection time links (day popover, hour bar) navigate: dot selected, grid centred, details open, Back restores.
   - [ ] Search shows N results, the × clears it, and zero results shows the in-grid empty state.
   - [ ] The Actions menu creates approvals only (APPROVAL_REQUESTED, nothing executed).
   - [ ] The sidebar rail collapses/expands and persists.
   - [ ] MITRE matches the old component for the same event (ids, tactics, ◇).
4. All tenants.

## h. Rollback
See §0: flags OFF → the legacy page, with no data impact.

## i. Known E1 items (still open, not E3 scope)
REPORTING freshness state machine (D-ENR-1); KUSHU backlog drain; TI client consolidation; IRG semantic isolation (InvestigationCanvas hunk decision); viewport payload capping; sensor gaps S-1..S-12; no macOS parser (macOS is fixture-only); E1 mapper ATT&CK drift (inventory §4).

## j. Day one for fields the sensor doesn't collect
Nothing is blank and nothing is shown as "Clean". Each missing field is listed under **"Not collected for this event (N)"** with an exact reason, such as "not collected by sensor (S-n …)", "not provided by source" or "provider not configured":
- Signer (S-8), bytes/duration (S-9), size (S-10), SHA-1/MD5 (S-11), protection engines (S-12), file-event SHA-256 (S-3), process end (S-7).
- Product/Version shows "not reported by sensor".
- Disposition shows **Unknown** (square) until TI or signature evidence exists. IOC shows "provider not configured".
- Action taken shows "No enforcement/response evidence recorded."
- The isolation chip shows "Isolation not reported".
- The no-data hatch means "0 retained observations", not "sensor offline".
