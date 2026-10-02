# DT AMP-Parity Gap Audit (E3 Phase 1)

Branch `feature/e3-edr-engines` from `eab566a9`. Cisco AMP's public Device Trajectory workflow is a **functional reference only**; nothing was copied.

**No real KUSHU evidence was available in E3.** Everything about KUSHU below comes from code: the sensor channel list, `edr_plane/windows_eventlog.py` `SUPPORTED`/`NOT_SUPPORTED`, and the canonical mapping. The `kushu_shape` fixture is **SHAPE-FAITHFUL / NOT PRODUCTION DATA**. E1 must confirm against read-only production evidence.

## 1. What KUSHU telemetry can carry (from code)
The sensor reads `Security`, `System` and `Microsoft-Windows-Sysmon/Operational` (`nivxforge_sensor.py:83`). The canonical mapping `windows_eventlog.SUPPORTED` admits Sysmon 1/3/5/11/12/13/22 and Security 4688/4624.

| Field needed for AMP-style DT | Carried? | Source / limitation |
|---|---|---|
| Process start time | YES for Sysmon 1 (`UtcTime` = start). **NO for 4688-only processes.** | `windows_eventlog.py:634,708` |
| Process identifier (GUID) | YES Sysmon (`ProcessGuid`). **NO for 4688** (pid only). | :669 |
| Parent identifiers | YES Sysmon 1 (`ParentProcessGuid`, `ParentProcessId`). 4688 has the creator pid only. | :672 |
| Creator vs reported parent (PPID-spoof evidence) | **NO.** Sysmon 1 reports the parent named by the creation record. A true-creator field needs ETW/kernel callback telemetry. | sensor item S-1 |
| Hashes | YES Sysmon 1 (`Hashes`, depending on the Sysmon config). **NO for file events** (`file.sha256` NOT_SUPPORTED for Sysmon 11). | :686; NOT_SUPPORTED |
| Command line | YES Sysmon 1 / 4688 (4688 needs the audit policy "include command line"). **NO on Sysmon 5.** | :677 |
| User | YES Sysmon 1 (`User`) | :713 |
| File create | YES (Sysmon 11) | SUPPORTED |
| File write/modify, delete, rename/move | **NO.** Sysmon 2/23/26 and rename aren't in `SUPPORTED`; Security 4663 isn't collected. | sensor items S-2, S-3 |
| File execute | Indirect only: execution = process create of that image. No separate "executed from" event. | — |
| Per-process network with process attribution | YES Sysmon 3 (`ProcessGuid` + `ProcessId`); `network.bytes` NOT_SUPPORTED. Security 5156 (WFP) isn't collected. | — |
| DNS by process | YES Sysmon 22 | — |
| Process end | Admitted (Sysmon 5) **only if the Sysmon config emits it** | :86-90 |
| Boot/session id | **NO** boot id in the canonical shape. The process key falls back to start time or GUID. | sensor item S-4 |
| Image load / injection / remote thread (Sysmon 7/8/10) | **NO** (not in SUPPORTED) | S-5 |

## 2. Capability status
Status:
- **E3 contract**: implemented and tested in `backend/edr_trajectory/` and served at `/api/e3/trajectory/*`.
- **UI**: the default page `EdrDeviceTrajectoryPage`/`dt2` (Phase 2).

| # | Capability | Default page today | E3 contract (Phase 1) | Telemetry ok? | Remaining gap / owner |
|---|---|---|---|---|---|
| 1 | Newest-first paging, full history | **partial.** Server is oldest-first `in_lane[:limit]` (RC8); client discloses and narrows. | **exists** (`paging.py`, `e3.dt.paging.newest_first.v1`, `as_of` session freeze) | n/a | E1: serve it from the production store (brief §5) |
| 2 | Stable process identity, PID-reuse safe | partial (dt2 graph uses source GUID) | **exists** (`identity.process_key`, three identity states) | Sysmon yes; 4688 pid-only | Sensor S-4 (boot id) |
| 3 | Parent→child PROVEN/CORRELATED/UNRESOLVED; synthetic roots | partial (parent_state on graph) | **exists** (`lineage.build_graph`). Proximity never creates an edge; PID-only gives at most CORRELATED. | Sysmon yes | — |
| 3b | Parent-spoof flag | missing | **exists** (`identity.parent_spoof`, needs creator evidence) | **NO creator field** | Sensor S-1. With current telemetry the flag can't fire. |
| 4 | Cross-store dedup | missing | **exists** (`identity.dedupe`: activity_identity, then canonical id, then content hash) | n/a | E1: verify `activity_identity` is present on both production stores |
| 5 | File status / TI provider-neutral | partial (DT-I1E contracts, V2 only) | **exists** (`ti.file_status`: 7 reputation states; detection ≠ verdict; CLEAN needs evidence; no providers, so UNKNOWN) | hashes: process yes, file no | E1: TI authority trace, then live providers (keys stay in E1) |
| 6 | EvidenceProvider (both stores) | missing (dt2 reads its own projection) | **exists** (`providers.py`; read-only; proven over in-memory doubles **and** motor against E3-namespaced seed collections) | n/a | E1: decide store authority from read-only production evidence |
| 7 | Retrospective status, append-only | missing | **exists** (`actions.StatusLog`) | n/a | E1: persistent append-only store + retro-scan producer |
| 8 | Coverage / gaps explicit | partial (time-model statement) | **exists** (`timeline.coverage`: NO_TELEMETRY_RECEIVED / SENSOR_DECLARED_GAP / SENSOR_OFFLINE) | gap records: the sensor journal has `integrity`/gap accounting | E1: expose acquisition gaps + heartbeats per endpoint |
| 9 | Late events | partial (time model) | **exists** (`timeline.lateness`; 5-min badge; backlog replay order-independent) | `ingest_time` exists | — |
| 10 | Viewport aggregation, >10k bounded, 30-day density | partial (day bins) | **exists** (`timeline.viewport`, ≤400 buckets × ≤200 rows; `density`) | n/a | Production: push down into Mongo aggregation (E1) |
| 11 | Lane model (process/file/unattributed network, clip flags, lineage isolation) | partial (graph rows) | **exists** (`lineage.lanes`, `isolate`) | file lanes are create-only (S-2) | — |
| 12 | Response approval-only | missing on DT | **exists** (`actions.ApprovalStore`: APPROVAL_REQUESTED only, idempotent, audited; pivots without records) | n/a | E1: route through the hardened response boundary; persistence |
| 13 | Cross-tenant isolation | exists server-side (E1) | **exists** (`require_tenant` on every read + post-filter) | n/a | — |
| — | AMP-style UI (rows × time, icons, lines, navigator, details) | partial (dt2 canvas) | Phase 2 | — | E3 Phase 2 |

## 3. Telemetry gaps: E1 / sensor items (not faked anywhere)
- **S-1** No true-creator field, so PPID spoofing can't be detected from Sysmon 1. Needs ETW/kernel creator telemetry.
- **S-2** No file write/modify/delete/rename: Sysmon 2/23/26 aren't admitted; Security 4663 isn't collected.
- **S-3** No file hash on file events: Sysmon 11 has no hash. Hashing would have to be done by the sensor.
- **S-4** No boot/session id; PID reuse across reboots relies on start time.
- **S-5** No image-load / remote-thread / process-access (Sysmon 7/8/10).
- **S-6** 4688-only processes have no GUID and no start time, so their identity is PID_ONLY_NOT_AUTHORITATIVE and their lineage is at best CORRELATED.
- **S-7** Process end requires the Sysmon config to emit EventID 5. Otherwise lanes show `continues_after`.
- **E1-1** Store authority (`v2_shadow_observations` vs `xdr_canonical_evidence`) is undecided. E3 selects neither.
- **E1-2** RC8 server ordering; push the aggregation down; the per-endpoint gap/heartbeat feed.

## M2 platform coverage (2026-10-02)
| Platform | Preview device | Path | Status |
|---|---|---|---|
| Windows | dev_f22d20b97b6d | E1 Windows pipeline (prodshape.py) | synthetic, shape-faithful |
| Linux | dev_syn_lnx01 | E1 Linux sensor path (canonical_bridge → observation_doc → E1 projection) | synthetic; FILE writer NOT_OBSERVED, network rows lack process_iid → UNRESOLVED connectors |
| macOS | dev_fix_mac01 | **fixture-only, no E1 macOS parser** | hand-built rows in E1 projection shape; proves MachO/GZ tags + narratives only |

