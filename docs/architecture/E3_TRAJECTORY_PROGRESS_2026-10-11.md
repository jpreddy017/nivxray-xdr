# E3 trajectory engineering progress — 2026-10-11

## Recovery and durable checkpoint

Continued the recovered E3 implementation at `258c8854`; no restart.
Local `e42e0195` was published with the identical file tree as `e4ed4f2f`
through the connected GitHub account because shell Git had no push credential.
The local commit remains on a backup branch. The engineering branch is
`engineering/e3-deterministic-gate-20261011`.

The first CI run produced 187 passes, one failure and two setup errors:
E1 trajectory imports required bcrypt, JWT and dotenv dependencies.
Remote fix `8424fbfd` adds the existing pinned dependencies. The resulting
[MongoDB CI run](https://github.com/jpreddy017/nivxray-xdr/actions/runs/38154418352)
passed **190 tests** on Python 3.11 with MongoDB 7, including the eight
previously unvalidated Mongo tests. Live preview HTTP tests remain excluded.

## Existing implementations inspected

| Capability | Existing implementation reused | Finding / disposition |
| --- | --- | --- |
| Device trajectory | `backend/edr_trajectory`, `backend/edr_plane/trajectory_window.py`, UI `trajectory_amp` and `trajectory_v3` | Existing identity, paging, lane and timeline contracts retained. Live UI validation pending. |
| Process tree / graph | E3 `lineage.py`; existing endpoint inventory and `EdrProcessTreePage.jsx` | Added cycle rejection and iterative lane traversal to E3. Other graph engines are not claimed covered by these fixes. |
| Fleet file trajectory | `backend/services/edr/file_trajectory.py`, `XdrFleetFileTrajectoryPage.jsx` | Corrected instant ordering, endpoint first/last seen and earliest host ties. Invalid timestamps stay visible but cannot establish earliest host. |
| Causal investigation | `backend/edr_investigation/causal.py`, builder and recorded fixtures | Existing evidence-backed relationship states retained and exercised in engine CI. |
| Behavior / ML | `backend/edr_behavior`, `backend/edr_ml` | Existing sequence, tenancy, suppression, features and model tests now run in the new gate. No second detection engine added. |
| AI investigation | Existing evidence-backed investigation contracts | No new AI integration in this increment. External model calls stay disabled in deterministic CI; model quality and live integration remain unverified. |

## Trajectory increment

- Cyclic and self-parent evidence is demoted to UNRESOLVED, preserving the
  reported candidate and reason; those edges cannot support proven lineage.
  Processes remain visible instead of disappearing from root traversal.
- Iterative traversal renders a tested 1,500-process chain without exceeding
  Python recursion depth, retaining the existing deterministic lane order.
- Fleet file chronology reuses `edr_plane.instant.parse_instant` instead of
  lexical timestamp comparison. Equivalent timezones preserve all earliest
  host ties. Added `timestamp_unresolved_events`; unparseable times are not
  fabricated, removed or used for first/last observed claims.
- Added regression tests for cycles, self-parents, deep trees, mixed Windows/
  ISO times, timezone ties, endpoint rollups and absent/invalid timestamps.

## Remaining gates

The trajectory increment must pass its own GitHub MongoDB gate. Frontend
rendering, live preview deep links, existing comprehensive security/release
gates and owner approval remain required. This gate is additive and does not
prove production readiness or activate branch protection requirements.
Windows re-enrollment Gate 4 and every existing security HOLD remain in force.
Tracked tokens and persisted runtime state were not changed. No merge or
production deployment is authorized by passing this engine gate alone.

Next: validate frontend trajectory/process-tree/graph fixtures and live API
contract integration, then make the next bounded implementation change using
the committed E1/E3 substrate. No direct access to uncommitted Emergent work.

## Follow-up: evidence identity boundaries

The trajectory increment at remote `2534adc3` passed **197 tests** including
MongoDB, plus **207 frontend fixture tests**, **18 Node time-window tests** and
the standalone Vite build. Browser/live-preview validation remains pending.

The subsequent review found and fixed three additional gaps in the existing
E3 evidence model:

- Deduplication now scopes a source event identifier to both tenant and device.
  A host-local identifier reused on another host cannot discard its evidence;
  same-host cross-store copies still merge provenance and earliest ingestion.
- POSIX and unknown-shaped file paths retain case in lane identity. Existing
  Windows-shaped path keys retain their case-insensitive behavior. This is a
  conservative path-shape rule, not a claim to know each filesystem's settings.
- Hash-based lineage pivots compare both recorded and requested hashes without
  hexadecimal letter-case differences, including shadow-store hashes.

Added six regression cases. The follow-up local deterministic scope passed
**194 tests**; its own remote MongoDB run is required before promotion. Existing
security HOLDs, live-preview checks and owner approval are unchanged.
