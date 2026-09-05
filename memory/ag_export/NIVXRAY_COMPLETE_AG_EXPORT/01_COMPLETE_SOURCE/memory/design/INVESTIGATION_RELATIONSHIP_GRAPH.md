# Investigation Relationship Graph (IRG) · Canonical Schema
_Foundation for every current and future NivXRay investigation view._

Single source of truth. Consumed identically by: Device Trajectory · Process Ancestry ·
File Trajectory · Registry Trajectory · Network Trajectory · Attack Chain · Report
Generator · STIX Export.

## Frame envelope (extended)
Every frame emitted by `build_from_observations` must carry these fields.
Backward-compatible: fields absent in older frames default to `None` / empty.

```python
{
  # ── Event (unchanged) ───────────────────────────────────────────
  "event": {
    "iid":         "evt_...",              # was frame_iid
    "timestamp":   "2026-07-22T13:04:54.612Z",
    "type":        "process_create" | "file_write" | ...,
    "source":      "adapter.cmd" | "adapter.ps" | ...,
    "confidence":  0.0..1.0,
  },
  # ── Entity ─────────────────────────────────────────────────────
  "entity": {
    "iid":    "ent_bin_powershell.exe",    # deterministic hash of type+name
    "type":   "process" | "file" | "network" | "registry" | "user" | "host",
    "name":   "powershell.exe",
    "start":  "2026-07-22T13:04:54.612Z" | None,
    "end":    "2026-07-22T13:04:54.892Z" | None,
  },
  # ── Relationship ───────────────────────────────────────────────
  "parent": {
    "iid":  "ent_bin_cmd.exe" | None,
    "type": "process",
  },
  "root":   { "iid": "ent_bin_explorer.exe" },
  "relationship": {
    "type":      "SPAWNED" | "CREATED" | "MODIFIED" | "READ" | "WROTE"
               | "CONNECTED" | "DOWNLOADED" | "LOADED" | "INJECTED"
               | "RENAMED" | "DELETED" | "REGISTRY_WRITE" | "MODULE_LOAD"
               | "THREAD_CREATE",
    "direction": "parent->child" | "child->parent" | "peer",
    "reason":    "cmd.exe /c invoked powershell.exe -e <encoded>",
  },
  # ── Execution ──────────────────────────────────────────────────
  "execution": {
    "process_start": 1721653494612,    # epoch ms
    "process_end":   1721653494892,    # epoch ms
    "session":       { "iid": "ses_..." } | None,
    "depth":         0..N,             # depth from root
  },
  # ── Evidence linkage ───────────────────────────────────────────
  "evidence": {
    "artifact":    { "iid": "art_..." } | None,   # link to /v2/artifacts
    "observation": { "iid": "obs_..." },          # link to v2_shadow_observations
    "case":        { "iid": "case_dfir_..." },
  },
  # ── Legacy fields preserved for backwards compat ───────────────
  "frame_iid":   "evt_...",                        # alias for event.iid
  "process":     { "iid": "ent_bin_..." },
  "ts":          "2026-07-22T13:04:54.612Z",
  "lane":        "process" | ...,
  "action":      "process_create" | ...,
  "label":       "powershell.exe",
  "mitre":       ["T1059.001", ...],
}
```

## Relationship types
`SPAWNED · CREATED · MODIFIED · READ · WROTE · CONNECTED · DOWNLOADED · LOADED · INJECTED · RENAMED · DELETED · REGISTRY_WRITE · MODULE_LOAD · THREAD_CREATE`

Rules:
- **SPAWNED** — process → child process
- **CREATED / MODIFIED / WROTE / RENAMED / DELETED** — process → file
- **REGISTRY_WRITE** — process → registry key
- **LOADED / MODULE_LOAD** — process → DLL / driver
- **CONNECTED / DOWNLOADED** — process → network endpoint
- **INJECTED / THREAD_CREATE** — process → foreign process
- **READ** — process → file / process (memory)

## Acceptance rules (per user P1 spec)
1. Every process traces to a root ancestor (via `parent` chain of type=process).
2. Multiple independent trees supported (multiple roots per case).
3. Missing `parent.iid` handled gracefully (frame renders as a top-level orphan).
4. Cycles detected and prevented (enricher walks with a visited-set).
5. Chronological order preserved (ordering by `event.timestamp`).
6. Every investigation view (Device Trajectory, Process Ancestry, File / Registry /
   Network Trajectory, Attack Chain) consumes this same graph.

## Implementation surface
- Enricher: `/app/backend/v2/shadow/irg.py`
- Called from: `/app/backend/v2/routers/trajectory.py` (device trajectory) and
  `/app/backend/v2/routers/ancestry.py` (process ancestry) — a single call each.
- Consumers: `frontend/src/v2/pages/DeviceTrajectoryV2.jsx` and all future
  trajectory views read `entity.iid`, `parent.iid`, `root.iid`, `relationship.type`.
