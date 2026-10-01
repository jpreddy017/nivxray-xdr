"""Device Trajectory builder · Phase 3d.

Deterministically turns a stream of CEM events into ordered
`TrajectoryFrame`s scoped to one device. Entity iids on the frames
are stable — the same input events produce byte-identical frames
across runs.

No RC5 imports. Pure function.
"""
from __future__ import annotations

import hashlib
from typing import Any, Iterable

from v2.trajectory.schema import EntityRef, TrajectoryFrame, lane_for


def _sha16(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _label_for(event: dict[str, Any]) -> str:
    """Prefer the semantic parser's rule label + target when present
    (produced by the enriched command-line normalizer in Phase 3f).
    Falls back to a generic verb + target for events lacking rules."""
    raw = event.get("raw") or {}
    if raw.get("rule_label") or raw.get("action"):
        entity = raw.get("entity") or ""
        action = raw.get("action") or event.get("kind", "").replace("_", " ")
        target = raw.get("target") or ""
        parts = [p for p in (entity, action, target) if p]
        return " · ".join(parts)[:180]
    kind = event.get("kind", "")
    proc = event.get("process") or {}
    p_name = (proc.get("name") or proc.get("image") or "").strip() or "process"
    return f"{p_name} · {kind.replace('_', ' ')}"


def build_device_trajectory(
    events: Iterable[dict[str, Any]],
    *,
    device_iid: str,
    device_hostname: str | None = None,
) -> list[TrajectoryFrame]:
    """Build a deterministic list of `TrajectoryFrame`s for one device.

    Input `events` are already CEM-shaped dictionaries (as
    `CanonicalEvent.to_dict()` produces). Events with a `device_iid`
    that doesn't match `device_iid` are silently skipped so the
    caller can pass a case-wide iterable without pre-filtering.
    """
    device_ref = EntityRef(kind="device", iid=device_iid, label=device_hostname)
    frames: list[TrajectoryFrame] = []

    for ev in events:
        if ev.get("device_iid") not in (None, device_iid):
            continue

        kind = ev.get("kind", "")
        lane = lane_for(kind)
        ts   = ev.get("ts") or ""

        # Deterministic frame iid: sha16 of (ts + kind + adapter + seq + evt_iid).
        # Falls through even if some fields are missing.
        frame_iid = "tf_" + _sha16(
            ts, kind, str(ev.get("adapter", "")),
            str(ev.get("sequence", 0)), str(ev.get("iid", "")),
        )

        proc_ref = None
        parent_ref = None
        if ev.get("process_iid"):
            pi = ev["process_iid"]
            proc_ref = EntityRef(kind="process", iid=pi,
                                 label=(ev.get("process") or {}).get("name"))
            parent_iid = (ev.get("process") or {}).get("parent_iid")
            if parent_iid:
                parent_ref = EntityRef(kind="process", iid=parent_iid)

        file_ref = None
        registry_ref = None
        network_ref = None
        art = ev.get("artefacts") or {}
        arts_iids = ev.get("artefacts_iids") or []
        for a in art.get("file", []) or []:
            if a.get("iid"):
                file_ref = EntityRef(kind="file", iid=a["iid"], label=a.get("path"))
                break
        for a in art.get("registry", []) or []:
            if a.get("iid"):
                registry_ref = EntityRef(kind="registry", iid=a["iid"], label=a.get("key"))
                break
        for a in art.get("network", []) or []:
            if a.get("iid"):
                label = a.get("dst_ip") or a.get("url") or a.get("host")
                network_ref = EntityRef(kind="network_conn", iid=a["iid"], label=label)
                break
        # Fallback: use artefacts_iids from CEM if the enriched
        # artefacts dict is missing (shadow observations use this).
        if not (file_ref or registry_ref or network_ref) and arts_iids:
            for iid in arts_iids:
                if iid.startswith("cmd_"):
                    file_ref = EntityRef(kind="command_line", iid=iid)
                elif iid.startswith("file_"):
                    file_ref = EntityRef(kind="file", iid=iid)
                elif iid.startswith("reg_"):
                    registry_ref = EntityRef(kind="registry", iid=iid)
                elif iid.startswith("net_"):
                    network_ref = EntityRef(kind="network_conn", iid=iid)

        user_ref = None
        if ev.get("actor_iid"):
            user_ref = EntityRef(kind="user", iid=ev["actor_iid"])

        frames.append(TrajectoryFrame(
            frame_iid=frame_iid,
            ts=ts,
            lane=lane,
            action=kind,
            label=_label_for(ev),
            device=device_ref,
            process=proc_ref,
            parent=parent_ref,
            file=file_ref,
            registry=registry_ref,
            network=network_ref,
            user=user_ref,
            mitre=tuple(ev.get("mitre") or ()),
            labels=tuple(ev.get("labels") or ()),
            evidence_ids=(ev.get("iid"),) if ev.get("iid") else (),
            provenance=ev.get("provenance") or {},
        ))

    # Deterministic order: (ts, sequence, frame_iid).
    frames.sort(key=lambda f: (f.ts, f.provenance.get("sequence", 0), f.frame_iid))
    return frames


async def build_from_observations(
    db: Any,
    *,
    case_id: str,
    device_iid: str | None = None,
    limit: int = 500,
) -> list[TrajectoryFrame]:
    """Load recent shadow observations for `case_id` from Mongo and
    turn them into TrajectoryFrames. If `device_iid` is None the
    frames span every device in the case (the first entity_iid of
    each observation becomes the synthetic device)."""
    from v2.case_engine.schema import COLLECTIONS
    coll = db[COLLECTIONS["shadow_observations"]]
    cursor = coll.find({"case_id": case_id},
                       sort=[("captured_at", 1)]).limit(max(1, min(limit, 5000)))
    events: list[dict[str, Any]] = []
    async for row in cursor:
        ev = row.get("event") or {}
        # Shadow adapter doesn't emit a device_iid — synthesise a
        # stable pseudo-device from the sha16 of the case_id so the
        # UI can group frames coherently even in the seed phase.
        if not ev.get("device_iid"):
            ev["device_iid"] = f"dev_shadow_{_sha16(case_id)}"
        events.append(ev)

    target = device_iid or (events[0].get("device_iid") if events else f"dev_shadow_{_sha16(case_id)}")
    return build_device_trajectory(events, device_iid=target)
