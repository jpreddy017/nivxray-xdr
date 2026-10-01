"""v2/ingestion/frame_enrich.py · Frame-level enricher for ingested telemetry.

The TrajectoryFrame is intentionally minimal — it only carries the
fields the UI Canvas needs. The Verdict Engine's signals, however,
read additional fields directly (`cmdline`, `target`, `parent.name`,
`mitre`) which the Trajectory builder currently doesn't populate for
shadow observations.

Rather than modify the frozen `TrajectoryFrame` schema or the shared
`build_device_trajectory` function, we run a small post-enricher that
merges CES-side fields (already stored on each CEM event via
`provenance.{cmdline,target,parent_name}`) back onto the frame dicts.

Deterministic, idempotent, side-effect free w.r.t. Mongo.
"""
from __future__ import annotations

from typing import Any

from v2.case_engine.schema import COLLECTIONS


async def enrich_frames_from_observations(db: Any, case_id: str,
                                          frames: list[dict[str, Any]]) -> int:
    """Mutate `frames` in place, filling cmdline/target/parent.name/mitre
    from the source CEM events. Returns the number of frames enriched.

    A frame is joined to its source event by the first entry in
    `frame.evidence_ids` (which build_device_trajectory sets to
    `ev["iid"]`).
    """
    if not frames:
        return 0

    # Index shadow observations by their event.iid — one Mongo round trip.
    wanted = {(f.get("evidence_ids") or [None])[0] for f in frames}
    wanted.discard(None)
    if not wanted:
        return 0
    coll = db[COLLECTIONS["shadow_observations"]]
    lookup: dict[str, dict] = {}
    async for row in coll.find({"case_id": case_id,
                                 "event.iid": {"$in": list(wanted)}}):
        ev = row.get("event") or {}
        iid = ev.get("iid")
        if iid:
            lookup[iid] = ev

    enriched = 0
    for f in frames:
        eids = f.get("evidence_ids") or []
        if not eids:
            continue
        ev = lookup.get(eids[0])
        if not ev:
            continue
        prov = ev.get("provenance") or {}
        raw = ev.get("raw") or {}
        cmd = prov.get("cmdline") or raw.get("command_line") or ""
        tgt = prov.get("target") or raw.get("target") or ""
        parent_name = prov.get("parent_name") or (ev.get("process") or {}).get("parent_name") or ""

        # Merge without overwriting existing values
        if cmd and not f.get("cmdline"):
            f["cmdline"] = cmd
        if tgt and not f.get("target"):
            f["target"] = tgt
        if not f.get("mitre") and ev.get("mitre"):
            f["mitre"] = list(ev.get("mitre") or [])
        # Preserve rule_id link from raw if present
        if raw.get("rule_id") and not f.get("rule_id"):
            f["rule_id"] = raw["rule_id"]
        # Enrich parent.name — signals' _parent_bin reads parent.name first
        if parent_name:
            parent = f.get("parent") or {}
            if not parent.get("name"):
                parent["name"] = parent_name
                f["parent"] = parent
        enriched += 1

    return enriched
