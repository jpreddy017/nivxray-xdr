"""P0-D · the canonical bridge — sensor telemetry → canonical evidence.

```
edr_raw_events  →  SENSOR DSM  →  canonical event  →  CES/CEM observation
   (immutable)      (this file)                        (v2_shadow_observations)
                                                              ↓
                          the EXISTING detection / IUE / ICE / IKG / VEEE
                          pipeline and Device Trajectory — unchanged
```

Two rules this file exists to honour.

**Reuse, never rebuild.** It produces the same canonical shape the CEF/LEEF
DSM produces and hands off to `telemetry_bridge.persist_live_observation`.
No new reasoning engine, no parallel evidence model, no second trajectory
projection.

**Never overwrite the original.** The raw event is untouched; the outcome
of this parse is APPENDED as a `Derivation`. A parse failure therefore
still leaves a retained, replayable raw event and an honest
`PARSER_FAILED` derivation rather than a silently missing event.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from edr_plane.raw_events import Derivation, add_derivation, next_generation

PARSER_NAME = "nivxforge-linux-sensor"
PARSER_VERSION = "1.0.0"
NORMALIZER_VERSION = "1.0.0"

#: What the sensor genuinely cannot produce. Recorded as NOT_SUPPORTED so
#: a downstream consumer never reads a gap as "nothing happened".
SENSOR_NOT_SUPPORTED = (
    "process.exit_time", "process.signer", "process.integrity",
    "file.actor_process", "registry", "usb_device", "memory",
)


def _iso(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and v else None


def activity_identity(ev: dict[str, Any], endpoint_id: str) -> str:
    """The identity of the ACTIVITY, independent of when we heard about it.

    Two deliveries describing the same real process (same endpoint, pid and
    start time) are ONE process, observed twice. Without this key a sensor
    restart re-reports the running process table and the same real process
    appears in the trajectory as if it had started many times, which
    inflates activity and corrupts first-seen reasoning.
    """
    activity = ev.get("activity")
    if activity == "PROCESS":
        parts = ("PROCESS", ev.get("pid"), ev.get("start_time"),
                 ev.get("image_path") or ev.get("image"))
    elif activity == "FILE":
        parts = ("FILE", ev.get("operation"), ev.get("path"),
                 ev.get("sha256"), ev.get("size"))
    else:
        parts = ("NETWORK", ev.get("protocol"), ev.get("local_ip"),
                 ev.get("local_port"), ev.get("remote_ip"),
                 ev.get("remote_port"), ev.get("tcp_state"))
    joined = "\x1f".join(str(p) for p in (endpoint_id, *parts))
    return "act_" + hashlib.sha256(joined.encode()).hexdigest()[:24]


def parse(line: str) -> dict[str, Any]:
    """Sensor JSON line → the authoritative canonical telemetry shape."""
    ev = json.loads(line)
    activity = ev.get("activity")
    if activity not in ("PROCESS", "FILE", "NETWORK"):
        raise ValueError(f"unknown sensor activity {activity!r}")

    observed = _iso(ev.get("observed_at")) or datetime.now(
        timezone.utc).isoformat()
    not_observed = list(ev.get("not_observed") or ())

    canonical: dict[str, Any] = {
        "source_vendor": "NivXForge",
        "source_product": "LinuxSensor",
        "event_time": _iso(ev.get("start_time")) or observed,
        "ingest_time": datetime.now(timezone.utc).isoformat(),
        "additional_fields": {
            "payload_format": "nivxforge-sensor-json",
            "activity_type": activity,
            "operation": ev.get("operation"),
            "collection_method": ev.get("collection_method"),
            # Directive §6 — the epistemic state travels WITH the evidence.
            "epistemic_state": {
                "not_observed": not_observed,
                "not_supported": list(SENSOR_NOT_SUPPORTED),
                "note": ("Fields listed under not_observed were not visible "
                         "to this collection method on this event. Fields "
                         "under not_supported cannot be produced by this "
                         "sensor at all. Neither means the activity did not "
                         "occur."),
            },
        },
        "host": {},
        "identity": {},
        "process": {},
        "file": {},
        "network": {},
    }

    if activity == "PROCESS":
        canonical["process"] = {
            "pid": ev.get("pid"),
            "ppid": ev.get("ppid"),
            "name": ev.get("image"),
            "executable_path": ev.get("image_path"),
            "command_line": ev.get("command_line"),
            "hashes": ({"sha256": ev["sha256"]} if ev.get("sha256") else {}),
            # Real parent evidence, or nothing. `parent_lookup_state` says
            # which — see the sensor's `_proc_parent`.
            "parent_pid": ev.get("ppid"),
            "parent_name": ev.get("parent_image"),
            "parent_executable_path": ev.get("parent_image_path"),
        }
        canonical["identity"] = {"username": ev.get("user")}
        # Lineage is evidence-based: a parent we actually resolved in /proc
        # is a real relationship; PID 0 is the kernel boundary, not an
        # invented root; and a pid we could not attribute stays
        # unattributed rather than becoming a fabricated ancestor.
        lookup = ev.get("parent_lookup_state")
        canonical["additional_fields"]["lineage_state"] = {
            "OBSERVED": "PARENT_OBSERVED",
            "KERNEL_BOUNDARY": "ROOT_KERNEL_BOUNDARY",
            "PARENT_NOT_PRESENT": "PARENT_NOT_OBSERVED",
            "PID_REUSED_PARENT_NOT_ATTRIBUTABLE":
                "PARENT_NOT_ATTRIBUTABLE_PID_REUSE",
        }.get(lookup, "PARENT_NOT_OBSERVED")
        canonical["additional_fields"]["parent_lookup_state"] = lookup

    elif activity == "FILE":
        canonical["file"] = {
            "path": ev.get("path"),
            "name": ev.get("filename"),
            "size": ev.get("size"),
            "hashes": ({"sha256": ev["sha256"]} if ev.get("sha256") else {}),
        }
        canonical["additional_fields"]["file_operation"] = ev.get("operation")

    else:  # NETWORK
        canonical["network"] = {
            "protocol": ev.get("protocol"),
            "src_ip": ev.get("local_ip"),
            "src_port": ev.get("local_port"),
            "dest_ip": ev.get("remote_ip"),
            "dest_port": ev.get("remote_port"),
            "direction": ev.get("direction"),
        }
        # The owning PID, when the socket inode resolved. Absent is absent.
        if ev.get("pid"):
            canonical["process"] = {"pid": ev["pid"]}
        canonical["additional_fields"]["tcp_state"] = ev.get("tcp_state")

    return canonical


async def bridge(db: Any, *, raw_id: str, tenant_id: str, payload: str,
                 endpoint_id: str, hostname: Optional[str],
                 authentication: dict) -> dict[str, Any]:
    """Parse → canonical → CES/CEM observation → append the derivation.

    Returns what actually happened. A parse failure is reported as a
    failure AND recorded on the raw event; it is never smoothed over.
    """
    from v2.case_engine.schema import COLLECTIONS
    from v2.ingestion.telemetry_bridge import persist_live_observation

    gen = await next_generation(db, tenant_id=tenant_id, raw_id=raw_id)

    try:
        canonical = parse(payload)
    except Exception as e:  # noqa: BLE001
        await add_derivation(db, tenant_id=tenant_id, raw_id=raw_id,
                             derivation=Derivation(
                                 replay_generation=gen,
                                 derived_at=datetime.now(
                                     timezone.utc).isoformat(),
                                 parser_name=PARSER_NAME,
                                 parser_version=PARSER_VERSION,
                                 parser_state="FAILED",
                                 parser_notes=[str(e)[:300]],
                                 outcome="NO_CANONICAL_EVIDENCE",
                                 reason=("sensor payload could not be "
                                         "parsed; the raw bytes are "
                                         "retained and replayable after a "
                                         "parser fix")))
        return {"canonicalized": False, "parser_state": "FAILED",
                "reason": str(e)[:300]}

    canonical["event_id"] = f"cev_{raw_id[4:]}_{gen}"
    canonical["raw_ref"] = {"raw_id": raw_id, "collection": "edr_raw_events"}
    canonical["host"] = {"host_id": endpoint_id, "hostname": hostname}
    canonical["provenance"] = {
        "trace_id": raw_id,
        "normalizer_id": f"{PARSER_NAME}/{NORMALIZER_VERSION}",
    }
    # The authenticated identity travels with the evidence, so
    # "which authenticated endpoint produced this exact evidence?" is
    # answerable from the observation itself and not only from the raw row.
    canonical["additional_fields"]["authentication"] = authentication
    canonical["additional_fields"]["endpoint_id"] = endpoint_id

    # One real activity produces ONE evidence row. A re-observation of the
    # same process / connection / file state is recorded on the raw event
    # as a duplicate observation and does NOT create a second piece of
    # evidence — otherwise a sensor restart would look like a burst of new
    # activity that never happened.
    act_id = activity_identity(json.loads(payload), endpoint_id)
    canonical["additional_fields"]["activity_identity"] = act_id
    prior = await db[COLLECTIONS["shadow_observations"]].find_one(
        {"tenant_id": tenant_id, "activity_identity": act_id},
        {"_id": 1, "canonical_event_id": 1})
    if prior:
        await add_derivation(db, tenant_id=tenant_id, raw_id=raw_id,
                             derivation=Derivation(
                                 replay_generation=gen,
                                 derived_at=datetime.now(
                                     timezone.utc).isoformat(),
                                 parser_name=PARSER_NAME,
                                 parser_version=PARSER_VERSION,
                                 parser_state="OK",
                                 normalizer_version=NORMALIZER_VERSION,
                                 event_id=prior.get("canonical_event_id"),
                                 evidence_ids=[str(prior["_id"])],
                                 outcome="DUPLICATE_OBSERVATION_OF_KNOWN_"
                                         "ACTIVITY",
                                 reason=("the same real activity is already "
                                         "represented by canonical "
                                         "evidence; this re-observation is "
                                         "retained raw and linked, not "
                                         "counted again")))
        return {"canonicalized": False,
                "parser_state": "OK",
                "duplicate_activity": True,
                "activity_identity": act_id,
                "existing_observation_id": str(prior["_id"]),
                "existing_canonical_event_id": prior.get(
                    "canonical_event_id"),
                "reason": ("re-observation of activity already held as "
                           "canonical evidence; no second evidence row "
                           "was created")}

    obs_id = await persist_live_observation(
        db, canonical,
        envelope={"source": "nivxforge-linux-sensor",
                  "connector_id": endpoint_id,
                  "collector_id": endpoint_id,
                  "collection_method": canonical["additional_fields"].get(
                      "collection_method") or "PROC_POLL",
                  "parser_version": PARSER_VERSION,
                  "source_event_id": canonical["event_id"],
                  "collection_timestamp": canonical["event_time"]},
        tenant_id=tenant_id)

    await add_derivation(db, tenant_id=tenant_id, raw_id=raw_id,
                         derivation=Derivation(
                             replay_generation=gen,
                             derived_at=datetime.now(timezone.utc).isoformat(),
                             parser_name=PARSER_NAME,
                             parser_version=PARSER_VERSION,
                             parser_state="OK",
                             normalizer_version=NORMALIZER_VERSION,
                             event_id=canonical["event_id"],
                             evidence_ids=[obs_id] if obs_id else [],
                             outcome="CANONICAL_EVIDENCE_CREATED"))

    return {"canonicalized": True, "parser_state": "OK",
            "canonical_event_id": canonical["event_id"],
            "observation_id": obs_id,
            "activity_type": canonical["additional_fields"]["activity_type"]}
