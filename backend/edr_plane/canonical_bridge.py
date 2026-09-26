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

from edr_plane.contracts.identity import ProcessIdentity
from edr_plane.raw_events import Derivation, add_derivation, next_generation
from services import event_time_basis
from services import provenance_timestamps as pts

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

    observed = _iso(ev.get("observed_at"))
    not_observed = list(ev.get("not_observed") or ())
    # D9/D12 · `event_time` carries one of several genuinely different
    # meanings. Which one is decided by the shared basis resolver, so this
    # path cannot drift from every other source — and so a missing
    # `observed_at` can no longer be filled from our own clock and then
    # presented as `sensor:observed_at`.
    activity_time = _iso(ev.get("start_time"))
    _clock = datetime.now(timezone.utc).isoformat()
    etb = event_time_basis.resolve(
        activity=([(activity_time, "sensor:/proc start_time")]
                  if activity_time else ()),
        observation=([(observed, "sensor:observed_at")] if observed else ()),
        clock=_clock,
        clock_source="pipeline:canonical_bridge clock",
        activity_absent_reason=("this collection method observes a state, "
                                "not the instant it began"),
        observation_absent_reason=("the sensor event carried no observed_at; "
                                   "when the sensor saw this was never "
                                   "reported"))

    canonical: dict[str, Any] = {
        "source_vendor": "NivXForge",
        "source_product": "LinuxSensor",
        "event_time": etb.event_time,
        "ingest_time": datetime.now(timezone.utc).isoformat(),
        "provenance": {
            "timestamps": pts.block(
                **etb.stamps(),
                # Directive §4 — the sensor IS the collector on this path.
                # There is no collector hop, so there is nothing to stamp.
                # A batch-send time is NOT a collector receipt.
                collector_received_at=pts.stamp(
                    status=pts.NOT_APPLICABLE,
                    reason="no collector boundary exists on the sensor "
                           "path: the sensor delivers straight to NivX "
                           "ingress"),
            ),
        },
        "additional_fields": {
            "payload_format": "nivxforge-sensor-json",
            "activity_type": activity,
            "operation": ev.get("operation"),
            "collection_method": ev.get("collection_method"),
            **etb.declarations(),
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
        # N2.1 · the PROCESS lane already collects the start identity, so
        # the same lifetime-bound identity is declared here and minted at
        # binding — one identity model for process AND network evidence.
        if ev.get("pid") and (ev.get("start_ticks") is not None
                              or ev.get("start_time")):
            canonical["process"].update({
                "start_time": ev.get("start_time"),
                "attribution_state": "ENDPOINT_SCOPE_PENDING",
                "attribution_reason": (
                    "the sensor read this process's start identity from "
                    "/proc/<pid>/stat; the endpoint scope is applied at "
                    "binding"),
                "field_provenance": {
                    "pid": "sensor:/proc/<pid>",
                    "start_time": "sensor:/proc/<pid>/stat field 22"},
            })
        elif ev.get("pid"):
            canonical["process"].update({
                "attribution_state": "PID_ONLY_NOT_AUTHORITATIVE",
                "attribution_reason": (
                    "no process start identity accompanied this event; a "
                    "PID is reused and is not a process identity"),
            })
        canonical["identity"] = {"username": ev.get("user")}
        # The process START IDENTITY travels with the evidence. Without it
        # a consumer holds a pid, and a pid alone is not a process — it is
        # reused. Response targeting binds to this.
        canonical["additional_fields"]["process_start_ticks"] = ev.get(
            "start_ticks")
        canonical["additional_fields"]["process_start_time"] = ev.get(
            "start_time")
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
        # ── N2.1 · the owning process, and how well we know it ──────────
        # The inode→PID resolution is real evidence. A PID by itself is
        # not a process identity, so the START identity decides whether
        # this connection can be ATTRIBUTED or only described.
        pid = ev.get("pid")
        start_ticks = ev.get("process_start_ticks")
        start_time = ev.get("process_start_time")
        if pid and start_ticks is not None:
            canonical["process"] = {
                "pid": pid,
                "start_time": start_time,
                # `process_iid` needs the endpoint scope, which this parser
                # does not have. `bind_process_identity()` mints it the
                # moment the authenticated endpoint is known.
                "attribution_state": "ENDPOINT_SCOPE_PENDING",
                "attribution_reason": (
                    "the socket inode resolved to a PID and its start "
                    "identity was read in the same collection pass; the "
                    "endpoint scope is applied at binding"),
                "field_provenance": {
                    "pid": "sensor:/proc/net socket inode → pid",
                    "start_time": "sensor:/proc/<pid>/stat field 22",
                },
            }
            canonical["additional_fields"]["process_start_ticks"] = start_ticks
            canonical["additional_fields"]["process_start_time"] = start_time
        elif pid:
            canonical["process"] = {
                "pid": pid,
                "attribution_state": "PID_ONLY_NOT_AUTHORITATIVE",
                "attribution_reason": (
                    "the owning PID resolved but its start identity did "
                    "not (the process most likely exited between the inode "
                    "map and the /proc read). A PID is reused, so this is "
                    "context and must never be read as attribution"),
                "field_provenance": {
                    "pid": "sensor:/proc/net socket inode → pid"},
            }
        else:
            canonical["process"] = {
                "attribution_state": "NOT_OBSERVED",
                "attribution_reason": (
                    "the socket inode did not resolve to an owning process "
                    "in this collection pass; which process held this "
                    "socket was not observed, and no process is named"),
            }
        canonical["additional_fields"]["tcp_state"] = ev.get("tcp_state")

    return canonical


def bind_process_identity(canonical: dict[str, Any],
                          endpoint_id: Optional[str]) -> dict[str, Any]:
    """Apply the ENDPOINT scope to a pending process identity.

    A `process_iid` is unique only within its endpoint — two hosts hold the
    same PID at the same instant every day. So the identity is minted here,
    where the authenticated endpoint is known, and a process identity that
    never gets an endpoint scope is downgraded rather than trusted.
    """
    proc = canonical.get("process")
    if not isinstance(proc, dict):
        return canonical
    state = proc.get("attribution_state")
    if state not in ("ENDPOINT_SCOPE_PENDING", None):
        return canonical
    if state is None:
        return canonical
    if not endpoint_id or proc.get("pid") is None:
        proc["attribution_state"] = "PID_ONLY_NOT_AUTHORITATIVE"
        proc["attribution_reason"] = (
            "process start identity was observed, but no authenticated "
            "endpoint scope was bound to this evidence; a process identity "
            "without its endpoint is not unique and is not attribution")
        return canonical
    proc["process_iid"] = ProcessIdentity.mint(
        endpoint_id=endpoint_id, pid=proc["pid"],
        start_time=proc.get("start_time"))
    proc["attribution_state"] = "SOURCE_PROCESS_IDENTITY"
    proc["attribution_reason"] = (
        "endpoint + pid + process start identity were all observed, so "
        "this connection is bound to one process LIFETIME and survives PID "
        "reuse and process restart")
    proc.setdefault("field_provenance", {})["process_iid"] = (
        "nivx:ProcessIdentity.mint(endpoint_id, pid, start_time)")
    return canonical


async def bridge(db: Any, *, raw_id: str, tenant_id: str, payload: str,
                 endpoint_id: str, hostname: Optional[str],
                 authentication: dict,
                 source_kind: Optional[str] = None,
                 sensor_version: Optional[str] = None,
                 nivx_received_at: Optional[str] = None) -> dict[str, Any]:
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
    # N2.1 · the authenticated endpoint is known here, so a pending process
    # identity becomes a real one (or is honestly downgraded).
    bind_process_identity(canonical, endpoint_id)
    canonical["provenance"] = {
        # The stamps seeded by `parse()` are the source-side truth and must
        # survive this assignment.
        **(canonical.get("provenance") or {}),
        "trace_id": raw_id,
        "normalizer_id": f"{PARSER_NAME}/{NORMALIZER_VERSION}",
        # P0-3 · the attribution recorded on the raw event travels with
        # the canonical evidence. Without it a downstream consumer cannot
        # tell live sensor evidence from anything else, and the freshest,
        # most certainly-real incident on the platform gets labelled
        # PROVENANCE_UNKNOWN — which is what actually happened.
        "source_kind": source_kind,
        "sensor_version": sensor_version,
        "trust_state": "AUTHENTICATED",
    }
    # The genuine NivX receipt time — the moment the raw row was written by
    # the authenticated ingest handler. Passed in by the caller; never
    # approximated here.
    if nivx_received_at:
        pts.put(canonical, "nivx_received_at",
                pts.stamp(nivx_received_at,
                          source="edr_raw_events.ingest_time"))
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
    # N2.1 · the endpoint's OWN address, as observed on its own
    # authenticated evidence. Recorded as a time-bounded observation, never
    # as an identity — see `endpoint_address_observation`.
    if canonical.get("additional_fields", {}).get("activity_type") \
            == "NETWORK":
        from edr_plane import endpoint_address_observation as eao
        await eao.record_from_canonical(
            db, tenant_id=tenant_id, endpoint_id=endpoint_id,
            canonical=canonical)

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

    # P0-F · the endpoint plane now CONSUMES the authoritative XDR
    # detection fabric. It does not evaluate anything itself: the event is
    # handed to the SAME process_event_through_pipeline that every other
    # source uses, so detection, IUE, ICE, VEEE and incident promotion are
    # unchanged and unduplicated. A fault here is recorded as its own
    # derivation and must never destroy the honest record that canonical
    # evidence was created.
    detection: dict[str, Any] = {"evaluated": False,
                                 "reason": "not attempted"}
    try:
        from detection_content.xdr_pipeline import (
            process_event_through_pipeline)
        sensor_event = json.loads(payload)
        sensor_event.setdefault("collection_method", "PROC_POLL")
        # The authenticated endpoint identity and the hostname the sensor
        # itself reported. Passed explicitly so the fabric can scope and
        # NAME the incident from real evidence instead of UNKNOWN.
        sensor_event["endpoint_id"] = endpoint_id
        sensor_event["hostname"] = hostname
        # Only the AUTHENTICATED ingest path can attach this. The DSM
        # stamps sensor provenance from it and from nothing else, so an
        # unauthenticated pipeline call cannot manufacture a
        # REAL_SENSOR_DERIVED label.
        sensor_event["_authenticated_ingest"] = {
            "source_kind": source_kind, "sensor_version": sensor_version,
            "trust_state": "AUTHENTICATED", "raw_id": raw_id,
            "authenticated_endpoint_id": (authentication or {}).get(
                "authenticated_endpoint_id"),
            # D1 · the real NivX receipt time travels with the authenticated
            # envelope, because the pipeline re-parses the payload and would
            # otherwise have no way to know it.
            "nivx_received_at": nivx_received_at,
        }
        result = await process_event_through_pipeline(
            db, sensor_event, trace_id=raw_id,
            integration_id=PARSER_NAME, collector_id=endpoint_id,
            tenant_id=tenant_id)
        det = (result.get("detection") or {})
        matches = det.get("detections") or []
        verdict = (result.get("verdict") or {})
        detection = {
            "evaluated": True,
            "blocker": result.get("blocker"),
            "status": det.get("status"),
            "engine_id": det.get("engine_id"),
            "matched": bool(det.get("matched")),
            "rule_ids": [m.get("rule_id") for m in matches],
            "rules": matches,
            "verdict": verdict.get("label"),
            "verdict_score": verdict.get("score"),
            "incident_id": (result.get("incident") or {}).get("incident_id"),
            "stages": [s.get("stage") for s in (result.get("stages") or ())],
        }
        await add_derivation(
            db, tenant_id=tenant_id, raw_id=raw_id,
            derivation=Derivation(
                replay_generation=gen,
                derived_at=datetime.now(timezone.utc).isoformat(),
                parser_name=PARSER_NAME, parser_version=PARSER_VERSION,
                parser_state="OK",
                detection_content_version=det.get("engine_id"),
                verdict_version=verdict.get("label"),
                event_id=canonical["event_id"],
                evidence_ids=[i for i in
                              [detection.get("incident_id")] if i],
                outcome=("DETECTION_MATCHED" if detection["matched"]
                         else "DETECTION_EVALUATED_NO_MATCH"),
                reason=("rules: " + ", ".join(
                    r for r in detection["rule_ids"] if r))
                if detection["matched"] else None))
        # P0-C · the detection outcome is now made DURABLE as an EDR
        # finding plus a recorded evaluation state. It projects what the
        # XDR pipeline just produced and says so; it invents nothing and
        # it cannot fail the ingest.
        from edr_plane.findings_intake import record_endpoint_detection
        detection["finding_plane"] = await record_endpoint_detection(
            db, tenant_id=tenant_id, endpoint_ref=endpoint_id,
            canonical_event_id=canonical["event_id"], raw_ref=raw_id,
            payload=payload, observed_at=canonical.get("event_time"),
            derivation={
                "outcome": ("DETECTION_MATCHED" if detection["matched"]
                            else "DETECTION_EVALUATED_NO_MATCH"),
                "event_id": canonical["event_id"],
                "reason": ("rules: " + ", ".join(
                    r for r in detection["rule_ids"] if r))
                if detection["matched"] else None,
                "detection_content_version": det.get("engine_id"),
                "verdict_version": verdict.get("label"),
                "derived_at": datetime.now(timezone.utc).isoformat()})
    except Exception as e:  # noqa: BLE001
        detection = {"evaluated": False, "reason": str(e)[:300]}
        await add_derivation(
            db, tenant_id=tenant_id, raw_id=raw_id,
            derivation=Derivation(
                replay_generation=gen,
                derived_at=datetime.now(timezone.utc).isoformat(),
                parser_name=PARSER_NAME, parser_version=PARSER_VERSION,
                parser_state="OK", event_id=canonical["event_id"],
                outcome="DETECTION_NOT_EVALUATED",
                reason=("the detection fabric could not be reached for this "
                        "event; canonical evidence EXISTS and the raw bytes "
                        "are replayable — this is a detection gap, not an "
                        "absence of activity: " + str(e)[:200])))
        # P0-C · NOT_EVALUATED is recorded as its own fact. Without this
        # row the evidence would simply have no finding, which a console
        # could read as "evaluated and clean".
        from edr_plane.findings_intake import record_endpoint_detection
        detection["finding_plane"] = await record_endpoint_detection(
            db, tenant_id=tenant_id, endpoint_ref=endpoint_id,
            canonical_event_id=canonical["event_id"], raw_ref=raw_id,
            payload=payload, observed_at=canonical.get("event_time"),
            derivation={
                "outcome": "DETECTION_NOT_EVALUATED",
                "event_id": canonical["event_id"],
                "reason": ("the detection fabric could not be reached for "
                           "this event; the evidence EXISTS and is "
                           "replayable — this is a detection gap, not an "
                           "absence of activity: " + str(e)[:200]),
                "derived_at": datetime.now(timezone.utc).isoformat()})

    return {"canonicalized": True, "parser_state": "OK",
            "canonical_event_id": canonical["event_id"],
            "observation_id": obs_id,
            "activity_type": canonical["additional_fields"]["activity_type"],
            "detection": detection}
