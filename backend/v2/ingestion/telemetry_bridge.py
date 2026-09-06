"""v2/ingestion/telemetry_bridge.py · P1.10 live-telemetry bridge.

Turns ONE canonical telemetry event — as produced authoritatively by
`detection_content.telemetry.cef_leef_dsm` inside
`process_event_through_pipeline` — into a CES record and then into the
CEM v1 observation shape that `v2_shadow_observations` already stores.

Boundaries:
  * No parsing here.  Parsing is the DSM's job.
  * No scoring, no correlation, no verdict.  Those are IUE / ICE / VEEE.
  * No case is invented.  A live observation carries `case_id=None`
    until — and only if — the VEEE gate promotes a real incident, at
    which point `link_observations_to_incident` back-fills the link.

Every document written here is tagged `origin="collector-live"` so live
telemetry is never confused with the golden corpus.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .canonical import CanonicalEventRecord, IngestionProvenance, ces_to_cem_dict
from v2.case_engine.schema import COLLECTIONS

LIVE_ORIGIN = "collector-live"


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def canonical_to_ces(canonical: dict[str, Any], *,
                     envelope: dict[str, Any]) -> CanonicalEventRecord:
    """Project the authoritative canonical telemetry event into CES."""
    host = canonical.get("host") or {}
    ident = canonical.get("identity") or {}
    proc = canonical.get("process") or {}
    net = canonical.get("network") or {}
    fil = canonical.get("file") or {}
    extra = canonical.get("additional_fields") or {}
    hashes = proc.get("hashes") or fil.get("hashes") or {}

    prov = IngestionProvenance(
        origin=LIVE_ORIGIN,
        format=_s(extra.get("payload_format")),
        source=_s(canonical.get("source_product")) or _s(canonical.get("source_vendor")),
        filename="",
        ingest_job_id=_s((canonical.get("provenance") or {}).get("trace_id")),
        ingested_at=_s(canonical.get("ingest_time")) or datetime.now(timezone.utc).isoformat(),
        normalizer=_s((canonical.get("provenance") or {}).get("normalizer_id")),
    )

    return CanonicalEventRecord(
        timestamp=_s(canonical.get("event_time")),
        provider=" ".join(p for p in (_s(canonical.get("source_vendor")),
                                      _s(canonical.get("source_product"))) if p),
        event_id=None,
        channel=_s(extra.get("payload_format")).upper(),
        computer=_s(host.get("hostname")) or _s(host.get("host_id")),
        user=_s(ident.get("username")),
        process_id=_s(proc.get("pid")),
        image=_s(proc.get("executable_path")) or _s(proc.get("name")),
        command_line=_s(proc.get("command_line")),
        file_path=_s(fil.get("path")),
        file_hash_md5=_s(hashes.get("md5")),
        file_hash_sha1=_s(hashes.get("sha1")),
        file_hash_sha256=_s(hashes.get("sha256")),
        src_ip=_s(net.get("src_ip")),
        src_port=_s(net.get("src_port")),
        dst_ip=_s(net.get("dest_ip")),
        dst_port=_s(net.get("dest_port")),
        protocol=_s(net.get("protocol")),
        dns_query=_s(net.get("dns_query")),
        raw_event={"canonical_event_id": canonical.get("event_id"),
                   "raw_ref": canonical.get("raw_ref") or {},
                   "envelope": {k: envelope.get(k) for k in
                                ("source", "connector_id", "collector_id",
                                 "collection_method", "parser_version",
                                 "source_event_id", "collection_timestamp")}},
        provenance=prov,
    )


def observation_doc(canonical: dict[str, Any], *, envelope: dict[str, Any],
                    tenant_id: str, sequence: int = 0) -> dict[str, Any]:
    """The `v2_shadow_observations` document for one live event."""
    ces = canonical_to_ces(canonical, envelope=envelope)
    ev = ces_to_cem_dict(ces, case_id=None, sequence=sequence)
    extra = canonical.get("additional_fields") or {}
    return {
        "adapter": ev["adapter"],
        "cem_version": "v1",
        # No case is fabricated — set only when an incident is promoted.
        "case_id": None,
        "tenant_id": tenant_id,
        "captured_at": ev["ts"],
        "kind": ev["kind"],
        "process_iid": ev.get("process_iid"),
        "artefacts_iids": list(ev.get("artefacts_iids") or ()),
        "input_sha256": (ev.get("raw") or {}).get("sha256"),
        "event": ev,
        "origin": LIVE_ORIGIN,
        "canonical_event_id": canonical.get("event_id"),
        "collector_id": envelope.get("collector_id"),
        "connector_id": envelope.get("connector_id"),
        "epistemic_state": extra.get("epistemic_state") or {},
        "ingest_job_id": (canonical.get("provenance") or {}).get("trace_id"),
    }


async def persist_live_observation(db: Any, canonical: dict[str, Any], *,
                                   envelope: dict[str, Any],
                                   tenant_id: str,
                                   sequence: int = 0) -> str | None:
    doc = observation_doc(canonical, envelope=envelope,
                          tenant_id=tenant_id, sequence=sequence)
    res = await db[COLLECTIONS["shadow_observations"]].insert_one(doc)
    return str(res.inserted_id) if res.inserted_id else None


async def link_observations_to_incident(db: Any, *, trace_id: str,
                                        incident_id: str) -> int:
    """Back-fill the incident link on the observations that produced it.

    Called ONLY after the VEEE gate actually materialised an incident.
    """
    res = await db[COLLECTIONS["shadow_observations"]].update_many(
        {"ingest_job_id": trace_id, "origin": LIVE_ORIGIN},
        {"$set": {"case_id": incident_id,
                  "promoted_incident_id": incident_id,
                  "promoted_at": datetime.now(timezone.utc).isoformat()}},
    )
    return int(res.modified_count or 0)
