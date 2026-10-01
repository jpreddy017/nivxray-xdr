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

from .canonical import (CanonicalEventRecord, IngestionProvenance,
                        ces_to_cem_dict, event_id_int, observation_identity)
from v2.case_engine.schema import COLLECTIONS

LIVE_ORIGIN = "collector-live"


def _s(v: Any) -> str:
    return "" if v is None else str(v)


#: TWO canonical dialects reach `canonical_to_ces()`: the EDR sensor
#: bridge, which carries the Windows record under
#: `additional_fields.winlog`, and the XDR DSM plane, whose
#: `CanonicalTelemetryEvent` carries the SAME authoritative identifier as
#: `source_event_id` / `raw_ref.sysmon_event_id`. Reading only the first
#: dialect is what dropped the Event ID for every DSM-normalised Sysmon
#: record, which then had no source-stated meaning and fell through to the
#: classifier's catch-all.
_EVENT_ID_PATHS = (
    ("additional_fields", "winlog", "event_id"),
    ("raw_ref", "sysmon_event_id"),
    ("raw_ref", "windows_event_id"),
    ("raw_ref", "event_id"),
    ("raw_ref", "System", "EventID"),
    ("source_event_id",),
)


def _dig(canonical: dict[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = canonical
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def source_event_id(canonical: dict[str, Any]) -> tuple[int | None, str]:
    """`(event id, where it came from)` — the AUTHORITATIVE source Event ID.

    Returns `(None, reason)` when no dialect carried a usable identifier,
    so an absent or malformed Event ID stays absent instead of being
    invented.
    """
    for path in _EVENT_ID_PATHS:
        raw = _dig(canonical, path)
        if raw in (None, ""):
            continue
        eid = event_id_int(raw)
        if eid is not None:
            return eid, ".".join(path)
        return None, f"MALFORMED_AT:{'.'.join(path)}:{str(raw)[:40]}"
    return None, "NOT_CARRIED_BY_SOURCE"


#: A privileged Windows channel is written by exactly ONE provider, so the
#: channel identifies the provider when the record did not name it. Same
#: rule the sensor plane already uses (`edr_plane/windows_eventlog.py`).
_PRIVILEGED_CHANNEL_PROVIDER = {
    "security": "Microsoft-Windows-Security-Auditing",
    "microsoft-windows-sysmon/operational": "Microsoft-Windows-Sysmon",
}

#: Where a SOURCE-STATED provider name can be found, in order of
#: authority. `source_vendor`/`source_product` are deliberately NOT here:
#: they are a display label ("Windows Security Log"), and event meaning
#: must never be keyed off a display string.
_PROVIDER_PATHS = (
    ("additional_fields", "winlog", "provider"),
    ("raw_ref", "System", "Provider"),
    ("raw_ref", "provider"),
    ("raw_ref", "Provider"),
)

_CHANNEL_PATHS = (
    ("additional_fields", "winlog", "channel"),
    ("additional_fields", "channel"),
    ("raw_ref", "channel"),
    ("raw_ref", "System", "Channel"),
)


#: Account / group / privilege fields the Windows Security DSM already
#: extracts into `additional_fields`. They are the difference between "an
#: account was created" and "WHO created WHICH account", so they are
#: preserved verbatim rather than flattened away.
_ACCOUNT_CONTEXT_KEYS = (
    "target_user_name", "target_domain_name", "target_user_sid",
    "group_name", "group_domain", "group_sid",
    "member_name", "member_sid", "privilege_list",
)


def _account_context(ident: dict[str, Any],
                     extra: dict[str, Any]) -> dict[str, Any]:
    """The actor and the account acted upon. Absent stays absent."""
    out: dict[str, Any] = {}
    for key in _ACCOUNT_CONTEXT_KEYS:
        value = extra.get(key)
        if value not in (None, "", [], {}):
            out[key] = value
    if not out:
        return {}
    for key in ("principal_id", "username", "domain", "user_sid", "logon_id"):
        value = ident.get(key)
        if value not in (None, ""):
            out[f"actor_{key}"] = value
    return out


def source_provider(canonical: dict[str, Any]) -> tuple[str, str]:
    """`(provider, basis)` — the provider the SOURCE named, where it did.

    The DSM plane reports `source_product = "Windows Security Log"`, which
    is a product label and not the Windows provider. Keying Windows event
    semantics off that string would make security meaning depend on a
    display name, so the source-stated `System.Provider` is preferred, then
    the privileged channel that only one provider can write, and only then
    the vendor+product label every non-Windows producer has always used.
    """
    for path in _PROVIDER_PATHS:
        value = _s(_dig(canonical, path)).strip()
        if value:
            return value, "SOURCE_STATED_PROVIDER:" + ".".join(path)
    for path in _CHANNEL_PATHS:
        channel = _s(_dig(canonical, path)).strip().lower()
        provider = _PRIVILEGED_CHANNEL_PROVIDER.get(channel)
        if provider:
            return provider, "PRIVILEGED_CHANNEL:" + ".".join(path)
    label = " ".join(p for p in (_s(canonical.get("source_vendor")),
                                 _s(canonical.get("source_product"))) if p)
    return label, "VENDOR_PRODUCT_LABEL"


def canonical_to_ces(canonical: dict[str, Any], *,
                     envelope: dict[str, Any]) -> CanonicalEventRecord:
    """Project the authoritative canonical telemetry event into CES."""
    host = canonical.get("host") or {}
    ident = canonical.get("identity") or {}
    proc = canonical.get("process") or {}
    net = canonical.get("network") or {}
    fil = canonical.get("file") or {}
    extra = canonical.get("additional_fields") or {}
    # B3 · the two hash classes are read SEPARATELY. They used to be
    # collapsed (`proc.hashes or fil.hashes`), which meant a process-image
    # SHA-256 arrived downstream in the FILE hash fields — so "we know the
    # exe that ran" was indistinguishable from "we know the bytes that
    # were written". Those are different facts about different objects.
    proc_hashes = proc.get("hashes") or {}
    file_hashes = fil.get("hashes") or {}
    # Phase 0 · Windows evidence classes. Absent for every other producer,
    # so this projection is byte-identical for them.
    reg = canonical.get("registry") or {}
    dns = canonical.get("dns") or {}
    auth = canonical.get("authentication") or {}
    wl = extra.get("winlog") or {}
    raw_ref = canonical.get("raw_ref") or {}
    eid, eid_basis = source_event_id(canonical)
    provider, provider_basis = source_provider(canonical)
    channel = (_s(wl.get("channel")) or _s(extra.get("channel"))
               or _s(raw_ref.get("channel"))
               or _s(_dig(canonical, ("raw_ref", "System", "Channel")))
               or _s(extra.get("payload_format")).upper())
    record_id = wl.get("record_id")
    if record_id is None:
        record_id = (raw_ref.get("record_id")
                     or _dig(canonical, ("raw_ref", "System",
                                         "EventRecordID")))

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
        # A Windows record names its own provider, and `resolve_kind()`
        # already owns Sysmon / Win-Sec event-id semantics. Every other
        # producer keeps the vendor+product provider it always had.
        provider=provider,
        event_id=eid,
        channel=channel,
        computer=_s(host.get("hostname")) or _s(host.get("host_id")),
        user=_s(ident.get("username")),
        sid=(_s(ident.get("sid")) or _s(ident.get("user_sid"))
             or _s(auth.get("target_sid"))),
        logon_id=_s(ident.get("logon_id")),
        process_guid=_s(proc.get("process_guid")),
        process_id=_s(proc.get("pid")),
        parent_process_guid=_s(proc.get("parent_process_guid")),
        image=_s(proc.get("executable_path")) or _s(proc.get("name")),
        original_file_name=_s(proc.get("original_file_name")),
        command_line=_s(proc.get("command_line")),
        current_directory=_s(proc.get("current_directory")),
        integrity_level=_s(proc.get("integrity_level")),
        process_start_time=_s(proc.get("start_time")),
        process_attribution_state=_s(proc.get("attribution_state")),
        process_attribution_reason=_s(proc.get("attribution_reason")),
        process_hash_md5=_s(proc_hashes.get("md5")),
        process_hash_sha1=_s(proc_hashes.get("sha1")),
        process_hash_sha256=_s(proc_hashes.get("sha256")),
        # Real parent evidence only. A source that carries no parent field
        # (CEF/LEEF do not) leaves these empty, so no ancestry is invented.
        parent_process_id=_s(proc.get("parent_pid")
                             if proc.get("parent_pid") is not None
                             else proc.get("ppid")),
        parent_image=_s(proc.get("parent_executable_path"))
        or _s(proc.get("parent_name")),
        parent_command_line=_s(proc.get("parent_command_line")),
        file_path=_s(fil.get("path")),
        file_name=_s(fil.get("name")),
        file_action=_s(fil.get("action")) or _s(fil.get("operation"))
        or _s(extra.get("file_operation")),
        file_size=_s(fil.get("size_bytes") if fil.get("size_bytes")
                     is not None else fil.get("size")),
        file_hash_md5=_s(file_hashes.get("md5")),
        file_hash_sha1=_s(file_hashes.get("sha1")),
        file_hash_sha256=_s(file_hashes.get("sha256")),
        field_provenance={
            **{f"process.{k}": str(v) for k, v in
               (proc.get("field_provenance") or {}).items()},
            **{f"file.{k}": str(v) for k, v in
               (fil.get("field_provenance") or {}).items()},
            **{f"network.{k}": str(v) for k, v in
               (net.get("field_provenance") or {}).items()},
        },
        # The DSM dialect names the same registry evidence `key_path` /
        # `target_object`; the sensor dialect names it `key`. Reading only
        # one dialect left `registry_key` empty, so a registry observation
        # could not even be recognised as one.
        registry_key=(_s(reg.get("key")) or _s(reg.get("key_path"))
                      or _s(reg.get("target_object"))),
        registry_value=_s(reg.get("value_name")),
        registry_data=_s(reg.get("value_data")),
        src_ip=_s(net.get("src_ip")),
        src_port=_s(net.get("src_port")),
        dst_ip=_s(net.get("dest_ip")),
        dst_port=_s(net.get("dest_port")),
        protocol=_s(net.get("protocol")),
        dns_query=_s(net.get("dns_query")) or _s(dns.get("query_name")),
        dns_answer=", ".join(dns.get("answers") or ()) or "",
        logon_type=_s(auth.get("logon_type")),
        raw_event={"canonical_event_id": canonical.get("event_id"),
                   "raw_ref": canonical.get("raw_ref") or {},
                   # A REFERENCE to the retained source evidence — not a
                   # second copy of it. Both planes retain the original:
                   # the sensor path in `edr_raw_events`, the DSM path in
                   # `xdr_canonical_evidence`.
                   "raw_evidence_ref": {k: v for k, v in (
                       ("raw_id", raw_ref.get("raw_id")),
                       ("collection", raw_ref.get("collection")
                        or ("xdr_canonical_evidence"
                            if canonical.get("source_event_id") else None)),
                       ("canonical_event_id", canonical.get("event_id")),
                       ("record_id", record_id),
                   ) if v not in (None, "")},
                   # The AUTHORITATIVE source identity, preserved so the
                   # canonical projection stays traceable back to the exact
                   # source observation. Nothing here is invented: a value
                   # the source did not state is simply absent.
                   "source_identity": {k: v for k, v in (
                       ("provider", provider or None),
                       ("provider_basis", provider_basis),
                       ("channel", channel or None),
                       ("event_id", eid),
                       ("event_id_basis", eid_basis),
                       ("event_id_source_value",
                        _s(canonical.get("source_event_id"))
                        or _s(wl.get("event_id")) or None),
                       ("record_id", record_id),
                       ("computer", _s(host.get("hostname")) or None),
                       ("source_time", _s(canonical.get("event_time")) or None),
                   ) if v not in (None, "")},
                   # The Windows evidence blocks travel with the record so
                   # the investigation surfaces read source truth rather
                   # than a lossy flattening of it.
                   **({"registry": reg} if reg else {}),
                   **({"dns": dns} if dns else {}),
                   **({"authentication": auth} if auth else {}),
                   **({"winlog": wl} if wl else {}),
                   # An account / group / privilege observation is only
                   # investigable if the ACTOR and the account acted UPON
                   # both survive. A future behavioural engine decides
                   # whether such an observation is suspicious, and it can
                   # only do that from these fields.
                   **({"account_context": _account_context(ident, extra)}
                      if _account_context(ident, extra) else {}),
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
    obs_id, obs_state, obs_key = observation_identity(ev, tenant_id=tenant_id)
    return {
        "adapter": ev["adapter"],
        "cem_version": "v1",
        # No case is fabricated — set only when an incident is promoted.
        "case_id": None,
        "tenant_id": tenant_id,
        # WHICH recorded observation this is. `event.iid` keeps its own
        # meaning as the CONTENT identity and is not unique per record, so
        # anything that must point at ONE observation — a compromise's
        # `contributing_event_refs[]` above all — points here.
        "observation_id": obs_id,
        "observation_identity_state": obs_state,
        "observation_identity_key": obs_key,
        "captured_at": ev["ts"],
        "kind": ev["kind"],
        "process_iid": ev.get("process_iid"),
        # B1/B2 · the SOURCE's own process identity, at the top level so
        # process identity can be QUERIED rather than only read after the
        # fact. Absent when the source stated none — never derived.
        "process_guid": (ev.get("process") or {}).get("guid"),
        "parent_process_guid": (ev.get("process") or {}).get("parent_guid"),
        "artefacts_iids": list(ev.get("artefacts_iids") or ()),
        "input_sha256": (ev.get("raw") or {}).get("sha256"),
        "event": ev,
        "origin": LIVE_ORIGIN,
        "canonical_event_id": canonical.get("event_id"),
        "collector_id": envelope.get("collector_id"),
        "connector_id": envelope.get("connector_id"),
        "epistemic_state": extra.get("epistemic_state") or {},
        "lineage_state": extra.get("lineage_state"),
        # Identity of the ACTIVITY, not of the delivery — set by the source
        # that can compute it. It is what keeps a re-observation from
        # becoming a second piece of evidence.
        "activity_identity": extra.get("activity_identity"),
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
