"""Lane H · the authoritative, SOURCE-AGNOSTIC event search contract.

Windows is the first population, not the architectural boundary. Every
query and every row below is expressed in canonical vocabulary, so Zeek,
auditd, M365, CloudTrail, CEF/LEEF, firewall, DNS, proxy, VPN, EDR,
identity and application sources appear in the same table the moment their
DSM produces canonical evidence. There is no Windows-specific schema here
to replace later.

The search reads `xdr_canonical_evidence` — the one collection every DSM
writes to. It never reads a frontend fixture, and it never fabricates a
row: an empty result is an empty result.

THE TRANSFORMATION CHAIN IS PRESERVED AND KEPT DISTINGUISHABLE

    Raw Event → Parsed Fields → Normalized Event → Canonical Evidence
              → Detection → Incident

Each stage is reported with its own state and its own evidence reference.
A stage that did not happen is `NOT_OBSERVED` with a reason — it is never
invented so the chain looks complete.
"""
from __future__ import annotations

from typing import Any

EVIDENCE_COLLECTION = "xdr_canonical_evidence"
RAW_COLLECTION = "xdr_canonical_events"
MATCH_COLLECTION = "xdr_detection_matches"
CASE_COLLECTION = "workspace_cases"

#: Free-text search reaches only fields a source actually populates.
_TEXT_FIELDS = (
    "host.hostname", "identity.principal_id", "identity.username",
    "process.name", "process.command_line", "process.executable_path",
    "event_type", "source_event_id", "source_product", "source_vendor",
    "network.dns_query", "network.dest_ip", "network.src_ip",
    "file.path", "registry.key_path",
    "additional_fields.script_block_text",
)

MAX_LIMIT = 500


def _regex(value: str) -> dict[str, Any]:
    import re as _re
    return {"$regex": _re.escape(value), "$options": "i"}


def build_query(*, tenant_id: str, q: str | None = None,
                host: str | None = None, channel: str | None = None,
                source: str | None = None, event_id: str | None = None,
                user: str | None = None, process: str | None = None,
                level: str | None = None, dsm_id: str | None = None,
                time_from: str | None = None, time_to: str | None = None,
                has_detection: bool | None = None,
                detection_event_ids: list[str] | None = None,
                ) -> dict[str, Any]:
    """One canonical filter, expressed in canonical field names only."""
    query: dict[str, Any] = {"tenant_id": tenant_id}
    if host:
        query["host.hostname"] = _regex(host)
    if channel:
        query["raw_ref.channel"] = channel
    if source:
        query["$or"] = [{"source_product": _regex(source)},
                        {"source_vendor": _regex(source)},
                        {"provenance.routing.declared_source_resolved":
                         _regex(source)}]
    if event_id:
        query["source_event_id"] = str(event_id)
    if user:
        query["$and"] = query.get("$and", []) + [{"$or": [
            {"identity.username": _regex(user)},
            {"identity.principal_id": _regex(user)}]}]
    if process:
        query["$and"] = query.get("$and", []) + [{"$or": [
            {"process.name": _regex(process)},
            {"process.command_line": _regex(process)},
            {"process.executable_path": _regex(process)}]}]
    if level:
        query["additional_fields.windows_level"] = str(level)
    if dsm_id:
        query["provenance.dsm_id"] = dsm_id
    if time_from or time_to:
        window: dict[str, Any] = {}
        if time_from:
            window["$gte"] = time_from
        if time_to:
            window["$lte"] = time_to
        query["event_time"] = window
    if q:
        query["$and"] = query.get("$and", []) + [
            {"$or": [{f: _regex(q)} for f in _TEXT_FIELDS]}]
    if has_detection is True:
        query["event_id"] = {"$in": detection_event_ids or []}
    elif has_detection is False and detection_event_ids is not None:
        query["event_id"] = {"$nin": detection_event_ids}
    return query


def _activity_label(doc: dict[str, Any]) -> str:
    """The canonical event type, in the source's own vocabulary.

    Not a friendly rewrite: a renamed activity is a different claim, and
    an analyst pivoting on `process_creation` must see the same token the
    rule and the evidence use.
    """
    return str(doc.get("event_type") or "")


def project_row(doc: dict[str, Any],
                detections: dict[str, dict[str, Any]] | None = None
                ) -> dict[str, Any]:
    """One analyst table row. Absent facts stay absent (None), never 0."""
    host = doc.get("host") or {}
    identity = doc.get("identity") or {}
    process = doc.get("process") or {}
    add = doc.get("additional_fields") or {}
    prov = doc.get("provenance") or {}
    raw_ref = doc.get("raw_ref") or {}
    det = (detections or {}).get(doc.get("event_id"))

    return {
        "event_id": doc.get("event_id"),
        "time": doc.get("event_time"),
        "time_basis": add.get("event_time_basis"),
        "time_source": add.get("event_time_source"),
        "time_substituted": add.get("event_time_substituted"),
        "host": host.get("hostname") or None,
        "os_family": host.get("os_family") or None,
        # `channel` is the Windows vocabulary; `source` is the universal
        # one. Both are shown so a multi-source estate reads naturally.
        "channel": raw_ref.get("channel") or None,
        "source_product": doc.get("source_product") or None,
        "source_vendor": doc.get("source_vendor") or None,
        "provider": (raw_ref.get("provider") or add.get("provider")
                     or doc.get("source_product") or None),
        "source_event_id": doc.get("source_event_id") or None,
        "event_type": _activity_label(doc),
        "user": (identity.get("principal_id") or identity.get("username")
                 or None),
        "user_sid": identity.get("user_sid") or None,
        "process": process.get("name") or None,
        "process_command_line": process.get("command_line") or None,
        "process_attribution": process.get("attribution_state") or None,
        "level": add.get("windows_level"),
        "dsm_id": prov.get("dsm_id") or None,
        "declared_source": (prov.get("routing") or {}).get(
            "declared_source_resolved"),
        "detection": ({"state": "MATCHED",
                       "count": det["count"],
                       "rules": det["rules"][:5]} if det else
                      {"state": "NO_MATCH", "count": 0, "rules": []}),
        "evidence_ref": f"{EVIDENCE_COLLECTION}/{doc.get('event_id')}",
        "has_raw": bool(raw_ref.get("xml") or raw_ref.get("evtx_xml")
                        or raw_ref),
    }


async def _detections_for(db, tenant_id: str, event_ids: list[str]
                          ) -> dict[str, dict[str, Any]]:
    if not event_ids:
        return {}
    cursor = db[MATCH_COLLECTION].aggregate([
        {"$match": {"tenant_id": tenant_id,
                    "canonical_event_id": {"$in": event_ids}}},
        {"$group": {"_id": "$canonical_event_id",
                    "count": {"$sum": 1},
                    "rules": {"$addToSet": "$rule_name"}}},
    ])
    out: dict[str, dict[str, Any]] = {}
    async for row in cursor:
        out[row["_id"]] = {"count": row["count"],
                           "rules": sorted(r for r in row["rules"] if r)}
    return out


async def detection_event_ids(db, tenant_id: str) -> list[str]:
    ids = await db[MATCH_COLLECTION].distinct(
        "canonical_event_id", {"tenant_id": tenant_id})
    return [i for i in ids if i]


async def search(db, *, tenant_id: str, limit: int = 100, offset: int = 0,
                 **filters) -> dict[str, Any]:
    limit = max(1, min(int(limit), MAX_LIMIT))
    has_detection = filters.get("has_detection")
    det_ids = None
    if has_detection is not None:
        det_ids = await detection_event_ids(db, tenant_id)
    query = build_query(tenant_id=tenant_id, detection_event_ids=det_ids,
                        **filters)
    total = await db[EVIDENCE_COLLECTION].count_documents(query)
    cursor = (db[EVIDENCE_COLLECTION].find(query, {"_id": 0})
              .sort("event_time", -1).skip(max(0, int(offset))).limit(limit))
    docs = [d async for d in cursor]
    dets = await _detections_for(db, tenant_id,
                                 [d.get("event_id") for d in docs])
    return {
        "rows": [project_row(d, dets) for d in docs],
        "total": total,
        "limit": limit,
        "offset": offset,
        "query": query,
        "source_agnostic_note": (
            "this search reads canonical evidence, so every source with a "
            "DSM appears here under the same contract. Windows is the first "
            "population, not the schema boundary"),
    }


async def facets(db, tenant_id: str) -> dict[str, Any]:
    """The values an analyst can actually filter by — measured, not guessed."""
    async def distinct(field: str) -> list[str]:
        vals = await db[EVIDENCE_COLLECTION].distinct(
            field, {"tenant_id": tenant_id})
        return sorted(str(v) for v in vals if v not in (None, ""))[:200]

    return {
        "hosts": await distinct("host.hostname"),
        "channels": await distinct("raw_ref.channel"),
        "source_products": await distinct("source_product"),
        "event_types": await distinct("event_type"),
        "source_event_ids": await distinct("source_event_id"),
        "dsm_ids": await distinct("provenance.dsm_id"),
        "users": (await distinct("identity.username"))[:100],
        "levels": await distinct("additional_fields.windows_level"),
    }


async def _incident_for(db, event_id: str, trace_id: str | None
                        ) -> dict[str, Any] | None:
    clauses: list[dict[str, Any]] = [
        {"detections.canonical_event_id": event_id},
        {"evidence.canonical_event_id": event_id},
        {"evidence_rows.canonical_event_id": event_id},
    ]
    if trace_id:
        clauses.append({"trace_id": trace_id})
    doc = await db[CASE_COLLECTION].find_one({"$or": clauses}, {"_id": 0})
    return doc


def _stage(name: str, state: str, *, ref: str | None = None,
           reason: str | None = None, detail: Any = None) -> dict[str, Any]:
    return {"stage": name, "state": state, "evidence_ref": ref,
            "reason": reason, "detail": detail}


async def detail(db, *, tenant_id: str, event_id: str) -> dict[str, Any] | None:
    """One event, with every stage of its transformation kept distinct."""
    doc = await db[EVIDENCE_COLLECTION].find_one(
        {"tenant_id": tenant_id, "event_id": event_id}, {"_id": 0})
    if not doc:
        return None

    prov = doc.get("provenance") or {}
    raw_ref = doc.get("raw_ref") or {}
    trace_id = prov.get("trace_id")

    matches = [m async for m in db[MATCH_COLLECTION].find(
        {"tenant_id": tenant_id, "canonical_event_id": event_id},
        {"_id": 0})]

    # ── Raw. For a Windows delivery this is the rendered XML, which is
    # IMMUTABLE source evidence and is never rewritten.
    raw_xml = raw_ref.get("xml") or raw_ref.get("evtx_xml")
    parsed_fields = raw_ref.get("EventData") or raw_ref.get("UserData") or {}

    raw_row = None
    ingest_ref = (prov.get("ingest") or {}).get("raw_ref") or {}
    if isinstance(ingest_ref, dict) and ingest_ref.get("id"):
        try:
            from bson import ObjectId
            raw_row = await db[RAW_COLLECTION].find_one(
                {"_id": ObjectId(str(ingest_ref["id"]))}, {"_id": 0})
        except Exception:                                   # noqa: BLE001
            raw_row = None

    incident = await _incident_for(db, event_id, trace_id)

    stages = [
        _stage("Raw Event",
               "OBSERVED" if (raw_xml or raw_ref) else "NOT_OBSERVED",
               ref=(f"{RAW_COLLECTION}/{ingest_ref.get('id')}"
                    if ingest_ref.get("id") else None),
               reason=(None if (raw_xml or raw_ref) else
                       "this evidence carries no raw reference"),
               detail={"format": ("WINDOWS_EVENT_XML" if raw_xml
                                  else "SOURCE_DOCUMENT"),
                       "immutable": True}),
        _stage("Parsed Fields",
               "OBSERVED" if parsed_fields else "NOT_OBSERVED",
               reason=(None if parsed_fields else
                       "the source format carried no discrete field block "
                       "(EventData/UserData)"),
               detail={"field_count": len(parsed_fields) if parsed_fields
                       else None,
                       "parser_id": prov.get("parser_id")}),
        _stage("Normalized Event", "OBSERVED",
               detail={"normalizer_id": prov.get("normalizer_id")}),
        _stage("Canonical Evidence", "OBSERVED",
               ref=f"{EVIDENCE_COLLECTION}/{event_id}",
               detail={"dsm_id": prov.get("dsm_id"),
                       "event_type": doc.get("event_type")}),
        _stage("Detection",
               "MATCHED" if matches else "EVALUATED_NO_MATCH",
               detail={"matches": len(matches),
                       "rules": [m.get("rule_name") for m in matches]}),
        _stage("Incident",
               "MATERIALISED" if incident else "NOT_MATERIALISED",
               ref=(f"{CASE_COLLECTION}/{incident.get('id')}"
                    if incident and incident.get("id") else None),
               reason=(None if incident else
                       "no incident references this canonical event. The "
                       "gate refuses promotion below its verdict threshold, "
                       "and that refusal is not a failure")),
    ]

    identity = doc.get("identity") or {}
    process = doc.get("process") or {}
    host = doc.get("host") or {}
    relationships = {
        "host": host.get("hostname") or None,
        "user": identity.get("principal_id") or identity.get("username")
                or None,
        "process": process.get("name") or None,
        "process_guid": process.get("process_guid") or None,
        "pivots": [p for p in [
            ({"kind": "host", "value": host.get("hostname"),
              "query": {"host": host.get("hostname")}}
             if host.get("hostname") else None),
            ({"kind": "user", "value": identity.get("username"),
              "query": {"user": identity.get("username")}}
             if identity.get("username") else None),
            ({"kind": "process", "value": process.get("name"),
              "query": {"process": process.get("name")}}
             if process.get("name") else None),
            ({"kind": "channel", "value": raw_ref.get("channel"),
              "query": {"channel": raw_ref.get("channel")}}
             if raw_ref.get("channel") else None),
        ] if p],
    }

    return {
        "summary": project_row(doc, {event_id: {
            "count": len(matches),
            "rules": sorted({m.get("rule_name") for m in matches
                             if m.get("rule_name")})}} if matches else None),
        "fields": parsed_fields,
        "raw": {"xml": raw_xml, "document": raw_ref,
                "raw_row": raw_row,
                "immutability_note": ("the rendered source record is "
                                      "immutable evidence; nothing in this "
                                      "platform rewrites it")},
        "normalized": (raw_row or {}).get("normalized"),
        "canonical": doc,
        "relationships": relationships,
        "detection": {"matches": matches,
                      "state": "MATCHED" if matches
                               else "EVALUATED_NO_MATCH"},
        "provenance": prov,
        "chain": stages,
    }
