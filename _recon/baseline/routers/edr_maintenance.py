"""Temporary, token-gated EDR development reset.

A faithful port of `SECURE_EXPORT/win-recovery-handoff/edr_dev_reset.mongosh.js`
— same selectors, same classification, same leaf→root order, same guards. It
exists only because neither the owner's laptop nor the preview pod can reach
the managed Atlas cluster, while this backend already holds a working
connection.

NOT a public destructive API:
  * the route 404s unless EDR_MAINTENANCE_TOKEN is set in the environment
  * every call must present that token in X-Maintenance-Token
  * `mode="dry"` is the default and writes nothing
  * `mode="execute"` additionally requires confirm="DELETE-EDR-DEV-DATA" and a
    non-empty backup reference (the owner's waiver string counts, and is
    echoed into the response so the decision is auditable)
Delete the env var to disable the route again.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from deps import db as _db

router = APIRouter(prefix="/edr/maintenance", tags=["edr-maintenance"])

TENANT = "ten_e759b7288598bd882e3dcac49d"
RAW = "edr_raw_events"

EDR_TELEMETRY = [
    "edr_processing_queue", "edr_rejected_telemetry", "edr_acquisition_gaps",
    "edr_acquisition_integrity", "edr_delivery_counters", "edr_findings",
    "edr_finding_evaluations", "edr_compromise_events",
    "edr_endpoint_address_observations", "edr_response_commands",
    "edr_policy_endpoint_state", "edr_endpoint_exclusion_enforcement",
]
EDR_IDENTITY = [
    "edr_endpoints", "edr_agent_credentials", "edr_agent_sessions",
    "edr_enrollment_tokens",
]
EDR_CONFIG = [
    "edr_policies", "edr_groups", "edr_policy_versions", "edr_exclusions",
    "edr_exclusion_sets", "edr_isolation_policy", "edr_tenant_boundary",
    "edr_connector_deployments", "edr_saved_views",
]
EDR_AUDIT = ["edr_enrollment_audit", "edr_policy_audit"]
DEPENDENTS = [
    ("xdr_investigation_activity", "incident_id"),
    ("xdr_investigations", "incident_id"),
    ("xdr_investigation_findings", "incident_id"),
    ("xdr_iue_understanding", "incident_id"),
    ("xdr_framework_mappings", "incident_id"),
    ("xdr_response_timeline", "incident_id"),
    ("xdr_intelligence_overlays", "incident_id"),
    ("xdr_intelligence_overlay_audit", "incident_id"),
]
REF_FIELDS = ["incident_id", "case_id", "id", "parent_incident_id",
              "promoted_incident_id", "incident_ids"]
CHUNK_THRESHOLD = 200_000
CHUNK_SIZE = 50_000


class ResetRequest(BaseModel):
    mode: str = Field("dry", pattern="^(dry|execute)$")
    confirm: str = ""
    backup: str = ""


def _guard(token: str | None) -> None:
    expected = os.environ.get("EDR_MAINTENANCE_TOKEN")
    if not expected:
        raise HTTPException(status_code=404, detail="Not Found")
    if token != expected:
        raise HTTPException(status_code=403, detail="maintenance token invalid")


async def _names() -> set[str]:
    return set(await _db.list_collection_names())


async def _count(have: set[str], coll: str, flt: dict) -> int:
    return await _db[coll].count_documents(flt) if coll in have else 0


async def _classify(have: set[str], eps: list[str]) -> dict[str, Any]:
    """EDR-ONLY / MIXED / UNKNOWN, then entanglement propagation."""
    edr_only, mixed, unknown = [], [], []
    if "workspace_cases" in have and eps:
        cursor = _db.workspace_cases.find(
            {"tenant_id": TENANT, "doc_type": "xdr_incident"},
            {"id": 1, "incident_number": 1, "title": 1,
             "xdr_pipeline.canonical_event_id": 1,
             "xdr_pipeline.source_provenance.collector_id": 1,
             "endpoint_campaign.endpoint_id": 1,
             "endpoint_campaign.detections.canonical_event_id": 1})
        async for inc in cursor:
            pipe = inc.get("xdr_pipeline") or {}
            prov = pipe.get("source_provenance") or {}
            camp = inc.get("endpoint_campaign") or {}
            if not (camp.get("endpoint_id") in eps or prov.get("collector_id") in eps):
                continue
            cids = [pipe.get("canonical_event_id")] + [
                (d or {}).get("canonical_event_id") for d in camp.get("detections") or []]
            cids = [c for c in cids if c]
            foreign = unresolved = 0
            for cid in cids:
                row = await _db.xdr_canonical_evidence.find_one(
                    {"tenant_id": TENANT, "event_id": cid},
                    {"provenance.collector_id": 1,
                     "additional_fields.endpoint_id": 1, "host.host_id": 1})
                if not row:
                    unresolved += 1
                    continue
                refs = {(row.get("provenance") or {}).get("collector_id"),
                        (row.get("additional_fields") or {}).get("endpoint_id"),
                        (row.get("host") or {}).get("host_id")}
                if not refs & set(eps):
                    foreign += 1
            entry = {"id": inc.get("id"), "incident_number": inc.get("incident_number"),
                     "title": inc.get("title"), "cited": len(cids),
                     "foreign": foreign, "unresolved": unresolved}
            (mixed if foreign else unknown if unresolved else edr_only).append(entry)

    del_ids = [i["id"] for i in edr_only if i.get("id")]
    keep_ids = [i["id"] for i in mixed + unknown if i.get("id")]
    entangled: list[str] = []
    if del_ids and keep_ids:
        for _ in range(10):
            promote: set[str] = set()
            for coll, field in DEPENDENTS:
                if coll not in have:
                    continue
                cursor = _db[coll].find(
                    {field: {"$in": del_ids},
                     "$or": [{g: {"$in": keep_ids}} for g in REF_FIELDS]},
                    {g: 1 for g in REF_FIELDS})
                async for doc in cursor:
                    if doc.get(field) in del_ids:
                        promote.add(doc[field])
            if not promote:
                break
            for pid in promote:
                entangled.append(pid)
                keep_ids.append(pid)
                del_ids = [x for x in del_ids if x != pid]
    return {"edr_only": edr_only, "mixed": mixed, "unknown": unknown,
            "entangled": entangled, "del_ids": del_ids, "keep_ids": keep_ids}


async def _pins(have: set[str], eps: list[str], keep_ids: list[str],
                ev_or: list[dict], obs_or: list[dict]) -> tuple[list[str], list[str]]:
    keep_cev: list[str] = []
    if keep_ids and "workspace_cases" in have:
        cursor = _db.workspace_cases.find(
            {"tenant_id": TENANT, "id": {"$in": keep_ids}},
            {"xdr_pipeline.canonical_event_id": 1,
             "endpoint_campaign.detections.canonical_event_id": 1})
        async for inc in cursor:
            camp = inc.get("endpoint_campaign") or {}
            for cid in [(inc.get("xdr_pipeline") or {}).get("canonical_event_id")] + [
                    (d or {}).get("canonical_event_id") for d in camp.get("detections") or []]:
                if cid and cid not in keep_cev:
                    keep_cev.append(cid)

    keep_raw: list[str] = []
    if "xdr_canonical_evidence" in have:
        for r in await _db.xdr_canonical_evidence.distinct(
                "provenance.trace_id",
                {"tenant_id": TENANT,
                 "$or": [{"event_id": {"$in": keep_cev}}, {"$nor": [{"$or": ev_or}]}]}):
            if r and r not in keep_raw:
                keep_raw.append(r)
    if "v2_shadow_observations" in have:
        for r in await _db.v2_shadow_observations.distinct(
                "event.raw.raw_evidence_ref.raw_id",
                {"tenant_id": TENANT,
                 "$or": [{"canonical_event_id": {"$in": keep_cev}},
                         {"$nor": [{"$or": obs_or}]}]}):
            if r and r not in keep_raw:
                keep_raw.append(r)
    return keep_cev, keep_raw


async def _wipe(coll: str, flt: dict) -> int:
    """Chunked above CHUNK_THRESHOLD so a multi-million sweep cannot stall."""
    total = await _db[coll].count_documents(flt)
    if not total:
        return 0
    if total <= CHUNK_THRESHOLD:
        return (await _db[coll].delete_many(flt)).deleted_count
    gone = 0
    while True:
        ids = [d["_id"] async for d in
               _db[coll].find(flt, {"_id": 1}).limit(CHUNK_SIZE)]
        if not ids:
            return gone
        gone += (await _db[coll].delete_many({"_id": {"$in": ids}})).deleted_count


@router.post("/dev-reset")
async def dev_reset(body: ResetRequest,
                    x_maintenance_token: str | None = Header(default=None)):
    _guard(x_maintenance_token)
    armed = (body.mode == "execute" and body.confirm == "DELETE-EDR-DEV-DATA"
             and bool(body.backup.strip()))
    if body.mode == "execute" and not armed:
        raise HTTPException(
            status_code=400,
            detail='execute requires confirm="DELETE-EDR-DEV-DATA" and a '
                   'non-empty backup reference')

    have = await _names()
    eps_docs = [d async for d in _db.edr_endpoints.find(
        {"tenant_id": TENANT},
        {"endpoint_id": 1, "hostname": 1, "enrollment_state": 1,
         "event_count": 1, "_id": 0})] if "edr_endpoints" in have else []
    eps = [d["endpoint_id"] for d in eps_docs if d.get("endpoint_id")]

    ev_or = [{"provenance.collector_id": {"$in": eps}},
             {"additional_fields.endpoint_id": {"$in": eps}},
             {"host.host_id": {"$in": eps}}]
    obs_or = [{"collector_id": {"$in": eps}}, {"connector_id": {"$in": eps}},
              {"event.raw.raw_evidence_ref.collection": RAW}]

    cls = await _classify(have, eps)
    keep_cev, keep_raw = await _pins(have, eps, cls["keep_ids"], ev_or, obs_or)

    evidence_filter: dict[str, Any] = {"tenant_id": TENANT, "$or": ev_or}
    obs_filter: dict[str, Any] = {"tenant_id": TENANT, "$or": obs_or}
    if keep_cev:
        evidence_filter = {"$and": [evidence_filter,
                                    {"event_id": {"$nin": keep_cev}}]}
        obs_filter = {"$and": [obs_filter,
                               {"canonical_event_id": {"$nin": keep_cev}}]}
    raw_filter: dict[str, Any] = ({"tenant_id": TENANT, "raw_id": {"$nin": keep_raw}}
                                  if keep_raw else {"tenant_id": TENANT})

    evidence_keyed = [
        ("xdr_detection_matches",
         {"tenant_id": TENANT, "source": "sensor",
          "canonical_event_id": {"$nin": keep_cev}}),
        ("xdr_spread_sightings",
         {"tenant_id": TENANT, "collector_id": {"$in": eps},
          "canonical_event_id": {"$nin": keep_cev}}),
        ("xdr_correlation_matches",
         {"$and": [{"tenant_id": TENANT},
                   {"trace_id": {"$regex": "^raw_[0-9a-f]{24}$"}},
                   {"trace_id": {"$nin": keep_raw}}]}),
    ]

    plan: list[dict[str, Any]] = []
    foreign_tenant = 0

    async def dep_filter(field: str) -> dict:
        flt: dict[str, Any] = {
            field: {"$in": cls["del_ids"]},
            "$and": [{"$or": [{"tenant_id": TENANT},
                              {"tenant_id": {"$exists": False}}]}]}
        if cls["keep_ids"]:
            flt["$and"].append(
                {"$nor": [{g: {"$in": cls["keep_ids"]}} for g in REF_FIELDS]})
        return flt

    for coll, field in DEPENDENTS:
        if coll not in have:
            plan.append({"collection": coll, "count": 0, "state": "absent"})
            continue
        in_scope = await _db[coll].count_documents(await dep_filter(field)) \
            if cls["del_ids"] else 0
        wrong = await _db[coll].count_documents(
            {field: {"$in": cls["del_ids"]},
             "tenant_id": {"$exists": True, "$ne": TENANT}}) if cls["del_ids"] else 0
        foreign_tenant += wrong
        plan.append({"collection": f"{coll}.{field}", "count": in_scope,
                     "foreign_tenant": wrong, "stage": "dependents"})

    plan.append({"collection": "workspace_cases",
                 "count": await _count(have, "workspace_cases",
                                       {"tenant_id": TENANT,
                                        "id": {"$in": cls["del_ids"]}}),
                 "stage": "edr-only incidents"})
    for coll, flt in evidence_keyed:
        plan.append({"collection": coll, "count": await _count(have, coll, flt),
                     "stage": "evidence-keyed",
                     "state": "absent" if coll not in have else "present"})
    plan.append({"collection": "v2_shadow_observations",
                 "count": await _count(have, "v2_shadow_observations", obs_filter),
                 "stage": "observations"})
    plan.append({"collection": "xdr_canonical_evidence",
                 "count": await _count(have, "xdr_canonical_evidence", evidence_filter),
                 "stage": "evidence"})
    plan.append({"collection": RAW, "count": await _count(have, RAW, raw_filter),
                 "stage": "telemetry"})
    for coll in EDR_TELEMETRY:
        plan.append({"collection": coll,
                     "count": await _count(have, coll, {"tenant_id": TENANT}),
                     "stage": "telemetry",
                     "state": "absent" if coll not in have else "present"})
    for coll in EDR_IDENTITY:
        plan.append({"collection": coll,
                     "count": await _count(have, coll, {"tenant_id": TENANT}),
                     "stage": "identity",
                     "state": "absent" if coll not in have else "present"})

    retained = {c: await _count(have, c, {"tenant_id": TENANT})
                for c in EDR_CONFIG + EDR_AUDIT}
    protected = {
        "xdr_canonical_evidence_tenant_total":
            await _count(have, "xdr_canonical_evidence", {"tenant_id": TENANT}),
        "xdr_canonical_evidence_all_tenants":
            await _count(have, "xdr_canonical_evidence", {}),
        "v2_shadow_observations_tenant_total":
            await _count(have, "v2_shadow_observations", {"tenant_id": TENANT}),
        "v2_shadow_observations_all_tenants":
            await _count(have, "v2_shadow_observations", {}),
        "workspace_cases_all_tenants":
            await _count(have, "workspace_cases", {}),
        "edr_rejected_telemetry_all_tenants":
            await _count(have, "edr_rejected_telemetry", {}),
        "edr_finding_evaluations_all_tenants":
            await _count(have, "edr_finding_evaluations", {}),
    }

    planned_total = sum(p["count"] for p in plan)
    result: dict[str, Any] = {
        "mode": body.mode,
        "armed": armed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "database": os.environ.get("DB_NAME"),
        "tenant": TENANT,
        "endpoints": eps_docs,
        "classification": {
            "edr_only": len(cls["edr_only"]), "mixed": len(cls["mixed"]),
            "unknown": len(cls["unknown"]), "entangled": len(cls["entangled"]),
            "mixed_ids": [i["id"] for i in cls["mixed"]][:50],
            "unknown_ids": [i["id"] for i in cls["unknown"]][:50],
        },
        "pinned": {"canonical_events": len(keep_cev), "raw_events": len(keep_raw),
                   "raw_ids": keep_raw[:20]},
        "plan": plan,
        "planned_total": planned_total,
        "retained": retained,
        "protected": protected,
        "guards": {"keep_config": True, "keep_audit": True, "cascade_xdr": True,
                   "foreign_tenant_dependents": foreign_tenant},
    }

    if not armed:
        result["note"] = "DRY RUN — nothing was changed."
        return result
    if foreign_tenant:
        raise HTTPException(
            status_code=409,
            detail="S2: a dependent of an EDR-ONLY incident carries another "
                   "tenant's id; resolve before deletion")

    deleted: dict[str, int] = {}
    if cls["del_ids"]:
        for coll, field in DEPENDENTS:
            if coll in have:
                deleted[f"{coll}.{field}"] = await _wipe(coll, await dep_filter(field))
        if "workspace_cases" in have:
            deleted["workspace_cases"] = await _wipe(
                "workspace_cases",
                {"tenant_id": TENANT, "id": {"$in": cls["del_ids"]}})
    for coll, flt in evidence_keyed:
        if coll in have:
            deleted[coll] = await _wipe(coll, flt)
    if "v2_shadow_observations" in have:
        deleted["v2_shadow_observations"] = await _wipe(
            "v2_shadow_observations", obs_filter)
    if "xdr_canonical_evidence" in have:
        deleted["xdr_canonical_evidence"] = await _wipe(
            "xdr_canonical_evidence", evidence_filter)
    if RAW in have:
        deleted[RAW] = await _wipe(RAW, raw_filter)
    for coll in EDR_TELEMETRY + EDR_IDENTITY:
        if coll in have:
            deleted[coll] = await _wipe(coll, {"tenant_id": TENANT})

    verification = {c: await _count(have, c, {"tenant_id": TENANT})
                    for c in [RAW] + EDR_TELEMETRY + EDR_IDENTITY}
    verification["xdr_canonical_evidence_edr_derived"] = await _count(
        have, "xdr_canonical_evidence", evidence_filter)
    verification["v2_shadow_observations_edr_derived"] = await _count(
        have, "v2_shadow_observations", obs_filter)
    dangling = 0
    for coll, field in DEPENDENTS:
        dangling += await _count(have, coll, {field: {"$in": cls["del_ids"]}})
    verification["dangling_dependents"] = dangling

    result.update({
        "backup_reference": body.backup.strip(),
        "deleted": deleted,
        "deleted_total": sum(deleted.values()),
        "verification": verification,
        "retained_after": {c: await _count(have, c, {"tenant_id": TENANT})
                           for c in EDR_CONFIG + EDR_AUDIT},
        "protected_after": {
            "workspace_cases_all_tenants":
                await _count(have, "workspace_cases", {}),
            "xdr_canonical_evidence_all_tenants":
                await _count(have, "xdr_canonical_evidence", {}),
            "preserved_incidents_present":
                await _count(have, "workspace_cases",
                             {"id": {"$in": cls["keep_ids"]}}),
        },
        "note": "No collection was dropped — indexes and validators intact.",
    })
    return result
