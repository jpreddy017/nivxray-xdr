"""P1 · EVIDENCE NAMESPACE BRIDGE — the ONE deterministic identity join.

Owner contract (2026-06):

    raw observation          edr_raw_events.raw_id / xdr_canonical_events._id
      → CANONICAL EVIDENCE   xdr_canonical_evidence.event_id   ← AUTHORITATIVE
      → observation          v2_shadow_observations.canonical_event_id
                             (+ its own identity  event.iid = evt_*)
      → trajectory frame     frame_iid = tf_*  (+ canonical_evidence_id)
      → incident             xdr_pipeline.canonical_event_id,
                             endpoint_campaign.detections[].canonical_event_id

`canonical_evidence_id` is NOT a new namespace: it is
`xdr_canonical_evidence.event_id`, already minted by the normalizer/DSM and
already persisted on every live observation. `evt_*` (observation) and `tf_*`
(trajectory frame) keep their own identity — they are different objects and
are never forced to share one literal id.

THE JOIN IS DETERMINISTIC AND PERSISTED. Nothing here matches on labels,
process names, hostnames, hashes, timestamps, time proximity, array
positions, nearest events or frontend-supplied ids.

Access authority is the INCIDENT, never an id: callers resolve the incident
through `routers.incidents.authorized_incident` first, and the canonical set
is then read from what the incident ITSELF persists. A canonical id presented
by a client is never a lookup key here.

Bridge states (owner-approved, exactly three):
  * ``BRIDGED``                   deterministic reference + the canonical
                                  record resolves under the incident's own
                                  tenant authority.
  * ``REFERENCED_RECORD_ABSENT``  a deterministic reference exists, but the
                                  canonical record is not retained /
                                  resolvable under this incident's tenant
                                  authority. NOT "no evidence", NOT benign.
  * ``LEGACY_UNBRIDGED``          no canonical evidence identifier was ever
                                  persisted for that observation, so no
                                  deterministic bridge can be established
                                  now. No heuristic reconstruction.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

CANONICAL_COLLECTION = "xdr_canonical_evidence"
OBSERVATION_COLLECTION = "v2_shadow_observations"

BRIDGED = "BRIDGED"
REFERENCED_RECORD_ABSENT = "REFERENCED_RECORD_ABSENT"
LEGACY_UNBRIDGED = "LEGACY_UNBRIDGED"

CONTRACT = (
    "canonical_evidence_id is xdr_canonical_evidence.event_id, propagated "
    "from the identifier the ingest pipeline already persisted on the "
    "observation. The join is deterministic and persisted; no label, hash, "
    "timestamp, proximity or array-position matching is used. The incident "
    "is the access authority — a canonical id is never a lookup key."
)


def _raw_reference(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The canonical record's own pointer back to its raw source."""
    ref = row.get("raw_ref")
    if not ref:
        return None
    if isinstance(ref, dict) and (ref.get("raw_id") or ref.get("collection")):
        return {"kind": "POINTER", "collection": ref.get("collection"),
                "id": ref.get("raw_id")}
    return {"kind": "EMBEDDED_RAW", "collection": None, "id": None}


async def authoritative_references(db, incident: Dict[str, Any]) -> tuple[
        Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """Every canonical reference the INCIDENT itself persists.

    Returns ``(references, legacy_observations)`` where ``references`` maps
    canonical_evidence_id → the persisted places that cite it, and
    ``legacy_observations`` are the case's observations that carry no
    canonical identifier at all.
    """
    refs: Dict[str, List[Dict[str, Any]]] = {}
    legacy: List[Dict[str, Any]] = []

    def add(cid: Any, source: str, detail: Dict[str, Any]) -> None:
        if not cid:
            return
        refs.setdefault(str(cid), []).append({"source": source, **detail})

    pipe = incident.get("xdr_pipeline") or {}
    add(pipe.get("canonical_event_id"), "incident_pipeline",
        {"field": "xdr_pipeline.canonical_event_id"})

    for d in ((incident.get("endpoint_campaign") or {}).get("detections") or []):
        if isinstance(d, dict):
            add(d.get("canonical_event_id"), "endpoint_campaign",
                {"field": "endpoint_campaign.detections[].canonical_event_id",
                 "rule_id": d.get("rule_id")})

    cursor = db[OBSERVATION_COLLECTION].find(
        {"case_id": incident.get("id")},
        {"_id": 0, "canonical_event_id": 1, "event.iid": 1, "adapter": 1,
         "captured_at": 1, "origin": 1, "ingest_job_id": 1})
    async for o in cursor:
        obs_iid = ((o.get("event") or {}).get("iid"))
        cid = o.get("canonical_event_id")
        if cid:
            add(cid, "case_observation",
                {"field": "v2_shadow_observations.canonical_event_id",
                 "observation_iid": obs_iid, "adapter": o.get("adapter"),
                 "captured_at": o.get("captured_at"),
                 "ingest_job_id": o.get("ingest_job_id")})
        else:
            legacy.append({
                "observation_iid": obs_iid, "adapter": o.get("adapter"),
                "captured_at": o.get("captured_at"),
                "bridge_state": LEGACY_UNBRIDGED,
                "reason": ("this observation was persisted without a "
                           "canonical evidence identifier, so no "
                           "deterministic bridge can be established now"),
            })
    return refs, legacy


async def _load_canonical_rows(db, ids: List[str], tenant_id: Optional[str]
                               ) -> Dict[str, Dict[str, Any]]:
    """Canonical records for the given ids, with the tenant assertion.

    A record stamped to a DIFFERENT tenant than the incident is never
    returned: the reference then resolves to nothing under this incident's
    tenant authority.
    """
    if not ids:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    cursor = db[CANONICAL_COLLECTION].find(
        {"event_id": {"$in": ids}},
        {"_id": 0, "event_id": 1, "tenant_id": 1, "event_type": 1,
         "event_time": 1, "timestamp": 1, "ingest_time": 1,
         "source_vendor": 1, "source_product": 1, "source": 1,
         "raw_ref": 1, "provenance": 1})
    async for row in cursor:
        row_tenant = row.get("tenant_id") or None
        if row_tenant and tenant_id and row_tenant != tenant_id:
            out[row["event_id"]] = {"__tenant_conflict__": True}
            continue
        row["__tenant_assertion__"] = ("MATCHED" if row_tenant
                                       else "NOT_STAMPED_ON_RECORD")
        out[row["event_id"]] = row
    return out


async def canonical_evidence_projection(db, incident: Dict[str, Any]
                                        ) -> Dict[str, Any]:
    """The incident's canonical evidence records, keyed by canonical id."""
    tenant_id = incident.get("tenant_id")
    refs, legacy = await authoritative_references(db, incident)
    rows_by_id = await _load_canonical_rows(db, list(refs.keys()), tenant_id)

    rows: List[Dict[str, Any]] = []
    for cid in sorted(refs.keys()):
        row = rows_by_id.get(cid)
        cited_by = refs[cid]
        observation_iids = [c["observation_iid"] for c in cited_by
                            if c.get("observation_iid")]
        if not row or row.get("__tenant_conflict__"):
            rows.append({
                "canonical_evidence_id": cid,
                "bridge_state": REFERENCED_RECORD_ABSENT,
                "tenant_assertion": ("CONFLICT" if row else "NO_RECORD"),
                "referenced_by": cited_by,
                "observation_iids": observation_iids,
                "record": None,
                "reason": ("the reference is deterministic, but no canonical "
                           "evidence record is resolvable under this "
                           "incident's tenant authority — this is not an "
                           "absence of evidence and supports no verdict"),
            })
            continue
        source = row.get("source") or {}
        rows.append({
            "canonical_evidence_id": cid,
            "bridge_state": BRIDGED,
            "tenant_assertion": row["__tenant_assertion__"],
            "referenced_by": cited_by,
            "observation_iids": observation_iids,
            "record": {
                "event_type": row.get("event_type"),
                "event_time": row.get("event_time") or row.get("timestamp"),
                "ingest_time": row.get("ingest_time"),
                "source_vendor": row.get("source_vendor")
                                 or source.get("vendor"),
                "source_product": row.get("source_product")
                                  or source.get("product"),
                "normalizer_id": (row.get("provenance") or {}).get(
                    "normalizer_id"),
                "trace_id": (row.get("provenance") or {}).get("trace_id"),
                "raw_reference": _raw_reference(row),
            },
        })

    counts = {
        BRIDGED: sum(1 for r in rows if r["bridge_state"] == BRIDGED),
        REFERENCED_RECORD_ABSENT: sum(
            1 for r in rows if r["bridge_state"] == REFERENCED_RECORD_ABSENT),
        LEGACY_UNBRIDGED: len(legacy),
    }
    return {
        "incident_id": incident.get("id"),
        "tenant_scope": "INCIDENT_RESOLVED",
        "rows": rows,
        "legacy_unbridged_observations": legacy,
        "counts": counts,
        "contract": CONTRACT,
    }


async def authoritative_canonical_ids(db, incident: Dict[str, Any]) -> set[str]:
    """The canonical ids this incident may address, server-resolved."""
    refs, _ = await authoritative_references(db, incident)
    return set(refs.keys())


async def resolvable_canonical_row(db, incident: Dict[str, Any], ref_id: str
                                   ) -> Optional[Dict[str, Any]]:
    """ONE canonical record, only if the INCIDENT itself references it.

    An id that the incident does not reference resolves to None, so a
    caller holding an id learns nothing — possession of an identifier is
    never lookup authority.
    """
    ids = await authoritative_canonical_ids(db, incident)
    if ref_id not in ids:
        return None
    rows = await _load_canonical_rows(db, [ref_id], incident.get("tenant_id"))
    row = rows.get(ref_id)
    if not row or row.get("__tenant_conflict__"):
        return None
    return row


def annotate_frames(frames: List[Dict[str, Any]],
                    bridged_ids: set[str]) -> List[Dict[str, Any]]:
    """Stamp the bridge state on trajectory frames.

    `canonical_evidence_id` is already on the frame (propagated from the
    observation). This only records whether the referenced canonical record
    resolves, so the UI never has to guess.
    """
    for f in frames:
        cid = f.get("canonical_evidence_id")
        if not cid:
            f["bridge_state"] = LEGACY_UNBRIDGED
        elif cid in bridged_ids:
            f["bridge_state"] = BRIDGED
        else:
            f["bridge_state"] = REFERENCED_RECORD_ABSENT
    return frames


async def bridged_ids_for_case(db, case_id: str) -> set[str]:
    """Canonical ids of `case_id` whose record resolves under its tenant."""
    incident = await db["workspace_cases"].find_one(
        {"id": case_id}, {"_id": 0, "id": 1, "tenant_id": 1,
                          "xdr_pipeline": 1, "endpoint_campaign": 1})
    if not incident:
        return set()
    projection = await canonical_evidence_projection(db, incident)
    return {r["canonical_evidence_id"] for r in projection["rows"]
            if r["bridge_state"] == BRIDGED}
