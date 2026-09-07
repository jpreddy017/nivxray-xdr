"""X2 · Unified NivXRay XDR global search.

One question — "what does this platform know about this string?" —
answered from the AUTHORITATIVE stores only:

    workspace_cases          incidents
    edr_endpoints/observations  endpoints (via the EDR identity plane)
    edr_raw_events.derivations  detections
    v2_shadow_observations   evidence · processes · files · network

It creates no index and no store of its own, and it fabricates nothing:
an entity type this platform cannot search is reported explicitly as
`NOT_SEARCHABLE_NO_INDEX` when it is asked for by name, rather than
returned as a silently empty category.

Tenant boundary: endpoints (and therefore every endpoint-derived result)
come from `device_identity.list_devices(scope)` — the same authorised
inventory P0-F.13.4 proved — so search can never surface another
customer's evidence.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends

from deps import get_current_user, sync_collection
from services.dashboard_lenses import resolve_tenant_scope
from services.edr import device_identity as dir_svc

router = APIRouter(prefix="/xdr/search", tags=["xdr-search"])

ENGINE_ID = "nivxray::xdr::global_search"
PER_GROUP = 10

#: Entity types the platform holds no searchable index for. Named, so a
#: request for one gets an honest answer instead of an empty list that
#: reads like "nothing was found".
NOT_SEARCHABLE = {
    "identity": "no identity/user directory is ingested by this platform",
    "users": "no identity/user directory is ingested by this platform",
    "network_asset": "network asset inventory is not implemented",
    "domain": "no DNS/domain telemetry is collected by this platform",
    "url": "no proxy/URL telemetry is collected by this platform",
    "email": "no email security telemetry is ingested",
    "vulnerability": "vulnerability findings are not indexed for search",
}

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_INC = re.compile(r"^(inc_[a-f0-9]+|INC\d+)$", re.I)
_RULE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z0-9-]+$")


def classify_term(term: str) -> str:
    """What the analyst most likely typed — a hint, never a filter."""
    if _SHA256.match(term):
        return "SHA256"
    if _IP.match(term):
        return "IP"
    if _INC.match(term):
        return "INCIDENT_REFERENCE"
    if _RULE.match(term):
        return "RULE_ID"
    if term.startswith(("raw_", "cev_", "evt_", "proc_")):
        return "EVIDENCE_IDENTIFIER"
    if term.startswith(("dev_", "ep_")):
        return "ENDPOINT_IDENTIFIER"
    return "FREE_TEXT"


def _rx(term: str) -> Dict[str, Any]:
    return {"$regex": re.escape(term), "$options": "i"}


def _incidents(term: str, scope: Dict[str, Any]) -> List[Dict[str, Any]]:
    q: Dict[str, Any] = {"$or": [{"id": _rx(term)},
                                 {"incident_number": _rx(term)},
                                 {"title": _rx(term)},
                                 {"rule_ids": term.upper()},
                                 {"endpoint_campaign.rule_ids":
                                  term.upper()}]}
    if not scope.get("all_tenants"):
        q["tenant_id"] = {"$in": scope.get("tenant_ids") or []}
    out = []
    for d in sync_collection("workspace_cases").find(
            q, {"_id": 0, "id": 1, "incident_number": 1, "title": 1,
                "tenant_id": 1, "state": 1, "priority": 1,
                "verdict": 1}).limit(PER_GROUP):
        out.append({"entity_type": "INCIDENT",
                    "id": d.get("id"),
                    "label": d.get("incident_number") or d.get("id"),
                    "detail": d.get("title"),
                    "tenant_id": d.get("tenant_id"),
                    "attributes": {"state": d.get("state"),
                                   "priority": d.get("priority"),
                                   "verdict": d.get("verdict")},
                    "href": f"/xdr/incidents/{d.get('id')}"})
    return out


def _authorised_endpoints(scope: Dict[str, Any]) -> List[Dict[str, Any]]:
    return dir_svc.list_devices({"all_tenants": bool(scope.get("all_tenants")),
                                 "tenant_ids": list(scope.get("tenant_ids")
                                                    or [])})


def _endpoints(term: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    t = term.lower()
    out = []
    for r in rows:
        hay = " ".join([str(r.get("hostname") or ""),
                        str(r.get("device_iid") or ""),
                        " ".join(r.get("owning_endpoint_ids") or [])]).lower()
        if t in hay:
            out.append({"entity_type": "ENDPOINT",
                        "id": r.get("device_iid"),
                        "label": r.get("hostname") or r.get("device_iid"),
                        "detail": (f"{r.get('observation_count', 0)} "
                                   f"observations"),
                        "tenant_id": r.get("tenant_id"),
                        "attributes": {
                            "device_iid": r.get("device_iid"),
                            "endpoint_id": (r.get("owning_endpoint_ids")
                                            or [None])[0],
                            "tenant_attribution": r.get("tenant_attribution"),
                        },
                        "href": ("/xdr/edr/device-trajectory?device="
                                 f"{r.get('device_iid')}")})
    return out[:PER_GROUP]


def _detections(term: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Authoritative DETECTION_MATCHED derivations, endpoint-scoped."""
    refs, by_ep = set(), {}
    for r in rows:
        for ep in (r.get("owning_endpoint_ids") or []):
            refs.add(ep)
            by_ep[ep] = r
    if not refs:
        return []
    q = {"endpoint_ref": {"$in": sorted(refs)},
         "derivations.outcome": "DETECTION_MATCHED",
         "$or": [{"raw_id": _rx(term)},
                 {"derivations.reason": _rx(term)},
                 {"derivations.event_id": _rx(term)}]}
    out = []
    for raw in sync_collection("edr_raw_events").find(
            q, {"_id": 0, "raw_id": 1, "endpoint_ref": 1, "tenant_id": 1,
                "derivations": 1}).limit(PER_GROUP):
        for d in (raw.get("derivations") or []):
            if d.get("outcome") != "DETECTION_MATCHED":
                continue
            ep = by_ep.get(raw.get("endpoint_ref")) or {}
            rules = [r.strip() for r in
                     str(d.get("reason") or "").replace("rules:", "")
                     .split(",") if r.strip()]
            out.append({
                "entity_type": "DETECTION",
                "id": raw.get("raw_id"),
                "label": ", ".join(rules) or raw.get("raw_id"),
                "detail": (f"{ep.get('hostname') or raw.get('endpoint_ref')}"
                           f" · verdict {d.get('verdict_version') or '◇'}"),
                "tenant_id": raw.get("tenant_id"),
                "attributes": {"rule_ids": rules,
                               "verdict": d.get("verdict_version"),
                               "canonical_event_id": d.get("event_id"),
                               "endpoint_id": raw.get("endpoint_ref")},
                # the proven identifier-only handoff
                "href": ("/xdr/edr/device-trajectory?device="
                         f"{ep.get('device_iid') or ''}"
                         f"&raw_event_id={raw.get('raw_id')}"
                         f"&canonical_event_id={d.get('event_id') or ''}"),
            })
            break
    return out[:PER_GROUP]


def _observations(term: str, rows: List[Dict[str, Any]],
                  ) -> Dict[str, List[Dict[str, Any]]]:
    """Evidence · processes · files · network, from canonical evidence."""
    iids = [r.get("device_iid") for r in rows if r.get("device_iid")]
    host_of = {r.get("device_iid"): (r.get("hostname") or r.get("device_iid"))
               for r in rows}
    if not iids:
        return {"EVIDENCE": [], "PROCESS": [], "FILE": [], "NETWORK": []}
    q = {"event.device_iid": {"$in": iids},
         "$or": [{"canonical_event_id": _rx(term)},
                 {"ingest_job_id": _rx(term)},
                 {"event.iid": _rx(term)},
                 {"event.process.iid": _rx(term)},
                 {"event.process.name": _rx(term)},
                 {"event.raw.command_line": _rx(term)},
                 {"event.raw.sha256": _rx(term)},
                 {"event.raw.target": _rx(term)},
                 {"event.raw.remote_ip": _rx(term)},
                 {"event.raw.entity": _rx(term)}]}
    groups: Dict[str, List[Dict[str, Any]]] = {
        "EVIDENCE": [], "PROCESS": [], "FILE": [], "NETWORK": []}
    seen: Dict[str, set] = {k: set() for k in groups}
    for d in sync_collection("v2_shadow_observations").find(
            q, {"_id": 0, "canonical_event_id": 1, "ingest_job_id": 1,
                "tenant_id": 1, "event": 1}).limit(400):
        ev = d.get("event") or {}
        raw = ev.get("raw") or {}
        proc = ev.get("process") or {}
        dev = ev.get("device_iid")
        host = host_of.get(dev, dev)
        base = {"tenant_id": d.get("tenant_id"),
                "attributes": {"device_iid": dev, "timestamp": ev.get("ts"),
                               "kind": ev.get("kind")}}
        cev = d.get("canonical_event_id")
        if cev and cev not in seen["EVIDENCE"] and len(
                groups["EVIDENCE"]) < PER_GROUP:
            seen["EVIDENCE"].add(cev)
            groups["EVIDENCE"].append({
                **base, "entity_type": "EVIDENCE", "id": cev,
                "label": cev, "detail": f"{ev.get('kind')} · {host}",
                "href": ("/xdr/edr/device-trajectory?device="
                         f"{dev}&canonical_event_id={cev}")})
        pid = proc.get("iid")
        if pid and pid not in seen["PROCESS"] and len(
                groups["PROCESS"]) < PER_GROUP:
            seen["PROCESS"].add(pid)
            groups["PROCESS"].append({
                **base, "entity_type": "PROCESS", "id": pid,
                "label": proc.get("name") or pid,
                "detail": (raw.get("command_line") or "")[:110] or host,
                "href": f"/edr/process-tree?device={dev}&process_iid={pid}"})
        target = raw.get("target") or raw.get("file")
        # `event.raw.sha256` is a digest of the parsed EVENT, not the
        # SHA-256 of a file on disk (see trajectory_window._project), so
        # it must never be offered as a file hash to search or pivot on.
        key = target
        if key and key not in seen["FILE"] and len(
                groups["FILE"]) < PER_GROUP:
            seen["FILE"].add(key)
            groups["FILE"].append({
                **base, "entity_type": "FILE", "id": key,
                "label": target, "detail": host,
                "href": ("/xdr/fleet-file-trajectory?key="
                         f"{key}&key_type=path")})
        peer = raw.get("remote_ip") or raw.get("destination")
        if peer and peer not in seen["NETWORK"] and len(
                groups["NETWORK"]) < PER_GROUP:
            seen["NETWORK"].add(peer)
            groups["NETWORK"].append({
                **base, "entity_type": "NETWORK", "id": peer,
                "label": peer, "detail": host,
                "href": f"/edr/network?device={dev}&peer={peer}"})
    return groups


@router.get("")
async def global_search(q: str, type: Optional[str] = None,
                        user=Depends(get_current_user)) -> Dict[str, Any]:
    term = (q or "").strip()
    scope = resolve_tenant_scope((user or {}).get("email"))
    out: Dict[str, Any] = {
        "engine_id": ENGINE_ID, "query": term,
        "term_classification": classify_term(term) if term else None,
        "tenant_scope": {"all_tenants": bool(scope.get("all_tenants")),
                         "tenant_ids": scope.get("tenant_ids") or []},
        "groups": [], "not_searchable": [], "creates_no_index": True,
    }
    if not term:
        out["state"] = "NO_QUERY"
        return out
    if not scope.get("authorized"):
        out["state"] = "NOT_AUTHORIZED"
        return out

    asked = (type or "").strip().lower()
    if asked in NOT_SEARCHABLE:
        out["state"] = "NOT_SEARCHABLE_NO_INDEX"
        out["not_searchable"] = [{"entity_type": asked.upper(),
                                  "state": "NOT_SEARCHABLE_NO_INDEX",
                                  "reason": NOT_SEARCHABLE[asked]}]
        return out

    rows = _authorised_endpoints(scope)
    obs = _observations(term, rows)
    found = [("INCIDENT", _incidents(term, scope)),
             ("ENDPOINT", _endpoints(term, rows)),
             ("DETECTION", _detections(term, rows)),
             ("EVIDENCE", obs["EVIDENCE"]),
             ("PROCESS", obs["PROCESS"]),
             ("FILE", obs["FILE"]),
             ("NETWORK", obs["NETWORK"])]
    out["groups"] = [{"entity_type": k, "count": len(v), "results": v}
                     for k, v in found if v]
    out["total"] = sum(len(v) for _, v in found)
    out["searched"] = {"authorised_endpoints": len(rows),
                       "sources": ["workspace_cases",
                                   "edr_endpoints/v2_shadow_observations",
                                   "edr_raw_events.derivations",
                                   "v2_shadow_observations"]}
    out["state"] = "RESULTS" if out["total"] else "NO_MATCH"
    if out["state"] == "NO_MATCH":
        out["message"] = ("No authoritative record in your authorised "
                          "customers matches this term. That is an absence "
                          "of a record, not proof the entity is unknown to "
                          "the world.")
    return out


@router.get("/capabilities")
async def search_capabilities(user=Depends(get_current_user)
                              ) -> Dict[str, Any]:
    """What global search can and cannot answer — stated, not implied."""
    return {
        "engine_id": ENGINE_ID,
        "searchable": [
            {"entity_type": "INCIDENT", "source": "workspace_cases"},
            {"entity_type": "ENDPOINT",
             "source": "EDR identity plane (tenant-authorised inventory)"},
            {"entity_type": "DETECTION",
             "source": "edr_raw_events.derivations[DETECTION_MATCHED]"},
            {"entity_type": "EVIDENCE", "source": "v2_shadow_observations"},
            {"entity_type": "PROCESS", "source": "v2_shadow_observations"},
            {"entity_type": "FILE", "source": "v2_shadow_observations"},
            {"entity_type": "NETWORK", "source": "v2_shadow_observations"},
        ],
        "not_searchable": [{"entity_type": k.upper(),
                            "state": "NOT_SEARCHABLE_NO_INDEX",
                            "reason": v}
                           for k, v in sorted(NOT_SEARCHABLE.items())],
    }
