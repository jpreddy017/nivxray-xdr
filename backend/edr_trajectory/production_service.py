"""§d PRODUCTION ASSEMBLY — real E1 evidence through the E3 capability contracts.

`page_device_evidence` supplies the evidence; this module composes the capability results that
Device Trajectory renders, using the SAME E3 contracts the preview already uses. It owns no
relationship, time or detection logic of its own, so a capability can only ever be as truthful
here as it is in E3.

Everything is derived from one bounded newest-first page. Nothing is read twice, nothing is
re-timed, and a capability with no supporting evidence reports its own absence rather than an
empty success.
"""
from __future__ import annotations

from typing import Any

from .contracts import iso
from .lineage import build_graph, lanes
from .paging import PAGE_DEFAULT
from .production_adapter import STORES, page_device_evidence, resolve_evidence
from .timeline import coverage, density, lateness

CONTRACT = "e3.dt.production.v1"

#: Activity families Device Trajectory can render. Each is reported as OBSERVED or
#: NOT_OBSERVED_IN_THIS_PAGE — never as "clean" and never silently omitted.
FAMILIES = {
    "PROCESS": ("PROCESS_START", "PROCESS_END"),
    "FILE": ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE", "FILE_MOVE", "FILE_EXECUTE"),
    "NETWORK": ("NETWORK_CONNECT",),
    "DNS": ("DNS_QUERY",),
    "REGISTRY": ("REGISTRY_SET",),
    "DETECTION": ("DETECTION",),
}

NOT_COLLECTED = "NOT_COLLECTED"
NOT_OBSERVED = "NOT_OBSERVED_IN_THIS_PAGE"


def _families(events: list[dict[str, Any]]) -> dict[str, Any]:
    kinds = {e["kind"] for e in events}
    return {fam: {"state": "OBSERVED" if kinds & set(ks) else NOT_OBSERVED,
                  "count": sum(1 for e in events if e["kind"] in ks),
                  "meaning": ("this family has evidence on this page" if kinds & set(ks) else
                              "no evidence of this family on this page. This is a statement "
                              "about collected telemetry, NOT that the activity did not happen")}
            for fam, ks in FAMILIES.items()}


def activity_details(ev: dict[str, Any]) -> dict[str, Any]:
    """Every field Device Trajectory shows for one selected observation.

    Populated ONLY from the row's own evidence. A field the sensor does not report stays
    explicitly NOT_COLLECTED, because an empty string reads to an analyst as "nothing there"
    when the truth is "we never collected it".
    """
    p, par, f, n = ev.get("process") or {}, ev.get("parent") or {}, ev.get("file") or {}, ev.get("network") or {}

    def v(x):
        return x if x not in (None, "", [], {}) else NOT_COLLECTED

    return {
        "event_id": ev["event_id"],
        "activity_type": ev["kind"],
        "observed_at": ev.get("observed_at"),
        "observation_time_authority": "STORED_OBSERVATION_TIME",
        "ingested_at": ev.get("ingested_at"),
        "lateness": ev.get("lateness") or lateness(ev),
        "severity": ev.get("severity"),
        "process": {"pid": v(p.get("pid")), "guid": v(p.get("guid")), "image": v(p.get("image")),
                    "command_line": v(p.get("command_line")), "user": v(p.get("user")),
                    "sha256": v(p.get("sha256")), "start_time": v(p.get("start_time")),
                    "identity_authority": ev.get("process_identity"),
                    "identity_key": v(ev.get("process_key"))},
        "parent": {"pid": v(par.get("pid")), "guid": v(par.get("guid")), "image": v(par.get("image")),
                   "identity_key": v(ev.get("parent_key")),
                   "identity_authority": v(ev.get("parent_identity"))},
        "file": {"path": v(f.get("path")), "previous_path": v(f.get("prev_path")),
                 "sha256": v(f.get("sha256")), "operation": v(f.get("operation"))} if f else NOT_COLLECTED,
        "network": {"dest_ip": v(n.get("dest_ip")), "dest_port": v(n.get("dest_port")),
                    "protocol": v(n.get("protocol")), "src_ip": v(n.get("src_ip")),
                    "dns_query": v(n.get("query"))} if n else NOT_COLLECTED,
        "detection": ev.get("detection") or {
            "state": "NO_DETECTION_ON_THIS_OBSERVATION",
            "meaning": "no detection engine has claimed this observation. That is not a "
                       "statement that the activity is benign"},
        "signer": NOT_COLLECTED,
        "integrity_level": NOT_COLLECTED,
        "provenance": ev.get("provenance") or {},
        "evidence_stores": ev.get("sources") or [],
    }


async def device_trajectory(db: Any, *, tenant_id: str, refs: list[str], endpoint_id: str,
                            page_size: int = PAGE_DEFAULT, cursor: str | None = None,
                            focus_event_id: str | None = None,
                            time_start: str | None = None, time_end: str | None = None,
                            stores: tuple[str, ...] = STORES) -> dict[str, Any]:
    """One production Device Trajectory read: evidence + lanes + lineage + coverage + focus."""
    page = await page_device_evidence(db, tenant_id=tenant_id, refs=refs,
                                      page_size=page_size, cursor=cursor,
                                      time_start=time_start, time_end=time_end, stores=stores)
    events = page["items"]
    for e in events:
        e["lateness"] = lateness(e)

    if not events:
        return {"contract": CONTRACT, "endpoint_id": endpoint_id, "state": page["state"],
                "evidence_state": "NO_REAL_EVIDENCE_FOR_THIS_ENDPOINT",
                "meaning": ("no stored observation for this endpoint in this customer"
                            + (" IN THE REQUESTED WINDOW" if page.get("window", {}).get("applied")
                               else "")
                            + ". Nothing is substituted: an empty trajectory is the truthful "
                              "answer, and it is not evidence that nothing happened."),
                "page": page, "lanes": [], "process_graph": {"nodes": {}},
                "families": _families([]), "focus": _focus_miss(focus_event_id),
                "mock_data_reachable": False}

    t1 = max(e["observed_ms"] for e in events)
    t0 = min(e["observed_ms"] for e in events)
    graph = build_graph(events)
    lane_model = lanes(events, t0, t1)

    focus = _focus_miss(focus_event_id)
    if focus_event_id:
        hit = next((e for e in events if e["event_id"] == focus_event_id), None)
        if hit:
            focus = {"state": "FOCUS_RESOLVED", "event_id": focus_event_id,
                     "observed_at": hit.get("observed_at"),
                     "lane_id": next(iter(_lane_ids_for(hit, lane_model)), None),
                     "details": activity_details(hit), "basis": "RESOLVED_WITHIN_LOADED_PAGE"}
        else:
            deep = await resolve_evidence(db, tenant_id=tenant_id, refs=refs,
                                          event_id=focus_event_id, stores=stores)
            focus = ({"state": "FOCUS_RESOLVED", "event_id": focus_event_id,
                      "observed_at": deep["observed_at"], "lane_id": None,
                      "details": activity_details(deep["event"]),
                      "basis": "RESOLVED_OUTSIDE_LOADED_PAGE_BY_EVIDENCE_IDENTITY",
                      "position": deep.get("position")}
                     if deep["state"] == "FOCUS_RESOLVED" else
                     {**_focus_miss(focus_event_id), "reason": deep.get("reason")})

    return {
        "contract": CONTRACT,
        "endpoint_id": endpoint_id,
        "state": page["state"],
        "evidence_state": "REAL_EVIDENCE",
        "mock_data_reachable": False,
        "observed_range": {"from": iso(t0), "to": iso(t1),
                           "basis": "EXTENT OF THIS PAGE, NOT OF THE ENDPOINT'S HISTORY"},
        "page": page,
        "lanes": lane_model["lanes"],
        "process_graph": {"nodes": graph["nodes"],
                          "unattributed_network": graph["unattributed_network"]},
        "families": _families(events),
        "coverage": coverage(events, t0, t1),
        "density": density(events, t1, 30),
        "focus": focus,
        "activity_details_sample": activity_details(events[0]),
    }


def _lane_ids_for(ev: dict[str, Any], lane_model: dict[str, Any]) -> list[str]:
    return [ln["lane_id"] for ln in lane_model["lanes"]
            if ev["event_id"] in (ln.get("event_ids") or [])]


def _focus_miss(event_id: str | None) -> dict[str, Any]:
    if not event_id:
        return {"state": "NO_FOCUS_REQUESTED", "event_id": None}
    return {"state": "FOCUS_NOT_RESOLVED", "event_id": event_id,
            "reason": "EVIDENCE_IDENTITY_NOT_FOUND_FOR_THIS_ENDPOINT",
            "meaning": "the deep link names evidence this endpoint and customer do not hold. "
                       "No other observation is selected in its place."}
