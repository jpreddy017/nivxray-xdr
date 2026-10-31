"""V3 PRESENTATION CONTRACT — the §d real-evidence contract, shaped for the exact E3 V3 surface.

This module is a PURE MAPPING. It performs no database read, owns no evidence, and decides no
chronology: it is handed the §d production result that `routers/edr.py` has ALREADY produced for
the request and re-expresses it in the field vocabulary `trajectory_v3/amp/*` consumes.

WHY A MAPPING AND NOT A SECOND READ
-----------------------------------
`GET /api/edr/endpoints/{id}/trajectory` already resolves the endpoint identity once, resolves the
customer once and reads the evidence once (`out["e3"]`). Producing `out["v3"]` from that same result
keeps ONE production truth path. A second query would be a second authority, and two authorities
drift.

ORDERING AUTHORITY IS NOT RESTATED HERE
---------------------------------------
`observed_us` (full source precision) remains the ordering and cursor authority in
`production_adapter`. `timestamp_instant_ms` emitted below is the RENDERING coordinate V3 draws
with — it is derived from the same stored observation time and is never fed back into ordering,
paging or resumption. The same-millisecond/different-microsecond fix therefore cannot regress
through this module: it does not sort, page, or compare times at all.

EVENT IDENTITY
--------------
V3 silently de-duplicates rows that repeat `event_iid` (`model.js`: `seen.has(e.event_iid)`), so a
collision here DELETES evidence from an analyst's screen. `event_iid` is therefore a bijective
encoding of the §d evidence identity `event_id`, and §d has already collapsed one activity seen in
several stores onto one `event_id` per customer. Uniqueness is a property of the construction, not
a probability: see `encode_iid`.
"""
from __future__ import annotations

import base64
from typing import Any

from .lineage import lane_of

CONTRACT = "e3.dt.v3_presentation.v1"
IID_PREFIX = "e3_"

NOT_COLLECTED = "NOT_COLLECTED"

#: §d activity family -> the `event_type` token `trajectory_v3/amp/labels.js` knows.
#: A family with no V3 token is passed through in lower case so the row still renders with its own
#: name under the generic glyph. It is never promoted into a token that would claim more than the
#: evidence does — e.g. FILE_EXECUTE is NOT mapped to `process_create`, because an execute flag on
#: a file observation is not an observed process start.
EVENT_TYPE = {
    "PROCESS_START": "process_create",
    "PROCESS_END": "process_end",
    "FILE_CREATE": "file_create",
    "FILE_WRITE": "file_write",
    "FILE_DELETE": "file_delete",
    "FILE_MOVE": "file_rename",
    "FILE_EXECUTE": "file_execute",
    "NETWORK_CONNECT": "network_connect",
    "DNS_QUERY": "dns_query",
    "REGISTRY_SET": "registry_value_set",
    "DETECTION": "detection",
    "OTHER": "other",
}


def encode_iid(event_id: str) -> str:
    """§d evidence identity -> V3 presentation identity. Bijective, URL-safe, content-free.

    Deterministic (pure function of the stored identity), so a repeated read and a deep link
    produce the same value. It carries no page position, no clock reading and no millisecond
    timestamp, so it cannot change because the page did. It is NOT derived from the physical store
    key: Mongo `_id` stays internal to `production_adapter` and is never exposed.

    The tenant is deliberately NOT encoded. Resolution is always performed against the customer and
    endpoint the SERVER authorized for the request, so an identity from another customer simply
    does not resolve — embedding the tenant would leak it into every URL without adding any
    isolation that the server does not already enforce.
    """
    raw = base64.urlsafe_b64encode(str(event_id).encode()).decode().rstrip("=")
    return IID_PREFIX + raw


def decode_iid(event_iid: str) -> str | None:
    """V3 presentation identity -> §d evidence identity, or None when this is not a V3 identity.

    Returning None is how the focus resolver keeps the V1 `event_iid` namespace untouched: an
    identifier this codec does not own is handed back to the existing V1 resolver unchanged.
    """
    s = str(event_iid or "")
    if not s.startswith(IID_PREFIX):
        return None
    body = s[len(IID_PREFIX):]
    try:
        return base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
    except Exception:                                   # noqa: BLE001
        return None


def _detection(ev: dict[str, Any]) -> dict[str, Any] | None:
    """The row's OWN detection evidence, or None.

    None means NO DETECTION HAS CLAIMED THIS OBSERVATION. It does not mean benign, and V3 renders
    it as an unflagged row rather than as a clean verdict.
    """
    d = ev.get("detection")
    if not d:
        return None
    if isinstance(d, str):
        return {"name": d, "severity": ev.get("severity"), "rule_id": None,
                "basis": "DETECTION_CARRIED_ON_THE_OBSERVATION"}
    return {"name": d.get("name") or d.get("rule_name") or d.get("rule_id"),
            "severity": d.get("severity") or ev.get("severity"),
            "rule_id": d.get("rule_id"),
            "basis": d.get("basis") or "DETECTION_CARRIED_ON_THE_OBSERVATION"}


def present_event(ev: dict[str, Any], *, lane_index: int | None,
                  lane_label: str | None) -> dict[str, Any]:
    """One §d evidence row -> one V3 presentation row.

    Only fields the evidence actually holds are emitted. An absent field is OMITTED rather than
    set to an empty string, because V3's own narrative renders a missing key as "not collected" /
    "not reported by sensor", whereas an empty string reads as "nothing was there".
    """
    p = ev.get("process") or {}
    par = ev.get("parent") or {}
    f = ev.get("file") or {}
    n = ev.get("network") or {}
    kind = ev.get("kind") or "OTHER"
    prov = ev.get("provenance") or {}

    row: dict[str, Any] = {
        "event_iid": encode_iid(ev["event_id"]),
        "event_type": EVENT_TYPE.get(kind, str(kind).lower()),
        "activity_family": kind,
        "timestamp": ev.get("observed_at"),
        "timestamp_instant_ms": ev.get("observed_ms"),
        "observation_time_authority": "STORED_OBSERVATION_TIME",
        "lane_index": lane_index,
        "lane_label": lane_label,
        "severity": ev.get("severity"),
        "evidence_stores": ev.get("sources") or [],
        "provenance": prov,
    }
    if prov.get("ref"):
        row["observation_id"] = prov["ref"]
    for key, value in (("pid", p.get("pid")), ("image", p.get("image")),
                       ("command_line", p.get("command_line")), ("user", p.get("user")),
                       ("file_sha256", p.get("sha256") if kind == "PROCESS_START" else f.get("sha256")),
                       ("process_iid", ev.get("process_key")),
                       ("parent_process_iid", ev.get("parent_key")),
                       ("parent_process_guid", par.get("guid")),
                       ("parent_image", par.get("image")),
                       ("process_guid", p.get("guid"))):
        if value is not None:
            row[key] = value
    # `file` is the V3 row's path-bearing field for file AND registry activity (model.js targetOf).
    if f.get("path"):
        row["file"] = f["path"]
    if f.get("prev_path"):
        row["previous_path"] = f["prev_path"]
    if n.get("dest_ip"):
        row["network"] = (f"{n['dest_ip']}:{n['dest_port']}" if n.get("dest_port") is not None
                          else str(n["dest_ip"]))
    if n.get("query"):
        row["entity"] = n["query"]
    det = _detection(ev)
    if det:
        row["e3_detection"] = det
    if ev.get("lateness"):
        row["lateness"] = ev["lateness"]
    # e3_assessment is DELIBERATELY ABSENT. E1 holds no disposition authority for a raw
    # observation, so V3 renders the neutral square ("Unknown disposition") rather than a verdict
    # this platform cannot support. e3_attack is likewise only attached when a real attribution
    # authority claims the observation (see `attach_attack`).
    return row


def _lane_axis(events: list[dict[str, Any]], lanes: list[dict[str, Any]]) -> tuple[dict[str, Any],
                                                                                   dict[str, int],
                                                                                   dict[str, str]]:
    """Stable lane ordering from the §d lineage model, plus per-event lane placement.

    Lane order is the order `lineage.lanes` produced (depth-first over proven causality), so the
    index is a property of the evidence graph and not of the page's arrival order.
    """
    index: dict[str, int] = {}
    label: dict[str, str] = {}
    axis: list[dict[str, Any]] = []
    for i, ln in enumerate(lanes):
        lane_id = str(ln.get("lane_id"))
        index[lane_id] = i
        label[lane_id] = ln.get("label") or lane_id
        axis.append({"lane_index": i, "lane_id": lane_id, "label": label[lane_id],
                     "lane_type": ln.get("lane_type"), "depth": ln.get("depth"),
                     "parent_lane": ln.get("parent_lane"),
                     "causal_state": ln.get("causal_state"),
                     "event_count": ln.get("event_count")})
    per_event_index: dict[str, int] = {}
    per_event_label: dict[str, str] = {}
    for ev in events:
        lane_id = lane_of(ev)
        if lane_id in index:
            per_event_index[ev["event_id"]] = index[lane_id]
            per_event_label[ev["event_id"]] = label[lane_id]
    return ({"total_lanes": len(axis), "lanes": axis,
             "basis": "PROVEN_CAUSAL_LINEAGE_OF_THIS_PAGE"},
            per_event_index, per_event_label)


def attach_attack(rows: list[dict[str, Any]], attribution: dict[str, Any] | None) -> None:
    """Attach ATT&CK attribution ONLY where an authority claimed the observation.

    `attribution` maps presentation identity -> the attribution block produced by
    `edr_trajectory.attack.annotate_row` from rule/finding metadata that has the authority to make
    the claim. An unclaimed row gets NOTHING, so V3 shows its empty ATT&CK state. A technique badge
    is never minted here and never implies a verdict.
    """
    if not attribution:
        return
    for row in rows:
        got = attribution.get(row["event_iid"])
        if got:
            row["e3_attack"] = got


def apply_findings(rows: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Join E1's REAL findings authority onto the presentation rows.

    E1 detections are production-wired and durable (`edr_plane.fabric`), so the trajectory must
    show the detection E1 actually recorded rather than a second detection notion of its own. The
    join is on the finding's OWN `evidence_refs` against the observation identity the row carries —
    an exact identifier match. Proximity in time is never used, so a detection is never attached
    to a neighbouring observation.

    A row with no finding is left untouched: NO DETECTION is not BENIGN, and nothing is written to
    say otherwise. ATT&CK is attached only from `attck` metadata the finding itself carries, i.e.
    from a rule with the authority to make that claim.
    """
    from .attack import annotate_row

    by_ref: dict[str, dict[str, Any]] = {}
    for f in findings or []:
        for ref in (f.get("evidence_refs") or []):
            if ref:
                by_ref.setdefault(str(ref), f)
    if not by_ref:
        return {"joined": 0, "findings_considered": len(findings or []),
                "basis": "NO_FINDING_CARRIES_AN_EVIDENCE_REFERENCE_FOR_THIS_ENDPOINT"}

    joined = 0
    for row in rows:
        keys = [k for k in (row.get("observation_id"), decode_iid(row["event_iid"])) if k]
        f = next((by_ref[str(k)] for k in keys if str(k) in by_ref), None)
        if not f:
            continue
        joined += 1
        row["e3_detection"] = {
            "name": f.get("rule_name") or f.get("label") or f.get("rule_id"),
            "severity": f.get("severity") or row.get("severity"),
            "rule_id": f.get("rule_id"),
            "finding_id": f.get("finding_id"),
            "basis": f.get("detection_source") or "E1_FINDING",
            "detection_source_detail": f.get("detection_source_detail"),
            "authority": "E1_DURABLE_FINDINGS",
        }
        attck = [str(x) for x in (f.get("attck") or []) if x]
        if attck:
            got = annotate_row({"mitre": attck,
                                "mitre_basis": f.get("attck_basis") or f.get("detection_source"),
                                "findings": [{"rule_id": f.get("rule_id"),
                                              "rule_name": f.get("rule_name"),
                                              "rule_version": f.get("rule_version"),
                                              "engine": f.get("analyzer_id"),
                                              "confidence": f.get("confidence"),
                                              "attck_basis": f.get("attck_basis"),
                                              "attck": attck,
                                              "severity": f.get("severity")}]})
            if got:
                row["e3_attack"] = got
    return {"joined": joined, "findings_considered": len(findings or []),
            "basis": "EXACT_EVIDENCE_REFERENCE_MATCH (no timestamp proximity)",
            "authority": "E1_DURABLE_FINDINGS"}


def build(e3: dict[str, Any], *, computer: dict[str, Any] | None,
          identity: dict[str, Any] | None,
          attribution: dict[str, Any] | None = None) -> dict[str, Any]:
    """The additive `v3` key: the §d page, in V3's vocabulary. No evidence is read here.

    Every number reported is a statement about THIS BOUNDED PAGE. Nothing claims to describe the
    endpoint's whole history, and an absence is always reported as an absence of collected
    telemetry rather than as a clean result.
    """
    if not isinstance(e3, dict) or e3.get("contract") != "e3.dt.production.v1":
        return {"contract": CONTRACT, "state": "V3_CONTRACT_UNAVAILABLE",
                "reason": "NO_PRODUCTION_EVIDENCE_CONTRACT_ON_THIS_RESPONSE",
                "events": [], "mock_data_reachable": False}

    page = e3.get("page") or {}
    events = page.get("items") or []
    lanes = e3.get("lanes") or []
    axis, lane_index, lane_label = _lane_axis(events, lanes)
    rows = [present_event(ev, lane_index=lane_index.get(ev["event_id"]),
                          lane_label=lane_label.get(ev["event_id"])) for ev in events]
    attach_attack(rows, attribution)

    detections = [{"event_iid": r["event_iid"], "observation_id": r.get("observation_id"),
                   "at": r["timestamp"], "ms": r["timestamp_instant_ms"],
                   "name": r["e3_detection"]["name"], "severity": r["e3_detection"]["severity"],
                   "rule_id": r["e3_detection"].get("rule_id")}
                  for r in rows if r.get("e3_detection")]

    density = e3.get("density") or {}
    days = [{"day": d["day"], "total": d["count"]} for d in (density.get("days") or [])]

    return {
        "contract": CONTRACT,
        "state": e3.get("state"),
        "evidence_state": e3.get("evidence_state"),
        "mock_data_reachable": False,
        "engine_id": "nivxray::edr_trajectory::v3_presentation",
        "events": rows,
        "returned": len(rows),
        "lane_axis": axis,
        "computer": computer,
        "identity": identity,
        "activity": {"days": days,
                     "basis": density.get("basis"),
                     "meaning": "activity density of the evidence on this page, placed by stored "
                                "observation time. A day with no bar is a day with no RETAINED "
                                "observation — it is not proof that nothing happened."},
        "matched_in_window": len(rows),
        "families": e3.get("families"),
        "coverage": e3.get("coverage"),
        "observed_range": e3.get("observed_range"),
        # V3 reads its page metadata from this key. The content is production evidence metadata:
        # the name is the consumer's, the facts are E1's, and `data_label` states exactly that.
        "e3_preview": {
            "window_rows": len(rows),
            "older_cursor": page.get("next_cursor"),
            "remaining_older": bool(page.get("has_more")),
            "data_label": "REAL PRODUCTION EVIDENCE — E1 authoritative stores, read-only",
            "source": "E1_PRODUCTION_EVIDENCE_STORES",
            "source_origin": ", ".join((page.get("provenance") or {}).get("stores_read") or []),
            "engine": e3.get("contract"),
            "detections_all": detections,
            "detections_basis": ("DETECTION_CARRIED_ON_THE_OBSERVATION — a row without a "
                                 "detection has NOT been evaluated as benign"),
            "page_meaning": "ONE BOUNDED NEWEST-FIRST PAGE, not the endpoint's whole history",
        },
        "provenance": page.get("provenance"),
        "ordering_authority": "observed_us (full source precision) in production_adapter; "
                              "timestamp_instant_ms below is a RENDERING coordinate only",
        "suppressed_duplicates": page.get("suppressed_duplicates"),
        "unplaceable_no_observation_time_count":
            page.get("unplaceable_no_observation_time_count"),
    }
