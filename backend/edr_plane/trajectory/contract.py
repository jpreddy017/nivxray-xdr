"""DT2-0 · read-only adapters from the V1 projection to the V2 contract.

The V1 windowed projection is authoritative for WHAT was observed. This
module promotes what V1 already computes implicitly — parenthood, actor
binding, detection attribution, day buckets, epistemic state — into the
explicit, evidence-referenced objects of `models.py`.

It performs NO database access and NO mutation: `augment()` takes the V1
response dict and returns additive keys.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import models as m

_FILE_KINDS = {"file_create", "file_write", "file_delete", "file_modify",
               "file_rename", "image_load", "file"}
_NET_KINDS = {"network_connect", "network", "network_accept",
              "network_listen", "http_request"}
_REG_KINDS = {"registry_create", "registry_value_set", "registry_delete",
              "registry_rename", "registry"}
_DNS_KINDS = {"dns_query", "dns"}
_AUTH_KINDS = {"logon_success", "logon_failure", "logon", "logoff"}

_GROUP_TO_ARTIFACT = {"FILE": "FILE", "REGISTRY": "REGISTRY", "DNS": "DNS",
                      "NETWORK": "NETWORK", "AUTHENTICATION": "AUTH"}


def _ref(kind: str, value: Any, collection: Optional[str] = None,
         byte_preserved: bool = False) -> Optional[m.EvidenceReference]:
    if not value:
        return None
    return m.EvidenceReference(kind=kind, id=str(value),
                               collection=collection,
                               byte_preserved=byte_preserved)


def _row_refs(row: Dict[str, Any]) -> Tuple[m.EvidenceReference, ...]:
    prov = row.get("provenance") or {}
    refs = [
        _ref("RAW_EVENT", prov.get("raw_event_id"), "edr_raw_events", True),
        _ref("CANONICAL_EVENT", prov.get("canonical_event_id")),
        _ref("OBSERVATION", prov.get("evidence_id") or row.get("event_iid"),
             "v2_shadow_observations"),
    ]
    return tuple(r for r in refs if r)


def _group(row: Dict[str, Any]) -> str:
    g = row.get("lane_group")
    if g in _GROUP_TO_ARTIFACT or g == "PROCESS":
        return g
    kind = (row.get("event_type") or "").lower()
    if kind in _FILE_KINDS:
        return "FILE"
    if kind in _NET_KINDS:
        return "NETWORK"
    if kind in _REG_KINDS:
        return "REGISTRY"
    if kind in _DNS_KINDS:
        return "DNS"
    if kind in _AUTH_KINDS:
        return "AUTHENTICATION"
    return "PROCESS" if row.get("process_iid") else "OTHER"


def _artifact_of(row: Dict[str, Any], endpoint_id: str
                 ) -> Optional[m.ArtifactInstance]:
    group = _group(row)
    a_type = _GROUP_TO_ARTIFACT.get(group)
    if not a_type:
        return None
    label = (row.get("file") if a_type in ("FILE",) else None) \
        or row.get("network") or row.get("entity") or row.get("user")
    if a_type == "AUTH":
        label = row.get("user") or label
    if not label:
        return None
    attrs: Dict[str, Any] = {}
    if a_type == "FILE":
        attrs = {"path": row.get("file"),
                 "sha256": row.get("event_content_digest")}
    elif a_type == "REGISTRY":
        attrs = {"key": row.get("entity") or row.get("file")}
    elif a_type == "DNS":
        attrs = {"query": row.get("entity") or row.get("network")}
    elif a_type == "NETWORK":
        attrs = {"destination": row.get("network")}
    elif a_type == "AUTH":
        attrs = {"user": row.get("user")}
    attributed = bool(row.get("process_iid"))
    return m.ArtifactInstance(
        artifact_id=f"{a_type.lower()}:{label}",
        artifact_type=a_type, endpoint_id=endpoint_id,
        identity_authority=(m.AUTHORITY_AUTHORITATIVE
                            if (a_type == "FILE"
                                and row.get("event_content_digest"))
                            else m.AUTHORITY_DERIVED),
        identity_basis=("OBSERVED_SHA256" if (a_type == "FILE" and
                        row.get("event_content_digest"))
                        else "OBSERVED_OBJECT_KEY"),
        label=str(label),
        attributes={k: v for k, v in attrs.items() if v},
        attributed_process_iid=row.get("process_iid") if attributed else None,
        attribution_state="ATTRIBUTED" if attributed else m.UNATTRIBUTED,
        evidence_ref=_row_refs(row))


def observation_of(row: Dict[str, Any], endpoint_id: str,
                   artifact_id: Optional[str]) -> m.Observation:
    prov = row.get("provenance") or {}
    group = _group(row)
    return m.Observation(
        observation_id=str(row.get("event_iid")),
        endpoint_id=endpoint_id,
        activity_class=None if group == "OTHER" else group,
        source_time=row.get("timestamp"),
        observed_time=row.get("timestamp"),
        time_basis="SOURCE_TIME_THEN_OBSERVED_TIME",
        operation=row.get("event_type"),
        process_iid=row.get("process_iid"),
        artifact_id=artifact_id,
        user=row.get("user"),
        raw_evidence_ref=_ref("RAW_EVENT", prov.get("raw_event_id"),
                              "edr_raw_events", True),
        canonical_evidence_ref=_ref("CANONICAL_EVENT",
                                    prov.get("canonical_event_id")),
        source=prov.get("source"),
        source_event_type=row.get("event_type"),
        support_state=(m.COV_NOT_CANONICALIZED
                       if prov.get("parser_state") in
                       ("UNSUPPORTED", "WINDOWS_EVENT_ID_NOT_SUPPORTED")
                       else m.COV_OBSERVED),
        evaluation_state=row.get("assessment_state"),
        disposition=row.get("disposition"),
        parser_state=prov.get("parser_state"),
        attribution_state=("ATTRIBUTED" if row.get("process_iid")
                           else m.UNATTRIBUTED),
        provenance=prov)


def process_instances(rows: Iterable[Dict[str, Any]], endpoint_id: str
                      ) -> List[m.ProcessInstance]:
    seen: Dict[str, m.ProcessInstance] = {}
    for row in rows:
        iid = row.get("process_iid")
        if not iid or iid in seen:
            continue
        guid = (row.get("provenance") or {}).get("process_guid") \
            or row.get("process_guid")
        if guid:
            authority, basis = (m.AUTHORITY_AUTHORITATIVE,
                                "SYSMON_PROCESS_GUID")
        elif row.get("pid") and (row.get("image") or row.get("process")):
            authority, basis = (m.AUTHORITY_DERIVED,
                                "COMPUTER_PID_IMAGE_DERIVED_NO_GUID")
        else:
            authority, basis = (m.AUTHORITY_UNSTABLE,
                                "PID_ONLY_NOT_GLOBALLY_STABLE")
        seen[iid] = m.ProcessInstance(
            process_iid=iid, endpoint_id=endpoint_id,
            identity_authority=authority, identity_basis=basis,
            process_guid=guid, pid=row.get("pid"), image=row.get("image"),
            name=row.get("process"), command_line=row.get("command_line"),
            user=row.get("user"),
            parent_process_iid=row.get("parent_process_iid"),
            parent_pid=row.get("ppid"),
            parent_state=row.get("parent_state"),
            first_seen=row.get("timestamp"), last_seen=row.get("timestamp"),
            exit_observed=False, end_time=None,     # no Sysmon 5 → no end
            detection_state=row.get("assessment_state"),
            evidence_ref=_row_refs(row))
    return list(seen.values())


def relationships(rows: Iterable[Dict[str, Any]], endpoint_id: str
                  ) -> List[m.Relationship]:
    """Derive only edges the canonical evidence itself binds.

    Process→process comes from the parent identity the sensor reported.
    Process→object comes from the acting process on that very observation.
    AUTH with no process binding yields NO edge — by owner decision, and
    because timestamp proximity is never authority.
    """
    out: List[m.Relationship] = []
    seen: set = set()
    for row in rows:
        refs = _row_refs(row)
        if not refs:
            continue
        pid_iid = row.get("process_iid")
        parent = row.get("parent_process_iid")
        group = _group(row)
        if pid_iid and parent:
            key = (m.REL_PROCESS_PROCESS, parent, pid_iid)
            if key not in seen:
                seen.add(key)
                out.append(m.Relationship(
                    relationship_id=f"rel:pp:{parent}:{pid_iid}",
                    relationship_type=m.REL_PROCESS_PROCESS,
                    source_id=parent, target_id=pid_iid,
                    endpoint_id=endpoint_id,
                    derivation_basis=m.BASIS_PARENT_IDENTITY,
                    authority=m.AUTHORITY_AUTHORITATIVE,
                    evidence_ref=refs, observed_at=row.get("timestamp"),
                    time_basis="SOURCE_TIME",
                    provenance={"parent_state": row.get("parent_state")}))
        rel_type = {"FILE": m.REL_PROCESS_FILE,
                    "REGISTRY": m.REL_PROCESS_REGISTRY,
                    "DNS": m.REL_PROCESS_DNS,
                    "NETWORK": m.REL_PROCESS_NETWORK}.get(group)
        artifact = _artifact_of(row, endpoint_id)
        if rel_type and pid_iid and artifact:
            key = (rel_type, pid_iid, artifact.artifact_id)
            if key not in seen:
                seen.add(key)
                out.append(m.Relationship(
                    relationship_id=f"rel:{rel_type}:{pid_iid}:"
                                    f"{artifact.artifact_id}",
                    relationship_type=rel_type,
                    source_id=pid_iid, target_id=artifact.artifact_id,
                    endpoint_id=endpoint_id,
                    derivation_basis=m.BASIS_ACTOR_BINDING,
                    authority=m.AUTHORITY_AUTHORITATIVE,
                    evidence_ref=refs, observed_at=row.get("timestamp"),
                    time_basis="SOURCE_TIME"))
        # DETECTION edges: observation always; process only when the
        # detection itself is bound to a process instance (DT2-3 renders).
        det = row.get("detection") or {}
        det_id = det.get("finding_id") or det.get("detection_id") \
            or row.get("rule_id")
        if det_id and row.get("is_detection"):
            out.append(m.Relationship(
                relationship_id=f"rel:do:{det_id}:{row.get('event_iid')}",
                relationship_type=m.REL_DETECTION_OBSERVATION,
                source_id=str(det_id), target_id=str(row.get("event_iid")),
                endpoint_id=endpoint_id,
                derivation_basis=m.BASIS_DETECTION_EVIDENCE,
                authority=m.AUTHORITY_AUTHORITATIVE,
                evidence_ref=refs, observed_at=row.get("timestamp"),
                time_basis="SOURCE_TIME"))
            if pid_iid:
                out.append(m.Relationship(
                    relationship_id=f"rel:dp:{det_id}:{pid_iid}",
                    relationship_type=m.REL_DETECTION_PROCESS,
                    source_id=str(det_id), target_id=pid_iid,
                    endpoint_id=endpoint_id,
                    derivation_basis=m.BASIS_DETECTION_EVIDENCE,
                    authority=m.AUTHORITY_AUTHORITATIVE,
                    evidence_ref=refs, observed_at=row.get("timestamp"),
                    time_basis="SOURCE_TIME"))
    return out


def detections(rows: Iterable[Dict[str, Any]], endpoint_id: str
               ) -> List[m.DetectionMarker]:
    by_id: Dict[str, m.DetectionMarker] = {}
    for row in rows:
        if not row.get("is_detection"):
            continue
        det = row.get("detection") or {}
        det_id = str(det.get("finding_id") or det.get("detection_id")
                     or row.get("rule_id") or row.get("event_iid"))
        prior = by_id.get(det_id)
        obs = tuple(sorted(set((prior.observation_ids if prior else ())
                               + (str(row.get("event_iid")),))))
        pid_iid = row.get("process_iid")
        by_id[det_id] = m.DetectionMarker(
            detection_id=det_id, endpoint_id=endpoint_id,
            detected_at=row.get("timestamp"),
            evaluation_state=("MATCHED" if row.get("detection")
                              else "NOT_RECORDED"),
            engine=(det.get("engine") or det.get("source")),
            engine_version=det.get("engine_version"),
            rule_id=row.get("rule_id"), severity=det.get("severity"),
            disposition=row.get("disposition"),
            mitre=tuple(row.get("mitre") or ()),
            mitre_authority=m.AUTHORITY_DERIVED,
            observation_ids=obs, process_iid=pid_iid,
            process_binding_authority=(m.AUTHORITY_AUTHORITATIVE if pid_iid
                                       else m.AUTHORITY_UNKNOWN),
            evidence_ref=_row_refs(row),
            provenance={"assessment_state": row.get("assessment_state")})
    return list(by_id.values())


def _parse(ts: Any) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def density(rows: List[Dict[str, Any]], start: Optional[str],
            end: Optional[str], buckets: int = 48) -> List[m.DensityBucket]:
    stamps = [t for t in (_parse(r.get("timestamp")) for r in rows) if t]
    if not stamps:
        return []
    lo = _parse(start) or min(stamps)
    hi = _parse(end) or max(stamps)
    if hi <= lo:
        hi = lo + timedelta(seconds=1)
    step = (hi - lo) / buckets
    grid: Dict[Tuple[int, str], int] = {}
    for row in rows:
        t = _parse(row.get("timestamp"))
        if not t:
            continue
        idx = min(buckets - 1, max(0, int((t - lo) / step)))
        for stream in ("events", _group(row).lower()):
            grid[(idx, stream)] = grid.get((idx, stream), 0) + 1
        if row.get("is_detection"):
            grid[(idx, "detection")] = grid.get((idx, "detection"), 0) + 1
    out: List[m.DensityBucket] = []
    for (idx, stream), count in sorted(grid.items()):
        b_lo = lo + step * idx
        out.append(m.DensityBucket(start=b_lo.isoformat(),
                                   end=(b_lo + step).isoformat(),
                                   stream=stream, count=count))
    return out


def coverage(v1: Dict[str, Any], rows: List[Dict[str, Any]],
             start: Optional[str], end: Optional[str]
             ) -> List[m.CoverageInterval]:
    """UNKNOWN-first. A state that asserts collection needs proof."""
    stamps = [t for t in (_parse(r.get("timestamp")) for r in rows) if t]
    out: List[m.CoverageInterval] = []
    if stamps:
        out.append(m.CoverageInterval(
            state=m.COV_OBSERVED,
            start=min(stamps).isoformat(), end=max(stamps).isoformat(),
            authority="OBSERVATIONS_PRESENT_IN_PROJECTION",
            boundary_certainty="PROVEN", absence_inferable=False,
            reason=None,
            proof_ref=tuple(r for row in rows[:1] for r in _row_refs(row))))
    unsupported = [r for r in rows
                   if (r.get("provenance") or {}).get("parser_state")
                   in ("UNSUPPORTED", "WINDOWS_EVENT_ID_NOT_SUPPORTED")]
    if unsupported:
        u_stamps = [t for t in (_parse(r.get("timestamp"))
                                for r in unsupported) if t]
        out.append(m.CoverageInterval(
            state=m.COV_NOT_CANONICALIZED,
            start=min(u_stamps).isoformat() if u_stamps else None,
            end=max(u_stamps).isoformat() if u_stamps else None,
            authority="PARSER_STATE_ON_RAW_EVIDENCE",
            boundary_certainty="PROVEN", absence_inferable=False,
            reason="raw retained; family not canonicalized",
            proof_ref=tuple(r for row in unsupported[:1]
                            for r in _row_refs(row))))
    requested_lo, requested_hi = _parse(start), _parse(end)
    if requested_lo and stamps and requested_lo < min(stamps):
        out.append(m.CoverageInterval(
            state=m.COV_UNKNOWN, start=requested_lo.isoformat(),
            end=min(stamps).isoformat(),
            authority="NOT_PROVABLE_FROM_THIS_PROJECTION",
            boundary_certainty="UNKNOWN", absence_inferable=False,
            reason="no proof of collection state before the first "
                   "observation in the window"))
    if requested_hi and stamps and requested_hi > max(stamps):
        out.append(m.CoverageInterval(
            state=m.COV_UNKNOWN, start=max(stamps).isoformat(),
            end=requested_hi.isoformat(),
            authority="NOT_PROVABLE_FROM_THIS_PROJECTION",
            boundary_certainty="UNKNOWN", absence_inferable=False,
            reason="no proof of collection state after the last observation"))
    if not rows:
        out.append(m.CoverageInterval(
            state=m.COV_UNKNOWN, start=start, end=end,
            authority="NOT_PROVABLE_FROM_THIS_PROJECTION",
            boundary_certainty="UNKNOWN", absence_inferable=False,
            reason="window returned no observations; this is not proof of "
                   "absence of activity"))
    return out


def resolve_focus(target: Optional[m.FocusTarget],
                  rows: List[Dict[str, Any]]) -> Optional[m.FocusResolution]:
    """Contract-level resolution over the current window (DT2-2 wires UI)."""
    if target is None:
        return None
    field_map = {
        "raw_event_id": lambda r: (r.get("provenance") or {}).get("raw_event_id"),
        "canonical_event_id": lambda r: (r.get("provenance") or {}).get("canonical_event_id"),
        "observation_id": lambda r: r.get("event_iid"),
        "process_iid": lambda r: r.get("process_iid"),
        "detection_id": lambda r: (r.get("detection") or {}).get("finding_id")
        or r.get("rule_id"),
    }
    if target.kind == "timestamp":
        return m.FocusResolution(
            state=m.FOCUS_RESOLVED, target=target, timestamp_only=True,
            basis="TIMESTAMP_IS_THE_BEST_AVAILABLE_TARGET",
            window={"at": target.value})
    getter = field_map[target.kind]
    hits = [r for r in rows if str(getter(r) or "") == target.value]
    if not hits:
        return m.FocusResolution(state=m.FOCUS_EVIDENCE_MISSING, target=target,
                                 basis="NOT_PRESENT_IN_THIS_WINDOW")
    if target.kind != "process_iid" and len(hits) > 1:
        return m.FocusResolution(state=m.FOCUS_AMBIGUOUS, target=target,
                                 basis=f"{len(hits)}_CANDIDATES")
    hit = hits[0]
    return m.FocusResolution(
        state=m.FOCUS_RESOLVED, target=target, basis="EXACT_EVIDENCE_ID",
        window={"at": hit.get("timestamp")},
        observation_id=str(hit.get("event_iid")),
        process_iid=hit.get("process_iid"),
        detection_id=str((hit.get("detection") or {}).get("finding_id")
                         or hit.get("rule_id") or "") or None)


def build(v1: Dict[str, Any], *, endpoint_id: str,
          requested_start: Optional[str] = None,
          requested_end: Optional[str] = None,
          focus: Optional[m.FocusTarget] = None) -> m.TrajectoryWindow:
    rows: List[Dict[str, Any]] = list(v1.get("events") or [])
    axis_v1 = v1.get("lane_axis") or {}
    scoped = (v1.get("projection") or {}).get("axis_scope") \
        or axis_v1.get("scope")
    axis = m.TrajectoryAxis(
        mode=("FILTER_SCOPED" if scoped and "FILTER" in str(scoped).upper()
              else "ENDPOINT_INVARIANT"),
        total_lanes=int(axis_v1.get("total_lanes") or 0),
        lane_ids=tuple(str(l.get("lane_id")) for l in
                       (axis_v1.get("lanes") or []) if l.get("lane_id")))
    artifacts: Dict[str, m.ArtifactInstance] = {}
    observations: List[m.Observation] = []
    for row in rows:
        art = _artifact_of(row, endpoint_id)
        if art:
            artifacts.setdefault(art.artifact_id, art)
        observations.append(observation_of(
            row, endpoint_id, art.artifact_id if art else None))
    tr = v1.get("time_range") or {}
    stamps = [t for t in (_parse(r.get("timestamp")) for r in rows) if t]
    available = {"from": min(stamps).isoformat() if stamps else None,
                 "to": max(stamps).isoformat() if stamps else None,
                 "state": (m.AVAIL_AVAILABLE if stamps else m.AVAIL_EMPTY)}
    return m.TrajectoryWindow(
        endpoint_id=endpoint_id,
        requested_range={"from": requested_start, "to": requested_end},
        effective_range={"from": tr.get("start") or tr.get("from"),
                         "to": tr.get("end") or tr.get("to")},
        available_range=available,
        retention_boundary={"from": None, "to": None,
                            "state": m.AVAIL_UNKNOWN,
                            "basis": "RETENTION_NOT_PROVABLE_FROM_WINDOW"},
        axis=axis, observations=observations,
        relationships=relationships(rows, endpoint_id),
        detections=detections(rows, endpoint_id),
        density=density(rows, requested_start, requested_end),
        coverage=coverage(v1, rows, requested_start, requested_end),
        process_instances=process_instances(rows, endpoint_id),
        artifacts=list(artifacts.values()),
        focus=resolve_focus(focus, rows),
        cursor=(m.TrajectoryCursor.parse(v1["cursor"])
                if isinstance(v1.get("cursor"), dict) else None),
        next_cursor=(m.TrajectoryCursor.parse(v1["next_cursor"])
                     if isinstance(v1.get("next_cursor"), dict) else None),
        has_more=bool(v1.get("has_more")),
        applied_filters=(v1.get("filters_applied")
                         or {"kinds": v1.get("kinds"),
                             "dispositions": v1.get("dispositions")}),
        applied_search={"q": (v1.get("q") or None),
                        "mode": "SERVER_SIDE_SUBSTRING_DT2_5_PENDING"},
        availability={
            "observations": m.AVAIL_AVAILABLE if rows else m.AVAIL_EMPTY,
            "relationships": m.AVAIL_AVAILABLE if rows else m.AVAIL_EMPTY,
            "detections": m.AVAIL_AVAILABLE if rows else m.AVAIL_EMPTY,
            "density": m.AVAIL_AVAILABLE if rows else m.AVAIL_EMPTY,
            "coverage": m.AVAIL_AVAILABLE,
            "process_end_evidence": m.AVAIL_UNAVAILABLE,   # no Sysmon 5
            "signer_evidence": m.AVAIL_UNAVAILABLE,
            "module_load_evidence": m.AVAIL_UNAVAILABLE,
        },
        provenance={"engine": "nivxforge.trajectory",
                    "contract": m.DT2_CONTRACT_VERSION,
                    "source_projection": (v1.get("projection") or {}).get(
                        "state"),
                    "creates_no_store": True})


def augment(v1: Dict[str, Any], *, endpoint_id: str,
            requested_start: Optional[str] = None,
            requested_end: Optional[str] = None,
            focus: Optional[m.FocusTarget] = None) -> Dict[str, Any]:
    """Return the V1 dict with ADDITIVE `dt2` key. V1 keys are untouched."""
    window = build(v1, endpoint_id=endpoint_id,
                   requested_start=requested_start,
                   requested_end=requested_end, focus=focus)
    v1["dt2"] = window.to_dict()
    return v1
