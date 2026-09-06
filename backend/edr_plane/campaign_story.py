"""P0-F.7 · Campaign Story — a READ MODEL, not a second source of truth.

It writes nothing and decides nothing. Every field on screen is copied
from the authoritative records the investigation and response planes
already use:

    workspace_cases.endpoint_campaign      the consolidated incident (P0-F.2)
    workspace_cases.xdr_pipeline           IUE id · ICE matches · VEEE
    edr_raw_events (+ derivations)          immutable bytes · parser state ·
                                            detection outcome
    v2_shadow_observations                  canonical evidence · process iids
    edr_endpoints                           endpoint identity + isolation
    edr_response_commands                   response lifecycle + verification

Two rules it exists to hold:

  * **Nothing is inferred from the existence of something else.** A step
    with no evidence renders as a GAP naming which of the six §6 states
    applies — never as an event that "must have" happened.
  * **The response link is honest about its own strength.** Response
    commands are endpoint-scoped, not incident-keyed, so a command is
    correlated by endpoint + the campaign's activity window and the story
    says exactly that instead of implying the analyst's kill was recorded
    against this incident.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from edr_plane.response import COLLECTION as RESPONSE_COLLECTION
from edr_plane.response import proof_of

ENGINE_ID = "nivxray::edr_plane::campaign_story"
#: Same window the incident materialiser consolidates on (P0-F.2).
RESPONSE_WINDOW_MINUTES = 30


def _iso_plus(ts: str, minutes: int) -> str:
    try:
        return (datetime.fromisoformat(ts) +
                timedelta(minutes=minutes)).isoformat()
    except (TypeError, ValueError):
        return ts or ""


def _hhmmss(ts: Optional[str]) -> str:
    return (ts or "")[11:19] or "unknown time"


async def _activity(db, tenant_id: str, det: Dict[str, Any]
                    ) -> Dict[str, Any]:
    """One observed behaviour, with its provenance chain and per-field
    evidence states. Absent evidence is named, never filled in."""
    raw_id = det.get("raw_event_id")
    raw = await db["edr_raw_events"].find_one(
        {"tenant_id": tenant_id, "raw_id": raw_id},
        {"_id": 0, "payload": 1, "derivations": 1, "ingest_time": 1,
         "trust_state": 1, "authentication": 1}) if raw_id else None
    ev: Dict[str, Any] = {}
    parser_state = "UNKNOWN"
    if raw:
        try:
            ev = json.loads(raw.get("payload") or "")
        except (ValueError, TypeError):
            parser_state = "PARSER_FAILED"
        ders = raw.get("derivations") or []
        parser_state = next((d.get("parser_state") for d in reversed(ders)
                             if d.get("parser_state")), parser_state)
        outcomes = [d.get("outcome") for d in ders if d.get("outcome")]
    else:
        outcomes = []

    obs = await db["v2_shadow_observations"].find_one(
        {"tenant_id": tenant_id,
         "canonical_event_id": det.get("canonical_event_id")},
        {"_id": 0, "event.process": 1, "event.kind": 1,
         "canonical_event_id": 1,
         "epistemic_state": 1}) if det.get("canonical_event_id") else None
    resolved_via = "canonical_event_id" if obs else None
    if not obs and raw_id:
        # A LOOKUP, not an inference: the pipeline stamps its own canonical
        # id suffix while the bridge stamps the generation, so the two ids
        # for one real event can differ. The raw event id is carried inside
        # the canonical evidence provenance, so it resolves the identity
        # exactly, without guessing.
        obs = await db["v2_shadow_observations"].find_one(
            {"tenant_id": tenant_id,
             "event.provenance.ingest_job_id": raw_id},
            {"_id": 0, "event.process": 1, "event.kind": 1,
             "canonical_event_id": 1, "epistemic_state": 1})
        resolved_via = "raw_event_id" if obs else None
    proc = ((obs or {}).get("event") or {}).get("process") or {}
    pdet = det.get("process") or {}

    lookup = ev.get("parent_lookup_state")
    states = {
        "process_image": "OBSERVED" if (ev.get("image_path")
                                        or pdet.get("name")) else "UNKNOWN",
        "command_line": "OBSERVED" if pdet.get("command_line") else
                        "NOT_OBSERVED",
        "process_start_identity": ("OBSERVED"
                                   if isinstance(ev.get("start_ticks"), int)
                                   else "NOT_COLLECTED"),
        "parent_process": {"OBSERVED": "OBSERVED",
                           "KERNEL_BOUNDARY": "OBSERVED",
                           "PARENT_NOT_PRESENT": "NOT_OBSERVED",
                           "PID_REUSED_PARENT_NOT_ATTRIBUTABLE": "UNKNOWN"
                           }.get(lookup, "UNKNOWN" if raw else "NOT_OBSERVED"),
        "process_exit": "NOT_SUPPORTED",
        "file_writer": "NOT_SUPPORTED",
        "parser": parser_state,
    }
    return {
        "at": det.get("at"),
        "verdict": det.get("verdict"), "score": det.get("score"),
        "rule_ids": det.get("rule_ids") or [],
        "process": {"pid": pdet.get("pid"), "ppid": pdet.get("ppid"),
                    "name": pdet.get("name") or ev.get("image"),
                    "image_path": ev.get("image_path"),
                    "command_line": pdet.get("command_line"),
                    "user": ev.get("user"),
                    "start_time": ev.get("start_time"),
                    "start_ticks": ev.get("start_ticks"),
                    "parent_name": ev.get("parent_image"),
                    "parent_lookup_state": lookup},
        "evidence_states": states,
        #: Copied verbatim from the canonical evidence — the evidence plane's
        #: own declaration of what it could not see and cannot produce.
        "epistemic_state": (obs or {}).get("epistemic_state"),
        "provenance": {
            "raw_event_id": raw_id,
            "raw_event_retained": bool(raw),
            "trust_state": (raw or {}).get("trust_state"),
            "authenticated_endpoint": ((raw or {}).get("authentication")
                                       or {}).get("authenticated_endpoint_id"),
            "canonical_event_id": det.get("canonical_event_id"),
            "canonical_event_id_in_evidence_plane": (obs or {}).get(
                "canonical_event_id"),
            "process_identity_resolved_via": resolved_via,
            "process_iid": proc.get("iid"),
            "parent_iid": proc.get("parent_iid"),
            "canonical_kind": ((obs or {}).get("event") or {}).get("kind"),
            "derivation_outcomes": outcomes,
            "detection_rule_ids": det.get("rule_ids") or [],
        },
    }


def _narrate(inc: Dict[str, Any], ep: Dict[str, Any],
             acts: List[Dict[str, Any]], reasoning: Dict[str, Any],
             responses: List[Dict[str, Any]]) -> List[str]:
    """Plain English, generated only from fields that exist."""
    camp = inc["campaign"]
    host = ep.get("hostname") or camp.get("endpoint_id")
    lines = [
        f"On {host} the sensor observed {camp['detection_count']} "
        f"behaviour(s) between {_hhmmss(camp.get('first_activity_at'))} and "
        f"{_hhmmss(camp.get('last_activity_at'))} UTC that the "
        f"authoritative detection content matched.",
    ]
    for a in acts[:6]:
        p = a["process"]
        who = p.get("command_line") or p.get("image_path") or p.get("name") \
            or "a process with no observed image"
        parent = (f"launched by {p['parent_name']}"
                  if a["evidence_states"]["parent_process"] == "OBSERVED"
                  and p.get("parent_name")
                  else "its parent was NOT OBSERVED, so no ancestry is "
                       "claimed")
        lines.append(
            f"{_hhmmss(a.get('at'))} · {who} (pid {p.get('pid')}, {parent}) "
            f"→ matched {', '.join(a['rule_ids']) or 'no rule'} · "
            f"{a.get('verdict')} {a.get('score')}")
    if len(acts) > 6:
        lines.append(f"… and {len(acts) - 6} further observed behaviour(s) "
                     f"in the same campaign.")
    v = reasoning.get("veee") or {}
    if v:
        lines.append(
            "Why it was judged " + str(v.get("label")).lower() + ": "
            + str(v.get("reason")) + ". Contributors: "
            + ("; ".join(f"{c.get('source')} +{c.get('weight')} "
                         f"({c.get('detail')})"
                         for c in (v.get("contributors") or []))
               or "none recorded")
            + f". ICE correlation state: {reasoning.get('ice_state')}.")
    lines.append(
        f"These detections were consolidated into ONE incident "
        f"({inc.get('incident_number')}) keyed on (tenant, endpoint) within "
        f"a rolling {camp.get('window_minutes')}-minute window, so one "
        f"intrusion does not read as many.")
    verified = [r for r in responses if r["proof"]["success_claimed"]]
    if not responses:
        lines.append("NO response action is on record for this endpoint "
                     "inside the campaign window. That is an absence of "
                     "action, not an absence of risk.")
    else:
        lines.append(
            f"{len(responses)} response action(s) are correlated to this "
            f"campaign by endpoint and time window (response commands are "
            f"endpoint-scoped, NOT incident-keyed): "
            + "; ".join(f"{r['action']} → {r['state']}" for r in responses)
            + f". {len(verified)} of them is/are backed by post-action "
              f"endpoint evidence.")
    return lines


async def build_story(db, *, tenant_id: str, incident_id: str
                      ) -> Dict[str, Any]:
    inc = await db["workspace_cases"].find_one(
        {"tenant_id": tenant_id, "id": incident_id}, {"_id": 0})
    if not inc:
        return {"error": "INCIDENT_NOT_FOUND",
                "reason": f"no incident {incident_id} in this tenant"}
    camp = inc.get("endpoint_campaign") or {}
    if not camp:
        return {"error": "NOT_AN_ENDPOINT_CAMPAIGN",
                "reason": ("this incident was not raised from endpoint "
                           "evidence, so no endpoint campaign story exists "
                           "for it. Nothing is invented to fill the page."),
                "incident_id": incident_id}

    dets = camp.get("detections") or []
    acts = [await _activity(db, tenant_id, d) for d in dets]
    acts.sort(key=lambda a: a.get("at") or "")

    pipe = inc.get("xdr_pipeline") or {}
    reasoning = {
        "iue_id": pipe.get("iue_id"),
        "ice_matches": pipe.get("ice_matches") or [],
        "ice_state": ((pipe.get("veee") or {}).get("inputs") or {})
        .get("ice_state") or ("MATCHED" if pipe.get("ice_matches")
                              else "NO_MATCH"),
        "veee": pipe.get("veee") or {},
        "verdict_card": inc.get("verdict_card") or {},
        "engines": {"detection": pipe.get("engine_id"),
                    "verdict": (inc.get("verdict_card") or {}).get("engine")},
    }

    ep = await db["edr_endpoints"].find_one(
        {"tenant_id": tenant_id, "endpoint_id": camp.get("endpoint_id")},
        {"_id": 0, "endpoint_id": 1, "hostname": 1, "platform": 1,
         "enrollment_state": 1, "credential_state": 1, "sensor_state": 1,
         "isolation": 1}) or {"endpoint_id": camp.get("endpoint_id")}

    window_end = _iso_plus(camp.get("last_activity_at") or "",
                           RESPONSE_WINDOW_MINUTES)
    responses: List[Dict[str, Any]] = []
    async for c in db[RESPONSE_COLLECTION].find(
            {"tenant_id": tenant_id, "endpoint_id": camp.get("endpoint_id")},
            {"_id": 0}).sort("requested_at", 1):
        inside = bool(camp.get("first_activity_at")
                      and camp["first_activity_at"] <= (c.get("requested_at")
                                                        or "") <= window_end)
        if not inside:
            continue
        responses.append({
            "command_id": c["command_id"], "action": c["action"],
            "state": c["state"], "requested_by": c.get("requested_by"),
            "requested_at": c.get("requested_at"),
            "verified_at": c.get("verified_at"),
            "target": c.get("target") or {},
            "authorisation": c.get("authorisation"),
            "history": c.get("history") or [],
            "sensor_result": c.get("sensor_result"),
            "verification": c.get("verification"),
            "proof": proof_of(c),
            "link_basis": ("endpoint_id + campaign activity window "
                           f"(+{RESPONSE_WINDOW_MINUTES} min)"),
            "link_strength": "CORRELATED_BY_ENDPOINT_AND_TIME_NOT_INCIDENT_"
                             "KEYED",
        })

    incident = {
        "incident_id": inc.get("id"),
        "incident_number": inc.get("incident_number"),
        "title": inc.get("title"), "state": inc.get("incident_state"),
        "priority": inc.get("incident_priority"),
        "created_at": inc.get("created_at"),
        "campaign": {**{k: camp.get(k) for k in
                        ("endpoint_id", "hostname", "first_activity_at",
                         "last_activity_at", "window_minutes", "rule_ids",
                         "max_label", "max_score")},
                     "detection_count": len(dets)},
    }

    gaps = [
        {"gap": "process_exit", "state": "NOT_SUPPORTED",
         "reason": "the sensor polls /proc; it cannot distinguish an exit "
                   "from a missed scan, so no exit time is ever claimed"},
        {"gap": "file_writer_attribution", "state": "NOT_SUPPORTED",
         "reason": "a path change does not identify the process that made "
                   "it without syscall-level fidelity (no eBPF)"},
        {"gap": "sub_poll_interval_execution", "state": "NOT_OBSERVED",
         "reason": "anything that starts and exits inside one poll interval "
                   "is never evaluated — a visibility gap, not an absence "
                   "of activity"},
        {"gap": "response_to_incident_binding", "state": "NOT_COLLECTED",
         "reason": "response commands are endpoint-scoped; this story "
                   "correlates them by endpoint and time and says so rather "
                   "than implying an incident-keyed link"},
    ]
    for a in acts:
        if a["evidence_states"]["parent_process"] != "OBSERVED":
            lookup_state = a["process"].get("parent_lookup_state") \
                or "not resolved"
            gaps.append({"gap": "process_ancestry",
                         "state": a["evidence_states"]["parent_process"],
                         "reason": (f"pid {a['process'].get('pid')} "
                                    f"({a['process'].get('name')}): parent "
                                    f"{lookup_state} — no ancestor is "
                                    f"invented")})
        if not a["provenance"]["raw_event_retained"]:
            gaps.append({"gap": "raw_evidence", "state": "NOT_OBSERVED",
                         "reason": ("raw event "
                                    + str(a["provenance"]["raw_event_id"])
                                    + " is referenced by the incident but "
                                      "was not found in this tenant")})
        if not a["provenance"]["process_iid"]:
            gaps.append({"gap": "canonical_process_identity",
                         "state": "NOT_OBSERVED",
                         "reason": ("canonical evidence "
                                    + str(a["provenance"]
                                          ["canonical_event_id"])
                                    + " carries no process identity")})
        elif a["provenance"]["process_identity_resolved_via"] == \
                "raw_event_id":
            gaps.append({"gap": "canonical_id_scheme_divergence",
                         "state": "UNKNOWN",
                         "reason": ("the incident records canonical id "
                                    + str(a["provenance"]
                                          ["canonical_event_id"])
                                    + " while the evidence plane holds "
                                    + str(a["provenance"]
                                          ["canonical_event_id_in_evidence_"
                                           "plane"])
                                    + " for the same raw event; the link "
                                      "was resolved by raw_event_id, which "
                                      "is exact, but the two id schemes "
                                      "diverging is a real defect and is "
                                      "shown rather than hidden")})

    ep_id = camp.get("endpoint_id")
    return {
        "engine_id": ENGINE_ID,
        "read_model": True,
        "sources": ["workspace_cases.endpoint_campaign",
                    "workspace_cases.xdr_pipeline", "edr_raw_events",
                    "v2_shadow_observations", "edr_endpoints",
                    RESPONSE_COLLECTION],
        "incident": incident, "endpoint": ep, "activities": acts,
        "reasoning": reasoning, "responses": responses, "gaps": gaps,
        "narrative": _narrate(incident, ep, acts, reasoning, responses),
        "pivots": {
            "process_tree": f"/edr/process-tree?endpoint_id={ep_id}",
            "device_trajectory": f"/xdr/endpoints/{ep_id}/trajectory",
            "endpoint_detections": f"/api/edr/endpoint-detections?"
                                   f"endpoint_id={ep_id}",
            "incident": f"/xdr/incidents/{inc.get('id')}",
            "response_verification": "/xdr/admin/edr-response",
        },
        "honesty_note": ("A projection over the SAME authoritative records "
                         "the investigation and response planes use. It "
                         "stores nothing, decides nothing, and never infers "
                         "one step from the existence of another."),
    }
