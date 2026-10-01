"""Deterministic Activity Details builder. Missing sources render NOT_WIRED; empty sources never mean clean."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import ABSENCE_STATEMENT, NO_DETECTION_STATEMENT, VIEW_MODEL_VERSION
from .contracts import (AnalystDisposition, ActivityDetail, Relationship, RetroEntry, Section, TIResult,
                        validate_history)

PROOF = {"REQUESTED": "NOTHING_HAS_HAPPENED_YET", "AUTHORIZED": "AUTHORISED_NOT_YET_SENT",
         "ACCEPTED": "ACCEPTED_NOT_EXECUTED", "DISPATCHED": "CLAIMED_BY_ENDPOINT_NO_RESULT",
         "EXECUTED": "SENSOR_CLAIM_ONLY_NOT_VERIFIED", "VERIFIED": "VERIFIED_BY_POST_ACTION_EVIDENCE",
         "FAILED": "FAILED", "VERIFICATION_FAILED": "VERIFICATION_FAILED",
         "CAPABILITY_UNAVAILABLE": "CAPABILITY_NOT_PRESENT", "REFUSED": "REFUSED_BEFORE_DISPATCH"}
NOT_WIRED = "No backend source is wired for this section yet."
MAX_ITEMS = 50


def _ent(f: Dict[str, Any], k: str) -> Dict[str, Any]:
    v = f.get(k)
    return v if isinstance(v, dict) else {}


def frame_keys(f: Dict[str, Any]) -> set:
    keys = {f.get("canonical_evidence_id"), f.get("frame_iid")} | set(f.get("evidence_ids") or ())
    return {k for k in keys if k}


def _refs_hit(refs: Iterable[Dict[str, Any]], keys: set) -> bool:
    return any(r.get("canonical_event_id") in keys or r.get("raw_id") in keys or r.get("record_id") in keys
               for r in refs or ())


def observables(f: Dict[str, Any]) -> List[Tuple[str, str]]:
    proc, net = _ent(f, "process"), _ent(f, "network")
    out = []
    for typ, val in (("sha256", f.get("sha256") or proc.get("sha256") or f.get("hash")),
                     ("ip", f.get("remote_ip") or f.get("destination_ip") or net.get("remote_ip")),
                     ("domain", f.get("domain") or net.get("domain"))):
        if isinstance(val, str) and val:
            out.append((typ, val[:512]))
    return out


def _sec(key, items=(), *, none_state="EMPTY", statements=()):
    items = tuple(items)[:MAX_ITEMS]
    return Section(key, "AVAILABLE" if items else none_state, items, tuple(statements))


def _observation(f):
    proc = _ent(f, "process")
    item = {k: v for k, v in {
        "action": f.get("action"), "label": f.get("label"), "ts": f.get("ts"), "lane": f.get("lane"),
        "command_line": f.get("command_line") or proc.get("command_line"),
        "process": proc.get("label") or proc.get("iid"), "parent": _ent(f, "parent").get("label")
        or _ent(f, "parent").get("iid"), "user": _ent(f, "user").get("label"),
        "device": _ent(f, "device").get("label") or _ent(f, "device").get("iid")}.items() if v}
    return Section("observation", "AVAILABLE" if item else "UNKNOWN", (item,) if item else ())


def _causal(f, relationships: Optional[Sequence[Relationship]]):
    rels = list(relationships or [])
    if not rels:
        parent, ent = _ent(f, "parent").get("iid"), (_ent(f, "entity") or _ent(f, "process")).get("iid")
        keys = sorted(frame_keys(f))
        if parent and ent and keys:
            rels.append(Relationship("process->child", parent, ent, "SUPPORTED_RELATIONSHIP", tuple(keys[:4]),
                                     linkage=None, reason="sensor-reported parent identity on this event"))
        else:
            rels.append(Relationship("process->child", ent or "unknown", None, "UNKNOWN",
                                     reason="parent linkage unavailable; no edge inferred"))
    items = [{"type": r.type, "source": r.source, "target": r.target, "state": r.state,
              "linkage": r.linkage, "evidence_refs": list(r.evidence_refs), "reason": r.reason} for r in rels]
    return _sec("causal_context", items, statements=("Temporal order alone is never shown as causality.",))


def _detections(f, behavior, keys):
    items = []
    rule = f.get("rule_id") or _ent(f, "provenance").get("rule_id")
    if rule:
        items.append({"engine": "deterministic_rules", "rule_id": rule, "confidence": f.get("confidence"),
                      "evidence_refs": sorted(keys)[:4]})
    for d in behavior or []:
        if _refs_hit(d.get("evidence_refs"), keys):
            items.append({"engine": "edr_behavior", "rule_id": d.get("rule_id"), "rule_version": d.get("rule_version"),
                          "detection_id": d.get("detection_id"), "status": d.get("status"),
                          "severity": d.get("severity"), "confidence": d.get("confidence"),
                          "mitre": [m.get("technique_id") for m in d.get("mitre") or []],
                          "evidence_refs": list(d.get("evidence_keys") or [])[:16]})
    return _sec("detection_attribution", items, statements=() if items else (NO_DETECTION_STATEMENT, ABSENCE_STATEMENT))


def _behavioral(behavior, keys):
    if behavior is None:
        return Section("behavioral", "NOT_WIRED", statements=(NOT_WIRED,))
    items = [{"rule_id": d.get("rule_id"), "explanation": d.get("explanation"),
              "matched_stages": [s.get("stage_id") for s in d.get("matched_stages") or []]}
             for d in behavior if _refs_hit(d.get("evidence_refs"), keys)]
    return _sec("behavioral", items, statements=() if items else ("No behavioral sequence matched this event.",
                                                                    ABSENCE_STATEMENT))


def _ml(ml, keys):
    if ml is None:
        return Section("ml", "NOT_WIRED", statements=(NOT_WIRED,))
    items = []
    for d in ml:
        env = d.get("signal") or {}
        if env and not _refs_hit(env.get("evidence_refs"), keys):
            continue
        if not env and d.get("anchor_canonical_event_id") not in keys:
            continue
        items.append({"model_id": d.get("model_id"), "model_version": d.get("model_version"),
                      "lifecycle": d.get("model_lifecycle") or "UNKNOWN", "outcome": d.get("outcome"),
                      "score": d.get("score"), "reasons": list(d.get("reasons") or []),
                      "top_features": [c.get("feature") for c in (env.get("explanation") or {}).get("top_features", [])]})
    return _sec("ml", items, statements=("ML is a signal, never a verdict.",) + (
        () if items else ("No ML decision recorded for this event.",)))


def _ti(f, ti):
    if ti is None:
        return Section("threat_intel", "NOT_WIRED", statements=(NOT_WIRED,))
    by = {(r.indicator_type, r.indicator): r for r in ti}
    items = []
    for typ, val in observables(f):
        r = by.get((typ, val)) or TIResult(val, typ, "UNKNOWN", None, {"reason": "not enriched"})
        items.append({"indicator": r.indicator, "type": r.indicator_type, "state": r.state, "provider": r.provider})
    return _sec("threat_intel", items, statements=("NO_DATA and UNKNOWN are not BENIGN.",))


def _mitre(f, detection_items):
    attributed = {t for d in detection_items for t in d.get("mitre") or []}
    items = [{"technique": t, "attribution": "ATTRIBUTED" if t in attributed else "UNATTRIBUTED",
              "style": "threat" if t in attributed else "neutral"} for t in sorted(set(f.get("mitre") or ()))]
    return _sec("mitre", items, statements=("Only engine-attributed techniques are styled as threats.",))


def _response(cmds):
    if cmds is None:
        return (Section("response", "NOT_WIRED", statements=(NOT_WIRED,)),
                Section("verification", "NOT_WIRED", statements=(NOT_WIRED,)))
    resp, ver = [], []
    for c in cmds:
        st = c.get("state") if c.get("state") in PROOF else "UNKNOWN_STATE"
        resp.append({"command_id": c.get("command_id"), "action": c.get("action"), "state": st,
                     "proof": PROOF.get(st, "UNKNOWN_OUTCOME")})
        ver.append({"command_id": c.get("command_id"), "verified": st == "VERIFIED",
                    "proof": PROOF.get(st, "UNKNOWN_OUTCOME")})
    stmt = ("Accepted ≠ executed ≠ contained ≠ verified.",)
    return _sec("response", resp, statements=stmt), _sec("verification", ver, statements=stmt)


def _missing(f, behavior_results, ml, ti_items, rel_items):
    out = []
    if f.get("bridge_state") in ("LEGACY_UNBRIDGED", "REFERENCED_RECORD_ABSENT"):
        out.append({"source": "evidence_bridge", "detail": f["bridge_state"]})
    for r in rel_items:
        if r["state"] == "UNKNOWN":
            out.append({"source": "causal", "detail": r["reason"]})
    for r in behavior_results or []:
        if r.get("outcome") == "INSUFFICIENT_EVIDENCE":
            out.append({"source": "edr_behavior", "rule_id": r.get("rule_id"), "detail": "; ".join(r.get("reasons") or [])})
    for d in ml or []:
        for reason in d.get("reasons") or []:
            out.append({"source": "edr_ml", "model_id": d.get("model_id"), "detail": reason})
    for t in ti_items:
        if t["state"] in ("UNKNOWN", "NO_DATA", "UNAVAILABLE", "RATE_LIMITED", "ERROR"):
            out.append({"source": "threat_intel", "indicator": t["indicator"], "detail": t["state"]})
    return _sec("missing_evidence", out)


def _retro(history):
    if history is None:
        return Section("retrospection", "NOT_WIRED", statements=(NOT_WIRED,))
    h = validate_history(list(history))
    return _sec("retrospection", [{"version": e.version, "at": e.at, "trigger": e.trigger,
                                   "assessment": e.assessment, "supersedes": e.supersedes,
                                   "evidence_refs": list(e.evidence_refs)} for e in h],
                statements=("History is append-only; earlier versions are never rewritten.",))


def _pivots(f, keys):
    ev = sorted(keys)[:1]
    out = [{"pivot": "process_ancestry", "target": _ent(f, "parent").get("iid"), "evidence_refs": ev}] \
        if _ent(f, "parent").get("iid") else []
    out += [{"pivot": {"sha256": "file_trajectory", "ip": "network_hunt", "domain": "dns_hunt"}[t],
             "target": v, "evidence_refs": ev} for t, v in observables(f)]
    return _sec("pivots", out)


def build_activity_detail(frame: Dict[str, Any], *, tenant_id: str, endpoint_id: Optional[str] = None,
                          behavior_detections: Optional[List[Dict[str, Any]]] = None,
                          behavior_results: Optional[List[Dict[str, Any]]] = None,
                          ml_decisions: Optional[List[Dict[str, Any]]] = None,
                          ti_results: Optional[List[TIResult]] = None,
                          response_commands: Optional[List[Dict[str, Any]]] = None,
                          assessment_history: Optional[List[RetroEntry]] = None,
                          analyst_disposition: Optional[AnalystDisposition] = None,
                          relationships: Optional[Sequence[Relationship]] = None) -> ActivityDetail:
    if not tenant_id:
        raise ValueError("tenant_id is mandatory (no default tenant)")
    for src in (behavior_detections or []) + [d.get("signal") or d for d in ml_decisions or []] \
            + (response_commands or []):
        if src.get("tenant_id") not in (None, tenant_id):
            raise ValueError("cross-tenant input rejected")
    keys = frame_keys(frame)
    det = _detections(frame, behavior_detections, keys)
    causal = _causal(frame, relationships)
    ti = _ti(frame, ti_results)
    ml = _ml(ml_decisions, keys)
    resp, ver = _response(response_commands)
    supporting = [dict(i, kind="detection") for i in det.items] + \
        [{"kind": "ml_signal", "model_id": i["model_id"], "lifecycle": i["lifecycle"], "score": i["score"]}
         for i in ml.items if i["outcome"] == "EMITTED"] + \
        [{"kind": "threat_intel", **i} for i in ti.items if i["state"] in ("MALICIOUS", "SUSPICIOUS")]
    contradicting = [{"kind": "threat_intel_context", **i, "note": "context, not exoneration"}
                     for i in ti.items if i["state"] == "BENIGN"]
    history = list(assessment_history or [])
    machine = history[-1].assessment if history else "NOT_ASSESSED"
    sections = (
        _observation(frame), causal, det, _behavioral(behavior_detections, keys), ti, ml,
        _sec("supporting_evidence", supporting),
        _sec("contradicting_evidence", contradicting,
             statements=() if contradicting else ("No contradicting evidence recorded; this is not proof of malice.",)),
        _missing(frame, behavior_results, ml_decisions, list(ti.items), [dict(i) for i in causal.items]),
        _mitre(frame, det.items), _retro(assessment_history), resp, ver,
        _sec("provenance", [{"frame_iid": frame.get("frame_iid"), "canonical_evidence_id":
                             frame.get("canonical_evidence_id"), "bridge_state": frame.get("bridge_state") or "UNKNOWN",
                             "frame_provenance": dict(_ent(frame, "provenance")), "view_version": VIEW_MODEL_VERSION}]),
        _pivots(frame, keys))
    return ActivityDetail(VIEW_MODEL_VERSION, tenant_id, endpoint_id, frame.get("frame_iid") or "unknown",
                          machine, analyst_disposition, sections)
