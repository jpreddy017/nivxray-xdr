"""Detection construction: deterministic ID, explanation, provenance and merge."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from . import CONTRACT_VERSION, ENGINE_ID, ENGINE_VERSION, ML_ONLY_REASON
from .contracts import (LINK_PID_SURROGATE, STATUS_OPEN, STATUS_SUPPRESSED,
                        STATUS_TESTING, Detection, EvaluationResult, sha, utc)
from .normalize import is_ml_evidence, scope_key
from .rules import SequenceRule

PID_SURROGATE_PENALTY = 15
NEGATIVE_UNPROVEN_PENALTY = 10


def detection_id(tenant_id: str, endpoint_id: str, rule: SequenceRule, scope: str,
                 anchor_time: datetime) -> str:
    """tenant + endpoint + rule/version + scope entity + bounded occurrence (window bucket).

    Generation, ObjectId, lease and retry count are deliberately excluded.
    """
    bucket = int(anchor_time.timestamp()) // rule.time_window_seconds
    return "e3det_" + sha("det.v1", tenant_id, endpoint_id, rule.rule_id, rule.version,
                          scope, bucket)[:32]


def _summary(rec) -> str:
    f = rec.fields
    k = rec.kind
    if k == "PROCESS":
        p = f.get("process", {})
        par = f.get("parent", {}).get("name") or "?"
        return f"process {p.get('name') or '?'} (parent {par})"
    if k == "FILE":
        return f"file {f.get('file', {}).get('operation') or '?'} {f.get('file', {}).get('name') or '?'}"
    if k == "REGISTRY":
        return f"registry {f.get('registry', {}).get('operation') or '?'} {f.get('registry', {}).get('key') or '?'}"
    if k == "DNS":
        return f"dns query {f.get('dns', {}).get('query_name') or '?'}"
    if k == "NETWORK":
        n = f.get("network", {})
        return f"network {n.get('direction') or '?'} to {n.get('dest_ip') or '?'}:{n.get('dest_port') or '?'}"
    if k == "AUTH":
        return f"logon type {f.get('auth', {}).get('logon_type') or '?'}"
    if k == "DETECTION":
        return f"detection {f.get('detection', {}).get('rule_id') or '?'}"
    return k.lower()


def explain(rule: SequenceRule, result: EvaluationResult, endpoint_id: str,
            suppression: Optional[Dict[str, Any]], notes: List[str]) -> str:
    lines = [f"Rule {rule.rule_id} v{rule.version} '{rule.name}' matched "
             f"{len(result.stages)} stage(s) on endpoint {endpoint_id} within "
             f"{rule.time_window_seconds}s."]
    for m in result.stages:
        for rec in m.evidence:
            lines.append(f"- [{m.stage_id}{' optional' if m.optional else ''}] {utc(rec.event_time)} "
                         f"{_summary(rec)} (evidence {rec.stable_key}, raw {rec.ref.raw_id})")
        for pair, how in sorted(m.linkage.items()):
            lines.append(f"  linkage {pair}: {how}")
    if rule.mitre:
        lines.append("MITRE: " + ", ".join(m["technique_id"] for m in rule.mitre))
    for u in result.reasons + notes:
        lines.append(f"note: {u}")
    if suppression:
        lines.append(f"suppressed: {suppression['kind']} ({suppression['reason']})")
    return "\n".join(lines)


def build(rule: SequenceRule, result: EvaluationResult, *, tenant_id: str, endpoint_id: str,
          suppression: Optional[Dict[str, Any]], notes: List[str], adjustments, mode: str,
          trigger: Optional[Dict[str, Any]], now: datetime) -> Detection:
    recs = [e for m in result.stages for e in m.evidence]
    if not recs:
        raise ValueError("a detection requires evidence")
    if all(is_ml_evidence(e) for e in recs):
        raise ValueError(ML_ONLY_REASON)
    anchor = result.stages[0].first
    scope, _ = scope_key(anchor, rule.entity_scope)
    conf = rule.confidence + sum(s.confidence_bonus for s in rule.stages
                                 if s.optional and any(m.stage_id == s.id for m in result.stages))
    links = {k: v for m in result.stages for k, v in m.linkage.items()}
    adj_notes = []
    if LINK_PID_SURROGATE in links.values():
        conf -= PID_SURROGATE_PENALTY
        adj_notes.append(f"-{PID_SURROGATE_PENALTY}: parent/child linkage is PID surrogate (not GUID)")
    if any(r.startswith("negative stage") for r in result.reasons):
        conf -= NEGATIVE_UNPROVEN_PENALTY
        adj_notes.append(f"-{NEGATIVE_UNPROVEN_PENALTY}: a negative stage could not be proven absent")
    for d, why in adjustments:
        conf += d
        adj_notes.append(f"{d:+d}: {why}")
    conf = max(0, min(100, conf))
    status = (STATUS_SUPPRESSED if suppression else
              STATUS_TESTING if rule.lifecycle == "TESTING" else STATUS_OPEN)
    by_key = {e.stable_key: e for e in recs}
    keys = sorted(by_key)
    ents: Dict[str, set] = {"process": set(), "user": set(), "file": set(), "domain": set(), "ip": set()}
    for e in recs:
        if e.process and e.process.process_iid:
            ents["process"].add(e.process.process_iid)
        for cat, path in (("user", ("user", "name")), ("file", ("file", "path")),
                          ("domain", ("dns", "query_name")), ("ip", ("network", "dest_ip"))):
            v = (e.fields.get(path[0]) or {}).get(path[1])
            if v:
                ents[cat].add(str(v))
    now_s = utc(now)
    return Detection(
        detection_id=detection_id(tenant_id, endpoint_id, rule, scope, anchor.event_time),
        tenant_id=tenant_id, endpoint_id=endpoint_id, rule_id=rule.rule_id,
        rule_version=rule.version, rule_content_hash=rule.content_hash,
        detection_type="BEHAVIORAL_SEQUENCE",
        first_seen=utc(min(e.event_time for e in recs)), last_seen=utc(max(e.event_time for e in recs)),
        severity=rule.severity, confidence=conf, status=status, scope_key=scope,
        matched_stages=[{"stage_id": m.stage_id, "type": m.kind, "optional": m.optional,
                         "evidence_keys": sorted({e.stable_key for e in m.evidence}),
                         "linkage": dict(sorted(m.linkage.items()))} for m in result.stages],
        involved_entities={k: sorted(v) for k, v in ents.items() if v},
        evidence_refs=[by_key[k].ref.to_dict() for k in keys], evidence_keys=keys,
        raw_refs=sorted({e.ref.raw_id for e in recs}),
        canonical_event_ids=sorted({e.ref.canonical_event_id for e in recs if e.ref.canonical_event_id}),
        process_identities=sorted(ents["process"]),
        mitre=[dict(m) for m in rule.mitre],
        explanation=explain(rule, result, endpoint_id, suppression, notes + adj_notes),
        provenance={"contract": CONTRACT_VERSION, "engine": ENGINE_ID,
                    "chain": ["RAW", "NORMALIZED", "ENTITY_PROCESS", "SEQUENCE_MATCH", "RULE",
                              "MITRE", "DETECTION"],
                    "normalizers": sorted({e.provenance.get("normalizer", "") for e in recs}),
                    "process_identity_authority": "edr_plane.canonical_bridge.bind_process_identity",
                    "evidence_stores": sorted({e.ref.store for e in recs}),
                    "rule": {"rule_id": rule.rule_id, "version": rule.version,
                             "content_hash": rule.content_hash, "lifecycle": rule.lifecycle,
                             "source": rule.provenance.get("source", "NATIVE")},
                    "mode": mode, "trigger": dict(trigger or {}),
                    "unknowns": list(result.reasons), "notes": list(notes),
                    "confidence_adjustments": adj_notes, "truncated_fields":
                        sorted({f for e in recs for f in e.truncated_fields})},
        engine_version=ENGINE_VERSION, created_at=now_s, suppression=suppression)


def merge(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Union evidence; never drops existing evidence. Rule version stays as created."""
    out = dict(existing)
    refs = {r["stable_key"]: r for r in existing.get("evidence_refs", [])}
    for r in new.get("evidence_refs", []):
        refs.setdefault(r["stable_key"], r)
    out["evidence_refs"] = [refs[k] for k in sorted(refs)]
    out["evidence_keys"] = sorted(refs)
    for k in ("raw_refs", "canonical_event_ids", "process_identities"):
        out[k] = sorted(set(existing.get(k, [])) | set(new.get(k, [])))
    ents = {c: set(v) for c, v in existing.get("involved_entities", {}).items()}
    for c, v in new.get("involved_entities", {}).items():
        ents.setdefault(c, set()).update(v)
    out["involved_entities"] = {c: sorted(v) for c, v in sorted(ents.items())}
    stages = {s["stage_id"]: dict(s) for s in existing.get("matched_stages", [])}
    for s in new.get("matched_stages", []):
        cur = stages.setdefault(s["stage_id"], dict(s))
        cur["evidence_keys"] = sorted(set(cur["evidence_keys"]) | set(s["evidence_keys"]))
    out["matched_stages"] = list(stages.values())
    out["first_seen"] = min(existing["first_seen"], new["first_seen"])
    out["last_seen"] = max(existing["last_seen"], new["last_seen"])
    out["confidence"] = max(existing["confidence"], new["confidence"])
    return out


def material(d: Dict[str, Any]) -> tuple:
    return (tuple(d.get("evidence_keys", [])), d.get("first_seen"), d.get("last_seen"),
            d.get("confidence"), d.get("status"))
