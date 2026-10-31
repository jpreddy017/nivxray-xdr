"""DT-I1D causal context (dt-i1.causal.v1). Deterministic, bounded, tenant-scoped. Chronology is never causality.

Mirrors frontend/src/v2/investigation/causalView.mjs; parity is asserted by tests/edr_investigation/test_dt_causal.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .contracts import CAUSAL_LINKAGES, RELATIONSHIP_STATES, _req

CAUSAL_VERSION = "dt-i1.causal.v1"
RESOLVER = "dt-i1d.frame_identity"
BASIS_GUID = "SYSMON_PROCESS_GUID"
BASIS_PID_ONLY = "PID_ONLY_NOT_GLOBALLY_STABLE"
WINDOW_MS = 60_000
MAX_ITEMS = 50
MAX_PRECEDING = 3
RELATIONSHIP_TYPES = ("spawned", "wrote", "executed", "queried", "resolved_to", "connected_to", "modified",
                      "co_occurred")
TEMPORAL = "Temporal order alone is never shown as causality."
PARENT_UNKNOWN = "Parent process: UNKNOWN — required parent-process identity unavailable for this observation."
PARENT_PID_ONLY = "Parent process: UNKNOWN — only a PID was reported; PID equality never establishes identity."
CHILD_UNKNOWN = "Process identity: UNKNOWN — this event carries no stable process identity."
ACTOR_UNKNOWN = "Actor process: UNKNOWN — this event carries no process identity."
ACTOR_PID_ONLY = "Actor process: UNKNOWN — only a PID was reported; PID equality never establishes identity."
NET_CORRELATED = ("Network relationship: CORRELATED — occurred in window; telemetry does not establish the "
                  "selected process initiated it.")
_EFFECT = {"file": "wrote", "registry": "modified", "network": "connected_to", "dns": "queried"}
_LANE = {"process": "Process", "file": "File", "registry": "Registry", "network": "Network", "dns": "DNS"}


@dataclass(frozen=True)
class CausalEdge:
    relationship_id: str
    relationship_type: str
    source_entity: Optional[str]
    target_entity: Optional[str]
    relationship_state: str
    evidence_refs: Tuple[str, ...]
    timestamp: Optional[str]
    window: Optional[Dict[str, str]]
    linkage: Optional[str]
    reason: str
    resolver: str
    resolver_version: str
    provenance: Dict[str, Any] = field(compare=False)

    def __post_init__(self) -> None:
        _req(self.relationship_state in RELATIONSHIP_STATES, f"bad relationship state {self.relationship_state!r}")
        _req(self.relationship_type in RELATIONSHIP_TYPES, f"bad relationship type {self.relationship_type!r}")
        _req(bool(self.reason), "every relationship states its reason")
        if self.relationship_state != "UNKNOWN":
            _req(bool(self.source_entity) and bool(self.target_entity) and bool(self.evidence_refs),
                 "non-UNKNOWN relationship needs source, target and evidence")
        if self.relationship_state == "PROVEN_CAUSAL":
            basis = self.provenance.get("identity_basis") or {}
            _req(self.linkage in CAUSAL_LINKAGES, "PROVEN_CAUSAL requires a deterministic identity linkage")
            _req(basis.get("source") == BASIS_GUID and basis.get("target") == BASIS_GUID,
                 "PROVEN_CAUSAL requires GUID-backed identity on both ends")
        _req((self.relationship_type == "co_occurred") == (self.relationship_state == "CORRELATED"),
             "co-occurrence is only ever CORRELATED, and CORRELATED is never a typed causal edge")
        if self.relationship_state == "CORRELATED":
            _req(bool(self.window), "CORRELATED states its window")

    def to_dict(self) -> Dict[str, Any]:
        return {"relationship_id": self.relationship_id, "relationship_type": self.relationship_type,
                "source_entity": self.source_entity, "target_entity": self.target_entity,
                "relationship_state": self.relationship_state, "evidence_refs": list(self.evidence_refs),
                "timestamp": self.timestamp, "window": self.window, "linkage": self.linkage, "reason": self.reason,
                "resolver": self.resolver, "resolver_version": self.resolver_version, "provenance": self.provenance}


def _d(f: Dict[str, Any], k: str) -> Optional[Dict[str, Any]]:
    v = f.get(k)
    return v if isinstance(v, dict) else None


def _ts(f: Dict[str, Any]) -> int:
    try:
        return int(datetime.fromisoformat(str(f.get("ts")).replace("Z", "+00:00")).timestamp() * 1000)
    except (TypeError, ValueError):
        return 0


def _iso(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def refs_of(f: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for r in [f.get("canonical_evidence_id"), f.get("frame_iid"), *(f.get("evidence_ids") or [])]:
        if r and r not in out:
            out.append(r)
    return out[:4]


def identity_of(e: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """PID never establishes identity: only a process_iid that is not PID-only counts."""
    if not e:
        return {"id": None, "basis": None, "pid_only": False}
    basis = e.get("identity_basis") or None
    if e.get("iid") and basis != BASIS_PID_ONLY:
        return {"id": e["iid"], "basis": basis or "PROCESS_IID", "pid_only": False}
    return {"id": None, "basis": basis, "pid_only": e.get("pid") is not None or basis == BASIS_PID_ONLY}


def _effect_type(f: Dict[str, Any]) -> Optional[str]:
    a = str(f.get("action") or "").lower()
    if f.get("lane") == "file" and "exec" in a:
        return "executed"
    if f.get("lane") == "network" and ("dns" in a or "query" in a):
        return "queried"
    return _EFFECT.get(f.get("lane"))


def _target(f: Dict[str, Any]) -> Optional[str]:
    if f.get("lane") == "network":
        return f.get("remote_ip") or f.get("domain") or None
    return f.get("target_path") or f.get("sha256") or f.get("label") or None


def _edge(f, typ, src, tgt, state, reason, *, basis=None, linkage=None, window=None) -> CausalEdge:
    inv = _d(f, "investigation") or {}
    return CausalEdge(
        f"rel:{typ}:{src or '?'}->{tgt or '?'}@{f['frame_iid']}", typ, src or None, tgt or None, state,
        tuple(refs_of(f)), f.get("ts") or None, window, linkage, reason, RESOLVER, CAUSAL_VERSION,
        {"frame_iid": f["frame_iid"], "canonical_evidence_id": f.get("canonical_evidence_id") or None,
         "identity_basis": basis, "data_origin": "SYNTHETIC_FIXTURE" if inv.get("synthetic") else "TRAJECTORY_API"})


def frame_edges(f: Dict[str, Any]) -> List[CausalEdge]:
    if not f or not f.get("frame_iid"):
        return []
    if f.get("lane") == "process":
        c, p = identity_of(_d(f, "entity") or _d(f, "process")), identity_of(_d(f, "parent"))
        basis = {"source": p["basis"], "target": c["basis"]}
        if not c["id"]:
            return [_edge(f, "spawned", p["id"], None, "UNKNOWN", CHILD_UNKNOWN, basis=basis)]
        if not p["id"]:
            return [_edge(f, "spawned", None, c["id"], "UNKNOWN",
                          PARENT_PID_ONLY if p["pid_only"] else PARENT_UNKNOWN, basis=basis)]
        proven = p["basis"] == BASIS_GUID and c["basis"] == BASIS_GUID
        return [_edge(f, "spawned", p["id"], c["id"], "PROVEN_CAUSAL" if proven else "SUPPORTED_RELATIONSHIP",
                      "parent and child process GUIDs are both stated on this event" if proven else
                      "parent process_iid reported on this event; identity is not GUID-backed",
                      basis=basis, linkage="SOURCE_PROCESS_GUID" if proven else None)]
    typ = _effect_type(f)
    if not typ:
        return []
    a, tgt = identity_of(_d(f, "process")), _target(f)
    basis = {"source": a["basis"], "target": None}
    if a["id"] and tgt:
        return [_edge(f, typ, a["id"], tgt, "SUPPORTED_RELATIONSHIP", "event states the acting process identity",
                      basis=basis)]
    return [_edge(f, typ, None, tgt, "UNKNOWN", ACTOR_PID_ONLY if a["pid_only"] else ACTOR_UNKNOWN, basis=basis)]


def _strong(e: CausalEdge) -> bool:
    return e.relationship_state in ("PROVEN_CAUSAL", "SUPPORTED_RELATIONSHIP")


def _corr_reason(f, ent) -> str:
    if f.get("lane") == "network":
        return NET_CORRELATED
    return (f"{_LANE.get(f.get('lane'), 'Event')} relationship: CORRELATED — occurred in window; telemetry does not "
            f"directly link it to the selected {'process' if ent else 'event'}.")


def build_causal_context(frames: Sequence[Dict[str, Any]], *, tenant_id: str,
                         subject_frame_iid: str) -> Optional[Dict[str, Any]]:
    _req(bool(tenant_id), "tenant_id is mandatory (no default tenant)")
    for f in frames or ():
        _req(f.get("tenant_id") in (None, tenant_id), "cross-tenant input rejected")
    lst = sorted((f for f in frames or () if f and f.get("frame_iid")), key=lambda f: (_ts(f), f["frame_iid"]))
    idx = next((i for i, f in enumerate(lst) if f["frame_iid"] == subject_frame_iid), -1)
    if idx < 0:
        return None
    s, t0 = lst[idx], _ts(lst[idx])
    ent = identity_of(_d(s, "entity") or _d(s, "process"))["id"] if s.get("lane") == "process" else None
    own = frame_edges(s)
    caused_by = [e for e in own if _strong(e)]
    unknown = [e for e in own if e.relationship_state == "UNKNOWN"]
    produced = [e for f in lst if f["frame_iid"] != s["frame_iid"] for e in frame_edges(f)
                if _strong(e) and e.source_entity == ent] if ent else []
    linked = {e.provenance["frame_iid"] for e in caused_by + produced}
    related = {x for x in [ent, *(e.source_entity for e in caused_by)] if x}
    window = {"start": _iso(t0 - WINDOW_MS), "end": _iso(t0 + WINDOW_MS)}
    correlated = [
        _edge(f, "co_occurred", ent or s["frame_iid"],
              _target(f) or identity_of(_d(f, "entity") or _d(f, "process"))["id"] or f["frame_iid"],
              "CORRELATED", _corr_reason(f, ent), window=window)
        for f in lst
        if t0 and f["frame_iid"] != s["frame_iid"] and f["frame_iid"] not in linked
        and not (f.get("lane") == "process" and identity_of(_d(f, "entity") or _d(f, "process"))["id"] in related)
        and abs(_ts(f) - t0) <= WINDOW_MS]
    preceded = [{"frame_iid": f["frame_iid"], "ts": f.get("ts") or None, "lane": f.get("lane") or None,
                 "label": f.get("label") or None, "relation": "CHRONOLOGICAL_ONLY"}
                for f in lst[max(0, idx - MAX_PRECEDING):idx]]
    evidence = sorted({r for e in caused_by + produced + unknown for r in e.evidence_refs} | set(refs_of(s)))
    groups = {
        "observed": [{"frame_iid": s["frame_iid"], "ts": s.get("ts") or None, "lane": s.get("lane") or None,
                      "label": s.get("label") or None, "entity": ent}],
        "preceded_by": preceded,
        "caused_by": [e.to_dict() for e in caused_by[:MAX_ITEMS]],
        "produced": [e.to_dict() for e in produced[:MAX_ITEMS]],
        "correlated": [e.to_dict() for e in correlated[:MAX_ITEMS]],
        "unknown": [e.to_dict() for e in unknown[:MAX_ITEMS]],
        "evidence": evidence[:MAX_ITEMS],
    }
    edges = (groups["caused_by"] + groups["produced"] + groups["correlated"] + groups["unknown"])[:MAX_ITEMS]
    return {"view_version": CAUSAL_VERSION, "tenant_id": tenant_id, "subject": s["frame_iid"], "groups": groups,
            "statements": [TEMPORAL], "edges": edges}
