"""Compare Cases — Phase A · item 2 · fingerprint-powered diff engine.

Master architecture reference: `/app/memory/ARCHITECTURE.md` v1.1 (FROZEN)
§7 (Provider Extension Architecture), §5 (CEM boundary), §8 (AI Boundary).

    Case A + Case B  (both post-convergence)
             ▼
      compare_cases(a, b)
             ▼
    { similarity_score, dimensions{...}, fingerprint_match, ... }

Contract (owner-locked 2026-02-16):

  1. **Read-only.** No mutations on either case, CEM, verdict, or
     evidence — pure function.
  2. **Deterministic.** Same (a, b) → byte-identical output. Sorted
     output, stable serialization, no clock/random access.
  3. **Fingerprint-powered.** Consumes the Attack Fingerprint's
     `similarity_vector` directly — no re-derivation of shared work.
  4. **Symmetric.** `compare(a, b) == compare(b, a)` for every
     scalar / set-shaped dimension. Provenance labels flip.
  5. **Gracefully degrades.** Pre-convergence cases still produce a
     comparison (with `hash=None`) but flag missing dimensions.

Compared dimensions (all deterministic):

    threat_summary        risk_score / verdict / interpreter
    attack_chain          canonical_artifact_graph edges
    timeline              analyzer.finding + rte.convergence order
    mitre                 MITRE technique IDs
    iocs                  {kind, value} indicator pairs
    recipe                decode-recipe steps
    transformation_trace  decoder-pass sequence
    decision_trace        RTE stage decisions
    interpreter_chain     final interpreter path
    artifact_graph        {kind, type, sha256} nodes
    attack_fingerprint    fingerprint_hash equality
    confidence_provenance (when available — Phase A · item 3)

Similarity score:  average of Jaccard indices over the set-shaped
dimensions above, weighted per the constants in _SIMILARITY_WEIGHTS.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from services.attack_fingerprint import emit_fingerprint
from services.cem import emit_cem

COMPARE_VERSION = "1.0"

# Per-dimension weights for the composite similarity score.
# Sum need not be 1.0 — score is normalised.
_SIMILARITY_WEIGHTS: Dict[str, float] = {
    "canonical_hashes":     3.0,   # strongest deterministic signal
    "artifact_types":       1.0,
    "mitre_ids":            2.0,
    "behavior_codes":       2.0,
    "recipe_shape":         1.5,
    "ioc_kinds":            1.0,
    "parent_child_edges":   1.5,
}


def compare_cases(case_a: Dict[str, Any],
                  case_b: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deterministic side-by-side comparison of two cases.

    Pure. Never raises. Never mutates its inputs.
    """
    if not isinstance(case_a, dict) or not isinstance(case_b, dict):
        return _stub("input_not_dict")

    cem_a = case_a.get("cem") if isinstance(case_a.get("cem"), dict) else emit_cem(case_a)
    cem_b = case_b.get("cem") if isinstance(case_b.get("cem"), dict) else emit_cem(case_b)
    fp_a = emit_fingerprint({**case_a, "cem": cem_a})
    fp_b = emit_fingerprint({**case_b, "cem": cem_b})

    dims = {
        "threat_summary":       _diff_threat_summary(cem_a, cem_b),
        "attack_chain":         _diff_attack_chain(cem_a, cem_b),
        "timeline":             _diff_timeline(cem_a, cem_b),
        "mitre":                _diff_set(_mitre(cem_a), _mitre(cem_b)),
        "iocs":                 _diff_set(_iocs(cem_a), _iocs(cem_b)),
        "recipe":               _diff_ordered(_recipe(cem_a), _recipe(cem_b)),
        "transformation_trace": _diff_ordered(_ttrace(cem_a), _ttrace(cem_b)),
        "decision_trace":       _diff_ordered(_dtrace(cem_a), _dtrace(cem_b)),
        "interpreter_chain":    _diff_ordered(_interp(cem_a), _interp(cem_b)),
        "artifact_graph":       _diff_artifact_graph(cem_a, cem_b),
        "canonical_hashes":     _diff_set(_hashes(cem_a), _hashes(cem_b)),
        "behavior_codes":       _diff_set(_behavior(cem_a), _behavior(cem_b)),
        "attack_fingerprint":   _diff_fingerprint(fp_a, fp_b),
        "confidence_provenance": _diff_confidence_provenance(case_a, case_b),
    }

    similarity_score = _composite_similarity_score(fp_a, fp_b)

    return {
        "compare_version":  COMPARE_VERSION,
        "case_a_id":        str(case_a.get("id") or case_a.get("_id") or ""),
        "case_b_id":        str(case_b.get("id") or case_b.get("_id") or ""),
        "fingerprint_match": bool(
            fp_a.get("hash") and fp_b.get("hash")
            and fp_a["hash"] == fp_b["hash"]),
        "similarity_score":  similarity_score,
        "dimensions":        dims,
        "verdicts": {
            "a": (cem_a.get("verdict") or {}),
            "b": (cem_b.get("verdict") or {}),
        },
    }


# =====================================================================
# Composite similarity score (Jaccard over the similarity_vector)
# =====================================================================
def _composite_similarity_score(fp_a: Dict[str, Any],
                                fp_b: Dict[str, Any]) -> Dict[str, Any]:
    sv_a = fp_a.get("similarity_vector") or {}
    sv_b = fp_b.get("similarity_vector") or {}

    per_dim: Dict[str, Dict[str, Any]] = {}
    weighted_sum = 0.0
    weight_total = 0.0
    for dim, weight in _SIMILARITY_WEIGHTS.items():
        a = set(sv_a.get(dim) or [])
        b = set(sv_b.get(dim) or [])
        j = _jaccard(a, b)
        per_dim[dim] = {"jaccard": j, "shared_count": len(a & b),
                        "a_only": len(a - b), "b_only": len(b - a),
                        "weight": weight}
        weighted_sum += j * weight
        weight_total += weight

    overall = round(weighted_sum / weight_total, 4) if weight_total else 0.0
    return {"overall": overall, "per_dimension": per_dim}


# =====================================================================
# Per-dimension diffs
# =====================================================================
def _diff_set(a: Set[str], b: Set[str]) -> Dict[str, Any]:
    a_set, b_set = set(a), set(b)
    return {
        "shared":  sorted(a_set & b_set),
        "a_only":  sorted(a_set - b_set),
        "b_only":  sorted(b_set - a_set),
        "jaccard": _jaccard(a_set, b_set),
    }


def _diff_ordered(a: List[str], b: List[str]) -> Dict[str, Any]:
    """Sequence-aware diff — preserves order for the equality check
    but also returns set-shaped shared/a_only/b_only for overlap use."""
    return {
        "equal":   list(a) == list(b),
        "a":       list(a),
        "b":       list(b),
        "shared":  sorted(set(a) & set(b)),
        "a_only":  sorted(set(a) - set(b)),
        "b_only":  sorted(set(b) - set(a)),
        "jaccard": _jaccard(set(a), set(b)),
    }


def _diff_threat_summary(cem_a: Dict[str, Any],
                         cem_b: Dict[str, Any]) -> Dict[str, Any]:
    va = cem_a.get("verdict") or {}
    vb = cem_b.get("verdict") or {}
    return {
        "verdict_equal":    va.get("verdict") == vb.get("verdict"),
        "risk_score_delta": _delta(va.get("risk_score"), vb.get("risk_score")),
        "interpreter_equal": va.get("interpreter") == vb.get("interpreter"),
        "a": va, "b": vb,
    }


def _diff_attack_chain(cem_a: Dict[str, Any],
                       cem_b: Dict[str, Any]) -> Dict[str, Any]:
    """Attack chain = ordered (parent_type → child_type) edges walked
    by the recursive pipeline."""
    ea = _attack_chain_edges(cem_a)
    eb = _attack_chain_edges(cem_b)
    return _diff_ordered(ea, eb)


def _diff_timeline(cem_a: Dict[str, Any],
                   cem_b: Dict[str, Any]) -> Dict[str, Any]:
    """Timeline is the ordered (kind, code) event tuple stream."""
    ta = _timeline(cem_a)
    tb = _timeline(cem_b)
    return {
        "a":        ta,
        "b":        tb,
        "equal":    ta == tb,
        "a_only":   [x for x in ta if x not in tb],
        "b_only":   [x for x in tb if x not in ta],
        "shared":   [x for x in ta if x in tb],
    }


def _diff_artifact_graph(cem_a: Dict[str, Any],
                         cem_b: Dict[str, Any]) -> Dict[str, Any]:
    a_nodes = _artifact_graph_nodes(cem_a)
    b_nodes = _artifact_graph_nodes(cem_b)
    return _diff_set(a_nodes, b_nodes)


def _diff_fingerprint(fp_a: Dict[str, Any],
                      fp_b: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "a_hash":            fp_a.get("hash"),
        "b_hash":            fp_b.get("hash"),
        "match":             bool(fp_a.get("hash")
                                   and fp_a.get("hash") == fp_b.get("hash")),
        "component_matches": _component_digest_matches(fp_a, fp_b),
    }


def _component_digest_matches(fp_a: Dict[str, Any],
                              fp_b: Dict[str, Any]) -> Dict[str, bool]:
    da = fp_a.get("component_digests") or {}
    db = fp_b.get("component_digests") or {}
    return {k: (da.get(k) is not None and da.get(k) == db.get(k))
            for k in sorted(set(da) | set(db))}


def _diff_confidence_provenance(case_a: Dict[str, Any],
                                case_b: Dict[str, Any]) -> Dict[str, Any]:
    """Placeholder wiring for Phase A · item 3. Once the Confidence
    Provenance Ledger is live it will surface at `case.confidence_
    provenance`; until then we return an availability flag so the UI
    can gracefully hide the dimension."""
    pa = case_a.get("confidence_provenance")
    pb = case_b.get("confidence_provenance")
    if not pa or not pb:
        return {"available": False,
                "a_available": bool(pa),
                "b_available": bool(pb)}
    return {"available": True, "equal": pa == pb, "a": pa, "b": pb}


# =====================================================================
# Extractors
# =====================================================================
def _mitre(cem: Dict[str, Any]) -> Set[str]:
    return {str(m["id"]).upper() for m in cem.get("mitre") or []
            if isinstance(m, dict) and m.get("id")}


def _iocs(cem: Dict[str, Any]) -> Set[str]:
    return {f"{i.get('kind')}:{i.get('value')}"
            for i in cem.get("indicators") or []
            if isinstance(i, dict) and i.get("kind") and i.get("value")}


def _recipe(cem: Dict[str, Any]) -> List[str]:
    return [_norm(s) for s in (cem.get("traces") or {}).get("recipe") or []]


def _ttrace(cem: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for step in (cem.get("traces") or {}).get("transformation_trace") or []:
        if isinstance(step, dict):
            token = step.get("pass") or step.get("name") or step.get("kind")
        else:
            token = str(step)
        if token:
            out.append(_norm(token))
    return out


def _dtrace(cem: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for step in (cem.get("traces") or {}).get("decision_trace") or []:
        if isinstance(step, dict):
            token = step.get("decision") or step.get("stage") or step.get("code")
        else:
            token = str(step)
        if token:
            out.append(_norm(token))
    return out


def _interp(cem: Dict[str, Any]) -> List[str]:
    v = (cem.get("verdict") or {}).get("interpreter") or []
    if isinstance(v, str):
        v = [v]
    return [_norm(t) for t in (v or []) if t]


def _behavior(cem: Dict[str, Any]) -> Set[str]:
    return {str(ev.get("code")) for ev in cem.get("events") or []
            if isinstance(ev, dict)
            and ev.get("kind") == "analyzer.finding"
            and ev.get("code")}


def _hashes(cem: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for a in cem.get("canonical_artifacts") or []:
        if isinstance(a, dict) and a.get("sha256"):
            out.add(str(a["sha256"]))
    for c in cem.get("child_artifacts") or []:
        if not isinstance(c, dict):
            continue
        h = c.get("hash")
        if isinstance(h, dict) and h.get("sha256"):
            out.add(str(h["sha256"]))
        if c.get("routed_sha256"):
            out.add(str(c["routed_sha256"]))
    return out


def _artifact_graph_nodes(cem: Dict[str, Any]) -> Set[str]:
    """Serialize each node as `kind:type:sha256` for set operations."""
    nodes: Set[str] = set()
    for a in cem.get("canonical_artifacts") or []:
        if isinstance(a, dict):
            nodes.add(f"{a.get('kind') or ''}:{a.get('type') or ''}:{a.get('sha256') or ''}")
    for c in cem.get("child_artifacts") or []:
        if isinstance(c, dict):
            h = c.get("hash")
            sha = h.get("sha256") if isinstance(h, dict) else (h or "")
            nodes.add(f"child:{c.get('type') or ''}:{sha}")
    return nodes


def _attack_chain_edges(cem: Dict[str, Any]) -> List[str]:
    parent = "root"
    for a in cem.get("canonical_artifacts") or []:
        if isinstance(a, dict) and a.get("kind") == "binary_artifact":
            parent = str(a.get("type") or "root")
            break
    edges = []
    for c in cem.get("child_artifacts") or []:
        if isinstance(c, dict):
            edges.append(f"{parent}->{c.get('type') or ''}")
    return edges


def _timeline(cem: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Ordered (kind, code) pairs — the event story of the investigation."""
    out: List[Tuple[str, str]] = []
    for ev in cem.get("events") or []:
        if isinstance(ev, dict):
            out.append((str(ev.get("kind") or ""), str(ev.get("code") or "")))
    return out


# =====================================================================
# Utilities
# =====================================================================
def _jaccard(a: Set[Any], b: Set[Any]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return round(len(a & b) / len(a | b), 4)


def _norm(v: Any) -> str:
    s = str(v).strip()
    return " ".join(s.split()).lower()


def _delta(a: Any, b: Any) -> Optional[float]:
    try:
        return round(float(b) - float(a), 4)
    except (TypeError, ValueError):
        return None


def _stub(reason: str) -> Dict[str, Any]:
    return {
        "compare_version":  COMPARE_VERSION,
        "reason":           reason,
        "similarity_score": {"overall": 0.0, "per_dimension": {}},
        "dimensions":       {},
    }


__all__ = ["COMPARE_VERSION", "compare_cases"]
