"""Attack Fingerprint (Attack DNA) — Phase A · first Analytical Consumer.

Master architecture reference: `/app/memory/ARCHITECTURE.md` v1.1 (FROZEN)
§7 (Provider Extension Architecture), §5 (CEM boundary), §8 (AI Boundary).

    Investigation SSOT  (case + CEM)
             ▼
    emit_fingerprint(case)
             ▼
    { fingerprint_version, hash, components, digests, similarity_vector }

Contract (owner-locked 2026-02-16):

  1. **Read-only.** This module NEVER modifies the case, CEM, verdict,
     evidence, or any other frozen-core state. It is a pure function.
  2. **Deterministic.** Same investigation → same fingerprint, byte-
     stable across processes / machines / releases (within the same
     `fingerprint_version`).
  3. **Convergence-gated.** Fingerprint is emitted only when the case
     reached deterministic convergence
     (`convergence.reached == True`). Pre-convergence cases return a
     stub with `hash=None` so downstream consumers degrade gracefully.
  4. **Versioned schema.** `fingerprint_version` starts at `"1.0"`.
     Future enhancements bump the version; historical fingerprints
     remain reproducible because their emitter is preserved.
  5. **Ignores volatile fields.** Timestamps, case IDs, user emails,
     analyst notes, and UI state are never hashed.
  6. **Component digests exposed.** Callers get per-component sha256s
     so Compare Cases can compute overlap without recomputing the
     full canonical form.

The fingerprint is the canonical *identity* of an investigation.
Two investigations with the same fingerprint are, by architectural
contract, byte-identical in every deterministic dimension that
matters — the same decoding chain produced the same canonical
artifacts, MITRE, and behavior.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from services.cem import emit_cem

FINGERPRINT_VERSION = "1.0"


def emit_fingerprint(case: Dict[str, Any]) -> Dict[str, Any]:
    """Return the Attack Fingerprint view of a recorded case doc.

    Deterministic. Never raises. Never mutates the input.
    Pre-convergence cases return a stub with `hash=None`.
    """
    if not isinstance(case, dict):
        return _stub("input_not_dict")

    cem = case.get("cem") if isinstance(case.get("cem"), dict) else emit_cem(case)
    if not isinstance(cem, dict):
        return _stub("cem_missing")

    if not cem.get("convergence", {}).get("reached"):
        return _stub("convergence_not_reached",
                     terminal_state=cem.get("convergence", {}).get("terminal_state"))

    components = _extract_components(case, cem)
    digests = _component_digests(components)
    similarity = _similarity_vector(cem, components)
    canonical = _canonical_form(components)
    fp_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "fingerprint_version": FINGERPRINT_VERSION,
        "hash":                fp_hash,
        "components":          components,
        "component_digests":   digests,
        "similarity_vector":   similarity,
        # Owner-requested top-level convenience aliases (see contract):
        "recipe":              components["recipe"],
        "interpreter_chain":   components["interpreter_chain"],
        "artifact_graph_digest": digests["artifact_graph_digest"],
        "mitre_digest":        digests["mitre_digest"],
        "behavior_digest":     digests["behavior_digest"],
    }


# =====================================================================
# Component extractors — one function per canonical dimension.
# Each returns a deterministic, order-stable value.
# =====================================================================
def _extract_components(case: Dict[str, Any],
                        cem: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "recipe":               _recipe(case, cem),
        "interpreter_chain":    _interpreter_chain(case, cem),
        "transformation_trace": _transformation_trace(cem),
        "artifact_graph":       _artifact_graph(cem),
        "mitre":                _mitre_ids(cem),
        "iocs":                 _iocs(cem),
        "behavior":             _behavior(cem),
        "parent_child_edges":   _parent_child_edges(cem),
        "canonical_artifact_hashes": _canonical_hashes(cem),
    }


def _recipe(case: Dict[str, Any], cem: Dict[str, Any]) -> List[str]:
    """Ordered list of decoder / recipe steps that produced the
    canonical form. Uses the CEM traces first, falling back to the
    case chain for older cases."""
    recipe = (cem.get("traces") or {}).get("recipe") or case.get("chain") or []
    return [_normalise_token(t) for t in recipe if t]


def _interpreter_chain(case: Dict[str, Any],
                       cem: Dict[str, Any]) -> List[str]:
    verdict = cem.get("verdict") or {}
    interp = verdict.get("interpreter") or case.get("chain") or []
    if isinstance(interp, str):
        interp = [interp]
    return [_normalise_token(t) for t in (interp or []) if t]


def _transformation_trace(cem: Dict[str, Any]) -> List[str]:
    trace = (cem.get("traces") or {}).get("transformation_trace") or []
    out: List[str] = []
    for step in trace:
        if isinstance(step, dict):
            token = step.get("pass") or step.get("name") or step.get("kind")
        else:
            token = str(step)
        if token:
            out.append(_normalise_token(token))
    return out


def _artifact_graph(cem: Dict[str, Any]) -> List[Dict[str, str]]:
    """Deterministic, order-stable list of artifact nodes.

    Each node: `{kind, type, sha256}`. Two investigations with the
    same recovered artifacts produce identical graph digests.
    """
    nodes: List[Dict[str, str]] = []
    for a in cem.get("canonical_artifacts") or []:
        if not isinstance(a, dict):
            continue
        nodes.append({
            "kind":   str(a.get("kind") or ""),
            "type":   str(a.get("type") or ""),
            "sha256": str(a.get("sha256") or ""),
        })
    # Also include recursively-declared children.
    for c in cem.get("child_artifacts") or []:
        if not isinstance(c, dict):
            continue
        nodes.append({
            "kind":   "child",
            "type":   str(c.get("type") or ""),
            "sha256": str((c.get("hash") or {}).get("sha256")
                          if isinstance(c.get("hash"), dict)
                          else c.get("hash") or ""),
        })
    nodes.sort(key=lambda n: (n["kind"], n["type"], n["sha256"]))
    return nodes


def _mitre_ids(cem: Dict[str, Any]) -> List[str]:
    return sorted({
        str(m["id"]).upper() for m in (cem.get("mitre") or [])
        if isinstance(m, dict) and m.get("id")
    })


def _iocs(cem: Dict[str, Any]) -> List[str]:
    out = set()
    for ind in cem.get("indicators") or []:
        if not isinstance(ind, dict):
            continue
        kind = ind.get("kind") or ""
        value = ind.get("value") or ""
        if kind and value:
            out.add(f"{kind}:{value}")
    return sorted(out)


def _behavior(cem: Dict[str, Any]) -> List[str]:
    """Sorted set of analyzer.finding codes — the behavioral fingerprint."""
    return sorted({
        str(ev.get("code") or "")
        for ev in (cem.get("events") or [])
        if isinstance(ev, dict)
        and ev.get("kind") == "analyzer.finding"
        and ev.get("code")
    })


def _parent_child_edges(cem: Dict[str, Any]) -> List[str]:
    """Normalized parent→child edges as `parent_type→child_type`. Parent
    is the top-level canonical artifact; children come from
    `child_artifacts`. Sorted for determinism."""
    parent_type = "root"
    for a in cem.get("canonical_artifacts") or []:
        if isinstance(a, dict) and a.get("kind") == "binary_artifact":
            parent_type = str(a.get("type") or "root")
            break
    edges = {
        f"{parent_type}->{c.get('type') or ''}"
        for c in (cem.get("child_artifacts") or [])
        if isinstance(c, dict)
    }
    return sorted(edges)


def _canonical_hashes(cem: Dict[str, Any]) -> List[str]:
    """All artifact sha256s the deterministic pipeline has produced —
    both top-level canonical artifacts and recursively-declared
    children (including their downstream recovered artifacts).
    Enables Compare Cases to match the same payload across different
    origins (e.g. a PE that appears both as a direct upload and as a
    recursive child of a `.docm`)."""
    out: set[str] = set()
    for a in cem.get("canonical_artifacts") or []:
        if isinstance(a, dict) and a.get("sha256"):
            out.add(str(a["sha256"]))
    for c in cem.get("child_artifacts") or []:
        if not isinstance(c, dict):
            continue
        # Intermediate hash (e.g. the PS wrapper text bytes).
        h = c.get("hash")
        if isinstance(h, dict) and h.get("sha256"):
            out.add(str(h["sha256"]))
        elif isinstance(h, str) and h:
            out.add(h)
        # Downstream recovered artifact hash (e.g. the PE the RTE
        # recovered from the PS wrapper).
        routed = c.get("routed_sha256")
        if routed:
            out.add(str(routed))
    return sorted(out)


# =====================================================================
# Digests + similarity vector
# =====================================================================
def _component_digests(components: Dict[str, Any]) -> Dict[str, str]:
    return {
        f"{name}_digest": hashlib.sha256(
            _canonical_json(value).encode("utf-8")
        ).hexdigest()
        for name, value in (
            ("recipe",               components["recipe"]),
            ("interpreter_chain",    components["interpreter_chain"]),
            ("transformation_trace", components["transformation_trace"]),
            ("artifact_graph",       components["artifact_graph"]),
            ("mitre",                components["mitre"]),
            ("iocs",                 components["iocs"]),
            ("behavior",             components["behavior"]),
            ("parent_child_edges",   components["parent_child_edges"]),
        )
    }


def _similarity_vector(cem: Dict[str, Any],
                       components: Dict[str, Any]) -> Dict[str, Any]:
    """Compact vector Compare Cases uses to compute Jaccard-style
    similarity without recomputing the fingerprint. Every field is a
    sorted, unique list."""
    return {
        "artifact_types":     sorted({n["type"] for n in components["artifact_graph"]
                                      if n.get("type")}),
        "canonical_hashes":   components["canonical_artifact_hashes"],
        "mitre_ids":          components["mitre"],
        "behavior_codes":     components["behavior"],
        "recipe_shape":       components["recipe"],
        "ioc_kinds":          sorted({i.split(":", 1)[0]
                                      for i in components["iocs"]}),
        "parent_child_edges": components["parent_child_edges"],
    }


# =====================================================================
# Canonicalization helpers
# =====================================================================
def _canonical_form(components: Dict[str, Any]) -> str:
    """Stable, order-independent JSON serialization of components.
    Sort every dict key; lists are already order-stable by construction."""
    return _canonical_json({
        "fingerprint_version": FINGERPRINT_VERSION,
        **components,
    })


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _normalise_token(v: Any) -> str:
    """Trim / lower / collapse whitespace to a deterministic form."""
    s = str(v).strip()
    # Collapse consecutive whitespace to one space so trivial spacing
    # differences don't fork fingerprints.
    return " ".join(s.split()).lower()


def _stub(reason: str,
          *, terminal_state: Optional[str] = None) -> Dict[str, Any]:
    return {
        "fingerprint_version": FINGERPRINT_VERSION,
        "hash":                None,
        "reason":              reason,
        "terminal_state":      terminal_state,
        "components":          {},
        "component_digests":   {},
        "similarity_vector":   {},
    }


__all__ = ["FINGERPRINT_VERSION", "emit_fingerprint"]
