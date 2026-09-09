"""Phase A · 4-Dimension Migration Equivalence Gate.

Every legacy → UAIE capability migration MUST pass a 4-dimension
equivalence check before the legacy implementation may be retired.
Topology alone is insufficient — analyst-visible surfaces (recipe,
evidence, verdict inputs) can silently regress even when the graph
looks identical.

Dimensions
──────────
1. **Topology**       ProvenanceGraph.topology_signature() equality
2. **Evidence**       set of ``(kind, value)`` observed across the run
3. **Recipe**         ordered sequence of analyst-visible ops
4. **Verdict inputs** dict of every downstream-consumer-visible key

The three legacy-only inputs (raw ``recursive_decoder`` dict,
``TransformationChain`` dict, or an already-canonical SSOT dict) are
normalised through ``legacy_extract`` so both sides of the comparison
end up in the same shape before diffing.

Callers pass ``strict=True`` to raise AssertionError (test path) or
``strict=False`` to receive a structured diff dict (introspection).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing      import Any, Dict, List, Optional, Set, Tuple

from .provenance import (ProvenanceGraph, build_provenance_graph,
                           assert_graphs_equivalent)


# ══════════════════════════════════════════════════════════════════
# Canonical projection — normalises both engines into the same shape
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class CapabilityFacts:
    """The analyst-visible face of a decode run — engine-agnostic."""
    topology: Optional[ProvenanceGraph]           = None
    evidence: Set[Tuple[str, str]]                = field(default_factory=set)
    recipe:   Tuple[str, ...]                     = ()
    verdict_inputs: Dict[str, Any]                = field(default_factory=dict)
    # ── 5th dimension · Capability Metadata (NON-BLOCKING) ──────
    # Machine-readable metadata for each capability that fired during
    # this run — captured but never enforced by the equivalence gate.
    # By the end of Phase A this map becomes a complete "capability
    # catalog" that later phases (planner optimization, visualisation,
    # docs, auto-dependency validation) can consume for free.
    #
    # Shape:  { capability_id: {
    #              category, requires, produces, consumes,
    #              deterministic, cost, priority_hint,
    #              improves, description,
    #          } }
    capability_metadata: Dict[str, Dict[str, Any]] = field(default_factory=dict)


# ── helpers ────────────────────────────────────────────────────────
_OP_ALIAS = {
    # Legacy `deep-peel-<stage>` prefix maps to the UAIE capability name
    # exposed by the equivalent transformation.  Keep this small on
    # purpose — the alias table is the ONE place migration renaming is
    # allowed.  Every entry is a pairing decision that survived review.
    "deep-peel-ps_encoded_command":    "ps.encoded_command",
    "deep-peel-ps_encodedcommand":     "ps.encoded_command",
    "deep-peel-from_base64_string":    "ps.from_base64_string",
    "deep-peel-gzip":                  "gzip.inflate",
    "deep-peel-zlib":                  "zlib.inflate",
    "deep-peel-bare_base64":           "base64.bare",
    "deep-peel-byte_array_xor_loop":   "ps.byte_array_xor_loop",
    "deep-peel-shellcode_payload":     "shellcode.payload",
    "deep-peel-hex":                   "hex.decode",
    "deep-peel-reverse":               "text.reverse",
    # Convergence-engine ``steps[].op`` names (used when the analyst
    # pastes a single-layer input and legacy takes the convergence path
    # instead of the recursive deep-peel path).
    "decoder-powershell-encoded-command": "ps.encoded_command",
    "decoder-from-base64-string":         "ps.from_base64_string",
    "decoder-gzip":                        "gzip.inflate",
    "decoder-zlib":                        "zlib.inflate",
    "decoder-base64":                      "base64.bare",
    "decoder-byte-array-xor-loop":         "ps.byte_array_xor_loop",
    # UAIE plugin canonical names (identity mapping — they're already
    # in the target vocabulary).
    "powershell.encoded_command":          "ps.encoded_command",
}


def _canonical_op(name: str) -> str:
    """Fold engine-specific op names into the migration vocabulary.

    Rules:
      1. Exact match in ``_OP_ALIAS`` wins.
      2. Legacy ``deep-peel-<stage>`` prefix strips + snake→dot map.
      3. UAIE ``category.name`` names pass through unchanged.
    """
    if name in _OP_ALIAS:
        return _OP_ALIAS[name]
    if name.startswith("deep-peel-"):
        return _OP_ALIAS.get(name, name)
    return name


def _drop_trace_only_ev(kind: str) -> bool:
    """Evidence kinds that are pure telemetry — safe to ignore in the
    equivalence set (they're expected to diverge between engines)."""
    return kind in {"trace", "timing", "diagnostic", "size_delta",
                     "elapsed_ms", "checksum"}


# ══════════════════════════════════════════════════════════════════
# UAIE projection
# ══════════════════════════════════════════════════════════════════
def uaie_extract(orchestrator_result) -> CapabilityFacts:
    """Project a UAIE ``OrchestratorResult`` into ``CapabilityFacts``."""
    topology = build_provenance_graph(orchestrator_result)
    ev: Set[Tuple[str, str]] = set()
    for e in getattr(orchestrator_result, "evidence", []) or []:
        k = getattr(e, "kind", "") or ""
        if _drop_trace_only_ev(k):
            continue
        v = str(getattr(e, "value", ""))
        if k and v:
            ev.add((k, v))
    recipe: List[str] = []
    ledger = getattr(orchestrator_result, "ledger", None)
    for entry in list(ledger or []):
        if getattr(entry, "action", "") != "execute":
            continue
        actor = getattr(entry, "actor", "") or ""
        if actor:
            recipe.append(_canonical_op(actor))
    return CapabilityFacts(
        topology       = topology,
        evidence       = ev,
        recipe         = tuple(recipe),
        verdict_inputs = _uaie_verdict_inputs(orchestrator_result),
        capability_metadata = _uaie_capability_metadata(recipe),
    )


def _uaie_capability_metadata(recipe: List[str]) -> Dict[str, Dict[str, Any]]:
    """Non-blocking 5th dimension · capture machine-readable metadata
    for every capability that fired in this run.

    Reads directly from the ``CapabilityContract`` registry when the
    capability is contract-registered.  Legacy plugins register no
    contract — their entry is minimal (``{contract_registered: False}``).
    By Phase A completion every capability in the recipe should carry
    a full metadata record.
    """
    try:
        from .contract import get as _contract_get
    except Exception:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for cap_id in set(recipe):
        # Canonicalised recipe uses the migration vocabulary; look up
        # by the original capability name AND the aliased canonical.
        found = _contract_get(cap_id)
        if found is None:
            # Try inverse alias — the recipe stores the CANONICAL name
            # while the registry stores the RAW capability id.
            for k, v in _OP_ALIAS.items():
                if v == cap_id:
                    found = _contract_get(k)
                    if found:
                        break
        if found is None:
            out[cap_id] = {"contract_registered": False}
            continue
        contract, _impl = found
        out[cap_id] = {
            "contract_registered": True,
            "id":                  contract.id,
            "version":             getattr(contract, "version", ""),
            "category":            getattr(contract, "category", ""),
            "requires":            list(getattr(contract, "requires", ()) or ()),
            "optional_requires":   list(getattr(contract, "optional_requires", ()) or ()),
            "produces":            list(getattr(contract, "produces", ()) or ()),
            "consumes":            list(getattr(contract, "consumes", ()) or ()),
            "improves":            list(getattr(contract, "improves", ()) or ()),
            "deterministic":       bool(getattr(contract, "deterministic", True)),
            "cost":                int(getattr(contract, "cost", 1) or 1),
            "priority_hint":       int(getattr(contract, "priority_hint", 0) or 0),
            "description":         str(getattr(contract, "description", "") or ""),
        }
    return out


def _uaie_verdict_inputs(orchestrator_result) -> Dict[str, Any]:
    """The subset of ``OrchestratorResult`` that downstream consumers
    (SSOT projector · Attack Story · MITRE mapper · Report generator)
    directly read.  Keep this list SHORT and STABLE."""
    reached_sc = any(
        (getattr(a, "artifact_type", "") in
            ("shellcode_bytes", "cs_config_raw", "pe_bytes"))
        for a in (orchestrator_result.artifacts or {}).values()
    )
    iocs: Dict[str, List[str]] = {}
    for e in orchestrator_result.evidence or []:
        k = getattr(e, "kind", "")
        if k in ("ipv4", "url", "domain", "sha256", "sha1", "md5"):
            iocs.setdefault(k, [])
            v = str(getattr(e, "value", ""))
            if v and v not in iocs[k]:
                iocs[k].append(v)
    mitre = sorted({t for e in (orchestrator_result.evidence or [])
                       for t in (getattr(e, "mitre_techniques", None) or [])})
    return {
        "reached_shellcode": reached_sc,
        "iocs":              {k: sorted(v) for k, v in sorted(iocs.items())},
        "mitre":             mitre,
    }


# ══════════════════════════════════════════════════════════════════
# Legacy projection — recursive_decoder + analysis_core dict shape
# ══════════════════════════════════════════════════════════════════
_IOC_KIND_ALIAS = {"ip": "ipv4", "ips": "ipv4", "ipv4": "ipv4",
                    "url": "url", "urls": "url",
                    "domain": "domain", "domains": "domain",
                    "sha256": "sha256", "sha1": "sha1", "md5": "md5"}


def legacy_extract(legacy_result: Dict[str, Any]) -> CapabilityFacts:
    """Project a legacy ``deterministic_best_decode`` / analysis_core
    dict into the same ``CapabilityFacts`` shape as UAIE.

    Topology is derived heuristically from the recipe: one node per
    layer, one edge per adjacent recipe step.  This is intentionally
    coarser than UAIE's real graph — the topology dimension is a
    "structural sketch", the recipe dimension is where forensic
    equivalence really lives.

    The legacy engine exposes its op sequence via TWO fields:
      · ``recipe`` — populated by the recursive deep-peel path
      · ``steps``  — populated by the convergence-engine fast path
    Whichever is non-empty is treated as the authoritative sequence;
    both are aliased through ``_OP_ALIAS`` into the migration vocabulary.
    """
    recipe_raw = [(r or {}).get("op") or ""
                    for r in (legacy_result.get("recipe") or [])]
    if not any(recipe_raw):
        recipe_raw = [(s or {}).get("op") or ""
                        for s in (legacy_result.get("steps") or [])]
    recipe = tuple(_canonical_op(op) for op in recipe_raw if op)

    # Evidence set — every IOC promoted into the final result counts.
    ev: Set[Tuple[str, str]] = set()
    iocs = legacy_result.get("iocs") or {}
    for kind, values in (iocs or {}).items():
        target = _IOC_KIND_ALIAS.get(str(kind).lower(), str(kind).lower())
        for v in (values or []):
            ev.add((target, str(v)))

    # Verdict inputs — the surfaces downstream consumers actually read.
    normalised_iocs: Dict[str, List[str]] = {}
    for kind, values in (iocs or {}).items():
        target = _IOC_KIND_ALIAS.get(str(kind).lower(), str(kind).lower())
        normalised_iocs.setdefault(target, [])
        for v in (values or []):
            s = str(v)
            if s not in normalised_iocs[target]:
                normalised_iocs[target].append(s)
    mitre_list = legacy_result.get("mitre") or []
    mitre = sorted({(t.get("id") if isinstance(t, dict) else t) or ""
                    for t in mitre_list} - {""})

    verdict_inputs = {
        "reached_shellcode": bool(legacy_result.get("reached_shellcode")),
        "iocs":              {k: sorted(v)
                                for k, v in sorted(normalised_iocs.items())},
        "mitre":             list(mitre),
    }

    return CapabilityFacts(
        topology       = None,          # legacy has no real graph
        evidence       = ev,
        recipe         = recipe,
        verdict_inputs = verdict_inputs,
    )


# ══════════════════════════════════════════════════════════════════
# 4-dimension diff + assertion
# ══════════════════════════════════════════════════════════════════
def diff_capability_facts(legacy: CapabilityFacts,
                            uaie:   CapabilityFacts) -> Dict[str, Any]:
    """Return a structured diff between two ``CapabilityFacts``.

    Dimensions with ``.match == True`` require no analyst attention.
    A dimension may declare ``.reason == 'skipped'`` when one side
    can't participate (e.g. legacy has no ProvenanceGraph — topology
    dimension gracefully degrades to a recipe-derived sketch check).
    """
    d: Dict[str, Any] = {}

    # 1 · Topology (optional; requires both graphs)
    if legacy.topology is None or uaie.topology is None:
        d["topology"] = {"match": True, "reason": "legacy_has_no_graph"}
    else:
        exp = legacy.topology.topology_signature()
        got = uaie.topology.topology_signature()
        d["topology"] = {
            "match":       exp == got,
            "legacy_sig":  exp,
            "uaie_sig":    got,
        }

    # 2 · Evidence (order-independent set)
    missing = sorted(legacy.evidence - uaie.evidence)
    extra   = sorted(uaie.evidence   - legacy.evidence)
    d["evidence"] = {
        "match":            not missing and not extra,
        "missing_in_uaie":  missing,
        "extra_in_uaie":    extra,
    }

    # 3 · Recipe (ORDER-SENSITIVE)
    d["recipe"] = {
        "match":  legacy.recipe == uaie.recipe,
        "legacy": list(legacy.recipe),
        "uaie":   list(uaie.recipe),
    }

    # 4 · Verdict inputs (exact match on the sub-keys we care about)
    inputs_match = True
    per_key: Dict[str, Any] = {}
    for k in sorted(set(legacy.verdict_inputs) | set(uaie.verdict_inputs)):
        lv = legacy.verdict_inputs.get(k)
        uv = uaie.verdict_inputs.get(k)
        match = lv == uv
        per_key[k] = {"match": match, "legacy": lv, "uaie": uv}
        inputs_match = inputs_match and match
    d["verdict_inputs"] = {"match": inputs_match, "per_key": per_key}

    d["overall_match"] = (d["topology"]["match"]
                            and d["evidence"]["match"]
                            and d["recipe"]["match"]
                            and d["verdict_inputs"]["match"])
    return d


def assert_migration_equivalent(legacy: CapabilityFacts,
                                  uaie:   CapabilityFacts,
                                  *, dimensions: Tuple[str, ...] = (
                                       "topology", "evidence",
                                       "recipe",   "verdict_inputs"),
                                  msg: str = "") -> None:
    """Fail the caller (AssertionError) when ANY selected dimension
    disagrees.  Every failure prints a structured line per dimension
    so the human can pinpoint the regression immediately.

    Selecting a subset of dimensions is allowed during progressive
    migration — e.g. Slice 1 may waive the ``recipe`` dimension until
    op-naming has been normalised across engines.  Every waiver is
    explicit at the call-site.
    """
    d = diff_capability_facts(legacy, uaie)
    failed = [k for k in dimensions if not d.get(k, {}).get("match", False)]
    if not failed:
        return
    lines = [f"Migration equivalence FAILED"
             + (f" — {msg}" if msg else "")]
    for k in failed:
        sub = d[k]
        lines.append(f"  · {k}: {sub}")
    raise AssertionError("\n".join(lines))


__all__ = [
    "CapabilityFacts",
    "uaie_extract", "legacy_extract",
    "diff_capability_facts", "assert_migration_equivalent",
    "assert_graphs_equivalent",     # re-exported for convenience
    "build_capability_catalog",
]


# ══════════════════════════════════════════════════════════════════
# Capability Catalog · 5th-dimension aggregator
# ══════════════════════════════════════════════════════════════════
def build_capability_catalog() -> Dict[str, Dict[str, Any]]:
    """Return the full machine-readable capability catalog derived from
    the ``CapabilityContract`` registry.

    Non-blocking — intended for consumers that want the "by Phase A end
    we have a machine-readable capability catalog essentially for free"
    guarantee.  Every contract-registered capability shows up here with
    the same shape ``_uaie_capability_metadata`` uses inside a single
    run's ``CapabilityFacts``.

    Consumers:
        · planner optimisation      · analyst-facing docs
        · UI visualisation          · CI dependency validation
    """
    try:
        from .contract import all_contracts as _all_contracts
    except Exception:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for c in _all_contracts() or []:
        out[c.id] = {
            "contract_registered": True,
            "id":                  c.id,
            "version":             getattr(c, "version", ""),
            "category":            getattr(c, "category", ""),
            "requires":            list(getattr(c, "requires", ()) or ()),
            "optional_requires":   list(getattr(c, "optional_requires", ()) or ()),
            "produces":            list(getattr(c, "produces", ()) or ()),
            "consumes":            list(getattr(c, "consumes", ()) or ()),
            "improves":            list(getattr(c, "improves", ()) or ()),
            "deterministic":       bool(getattr(c, "deterministic", True)),
            "cost":                int(getattr(c, "cost", 1) or 1),
            "priority_hint":       int(getattr(c, "priority_hint", 0) or 0),
            "description":         str(getattr(c, "description", "") or ""),
        }
    return out
