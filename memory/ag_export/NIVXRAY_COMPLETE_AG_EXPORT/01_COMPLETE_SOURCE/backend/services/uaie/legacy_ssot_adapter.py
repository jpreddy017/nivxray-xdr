"""UAIE · Legacy SSOT Adapter + Graph Diff · Phase 3 unblock.

Two pieces:

1. ``legacy_to_canonical(legacy_result)``
   Takes whatever ``analysis_core`` (or any legacy convergence path)
   emits and normalises it to the SAME SSOT shape produced by
   ``ssot_projector.project(orchestrator_result)``.  Pure projection,
   no reimplementation.

2. ``diff(ssot_legacy, ssot_uaie)``
   Deterministic side-by-side comparison of two canonical SSOTs.
   Emits:
     · verdict_diff       — {legacy, uaie, match}
     · missing_in_uaie    — evidence kinds+values present only on legacy
     · extra_in_uaie      — evidence kinds+values present only on UAIE
     · mitre_delta        — {missing, extra}
     · ioc_delta          — {missing, extra}  (per kind)
     · decode_trace_delta — {legacy_ops, uaie_ops, common}
     · confidence_delta   — |legacy - uaie|
     · overall_match      — bool (all deltas empty)

Enforces R28 "restore is rendering": no LLM, no decoder, no classifier.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple


def legacy_to_canonical(legacy: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a legacy analysis result to the canonical SSOT shape.

    Accepts any dict-shape and gracefully back-fills missing keys so
    the diff never trips on optional fields.  Never mutates input.
    """
    src = dict(legacy or {})
    analysis = src.get("analysis") or {}
    iocs     = analysis.get("iocs") or src.get("iocs") or {}
    mitre    = analysis.get("mitre") or src.get("mitre") or []
    return {
        "verdict_card":               src.get("verdict_card") or {},
        "analysis":                   {"iocs": iocs, "mitre": mitre,
                                       "ai_verdict": (src.get("verdict_card") or {}).get("verdict")},
        "mitre":                      list(mitre),
        "lolbas":                     src.get("lolbas") or analysis.get("lolbas") or [],
        "chain":                      src.get("chain") or [],
        "steps":                      src.get("steps") or [],
        "decode_trace":               src.get("decode_trace") or src.get("trace") or [],
        "reached_shellcode":          bool(src.get("reached_shellcode")),
        "corrupted_container":        src.get("corrupted_container"),
        "semantic":                   src.get("semantic") or {},
        "iedde":                      src.get("iedde"),
        "iedde_terminal_state":       src.get("iedde_terminal_state"),
        "canonical_confidence":       src.get("canonical_confidence"),
        "canonical_confidence_reason": src.get("canonical_confidence_reason") or "legacy_convergence",
        "understanding":              src.get("understanding"),
        "analyst_narrative":          src.get("analyst_narrative"),
        "inline_story_preproc":       src.get("inline_story_preproc"),
        "investigation_object":       src.get("investigation_object"),
        "investigation_mode":         bool(src.get("investigation_mode")),
        "predicted_tree":             src.get("predicted_tree"),
        "source_engine":              "legacy",
    }


# ═════════════════════════════════════════════════════════════════════════
# Graph Diff
# ═════════════════════════════════════════════════════════════════════════
def _iocset(ssot: Dict[str, Any]) -> Set[Tuple[str, str]]:
    """Flatten IOCs into a set of (kind, value) tuples."""
    out: Set[Tuple[str, str]] = set()
    iocs = ((ssot.get("analysis") or {}).get("iocs")) or {}
    for kind, values in (iocs or {}).items():
        for v in (values or []):
            out.add((str(kind), str(v)))
    return out


def _mitreset(ssot: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for t in (ssot.get("mitre") or []):
        if isinstance(t, dict):
            v = t.get("id") or t.get("technique") or t.get("name")
        else:
            v = t
        if v:
            out.add(str(v))
    return out


def _ops(ssot: Dict[str, Any], key: str) -> List[str]:
    return [str((r.get("op") if isinstance(r, dict) else r) or "")
            for r in (ssot.get(key) or [])]


def diff(legacy: Dict[str, Any], uaie: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic diff between two canonical SSOTs."""
    lv = (legacy.get("verdict_card") or {}).get("verdict")
    uv = (uaie.get("verdict_card") or {}).get("verdict")
    lc = (legacy.get("verdict_card") or {}).get("confidence") or 0
    uc = (uaie.get("verdict_card") or {}).get("confidence") or 0

    legacy_iocs = _iocset(legacy)
    uaie_iocs   = _iocset(uaie)
    legacy_mit  = _mitreset(legacy)
    uaie_mit    = _mitreset(uaie)

    dt_legacy = _ops(legacy, "decode_trace")
    dt_uaie   = _ops(uaie,   "decode_trace")

    ioc_missing = sorted(list(legacy_iocs - uaie_iocs))
    ioc_extra   = sorted(list(uaie_iocs - legacy_iocs))
    mit_missing = sorted(list(legacy_mit - uaie_mit))
    mit_extra   = sorted(list(uaie_mit - legacy_mit))

    return {
        "verdict_diff": {
            "legacy": lv, "uaie": uv, "match": (lv == uv),
        },
        "confidence_delta": abs(int(lc or 0) - int(uc or 0)),
        "mitre_delta": {"missing": mit_missing, "extra": mit_extra},
        "ioc_delta":   {"missing": [{"kind": k, "value": v} for k, v in ioc_missing],
                        "extra":   [{"kind": k, "value": v} for k, v in ioc_extra]},
        "decode_trace_delta": {
            "legacy_ops": dt_legacy,
            "uaie_ops":   dt_uaie,
            "common":     [op for op in dt_legacy if op in dt_uaie],
        },
        "overall_match": (
            lv == uv
            and not ioc_missing and not ioc_extra
            and not mit_missing and not mit_extra
        ),
    }


__all__ = ["legacy_to_canonical", "diff"]
