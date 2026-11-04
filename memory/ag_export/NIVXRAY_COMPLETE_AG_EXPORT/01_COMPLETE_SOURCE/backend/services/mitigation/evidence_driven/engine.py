"""Public entry-point for the Evidence-Driven Recommendation Engine.

Callers pass a decode_result dict (same shape ``derive_mitigations``
takes) and receive a schema-versioned response with:

    · verdict           (severity + one_liner)
    · recommendations   (list — trigger-fired only)
    · dimensions        (the 12 case-context dimensions, so the
                          analyst can audit WHY each rule fired)
    · disabled          (True when the feature flag is OFF — the
                          engine returns an empty response and
                          the caller must NOT render anything)

The engine can be *disabled* via ``NVX_EVIDENCE_ENGINE=off``.  When
disabled it returns immediately with an empty structure — no
computation, no dependency on rule imports.  This is the isolation
requirement: the Workspace can be shipped even if this engine is
switched off.

Response schema version is 2 to avoid ANY collision with the
legacy ``mitigation.schema_version = 1`` contract.  The two engines
never share a schema.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

RECOMMENDATIONS_SCHEMA_VERSION = 2


def is_engine_enabled() -> bool:
    """Feature flag — analysts/operators can turn the engine off
    without touching the Workspace.  Defaults to ON."""
    return os.environ.get("NVX_EVIDENCE_ENGINE", "on").strip().lower() != "off"


def evidence_driven_recommendations(decode_result: Dict[str, Any] = None,
                                      *,
                                      investigation_outcome: Dict[str, Any] = None,
                                      ) -> Dict[str, Any]:
    """The one function callers use.  Pure derivation.

    Preferred (per user directive 2026-02-04): pass
    ``investigation_outcome=<workspace-produced findings>`` — the
    engine reasons ONLY over what the Workspace already discovered.

    Positional ``decode_result`` is kept for the ``/compare``
    endpoint which still runs legacy v1 on a raw paste — its
    projection uses light heuristics on the decode result, not a
    full re-investigation.
    """
    if not is_engine_enabled():
        return {
            "schema_version":  RECOMMENDATIONS_SCHEMA_VERSION,
            "disabled":        True,
            "reason":          "NVX_EVIDENCE_ENGINE=off",
            "verdict":         {"severity": "informational", "one_liner": ""},
            "recommendations": [],
            "dimensions":      {},
        }

    if investigation_outcome is None and decode_result is None:
        raise ValueError("investigation_outcome or decode_result required")
    if investigation_outcome is not None and decode_result is not None:
        raise ValueError("provide only one of investigation_outcome / decode_result")

    # Lazy imports — keeps disabled-mode overhead at zero.
    from .case_context  import (project_from_decode_result,
                                  project_from_investigation_outcome)
    from .rules         import evaluate_rules
    from .rule_library  import rules_for

    if investigation_outcome is not None:
        ctx = project_from_investigation_outcome(investigation_outcome)
    else:
        ctx = project_from_decode_result(decode_result or {})
    rules = rules_for(ctx)
    fired = evaluate_rules(rules, ctx)
    fired_dicts: List[Dict[str, Any]] = [r.as_dict() for r in fired]

    # Sort deterministically — critical first, then by category order.
    _P = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    _C = {"investigate": 0, "hunt": 1, "contain": 2,
            "eradicate":   3, "recover": 4, "harden": 5}
    fired_dicts.sort(key=lambda r: (_P.get(r["priority"], 9),
                                       _C.get(r["category"], 9),
                                       r["id"]))

    verdict = _derive_verdict(ctx, fired_dicts)

    return {
        "schema_version":  RECOMMENDATIONS_SCHEMA_VERSION,
        "disabled":        False,
        "verdict":         verdict,
        "recommendations": fired_dicts,
        "dimensions":      _dimensions_snapshot(ctx),
        "totals": {
            "count":       len(fired_dicts),
            "by_category": _tally(fired_dicts, "category"),
            "by_priority": _tally(fired_dicts, "priority"),
        },
    }


# ── helpers ────────────────────────────────────────────────────────
def _tally(recs: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in recs:
        v = r.get(key, "")
        out[v] = out.get(v, 0) + 1
    return out


def _dimensions_snapshot(ctx) -> Dict[str, Any]:
    """Copy the 12 dimensions into a JSON-safe dict for analyst audit."""
    return {
        "observed_evidence": {
            "processes":     list(ctx.processes),
            "commands":      list(ctx.commands),
            "hosts":         list(ctx.hosts),
        },
        "detection_types":       sorted(ctx.detection_types),
        "behaviors":             sorted(ctx.behaviors),
        "mitre_techniques":      sorted(ctx.mitre_techniques),
        "malware_family":        ctx.malware_family,
        "apt_group":             ctx.apt_group,
        "apt_confidence":        ctx.apt_confidence,
        "lolbas_hits":           list(ctx.lolbas_hits),
        "iocs": {
            "ips":     list(ctx.ips),
            "domains": list(ctx.domains),
            "urls":    list(ctx.urls),
            "hashes":  list(ctx.hashes),
        },
        "attack_pattern": {
            "obfuscation_layers":  ctx.obfuscation_layers,
            "kill_chain_phases":   sorted(ctx.kill_chain_phases),
        },
        "impacts":                 sorted(ctx.impacts),
        "reached_shellcode":       ctx.reached_shellcode,
        "scope": {
            "affected_hosts":              ctx.affected_hosts,
            "privileged_users_affected":   ctx.privileged_users_affected,
            "critical_assets_affected":    ctx.critical_assets_affected,
        },
        "detection_confidence":    ctx.detection_confidence,
    }


def _derive_verdict(ctx, fired: List[Dict[str, Any]]) -> Dict[str, str]:
    """Verdict is EVIDENCE-DRIVEN — never blind to what actually
    happened.  Priority of the highest-fired rule sets severity."""
    if not fired:
        return {
            "severity":  "informational",
            "one_liner": ("No recommendations — no evidence dimension "
                          "satisfied a rule trigger for this case."),
        }
    severity = ("critical" if any(r["priority"] == "critical" for r in fired) else
                "high"      if any(r["priority"] == "high"     for r in fired) else
                "medium"    if any(r["priority"] == "medium"   for r in fired) else
                "low")
    family = ctx.malware_family
    if family == "cobalt_strike":
        one = ("Cobalt Strike beacon stager identified — evidence-driven "
                "recommendations tailored to the observed chain.")
    elif ctx.reached_shellcode:
        one = ("Multi-stage loader reaching in-memory shellcode — "
                "recommendations reflect the specific observed chain.")
    elif "impact" in ctx.behaviors:
        one = "Impact behaviour observed — recovery actions included."
    else:
        one = ("Suspicious activity — recommendations limited to the "
                "actual evidence dimensions the engine could confirm.")
    return {"severity": severity, "one_liner": one}


__all__ = [
    "evidence_driven_recommendations",
    "is_engine_enabled",
    "RECOMMENDATIONS_SCHEMA_VERSION",
]
