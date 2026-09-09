"""project_executive_summary — canonical exec-card prose.

Prose; canonical_normalised comparison.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..ssot import AuthoritativeSSOT
from ._helpers import command_nodes, ioc_nodes, mitre_nodes
from .verdict import project_verdict
from .attck   import project_attck


def project_executive_summary(ssot: AuthoritativeSSOT) -> Optional[Dict[str, Any]]:
    """Short executive summary — headline + one-liner + severity.

    Returns None when no evidence at all (P4-FW3 spirit — no fabrication).
    """
    if not (mitre_nodes(ssot) or command_nodes(ssot) or ioc_nodes(ssot)):
        return None

    verdict = project_verdict(ssot)
    attck   = project_attck(ssot)

    severity_map = {
        "MALICIOUS":       "critical",
        "SUSPICIOUS":      "high",
        "LIKELY_BENIGN":   "low",
        "INCONCLUSIVE":    "unknown",
    }

    headline = (
        f"Verdict: {verdict.label} · confidence {verdict.confidence}"
    )
    if attck.techniques:
        oneliner = (
            f"Observed {len(attck.techniques)} MITRE technique(s) across "
            f"{len(attck.tactics)} tactic(s)."
        )
    else:
        oneliner = "No MITRE technique evidence in canonical SSOT."

    return {
        "schema": "canonical.projection.executive_summary/1.0.0-phase4",
        "headline": headline,
        "oneliner": oneliner,
        "severity": severity_map.get(verdict.label, "unknown"),
        "confidence": verdict.confidence,
    }
