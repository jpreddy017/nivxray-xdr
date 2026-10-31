"""project_analyst_summary — canonical L4-analyst prose summary.

Prose; canonical_normalised comparison. NEVER templates over missing
evidence — returns None when SSOT is empty.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..ssot import AuthoritativeSSOT
from ._helpers import (
    command_nodes,
    executed_capabilities,
    ioc_nodes,
    mitre_nodes,
)
from .attck   import project_attck
from .iocs    import project_iocs
from .verdict import project_verdict


def project_analyst_summary(ssot: AuthoritativeSSOT) -> Optional[Dict[str, Any]]:
    """L4 analyst summary — deterministic prose with facts, not opinions.

    Returns None when the SSOT carries no analytical evidence.
    """
    mnodes = mitre_nodes(ssot)
    cnodes = command_nodes(ssot)
    inodes = ioc_nodes(ssot)
    if not (mnodes or cnodes or inodes):
        return None

    verdict = project_verdict(ssot)
    attck   = project_attck(ssot)
    iocs    = project_iocs(ssot)

    caps = executed_capabilities(ssot)

    key_findings: List[str] = []
    if attck.techniques:
        key_findings.append(
            f"MITRE technique(s): {', '.join(t['id'] for t in attck.techniques)}"
        )
    if attck.tactics:
        key_findings.append(
            f"tactic(s) observed: {', '.join(attck.tactics)}"
        )
    total_iocs = (len(iocs.urls) + len(iocs.ips) + len(iocs.domains)
                  + len(iocs.emails) + sum(len(v) for v in iocs.hashes.values())
                  + len(iocs.files) + len(iocs.registry))
    if total_iocs:
        key_findings.append(f"{total_iocs} IOC(s) extracted")
    if cnodes:
        key_findings.append(f"{len(cnodes)} command-line indicator(s)")

    return {
        "schema": "canonical.projection.analyst_summary/1.0.0-phase4",
        "verdict": verdict.label,
        "confidence": verdict.confidence,
        "reason": verdict.reason,
        "executed_capabilities": sorted(caps),
        "key_findings": key_findings,
        "prose": (
            f"Canonical analysis yields verdict {verdict.label} "
            f"(confidence {verdict.confidence}). "
            f"{len(mnodes)} MITRE evidence, "
            f"{total_iocs} IOC(s), "
            f"{len(cnodes)} command(s) considered. "
            f"Reason: {verdict.reason}."
        ),
    }
