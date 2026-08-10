"""project_canonical — canonical die-Canonical shape (SSOT-B shape).

Backwards-compat projection of a die-style canonical block from the
AuthoritativeSSOT. Pure fn; byte_identity.
"""
from __future__ import annotations

from typing import Any, Dict

from ..ssot import AuthoritativeSSOT
from .iocs        import project_iocs
from .attck       import project_attck
from .verdict     import project_verdict
from .activity    import project_activity


def project_canonical(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """Return the die-Canonical shape.

    This is a compact, structured view derived entirely from the
    authoritative SSOT + upstream projections. NEVER writes back.
    """
    verdict = project_verdict(ssot)
    attck   = project_attck(ssot)
    iocs    = project_iocs(ssot)
    activity = project_activity(ssot)

    return {
        "schema": "canonical.projection.canonical/1.0.0-phase4",
        "ssot_id": ssot.id,
        "fingerprint": ssot.fingerprint(),
        "input_profile": dict(ssot.input_profile),
        "verdict": {
            "label": verdict.label,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
        },
        "techniques": [t["id"] for t in attck.techniques],
        "tactics":    attck.tactics,
        "kill_chain": attck.kill_chain,
        "iocs": {
            "urls": iocs.urls,
            "ips": iocs.ips,
            "domains": iocs.domains,
            "emails": iocs.emails,
            "hashes": iocs.hashes,
            "files": iocs.files,
        },
        "activity": {
            "processes": activity.processes,
            "files": activity.files,
            "network": activity.network,
            "registry": activity.registry,
            "auth": activity.auth,
        },
    }
