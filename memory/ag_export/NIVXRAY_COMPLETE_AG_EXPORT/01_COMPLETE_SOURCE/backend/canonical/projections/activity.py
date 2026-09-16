"""project_activity — canonical activity projection (SSOT-A shape).

Backwards-compat projection: derives the InvestigationModel-style
activity buckets from the AuthoritativeSSOT evidence graph. Pure fn.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ..ssot.models import ActivityProjection
from ._helpers import command_nodes, ioc_nodes, nodes_of_kind


def project_activity(ssot: AuthoritativeSSOT) -> ActivityProjection:
    """Group evidence into activity buckets.

    Mapping (canonical & deterministic):
      command nodes with tool in {powershell, cmd, wmic, ...} → processes
      IOC nodes with kind=file / registry               → files / registry
      IOC nodes with kind=url / ip / domain             → network
      evidence_node kind=auth                           → auth
    """
    processes: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    network: List[Dict[str, Any]] = []
    registry: List[Dict[str, Any]] = []
    auth: List[Dict[str, Any]] = []

    for n in command_nodes(ssot):
        processes.append({
            "evidence_id": n.id,
            "process": n.attrs.get("tool", ""),
            "command_line": n.label,
        })

    for n in ioc_nodes(ssot):
        kind = str(n.attrs.get("ioc_kind", ""))
        if kind in ("file",):
            files.append({"evidence_id": n.id, "path": n.label})
        elif kind in ("registry",):
            registry.append({"evidence_id": n.id, "key": n.label})
        elif kind in ("url", "ip", "domain"):
            network.append({"evidence_id": n.id, "kind": kind, "value": n.label})

    for n in nodes_of_kind(ssot, "auth"):
        auth.append({"evidence_id": n.id, "detail": n.label,
                     "attrs": dict(n.attrs)})

    return ActivityProjection(
        processes=processes,
        files=files,
        network=network,
        registry=registry,
        auth=auth,
    )
