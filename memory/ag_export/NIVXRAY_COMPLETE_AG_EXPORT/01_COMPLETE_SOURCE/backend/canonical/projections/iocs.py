"""project_iocs — canonical IOC projection (P4-FW1..P4-FW5).

Pure function of AuthoritativeSSOT.evidence_graph. Byte-identity oracle.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ..ssot.models import IOCProjection
from ._helpers import ioc_by_kind


def project_iocs(ssot: AuthoritativeSSOT) -> IOCProjection:
    """Extract IOCs from evidence_graph.nodes (kind='ioc').

    Comparison mode: byte_identity vs legacy IOCIntelligence output.
    Reads authoritative-only. Returns IOCProjection with sorted-unique
    lists per kind. Empty projection when SSOT has no ioc nodes.
    """
    urls    = ioc_by_kind(ssot, "url")
    ips     = ioc_by_kind(ssot, "ip")
    domains = ioc_by_kind(ssot, "domain")
    emails  = ioc_by_kind(ssot, "email")
    md5s    = ioc_by_kind(ssot, "md5")
    sha1s   = ioc_by_kind(ssot, "sha1")
    sha256s = ioc_by_kind(ssot, "sha256")
    files   = ioc_by_kind(ssot, "file")
    registry = ioc_by_kind(ssot, "registry")
    uas      = ioc_by_kind(ssot, "user_agent")
    btcs     = ioc_by_kind(ssot, "bitcoin")

    hashes: Dict[str, List[str]] = {}
    if md5s:
        hashes["md5"] = md5s
    if sha1s:
        hashes["sha1"] = sha1s
    if sha256s:
        hashes["sha256"] = sha256s

    return IOCProjection(
        urls=urls,
        ips=ips,
        domains=domains,
        emails=emails,
        hashes=hashes,
        files=files,
        registry=registry,
        user_agents=uas,
        bitcoin_addresses=btcs,
    )
