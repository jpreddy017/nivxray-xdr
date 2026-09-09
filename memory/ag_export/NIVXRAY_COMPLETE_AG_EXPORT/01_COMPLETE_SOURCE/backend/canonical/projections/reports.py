"""project_reports — canonical STIX/Sigma/YARA/Navigator/MDR projections.

Machine-schema outputs: byte_identity for structured fields.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ..ssot.models import ReportsProjection
from ._helpers import ioc_by_kind, mitre_nodes
from .attck             import project_attck
from .attack_chain      import project_attack_chain
from .verdict           import project_verdict
from .recommendations   import project_recommendations
from .iocs              import project_iocs


REPORT_SCHEMA_VERSION = "1.0.0-phase4"


# ── STIX ────────────────────────────────────────────────────────────────
def _project_stix(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """STIX 2.1 bundle. Deterministic ids derived from fingerprint."""
    iocs = project_iocs(ssot)
    fp = ssot.fingerprint()
    objects: List[Dict[str, Any]] = []
    idx = 0

    def _emit(kind: str, value: str, pattern: str):
        nonlocal idx
        objects.append({
            "type": "indicator",
            "id": f"indicator--{fp[:8]}-{idx:04d}",
            "pattern": pattern,
            "pattern_type": "stix",
            "labels": [kind],
            "value": value,
        })
        idx += 1

    for u in iocs.urls:
        _emit("url", u, f"[url:value = '{u}']")
    for ip in iocs.ips:
        _emit("ipv4-addr", ip, f"[ipv4-addr:value = '{ip}']")
    for d in iocs.domains:
        _emit("domain-name", d, f"[domain-name:value = '{d}']")
    for kind, hashes in sorted(iocs.hashes.items()):
        for h in hashes:
            _emit(f"file-{kind}", h,
                  f"[file:hashes.'{kind.upper()}' = '{h}']")

    return {
        "type": "bundle",
        "id": f"bundle--{fp[:8]}",
        "schema": f"canonical.projection.reports.stix/{REPORT_SCHEMA_VERSION}",
        "objects": objects,
    }


# ── Sigma ───────────────────────────────────────────────────────────────
def _project_sigma(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """Emit a deterministic Sigma-style rule per observed technique."""
    attck = project_attck(ssot)
    rules: List[Dict[str, Any]] = []
    for t in attck.techniques:
        rules.append({
            "title": f"canonical.{t['id']}",
            "id": f"canonical-sigma-{t['id']}",
            "status": "experimental",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"technique_id": t["id"],
                              "matched_terms": t["matched_terms"]},
                "condition": "selection",
            },
            "tags": [t["tactic"]],
        })
    return {
        "schema": f"canonical.projection.reports.sigma/{REPORT_SCHEMA_VERSION}",
        "rules": rules,
    }


# ── YARA ────────────────────────────────────────────────────────────────
def _project_yara(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """Emit YARA-shaped rule descriptors for IOC hashes + strings."""
    iocs = project_iocs(ssot)
    fp = ssot.fingerprint()
    strings: List[Dict[str, Any]] = []
    for kind in ("sha256", "sha1", "md5"):
        for i, h in enumerate(iocs.hashes.get(kind, [])):
            strings.append({"kind": f"hash_{kind}", "id": f"$h{kind[0]}{i}", "value": h})
    for i, u in enumerate(iocs.urls):
        strings.append({"kind": "url", "id": f"$u{i}", "value": u})
    return {
        "schema": f"canonical.projection.reports.yara/{REPORT_SCHEMA_VERSION}",
        "rule_name": f"canonical_yara_{fp[:8]}",
        "strings": strings,
        "condition": "any of them" if strings else "false",
    }


# ── Navigator ───────────────────────────────────────────────────────────
def _project_navigator(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """MITRE Navigator layer JSON."""
    attck = project_attck(ssot)
    fp = ssot.fingerprint()
    techniques = [
        {"techniqueID": t["id"], "score": 100, "comment": t["name"]}
        for t in attck.techniques
    ]
    return {
        "schema": f"canonical.projection.reports.navigator/{REPORT_SCHEMA_VERSION}",
        "name": f"canonical_{fp[:8]}",
        "domain": "enterprise-attack",
        "techniques": techniques,
    }


# ── MDR ─────────────────────────────────────────────────────────────────
def _project_mdr(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """Managed-Detection-Response report shape.

    Structured fields (byte_identity) + prose (canonical_normalised).
    """
    verdict = project_verdict(ssot)
    attck   = project_attck(ssot)
    chain   = project_attack_chain(ssot)
    recs    = project_recommendations(ssot)
    return {
        "schema": f"canonical.projection.reports.mdr/{REPORT_SCHEMA_VERSION}",
        "verdict": {
            "label": verdict.label,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
        },
        "techniques": [t["id"] for t in attck.techniques],
        "kill_chain": [s["stage"] for s in chain],
        "recommendations": recs["items"],
        "prose": (
            f"Canonical MDR report — verdict {verdict.label} "
            f"({verdict.confidence}) with {len(attck.techniques)} "
            f"technique(s)."
        ),
    }


# ── Facade ─────────────────────────────────────────────────────────────
def project_reports(ssot: AuthoritativeSSOT) -> ReportsProjection:
    """Return the full ReportsProjection (all 5 sub-reports)."""
    return ReportsProjection(
        stix=_project_stix(ssot),
        sigma=_project_sigma(ssot),
        yara=_project_yara(ssot),
        navigator=_project_navigator(ssot),
        mdr=_project_mdr(ssot),
    )
