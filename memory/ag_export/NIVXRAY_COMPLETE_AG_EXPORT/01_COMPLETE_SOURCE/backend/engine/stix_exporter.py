"""AnalystReport → STIX 2.1 bundle adapter (RC2.1b).

The heavy lifting lives in `stix_export.build_investigation_bundle`; this
module simply projects the new deterministic `AnalystReport` shape onto the
input contract that the existing STIX 2.1 builder consumes so the /api/v2
surface can emit TIP/SIEM-compatible bundles without duplicating logic.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from stix_export import build_investigation_bundle

from .models import AnalystReport


def _iocs_dict(report: AnalystReport) -> Dict[str, Any]:
    b = report.findings.iocs
    return {
        "urls": list(b.urls),
        "ips": list(b.ips),
        "domains": list(b.domains),
        "emails": list(b.emails),
        "md5": list(b.md5),
        "sha1": list(b.sha1),
        "sha256": list(b.sha256),
        "files": list(b.file_paths),
    }


def _mitre_list(report: AnalystReport):
    return [
        {
            "id": m.id,
            "technique": m.technique,
            "tactic": m.tactic,
            "evidence": m.evidence,
        }
        for m in report.findings.mitre_techniques
    ]


def _aggregate(report: AnalystReport) -> Dict[str, Any]:
    fam = report.findings.family
    return {
        "family": {
            "family": fam.family,
            "confidence": int(fam.confidence * 100),
        } if fam.family and fam.family != "unknown" else {},
    }


def _verdict(report: AnalystReport) -> Dict[str, Any]:
    return {
        "verdict": report.findings.verdict,
        "risk_score": report.findings.risk_score,
        "summary": report.executive_summary,
    }


def analyst_report_to_stix(
    report: AnalystReport,
    *,
    analyst_email: str,
    input_preview: str,
    analyst_notes: str = "",
    tlp: str = "AMBER",
) -> Dict[str, Any]:
    """Build a full STIX 2.1 bundle from an AnalystReport."""
    return build_investigation_bundle(
        analyst_email=analyst_email or "unknown@nivxforge",
        input_preview=(input_preview or "")[:2000],
        output_preview=(report.output or "")[:2000],
        engine=report.engine or "orchestrator-v1",
        confidence=int(report.confidence_breakdown.total or 0),
        trace=[{"op": s.decoder, "args": s.args or {}} for s in report.trace],
        iocs=_iocs_dict(report),
        mitre=_mitre_list(report),
        verdict=_verdict(report),
        kind="single",
        aggregate=_aggregate(report),
        analyst_notes=analyst_notes,
        tlp=tlp,
    )
