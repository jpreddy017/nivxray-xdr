"""RC3.1 · terminal-layer RECOVERED downgrade + Cloudflare origin-parse cap.

These two P1 UX / infra bugs were the last items pushed from the RC3.0
baseline milestone. Locked here so any subsequent refactor keeps the
"looks-like-failure-but-actually-succeeded" behaviour and the
`/analyze/status` payload size / sanitisation guarantees.
"""
from __future__ import annotations

import json

import pytest


# --------------------------------------------------------------------
# 1 · /analyze/status/{job_id} payload sanitisation + size cap
# --------------------------------------------------------------------

def test_analyze_status_strips_illegal_control_chars():
    from routers.analyze import _clean_str
    dirty = "hello\x00\x01\x02world\x1f\x7f end"
    clean = _clean_str(dirty)
    # NUL and other C0 controls stripped; tab / newline / CR kept
    assert "\x00" not in clean
    assert "\x01" not in clean
    assert "helloworld" in clean, clean


def test_analyze_status_caps_string_fields():
    from routers.analyze import _cap_str, _MAX_FIELD_BYTES
    big = "X" * (_MAX_FIELD_BYTES + 10_000)
    capped = _cap_str(big)
    assert len(capped.encode("utf-8")) <= _MAX_FIELD_BYTES + 200
    assert "truncated" in capped


def test_analyze_status_shrinks_massive_doc():
    """When the full JSON body exceeds 512 KB the shrinker keeps the
    analyst-critical surface but drops raw AI description / decoded
    preview payloads."""
    from routers.analyze import _shrink_job_doc
    doc = {
        "job_id": "x",
        "status": "done",
        "phase": "complete",
        "progress": 100,
        "iocs": {"urls": ["http://a"], "domains": ["a"], "ips": []},
        "mitre": [{"id": "T1105"}],
        "lolbas": [{"binary": "certutil.exe"}],
        "risk": 78,
        "verdict_card": {"verdict": "malicious"},
        "ai_verdict": "malicious",
        # These MUST be dropped by the shrinker
        "ai_description":       "A" * 400_000,
        "decoded_preview":      "B" * 400_000,
        "raw_shellcode_hex":    "C" * 400_000,
    }
    slim = _shrink_job_doc(doc)
    assert slim.get("_truncated") is True
    assert "ai_description" not in slim
    assert "decoded_preview" not in slim
    assert "raw_shellcode_hex" not in slim
    # Critical analyst surface preserved
    for k in ("job_id", "iocs", "mitre", "lolbas", "verdict_card", "risk"):
        assert k in slim, f"critical field missing: {k}"


def test_analyze_status_json_serialisable_after_sanitize():
    """Full sanitisation must leave the doc round-trippable through
    json.dumps so FastAPI's ASGI layer can emit a proper Content-Length
    response (no chunked-transfer fallback)."""
    from routers.analyze import _sanitize_job_doc
    doc = {
        "job_id": "abc",
        "phase": "enriching",
        "output": "hello\x00world",
        "trace": [
            {"op": "base64-decode", "preview": "text\x01\x02here"},
            {"op": "ioc-extract",   "preview": "safe"},
        ],
        "iocs": {"urls": ["http://a.example.com\x00drop.com"]},
    }
    _sanitize_job_doc(doc)
    body = json.dumps(doc, ensure_ascii=False, default=str)
    assert "\x00" not in body
    assert "hello" in body and "world" in body


# --------------------------------------------------------------------
# 2 · Terminal-layer RECOVERED downgrade (frontend-side, mirror rule)
# --------------------------------------------------------------------

def test_orchestrator_ships_investigation_signals_for_recovered_downgrade():
    """DecodingTracePanel derives its `overallSuccess` flag from the
    orchestrator finding surface (`iocs`, `mitre`, `lolbas`, `family`,
    `verdict`). Guard against a refactor that accidentally drops any of
    these fields so the frontend UX polish stays wired."""
    from engine import AnalysisContext, Budget, Orchestrator
    import decoders  # noqa: F401
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    r = Orchestrator(ctx).run("cmd.exe /c whoami")
    # Every field the panel checks MUST exist even for a benign sample.
    assert hasattr(r.findings, "iocs")
    assert hasattr(r.findings, "mitre_techniques")
    assert hasattr(r.findings, "lolbas")
    assert hasattr(r.findings, "family")
    assert hasattr(r.findings, "verdict")
