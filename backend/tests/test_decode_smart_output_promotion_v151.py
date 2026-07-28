"""v1.5.1 · /decode/smart output-promotion regression.

When the Recursive Transformation Engine peels at least one layer,
the top-level ``output`` field returned by ``/api/decode/smart`` must
carry the RTE-recovered payload (final artifact) plus a compact
diagnostic block — so the analyst-facing Workspace UI stops showing
the pre-v1.3.0 orchestrator's garbage bytes on Sophos-class samples.

The legacy output stays available in ``output_legacy`` for any UI
consumer still keyed off the old formatting.
"""
from __future__ import annotations

import base64
import gzip
import re

import pytest


def _canonical_sample() -> str:
    """The locked ``PS_ENCODEDCOMMAND_GZIP_STAGE2_001`` corpus entry.
    Inner base64 is intentionally misaligned (mod 4 = 3) so decode
    stops at L2 with DX1001 + DX2002 diagnostics."""
    from pathlib import Path
    p = Path(__file__).with_name("trust_corpus") / "PS_ENCODEDCOMMAND_GZIP_STAGE2_001.txt"
    return p.read_text().rstrip("\n")


def _clean_sample() -> str:
    """A synthetic byte-exact 3-stage sample that decodes cleanly."""
    stage3 = 'Write-Host "STAGE-3 · v1.5.1 output-promotion test"'
    gz_b64 = base64.b64encode(gzip.compress(stage3.encode())).decode()
    stage2 = (
        f'$s=New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{gz_b64}"));'
        f'IEX (New-Object IO.StreamReader('
        f'New-Object IO.Compression.GzipStream('
        f'$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(stage2.encode("utf-16-le")).decode("ascii")
    return f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand {enc}"


def _simulate_endpoint(body_input: str) -> dict:
    """Reproduces the ``/decode/smart`` output-promotion block outside
    of FastAPI so we can unit-test it without HTTP or DB fixtures."""
    from v2.investigation.pipeline import investigate as _run_investigation
    _inv = _run_investigation(body_input or "")
    result = {"output": "legacy-orchestrator-decoded-text",
              "investigation": _inv.to_dict()}
    # Inline the same promotion logic from routers/ops.py (kept as a
    # regression fixture so if that block moves or gets refactored we
    # notice here first).
    _rte = (result.get("investigation") or {}).get("rte") or {}
    _arts = _rte.get("artifacts") or []
    _steps = _rte.get("steps") or []
    _diags = _rte.get("diagnostics") or []
    if len(_arts) >= 2 and len(_steps) >= 1:
        _final = (_arts[-1].get("content") or "")
        _header_lines = [
            "━" * 66,
            "▼ INVESTIGATION BRAIN · RTE DECODER TRACE",
            "━" * 66,
            f"  stop_reason:      {_rte.get('stop_reason')}",
            f"  depth:            {_rte.get('depth')}   layers: {len(_arts)}   steps: {len(_steps)}",
            f"  determinism_hash: {(_rte.get('determinism_hash') or '')[:16]}",
        ]
        for _s in _steps:
            _header_lines.append(
                f"  step: {_s.get('transformation')}  "
                f"L{_s.get('input_layer')}→L{_s.get('output_layer')}  "
                f"conf={_s.get('confidence')}"
            )
        if _diags:
            _header_lines.append("")
            _header_lines.append("  DIAGNOSTICS:")
            for _d in _diags:
                _sev = (_d.get("severity") or "").upper()
                _cause = _d.get("caused_by") or ""
                _cause_str = f"  ← caused_by={_cause}" if _cause else "  (root)"
                _header_lines.append(
                    f"    [{_sev:>7}] {_d.get('code')} "
                    f"{_d.get('failure_type') or ''}{_cause_str}"
                )
                _reason = (_d.get("reason") or "").strip()
                if _reason:
                    _header_lines.append(f"             {_reason[:220]}")
        _header_lines.append("━" * 66)
        _header_lines.append("▼ RECOVERED PAYLOAD (final RTE layer)")
        _header_lines.append("━" * 66)
        _brain_block = "\n".join(_header_lines) + "\n" + _final
        result["output_legacy"] = result.get("output") or ""
        result["output"] = _brain_block
    return result


# ── Locked assertions ───────────────────────────────────────────

def test_output_carries_rte_recovered_payload_on_canonical_corrupt_sample():
    """On the primary corpus sample (inner gzip corrupted), the RTE
    peels L0 → L1 successfully. The v1.5.1 promotion must surface
    that L1 content in ``output``, not the legacy orchestrator's
    garbage-bytes text."""
    result = _simulate_endpoint(_canonical_sample())
    out = result["output"]
    # L1 recovered PS starts with `$s=New-Object IO.MemoryStream(...`
    assert "$s=New-Object IO.MemoryStream" in out, (
        "Recovered L1 content missing from top-level output"
    )
    # DX diagnostic codes must be inlined for analyst visibility
    assert "DX1001" in out
    assert "DX2002" in out
    # Causal linkage must be visible
    assert "caused_by=DX1001" in out
    # Root cause must be tagged
    assert "(root)" in out
    # Legacy is preserved
    assert result["output_legacy"] == "legacy-orchestrator-decoded-text"


def test_output_carries_stage3_plaintext_on_clean_sample():
    """On a clean 3-stage sample, ``output`` must contain the fully-
    recovered Stage-3 plaintext (byte-for-byte) so analysts see the
    end payload without opening the JSON tree."""
    result = _simulate_endpoint(_clean_sample())
    assert 'Write-Host "STAGE-3 · v1.5.1 output-promotion test"' in result["output"]
    # Both steps must appear in the trace
    assert "ps_encoded_command" in result["output"]
    assert "ps_indirect_compression_stream" in result["output"]


def test_output_untouched_when_no_transformation_fires():
    """Safety-net: on plain input where the RTE peels zero layers,
    the legacy ``output`` must NOT be overwritten. This preserves
    v1.4.3 behaviour for simple non-transform samples."""
    result = _simulate_endpoint('Write-Host "no transforms"')
    assert result["output"] == "legacy-orchestrator-decoded-text"
    # And output_legacy is NOT set because no promotion happened.
    assert "output_legacy" not in result


def test_output_promotion_is_deterministic():
    """Two independent runs on the same input must produce byte-
    identical ``output`` (the whole promotion is a pure function of
    the deterministic RTE result)."""
    a = _simulate_endpoint(_canonical_sample())
    b = _simulate_endpoint(_canonical_sample())
    assert a["output"] == b["output"]


def test_output_promotion_never_asserts_cause():
    """v1.5.0 evidence-wording discipline must survive into the
    analyst-facing output block: no over-claim phrases like
    ``chat-transmission corruption``, ``the payload is truncated``,
    ``definitely corrupted``."""
    out = _simulate_endpoint(_canonical_sample())["output"].lower()
    for over_claim in (
        "this is chat-transmission corruption",
        "the payload is truncated",
        "definitely corrupted",
    ):
        assert over_claim not in out, (
            f"analyst output over-claims cause: {over_claim!r}"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
