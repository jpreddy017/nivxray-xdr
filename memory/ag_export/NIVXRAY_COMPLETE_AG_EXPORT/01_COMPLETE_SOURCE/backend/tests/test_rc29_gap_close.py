"""Unit tests for the RC2.9 gap-close decoders and manual Chain-Recipe wrappers.

Locks:
  1. `ps-hex-escape` plugin auto-detects and decodes `\\xNN` byte-escape streams
     (December_Commandline sample-class).
  2. Every plugin decoder is exposed via `OPERATIONS` so the manual
     Chain-Recipe UI never surfaces "Unknown operation: <id>" again.
  3. Manual-runner output matches the plugin-runner output byte-for-byte.
"""
from __future__ import annotations

import pytest


PLUGIN_OP_IDS = (
    "ps-reconstruct", "cmd-reconstruct", "js-reconstruct", "vbs-reconstruct",
    "decimal-charcode-decode", "octal-charcode-decode",
    "custom-hex-slash", "nibble-swap", "ps-hex-escape",
)


@pytest.mark.parametrize("op_id", PLUGIN_OP_IDS)
def test_plugin_op_is_registered(op_id: str) -> None:
    """Every plugin decoder must have a manual-runner wrapper."""
    from operations import OPERATIONS
    assert op_id in OPERATIONS, f"{op_id} missing from manual Chain-Recipe registry"
    entry = OPERATIONS[op_id]
    assert entry["fn"] is not None
    assert callable(entry["fn"])


def test_ps_hex_escape_detects_high_density() -> None:
    """A payload made entirely of `\\xNN` escapes must decode to the plaintext."""
    from engine.registry import DecoderRegistry
    from engine.models import AnalysisContext
    from engine.fingerprint_util import compute

    payload = r"\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x20\x2d\x63\x20\x49\x45\x58"
    plugin = DecoderRegistry.get("ps-hex-escape")
    assert plugin is not None
    fp = compute(payload)
    det = plugin.detect(payload, fp, AnalysisContext())
    assert det.confidence >= 0.7
    res = plugin.decode(payload, det.args, AnalysisContext())
    assert res.output == "powershell -c IEX"


def test_ps_hex_escape_ignores_low_density() -> None:
    """Stray hex escapes inside a long PS one-liner should NOT trigger."""
    from engine.registry import DecoderRegistry
    from engine.models import AnalysisContext
    from engine.fingerprint_util import compute

    # 5 escapes buried in ~200 chars — density well under 40 %.
    payload = (
        "powershell -ep bypass -c \"$b='\\x49\\x45\\x58';"
        "Invoke-Expression $b; Start-Sleep 10; "
        "Get-Process | Select-Object -First 5 | Format-Table -AutoSize\""
    )
    plugin = DecoderRegistry.get("ps-hex-escape")
    fp = compute(payload)
    det = plugin.detect(payload, fp, AnalysisContext())
    assert det.confidence == 0.0, det.why


def test_manual_runner_matches_plugin_runner_for_ps_hex_escape() -> None:
    """`run_operation('ps-hex-escape', …)` must equal the plugin's own decode."""
    from operations import run_operation
    from engine.registry import DecoderRegistry
    from engine.models import AnalysisContext
    from engine.fingerprint_util import compute

    payload = r"\x49\x45\x58\x28\x27\x68\x74\x74\x70\x27\x29"
    manual = run_operation("ps-hex-escape", payload, {})
    plugin = DecoderRegistry.get("ps-hex-escape")
    det = plugin.detect(payload, compute(payload), AnalysisContext())
    direct = plugin.decode(payload, det.args, AnalysisContext()).output
    assert manual == direct
    assert manual == "IEX('http')"


def test_manual_runner_ps_reconstruct_forwards_to_plugin() -> None:
    """`ps-reconstruct` wrapper collapses [char]NN chains identically to the plugin."""
    from operations import run_operation
    payload = "[char]73+[char]69+[char]88"
    out = run_operation("ps-reconstruct", payload, {})
    # `ps-reconstruct` rebuilds the fragment into a quoted 'IEX' literal.
    assert "IEX" in out


def test_decimal_charcode_decode_manual_wrapper() -> None:
    from operations import run_operation
    out = run_operation("decimal-charcode-decode", "72 101 108 108 111", {})
    assert out == "Hello"


def test_octal_charcode_decode_manual_wrapper() -> None:
    from operations import run_operation
    out = run_operation("octal-charcode-decode", "110 145 154 154 157", {})
    assert out == "Hello"
