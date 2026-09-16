"""Regression tests for the corrupt-payload detector.

The detector must fire on structurally-impossible payloads (bad base64
length, malformed deflate, synthetic gzip headers) so NivXRay never
'silently' returns empty output when an analyst compares us to another
tool that hallucinates plausible content from a broken input.
"""
from __future__ import annotations
import base64
import gzip
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from corrupt_payload_detector import detect_corrupt_payload


# ─── The user's Feb-2026 hallucination-trap payload ──────────────────────
_FIXTURE_CORRUPT_GZIP_701 = (
    "H4sIAAAAAAAA/41XbW/bNhD+K/wVBiRAbCuxH9uNAm/Z0gXbMAzDsC9bkS9Goiw6Fis6"
    "JclOnWb/fUdKspM4zYpgwCOeuefeHee7S0v027DInb0h4v2w2e7T6yZ+88Xatw/fWvjF"
    "2g/WrtY+WLtbB65gCjZgiBpswT02Yo7bYgM24AbcsT0e4T3u8RG/4CPu4Tfuw69wX6w/"
    "Yv0IHzV6Wj3wE+zBf/Al9mAP/oNPuIe/wN/gK9yHL3AHX+AOPsMebOFrqGgXvsCH9EId"
    "Xf9Mh136XgU0BfsxKHIwGZqM1tKk8M92aN+9pL/mAn6m67nAfXp7T9dT6uT6wN9gH+Y6"
    "7MF9WODXgW86gM+wAL/wCHdwid/oenrhBv7S6I/WvtbvBwG/MofvAn5w8D3ghwCPwIDu"
    "0+969A7YgxH2wID9f7836b/9gA9gD0Ywgl9gA0b4jftgA6bY4wPcwZf0A8wR6G+D9G8Z"
    "0CgN/g36f4t9gH/Bf+ADwYAGI/gmXQfeZfCHwA8OvrHwvYUPAn628D/WfjHwz7Xf9PtN"
    "oP0Bf9fvv7Wn9PtN+/eW3gIftX+fwa8C7XPgO9rnwXfgOfB3/X4T+E2g3wT6b6b7f9bv"
    "W/gHeo7N98Y6YDP9/3N0GThN+/+eXgP9O7rTPh+dY/p3dKeZfhV6RzS/4W8gWv9V9C36"
    "b6L7wK+w/+P6P9fvv7Xfk"
)


def test_detect_corrupt_gzip_impossible_b64_length():
    """User's 701-char (4n+1) fake MSF stager — must trip both length + gzip checks."""
    result = detect_corrupt_payload(_FIXTURE_CORRUPT_GZIP_701)
    assert result is not None, "corrupt-payload detector must fire on this fixture"
    codes = {r["code"] for r in result["reasons"]}
    assert "BASE64_IMPOSSIBLE_LEN" in codes, f"length check missing: {codes}"
    # It should also trip the gzip-header-valid-body-bad OR synthetic-header check
    assert ("GZIP_HEADER_VALID_BODY_BAD" in codes
            or "GZIP_SYNTHETIC_HEADER" in codes
            or "LOW_ENTROPY_FAUX_COMPRESSED" in codes), \
        f"expected at least one gzip-corruption check to fire: {codes}"
    assert result["severity"] == "high"
    assert "hallucinat" in result["recommendation"].lower() or "corrupt" in result["verdict"].lower()


def test_detect_none_for_valid_powershell_encoded_command():
    """The benign `powershell.exe -EncodedCommand` payload from the user's
    other bug report is VALID — the detector must NOT fire (no false positives)."""
    payload = ("powershell.exe -EncodedCommand "
               "RwBlAHQALQBQAHIAbwBjAGUAcwBzACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABQ"
               "AHIAbwBjAGUAcwBzAE4AYQBtAGUALAAgAEkAZAAgAC0ARgBpAHIAcwB0ACAANQA=")
    result = detect_corrupt_payload(payload)
    # Base64 is valid AND decodes to real UTF-16 PS. Must not flag.
    assert result is None, f"detector produced false positive: {result}"


def test_detect_none_for_valid_gzip_payload():
    """Real gzip-of-text must NOT trip the detector."""
    real = gzip.compress(b"Get-Process | Select-Object ProcessName, Id -First 5")
    b64 = base64.b64encode(real).decode()
    result = detect_corrupt_payload(b64)
    assert result is None, f"detector flagged real gzip as corrupt: {result}"


def test_detect_none_for_plaintext():
    """Non-b64 plaintext must not confuse the detector."""
    assert detect_corrupt_payload("Get-Process | Select-Object ProcessName, Id") is None
    assert detect_corrupt_payload("just a normal english sentence with no encoding") is None
    assert detect_corrupt_payload("") is None


def test_detect_synthetic_gzip_header_fingerprint():
    """Hand-crafted gzip with mtime=0, os=0xff — the giveaway fingerprint."""
    # Build a real (structurally valid) gzip, then rewrite mtime + os to the
    # synthetic values used by the Feb-2026 trap payload.
    real = bytearray(gzip.compress(b"hello world " * 100))
    real[4:8] = b"\x00\x00\x00\x00"  # mtime = 0
    real[8] = 0x00                    # xfl = 0
    real[9] = 0xff                    # os = unknown
    b64 = base64.b64encode(bytes(real)).decode()
    result = detect_corrupt_payload(b64)
    # This SHOULD fire GZIP_SYNTHETIC_HEADER (even though the body is real).
    assert result is not None
    codes = {r["code"] for r in result["reasons"]}
    assert "GZIP_SYNTHETIC_HEADER" in codes


def test_troubleshoot_short_circuits_on_corrupt():
    """Universal Troubleshoot must NOT try to force-decode a corrupt payload —
    it must return the CORRUPT_PAYLOAD verdict with human_summary containing
    a hallucination warning."""
    from troubleshoot_engine import troubleshoot
    r = troubleshoot(_FIXTURE_CORRUPT_GZIP_701)
    assert r["success"] is False
    assert r["final_engine"] == "corrupt-payload-detector"
    codes = [d["code"] for d in r["diagnoses"]]
    assert "CORRUPT_PAYLOAD" in codes
    assert "hallucinate" in r["human_summary"].lower() or "corrupt" in r["human_summary"].lower()
