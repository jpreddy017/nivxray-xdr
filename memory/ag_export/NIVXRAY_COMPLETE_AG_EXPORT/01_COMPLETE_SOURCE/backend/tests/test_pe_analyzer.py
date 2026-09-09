"""PE Static Analysis — deterministic contract tests (Cycle 1 · 2026-02).

Verifies:
  • `is_available()` correctly reports pefile capability.
  • `analyze_pe(bytes)` never raises.
  • Non-PE input surfaces a reasoned `error: "not_a_pe"`.
  • A real PE is parsed into stable structured fields with findings.
  • The report is byte-identical across two runs on the same input.
  • BinaryArtifact.pe_analysis is populated when kind == "PE".
"""
import pytest

from services.pe_analyzer import analyze_pe, is_available
from services.recipe_planner import _detect_binary_artifact


# Real PE ships with pip's vendored distlib — a known-good x86 launcher.
_SAMPLE_PE = "/root/.venv/lib/python3.11/site-packages/pip/_vendor/distlib/t32.exe"


def _read_sample():
    with open(_SAMPLE_PE, "rb") as f:
        return f.read()


def test_capability_flag_matches_import():
    """`is_available` must reflect actual pefile availability."""
    try:
        import pefile  # noqa
        expected = True
    except Exception:
        expected = False
    assert is_available() is expected


def test_non_pe_input_surfaces_reasoned_error():
    for payload in [b"", b"AB", b"whoami", b"this is plain text " * 40]:
        rep = analyze_pe(payload)
        assert rep["available"] is True, "capability must still be true for non-PE"
        assert rep["error"] == "not_a_pe"
        assert "MZ" in rep["message"]


def test_analyze_pe_returns_full_report_for_real_pe():
    data = _read_sample()
    rep = analyze_pe(data)
    assert rep["available"] is True
    assert rep.get("error") is None
    for key in ("overview", "hashes", "sections", "imports", "exports",
                 "resources", "packer_hints", "strings", "findings"):
        assert key in rep
    # Overview basics
    assert rep["overview"]["arch"] in ("x86", "x64", "ARM", "ARM64")
    assert rep["overview"]["kind"] in ("exe", "dll")
    assert rep["overview"]["file_size"] == len(data)
    # Hashes present + deterministic length
    for h in ("md5", "sha1", "sha256"):
        assert isinstance(rep["hashes"][h], str) and len(rep["hashes"][h]) in (32, 40, 64)
    # Sections present
    assert len(rep["sections"]) >= 1
    for s in rep["sections"]:
        assert isinstance(s["entropy"], float)
        for k in ("read", "write", "exec"):
            assert k in s["characteristics"]
    # Findings always carry the informational imphash pivot when imphash exists
    if rep["hashes"].get("imphash"):
        assert any(f["code"] == "imphash_available" for f in rep["findings"])


def test_analyze_pe_is_deterministic():
    data = _read_sample()
    r1 = analyze_pe(data)
    r2 = analyze_pe(data)
    # Every deterministic key must be identical.
    for k in ("overview", "hashes", "sections", "imports", "exports",
              "resources", "packer_hints", "findings"):
        assert r1[k] == r2[k], f"{k} not deterministic"


def test_detect_binary_artifact_attaches_pe_analysis():
    """When the recipe planner detects a PE, it must attach the analysis."""
    data = _read_sample()
    content = data.decode("latin-1", errors="replace")
    ba = _detect_binary_artifact(content, ["base64", "manual"])
    assert ba is not None
    assert ba.kind == "PE"
    assert isinstance(ba.pe_analysis, dict)
    if is_available():
        assert ba.pe_analysis["available"] is True
        assert "overview" in ba.pe_analysis
        assert ba.pe_analysis["overview"]["file_size"] == len(data)
    else:
        # Graceful degradation — panel would render "capability unavailable".
        assert ba.pe_analysis["available"] is False


def test_binary_artifact_to_dict_includes_pe_analysis():
    data = _read_sample()
    ba = _detect_binary_artifact(data.decode("latin-1", errors="replace"), ["manual"])
    d = ba.to_dict()
    assert "pe_analysis" in d
    # to_dict must be JSON-serializable.
    import json
    json.dumps(d)


def test_analyze_pe_never_raises_on_garbage():
    """Corrupted PEs must surface a diagnostic dict, never raise."""
    # MZ header but zero rest — pefile will refuse.
    r = analyze_pe(b"MZ" + b"\x00" * 500)
    assert r["available"] is True
    assert r.get("error") in {"pe_parse_failed", "not_a_pe"}
