"""ELF Analyzer — Phase 3 · Cycle C · 2026-02.

Uses `/bin/ls` (present on every Linux pod) as the golden PE-free real
binary to verify the analyzer's contract.
"""
import pytest

from services.artifact_intelligence import dispatch


_LS = "/bin/ls"


def _read_sample():
    with open(_LS, "rb") as f:
        return f.read()


def test_registry_contains_elf():
    from services.artifact_intelligence import registered_types
    ids = {t["artifact_type"] for t in registered_types()}
    assert "elf" in ids


def test_dispatch_elf_routes_to_elf_analyzer():
    data = _read_sample()
    r = dispatch(data)
    assert r.artifact_type == "elf"
    assert r.capability_available is True
    assert r.confidence == 99
    a = r.analysis
    assert a["available"] is True
    for key in ("overview", "sections", "segments", "dynamic", "symbols", "notes", "findings", "hashes"):
        assert key in a
    o = a["overview"]
    assert o["elf_class"] in (32, 64)
    assert o["type"] in ("ET_DYN", "ET_EXEC")
    assert o["endianness"] in ("little", "big")
    assert o["num_sections"] >= 1
    assert o["num_segments"] >= 1


def test_elf_analyzer_is_deterministic():
    data = _read_sample()
    r1 = dispatch(data)
    r2 = dispatch(data)
    assert r1.to_dict() == r2.to_dict()


def test_elf_analyzer_never_raises_on_garbage():
    r = dispatch(b"\x7fELF" + b"\x00" * 500)
    # Either parse failed OR the routed analysis has an error — never raises.
    assert r.artifact_type == "elf"
    a = r.analysis
    assert isinstance(a, dict)
    # If it did parse, `available: True` with the shape. If not, error present.
    if a.get("error"):
        assert a["error"] == "elf_parse_failed"


def test_elf_findings_always_include_summary():
    data = _read_sample()
    r = dispatch(data)
    codes = {f["code"] for f in r.analysis["findings"]}
    assert "elf_summary" in codes


def test_binary_artifact_routes_elf_via_recipe_planner():
    from services.recipe_planner import _detect_binary_artifact
    data = _read_sample()
    ba = _detect_binary_artifact(data.decode("latin-1", errors="replace"), ["manual"])
    assert ba is not None
    assert ba.kind == "ELF"
    routed = ba.routed_analysis
    assert routed is not None
    assert routed["artifact_type"] == "elf"
    assert routed["capability_available"] is True
