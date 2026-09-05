"""PE Extractor + .NET Recognizer · Capability Pack (Priority 6 · CI Gate).

Proves:
  1. `pe.extractor` finds an embedded MZ+PE header inside a peeled
     buffer and emits a `pe_bytes` child artifact.
  2. `pe.dotnet_recognizer` reads the PE Optional-Header directory[14]
     (COR20) and emits `dotnet_pe` evidence + managed-loader family.
  3. Both plugins are deterministic and silent on non-PE input.

Run:  cd /app/backend && python -m pytest tests/test_pe_extractor_and_dotnet.py -v
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie              import plugins as _plugins_pkg
from services.uaie.orchestrator import Orchestrator


# ─────────────────────────────────────────────────────────────────────
# Synthetic PE / .NET builder — minimum viable optional header.
# Only the fields the recognizers touch are populated:
#   · DOS header at offset 0 + e_lfanew → PE header
#   · PE\0\0 signature + File Header
#   · Optional Header (PE32 magic 0x10B) with 16 data directories
#   · Data Directory index 14 (COR20) points at a fake CLR header
# ─────────────────────────────────────────────────────────────────────
def _make_minimal_pe(*, dotnet: bool) -> bytes:
    """Build a minimally-structural PE that passes the recognizer's
    header math.  Not runnable — but bit-accurate for our detectors."""
    e_lfanew = 0x80
    dos_stub = bytearray(e_lfanew)
    dos_stub[:2] = b"MZ"
    struct.pack_into("<I", dos_stub, 0x3C, e_lfanew)

    # File Header (20 bytes): Machine, NumSections, TimeDate, PtrSymTab,
    # NumSyms, OptHdrSize, Characteristics
    file_header = struct.pack("<HHIIIHH",
                               0x14C,   # Machine = i386
                               1,       # NumberOfSections
                               0,       # TimeDateStamp
                               0,       # PointerToSymbolTable
                               0,       # NumberOfSymbols
                               0xE0,    # SizeOfOptionalHeader
                               0x2102)  # Characteristics

    # Optional Header (PE32) = 224 bytes = 96 (std) + 128 (16 dirs × 8).
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)   # Magic = PE32

    # Data Directory[14] = COR20 (only present in managed PEs).
    if dotnet:
        struct.pack_into("<II", opt, 96 + 14 * 8, 0x2008, 0x48)

    body = bytes(dos_stub) + b"PE\x00\x00" + file_header + bytes(opt)
    # Pad up so it clears _MIN_PE_SIZE (=512).
    return body + b"\x00" * max(0, 1024 - len(body))


def _make_pe_with_clr_markers() -> bytes:
    """Managed PE + explicit `mscoree.dll` / `Assembly.Load` strings
    so the marker-based recognition path is exercised."""
    pe = bytearray(_make_minimal_pe(dotnet=True))
    tail = (b"mscoree.dll\x00clr.dll\x00CorBindToRuntime\x00"
             b"Assembly.Load\x00ExecuteInDefaultAppDomain\x00"
             b"ICorRuntimeHost\x00AppDomain\x00")
    return bytes(pe + tail)


# ─────────────────────────────────────────────────────────────────────
# T1 · Both plugins registered.
# ─────────────────────────────────────────────────────────────────────
def test_plugins_registered():
    names = {p["name"] for p in _plugins_pkg.all_plugins()}
    assert "pe.extractor" in names, "pe.extractor plugin missing"
    assert "pe.dotnet_recognizer" in names, "pe.dotnet_recognizer plugin missing"


# ─────────────────────────────────────────────────────────────────────
# T2 · Embedded PE inside a text host produces a pe_bytes child.
# ─────────────────────────────────────────────────────────────────────
def test_embedded_pe_extracted_from_text_host():
    pe = _make_minimal_pe(dotnet=False)
    junk = b"# junk header text " * 8         # ~150 bytes of noise
    host = junk + pe + b"# trailing"
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(host, root_type="text")

    pe_children = [a for a in result.artifacts.values()
                     if a.artifact_type == "pe_bytes" and a.uri != next(iter(result.artifacts))]
    assert pe_children, (
        f"pe.extractor failed to emit a pe_bytes child.  "
        f"Types seen: {sorted({a.artifact_type for a in result.artifacts.values()})}"
    )
    embedded_ev = [ev for ev in result.evidence if ev.kind == "embedded_pe"]
    assert embedded_ev, "expected an 'embedded_pe' evidence entry"
    assert any("T1027.009" in ev.mitre_techniques for ev in embedded_ev)


# ─────────────────────────────────────────────────────────────────────
# T3 · .NET recognizer fires on a managed PE with COR20 directory.
# ─────────────────────────────────────────────────────────────────────
def test_dotnet_recognizer_via_cor20_directory():
    pe = _make_minimal_pe(dotnet=True)
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(pe, root_type="pe_bytes")

    dotnet_ev = [ev for ev in result.evidence if ev.kind == "dotnet_pe"]
    assert dotnet_ev, (
        f"pe.dotnet_recognizer failed on a PE with COR20 directory.  "
        f"Evidence kinds: {sorted({e.kind for e in result.evidence})}"
    )
    assert dotnet_ev[0].value["cor20_present"] is True
    assert dotnet_ev[0].value["cor20_rva"] == 0x2008


# ─────────────────────────────────────────────────────────────────────
# T4 · Managed loader family is emitted when CLR markers present.
# ─────────────────────────────────────────────────────────────────────
def test_dotnet_managed_loader_family_emitted():
    pe = _make_pe_with_clr_markers()
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(pe, root_type="pe_bytes")

    fam = [ev for ev in result.evidence
             if ev.kind == "family"
             and ev.source_capability == "pe.dotnet_recognizer"]
    assert fam, (
        f".NET managed-loader family not emitted.  "
        f"Family evs: {[(e.value, e.source_capability) for e in result.evidence if e.kind == 'family']}"
    )
    ev = fam[0]
    assert "T1620" in ev.mitre_techniques
    assert ev.meta.get("family_id") == "dotnet-managed-loader"


# ─────────────────────────────────────────────────────────────────────
# T5 · Non-PE inputs never produce false-positive extraction.
# ─────────────────────────────────────────────────────────────────────
def test_no_false_positive_on_random_text():
    payload = (b"This is a benign document containing the letters MZ "
                b"but no valid DOS header at any offset.  MZ MZ MZ.")
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    pe_kids = [a for a in result.artifacts.values()
                if a.artifact_type == "pe_bytes"]
    assert not pe_kids, (
        f"pe.extractor produced a false-positive child on ASCII text.  "
        f"Children: {pe_kids}"
    )
    dotnet_ev = [ev for ev in result.evidence if ev.kind == "dotnet_pe"]
    assert not dotnet_ev, "pe.dotnet_recognizer emitted on non-PE input"


# ─────────────────────────────────────────────────────────────────────
# T6 · Determinism (R28 purity).
# ─────────────────────────────────────────────────────────────────────
def test_pe_extractor_and_dotnet_are_deterministic():
    pe = _make_pe_with_clr_markers()
    payload = b"prefix bytes " * 4 + pe + b"trailer" * 4
    r1 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="unknown")
    r2 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="unknown")

    def _fp(evs):
        return sorted((e.kind, str(e.value)[:200],
                        e.source_capability) for e in evs)
    assert _fp(r1.evidence) == _fp(r2.evidence)
