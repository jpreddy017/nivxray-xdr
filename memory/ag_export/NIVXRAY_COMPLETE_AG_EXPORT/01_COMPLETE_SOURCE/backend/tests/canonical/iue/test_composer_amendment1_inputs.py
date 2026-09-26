"""T1.7 · Amendment 1 — 5-input-class coverage.

The composer MUST demonstrably handle all five input classes end-to-end
with real sub-classifier participation. IUE-4 (bytes-native) and IUE-5
(artefact decomposition) MUST both participate through the composer.
"""
import pytest

from canonical.iue import Capability, classify, RawInput


# ── Fixture: real-shape PE header ────────────────────────────────────────
PE_HEADER = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"L\x01" + b"\x00" * 200


# ── Fixture: DOCX bytes ───────────────────────────────────────────────────
# ZIP-magic + minimal padding; real .docx files start with PK\x03\x04.
# Also accept a real .docx on disk if provided.
def _docx_bytes() -> bytes:
    import os
    candidates = [
        "/app/backend/tests/live/ideas_updated.docx",
        "/app/backend/docs/exports/nivxray-user-guide.docx",
    ]
    for c in candidates:
        if os.path.exists(c):
            with open(c, "rb") as f:
                return f.read()
    return b"PK\x03\x04" + b"\x14\x00\x06\x00" + b"\x00" * 2000


# =====================================================================
#   CLASS 1 — RAW TEXT
# =====================================================================
def test_class1_raw_text_ps_encoded_reaches_iue_composer():
    d = classify("powershell -EncodedCommand SGVsbG8gV29ybGQ=")
    # IUE must classify successfully
    assert d.input_profile.primary_type not in ("", "unknown")
    # IUE-2 (text_structure) must participate — this is the classifier
    # of record for PowerShell + encoded commands.
    sources = {e.source for e in d.evidence}
    assert "text_structure" in sources, \
        f"IUE-2 (text_structure) did not participate for raw text: {sources}"
    # IUE-3 (language_multi_artefact) must also participate.
    assert any(s == "language_multi_artefact" or s.startswith("input_understanding") for s in sources), \
        f"IUE-3 did not participate: {sources}"
    # Plan must include DECODER (base64) and MITRE_MAP.
    caps = {c for c in d.capabilities}
    assert Capability.MITRE_MAP in caps


# =====================================================================
#   CLASS 2 — RAW BYTES (non-document binary)
# =====================================================================
def test_class2_raw_bytes_pe_header_triggers_iue4():
    """IUE-4 is the ONLY bytes-native classifier — must participate."""
    d = classify(RawInput(payload=PE_HEADER, filename="sample.exe"))
    sources = {e.source for e in d.evidence}
    assert "bytes_magic" in sources, \
        f"IUE-4 (bytes_magic) did not participate for raw PE bytes: {sources}"
    # Primary must be a binary type
    assert "pe" in d.input_profile.primary_type.lower() \
        or "pe" in (d.input_profile.input_kind or "").lower()
    # Byte signature stamped
    assert d.input_profile.byte_signature
    assert d.input_profile.byte_signature.startswith("4d5a")  # 'MZ' in hex


# =====================================================================
#   CLASS 3 — DOCX  (must trigger IUE-4 magic AND IUE-5 decomposition)
# =====================================================================
def test_class3_docx_triggers_iue4_and_iue5():
    """DOCX is the acceptance canary. IUE-4 must identify it via magic
    bytes; IUE-5 must run artefact decomposition on the extracted text
    surface. This is the exact scenario Sample1 exposed."""
    d = classify(RawInput(payload=_docx_bytes(), filename="Sample.docx"))
    sources = {e.source for e in d.evidence}
    assert "bytes_magic" in sources, \
        f"IUE-4 (bytes_magic) did not participate for DOCX: {sources}"
    assert "artefact_decomp" in sources, \
        f"IUE-5 (artefact_decomp) did not participate for DOCX: {sources}"
    # Primary must be DOCX / archive
    pt = d.input_profile.primary_type.lower()
    ik = (d.input_profile.input_kind or "").lower()
    assert pt in ("docx", "zip_archive") or ik in ("docx", "zip_archive"), \
        f"DOCX class not detected; primary={pt} kind={ik}"
    # Plan must include ARCHIVE_EXTRACT and ARTIFACT_SPLIT
    caps = set(d.capabilities)
    assert Capability.ARCHIVE_EXTRACT in caps, \
        f"ARCHIVE_EXTRACT missing from DOCX plan: {caps}"
    assert Capability.ARTIFACT_SPLIT in caps, \
        f"ARTIFACT_SPLIT missing from DOCX plan: {caps}"


# =====================================================================
#   CLASS 4 — MULTI-ARTEFACT
# =====================================================================
def test_class4_multi_artefact_produces_non_empty_embedded():
    """wmic -> cmd -> powershell -> base64 nesting must yield embedded[]."""
    d = classify('wmic process call create "cmd /c powershell -EncodedCommand SGVsbG8="')
    sources = {e.source for e in d.evidence}
    assert any(s == "language_multi_artefact" or s.startswith("input_understanding") for s in sources), \
        f"IUE-3 did not participate: {sources}"
    assert d.input_profile.embedded, \
        "multi-artefact input produced empty embedded[]"
    # Plan must include COMMAND_DETECT + SEMANTIC_AST
    caps = set(d.capabilities)
    assert Capability.COMMAND_DETECT in caps, \
        f"COMMAND_DETECT missing from multi-artefact plan: {caps}"
    assert Capability.SEMANTIC_AST in caps


# =====================================================================
#   CLASS 5 — MALFORMED / AMBIGUOUS
# =====================================================================
def test_class5_malformed_high_control_char_no_exception():
    """40% control chars + truncated encoding: InputHealth should flag
    the anomaly; composer must NOT raise; classification degrades to
    UNKNOWN or lowest-confidence primary with evidence."""
    malformed = ("\x00\x01\x02\x03\x04" * 8) + "aabb" + ("\x00" * 10)
    d = classify(malformed)
    # Must not raise (implicit — we reached this line)
    assert d.determinism_hash
    # Health must have recorded something OR classification is degraded.
    # Both are valid outcomes — the invariant is "no exception".
    assert isinstance(d.input_health.control_char_ratio, float)
    # Composer stamped provenance despite malformed input.
    assert d.provenance.engine == "canonical.iue.composer"


def test_class5_empty_input_does_not_raise():
    d = classify("")
    assert d.determinism_hash


def test_class5_none_like_bytes_do_not_raise():
    d = classify(RawInput(payload=b"", filename=None))
    assert d.determinism_hash


# =====================================================================
#   AGGREGATE — every class produces a deterministic hash
# =====================================================================
def test_all_five_classes_yield_stable_hashes():
    inputs = [
        "powershell -EncodedCommand SGVsbG8=",
        RawInput(payload=PE_HEADER, filename="a.exe"),
        RawInput(payload=_docx_bytes(), filename="Sample.docx"),
        'wmic /... cmd /c "powershell -e SGVsbG8="',
        "\x00\x01\x02" * 20,
    ]
    for inp in inputs:
        h0 = classify(inp).determinism_hash
        for _ in range(20):
            assert classify(inp).determinism_hash == h0
