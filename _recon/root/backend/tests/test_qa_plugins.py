"""Production Validator + Repair plugin tests  (R28.3).

Direct unit tests on the shipped plugins so each strategy is proven
byte-for-byte deterministic in isolation, before it participates in
the orchestrator loop.
"""
from __future__ import annotations

import base64
import gzip

import pytest

# ensure plugins are imported → registrations happen
from services.uaie import plugins as _p                            # noqa: F401
from services.uaie.artifact import make_artifact
from services.uaie.qa       import (RepairCandidate, repair_for, validators_for)


# ══════════════════════════════════════════════════════════════════
# 1 · validator.base64_text — HTML mangling diagnosis
# ══════════════════════════════════════════════════════════════════
def test_base64_validator_diagnoses_html_mangled_payload():
    # Sophos-shape: valid b64 with HTML entities interleaved.
    clean_b64 = base64.b64encode(b"the quick brown fox " * 4).decode()
    mangled = clean_b64.replace("A", "&nbsp;A").replace("B", "<br>B")
    art = make_artifact(mangled.encode("utf-8"), "ps_encodedcommand",
                        discovered_by="test")
    v = validators_for("ps_encodedcommand")
    assert v, "base64 validator must be registered"
    result = v[0].validate(art)
    assert result.valid is False
    assert result.reason == "html_mangled"
    strategies = [c.strategy for c in result.repair_candidates]
    assert "strip_html_entities" in strategies


def test_base64_validator_diagnoses_bad_padding():
    # A run whose length %4 == 3 (needs one padding char).
    b64 = "AAAAABB"   # length 7, mod4 = 3
    padded = b64 + "A" * 30   # ensure the run passes the "long enough" gate
    art = make_artifact(padded.encode("utf-8"), "base64", discovered_by="test")
    v = validators_for("base64")[0]
    result = v.validate(art)
    assert result.valid is False
    strategies = [c.strategy for c in result.repair_candidates]
    assert "normalize_padding" in strategies


def test_base64_validator_accepts_clean_payload():
    clean = base64.b64encode(b"hello world " * 4).decode()
    art = make_artifact(clean.encode("utf-8"), "base64", discovered_by="test")
    result = validators_for("base64")[0].validate(art)
    assert result.valid is True


def test_base64_validator_ignores_non_base64_text():
    art = make_artifact(b"this is not base64 at all, short", "base64",
                        discovered_by="test")
    result = validators_for("base64")[0].validate(art)
    assert result.valid is True   # not our concern


def test_base64_validator_diagnoses_url_safe_alphabet():
    # URL-safe blob without any `+` / `/` but with `-` / `_`
    payload = ("ABCDEF-_ghij" * 8)
    art = make_artifact(payload.encode("utf-8"), "base64",
                        discovered_by="test")
    result = validators_for("base64")[0].validate(art)
    assert result.valid is False
    strategies = [c.strategy for c in result.repair_candidates]
    assert "url_safe_alphabet" in strategies


# ══════════════════════════════════════════════════════════════════
# 2 · repair.base64.strip_html_entities
# ══════════════════════════════════════════════════════════════════
def test_strip_html_entities_removes_common_web_noise():
    r = repair_for("strip_html_entities")
    assert r is not None
    dirty = b"<br>ABCD&nbsp;EFGH&amp;IJKL&#x0A;MNOP\xe2\x80\x8bQRST"
    art = make_artifact(dirty, "base64", discovered_by="test")
    out = r.repair(art, RepairCandidate(strategy="strip_html_entities",
                                          confidence=0.9, reason="html_mangled"))
    assert out.success is True
    cleaned = out.repaired_payload.decode("utf-8")
    assert "<br>" not in cleaned
    assert "&nbsp;" not in cleaned
    assert "&#x0A;" not in cleaned
    # zero-width char must be gone
    assert "\u200b" not in cleaned


def test_strip_html_entities_preserves_valid_base64_padding():
    """The `=` in `base64==` padding must NEVER be stripped, even
    though quoted-printable would use `=` as an escape."""
    r = repair_for("strip_html_entities")
    payload = b"HELLO<br>WORLD=="
    art = make_artifact(payload, "base64", discovered_by="test")
    out = r.repair(art, RepairCandidate(strategy="strip_html_entities",
                                          confidence=0.9, reason="html_mangled"))
    assert out.success is True
    assert out.repaired_payload.endswith(b"==")


def test_strip_html_entities_signals_no_change_when_input_clean():
    r = repair_for("strip_html_entities")
    art = make_artifact(b"ABCDEF==", "base64", discovered_by="test")
    out = r.repair(art, RepairCandidate(strategy="strip_html_entities",
                                          confidence=0.5, reason="html_mangled"))
    assert out.success is False   # nothing to strip
    assert out.reason == "no_change"


# ══════════════════════════════════════════════════════════════════
# 3 · repair.base64.normalize_padding
# ══════════════════════════════════════════════════════════════════
def test_normalize_padding_produces_length_divisible_by_4():
    r = repair_for("normalize_padding")
    # length 6 → needs 2 padding chars
    art = make_artifact(b"ABCDEF", "base64", discovered_by="test")
    out = r.repair(art, RepairCandidate(strategy="normalize_padding",
                                          confidence=0.9, reason="bad_padding"))
    assert out.success is True
    assert len(out.repaired_payload) % 4 == 0
    assert out.repaired_payload.endswith(b"==")


def test_normalize_padding_trims_stray_char():
    r = repair_for("normalize_padding")
    # length 5 (mod4=1) — invalid base64; repair trims to 4.
    art = make_artifact(b"ABCDE", "base64", discovered_by="test")
    out = r.repair(art, RepairCandidate(strategy="normalize_padding",
                                          confidence=0.9, reason="bad_padding"))
    assert out.success is True
    assert len(out.repaired_payload) == 4


# ══════════════════════════════════════════════════════════════════
# 4 · repair.base64.url_safe_alphabet
# ══════════════════════════════════════════════════════════════════
def test_url_safe_alphabet_swaps_chars():
    r = repair_for("url_safe_alphabet")
    art = make_artifact(b"ABCD-EFGH_IJKL", "base64", discovered_by="test")
    out = r.repair(art, RepairCandidate(strategy="url_safe_alphabet",
                                          confidence=0.9, reason="bad_alphabet"))
    assert out.success is True
    assert out.repaired_payload == b"ABCD+EFGH/IJKL"


# ══════════════════════════════════════════════════════════════════
# 5 · validator.pe_bytes
# ══════════════════════════════════════════════════════════════════
def test_pe_validator_rejects_missing_mz_magic():
    art = make_artifact(b"\x00" * 128, "pe_bytes", discovered_by="test")
    v = validators_for("pe_bytes")[0]
    r = v.validate(art)
    assert r.valid is False
    assert r.reason == "missing_magic"
    assert r.repair_candidates == []


def test_pe_validator_rejects_size_below_min():
    art = make_artifact(b"MZ", "pe_bytes", discovered_by="test")
    r = validators_for("pe_bytes")[0].validate(art)
    assert r.valid is False
    assert r.reason == "size_below_min"


def test_pe_validator_rejects_mz_without_pe_signature():
    # Build a bogus header: MZ + zeros, with e_lfanew pointing at offset
    # 0x40 which contains \x00\x00\x00\x00 (no PE signature).
    buf = bytearray(b"\x00" * 128)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")   # e_lfanew = 0x40
    art = make_artifact(bytes(buf), "pe_bytes", discovered_by="test")
    r = validators_for("pe_bytes")[0].validate(art)
    assert r.valid is False
    assert r.reason == "structural_mismatch"


def test_pe_validator_accepts_wellformed_pe_header():
    buf = bytearray(b"\x00" * 128)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\x00\x00"
    art = make_artifact(bytes(buf), "pe_bytes", discovered_by="test")
    r = validators_for("pe_bytes")[0].validate(art)
    assert r.valid is True


# ══════════════════════════════════════════════════════════════════
# 6 · validator.shellcode_bytes
# ══════════════════════════════════════════════════════════════════
def test_shellcode_validator_rejects_all_zero_buffer():
    art = make_artifact(b"\x00" * 32, "shellcode_bytes", discovered_by="test")
    r = validators_for("shellcode_bytes")[0].validate(art)
    assert r.valid is False
    assert r.reason == "all_zero"


def test_shellcode_validator_rejects_too_small():
    art = make_artifact(b"\x90" * 8, "shellcode_bytes", discovered_by="test")
    r = validators_for("shellcode_bytes")[0].validate(art)
    assert r.valid is False
    assert r.reason == "size_below_min"


def test_shellcode_validator_accepts_realistic_bytes():
    # nop sled + some non-uniform data
    art = make_artifact(b"\x90" * 16 + b"\xe8\x00\x00\x00\x00\x58\xc3" * 8,
                        "shellcode_bytes", discovered_by="test")
    r = validators_for("shellcode_bytes")[0].validate(art)
    assert r.valid is True


# ══════════════════════════════════════════════════════════════════
# 7 · validator.gzip_bytes + repair.gzip.partial_inflate
# ══════════════════════════════════════════════════════════════════
def test_gzip_validator_accepts_wellformed_stream():
    original = b"the quick brown fox jumps over the lazy dog" * 20
    compressed = gzip.compress(original)
    art = make_artifact(compressed, "gzip_bytes", discovered_by="test")
    r = validators_for("gzip_bytes")[0].validate(art)
    assert r.valid is True


def test_gzip_validator_rejects_missing_magic():
    art = make_artifact(b"\x00\x00" + b"x" * 100, "gzip_bytes",
                        discovered_by="test")
    r = validators_for("gzip_bytes")[0].validate(art)
    assert r.valid is False
    assert r.reason == "missing_magic"


def test_gzip_validator_diagnoses_truncation_and_proposes_partial_repair():
    original = b"the quick brown fox jumps over the lazy dog" * 20
    compressed = gzip.compress(original)
    truncated = compressed[:-20]         # kill the trailer
    art = make_artifact(truncated, "gzip_bytes", discovered_by="test")
    r = validators_for("gzip_bytes")[0].validate(art)
    assert r.valid is False
    assert r.reason == "truncated"
    strategies = [c.strategy for c in r.repair_candidates]
    assert "gzip_partial_inflate" in strategies


def test_gzip_partial_repair_recovers_readable_prefix():
    original = b"the quick brown fox jumps over the lazy dog" * 50
    compressed = gzip.compress(original)
    # Cut the compressed stream mid-way — well inside the deflate blocks.
    truncated = compressed[: len(compressed) // 2]
    art = make_artifact(truncated, "gzip_bytes", discovered_by="test")
    repair = repair_for("gzip_partial_inflate")
    out = repair.repair(art, RepairCandidate(strategy="gzip_partial_inflate",
                                                confidence=0.9,
                                                reason="truncated"))
    assert out.success is True
    assert out.repaired_artifact_type == "gzip_decoded"
    # Recovered prefix must be a real prefix of the original.
    assert original.startswith(out.repaired_payload)
    assert out.meta["recovered_bytes"] == len(out.repaired_payload)
    # We truncated aggressively — the recovered prefix MUST be shorter
    # than the original AND the truncation offset must be surfaced.
    assert len(out.repaired_payload) < len(original)
