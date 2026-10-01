"""Regression tests — Feb-2026 fixes for:
  1. PowerShell variable-indirection archetype match
     ($b='<b64>'; ...FromBase64String($b))
  2. CRC-corrupt gzip salvage via raw-deflate fallback
  3. Destructive Wiper / Ransomware Precursor family classifier
  4. New LOLBAS binaries (wevtutil, fsutil, cipher) hit the allow-list
"""
from __future__ import annotations

import asyncio

import pytest

from wrapper_archetypes import (
    resolve_ps_variables,
    try_archetypes,
    robust_b64_then_gunzip,
)
from chain_analyzer import analyze_chain, detect_malware_family
from lolbas import scan_lolbas


# ─── 1. Variable-indirection archetype ───────────────────────────────
def test_ps_var_assign_is_resolved():
    text = (
        "$b='H4sICD12mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA=';"
        "$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));"
        "$g=New-Object IO.Compression.GzipStream($m,"
        "[IO.Compression.CompressionMode]::Decompress);"
        "$r=New-Object IO.StreamReader($g);IEX $r.ReadToEnd();"
    )
    resolved = resolve_ps_variables(text)
    # LHS assignment preserved (readability)
    assert "$b='H4sIC" in resolved
    # References inlined as string literals so the archetype regex fires
    assert "FromBase64String('H4sIC" in resolved


def test_archetype_matches_ps_memstream_gzip_with_var_indirection():
    text = (
        "powershell.exe -NoProfile -WindowStyle Hidden -Command "
        "$b='H4sICD12mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA=';"
        "$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));"
        "$g=New-Object IO.Compression.GzipStream($m,"
        "[IO.Compression.CompressionMode]::Decompress);"
        "$r=New-Object IO.StreamReader($g);IEX $r.ReadToEnd();"
    )
    r = try_archetypes(text)
    assert r is not None
    assert r["archetype_id"] == "PS_MemoryStream_Gzip_IEX"
    assert "Fensworld" in r["output"]


# ─── 2. CRC-corrupt gzip salvage ─────────────────────────────────────
def test_gzip_crc_salvage_via_raw_deflate():
    # This blob has a valid header + FNAME 'code' + deflate('Fensworld!')
    # but a CRC that Python's strict gzip refuses.
    blob = "H4sICD12mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA="
    out = robust_b64_then_gunzip(blob)
    assert "Fensworld!" in out
    assert "GZIP CRC INVALID" in out


# ─── 3. End-to-end chain analysis ────────────────────────────────────
def test_end_to_end_var_indirection_chain_stage_zero():
    text = (
        "powershell.exe -NoProfile -WindowStyle Hidden -NonInteractive -Command "
        "\"IO.Compression.GzipStream\" "
        "$b='H4sICD12mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA=';"
        "$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));"
        "$g=New-Object IO.Compression.GzipStream($m,"
        "[IO.Compression.CompressionMode]::Decompress);"
        "$r=New-Object IO.StreamReader($g);IEX $r.ReadToEnd();"
    )
    r = asyncio.run(analyze_chain([text]))
    stage = r["stages"][0]
    assert stage["confidence"] == 100
    assert "archetype:PS_MemoryStream_Gzip_IEX" in stage["engine"]
    assert "Fensworld" in stage["output"]


# ─── 4. LOLBAS additions ─────────────────────────────────────────────
@pytest.mark.parametrize("cmdline,expected_bin", [
    ("wevtutil.exe cl Security", "wevtutil.exe"),
    ("fsutil.exe usn deletejournal /d C:", "fsutil.exe"),
    ("cipher.exe /w:C:\\", "cipher.exe"),
])
def test_new_lolbas_binaries_match(cmdline, expected_bin):
    hits = scan_lolbas(cmdline)
    bins = {h["binary"] for h in hits}
    assert expected_bin in bins, f"expected {expected_bin} in {bins}"


# ─── 5. Destructive Wiper family classifier ──────────────────────────
def _stage(idx: int, lolbas_bins: list) -> dict:
    return {
        "stage_index": idx,
        "input_preview": "",
        "output": "",
        "lolbas": [{"binary": b} for b in lolbas_bins],
    }


def test_destructive_wiper_family_fires_on_three_bins():
    stages = [
        _stage(0, ["vssadmin.exe"]),
        _stage(1, ["wbadmin.exe", "bcdedit.exe"]),
        _stage(2, ["wevtutil.exe"]),
    ]
    fam = detect_malware_family(stages)
    assert fam is not None
    assert fam["family"] == "Destructive Wiper / Ransomware Precursor"
    assert fam["hits"] >= 3


def test_destructive_wiper_does_not_fire_on_two_bins():
    stages = [
        _stage(0, ["vssadmin.exe"]),
        _stage(1, ["wbadmin.exe"]),
    ]
    fam = detect_malware_family(stages)
    # Should either return None or a different family — not Destructive Wiper
    assert fam is None or fam["family"] != "Destructive Wiper / Ransomware Precursor"


def test_destructive_wiper_beats_generic_regex_family():
    # Even with a weak generic PS Downloader signal in text, the LOLBAS
    # signal should win because it's higher fidelity.
    stages = [
        {"stage_index": 0, "input_preview": "invoke-webrequest http://x",
         "output": "", "lolbas": [{"binary": "vssadmin.exe"}]},
        {"stage_index": 1, "input_preview": "", "output": "",
         "lolbas": [{"binary": "wbadmin.exe"}]},
        {"stage_index": 2, "input_preview": "", "output": "",
         "lolbas": [{"binary": "fsutil.exe"}, {"binary": "cipher.exe"}]},
    ]
    fam = detect_malware_family(stages)
    assert fam["family"] == "Destructive Wiper / Ransomware Precursor"
