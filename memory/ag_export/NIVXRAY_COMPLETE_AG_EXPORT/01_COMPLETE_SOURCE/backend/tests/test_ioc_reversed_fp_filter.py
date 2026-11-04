"""IOC false-positive filter regression — Feb-2026 analyst-reported bug.

Reversed intermediates from the magic-decoder's `reverse` candidate op
were leaking into the domain IOC list (e.g. `maertspizg.noisserpmoc.oi`
from a reversed `io.compression.gzipstream`). This suite pins the fix:

  1. Real-TLD allow-list gate rejects any domain whose TLD is not a
     known public TLD.
  2. Reversed-TLD tokens (`moc`, `ten`, `gro`, `oi`, `ia`, …) inside
     any label are treated as strong reverse-code signal → reject.
  3. Executable-extension leading labels (`exe.`, `dll.`, …) are added
     to the code-namespace prefix filter.
  4. Real IOCs continue to pass (evil.example.com, sub.domain.io,
     example.co.uk, 1.2.3.4, hashes, URLs).
"""
from __future__ import annotations

import asyncio
import pytest

from operations import extract_iocs
from chain_analyzer import analyze_chain


# ─── 1. Reversed-string false positives ───────────────────────────────
@pytest.mark.parametrize("junk", [
    "maertspizg.noisserpmoc.oi",   # reversed io.compression.gzipstream
    "exe.nimdassv",                 # reversed vssadmin.exe
    "gninnacs.moc",                 # reversed com.scanning (contains `moc`)
    "dll.something",                # dll.* prefix
    "kernel32.dll",                 # nope — TLD dll not real
])
def test_reversed_or_binary_junk_is_rejected(junk):
    r = extract_iocs(f"prefix {junk} suffix")
    assert junk not in r["domains"], f"reversed junk leaked: {junk} → {r['domains']}"


# ─── 2. Real domains must still pass ──────────────────────────────────
@pytest.mark.parametrize("real", [
    "evil.example.com",
    "malware.example.io",
    "phish.example.co.uk",
    "c2.example.net",
    "attacker.example.org",
    "loader.example.xyz",
])
def test_real_domains_pass(real):
    r = extract_iocs(f"visit http url http://{real}/x and callback {real}/y")
    assert real in r["domains"], f"real domain rejected: {real} → {r['domains']}"


# ─── 3. IPs, URLs, hashes untouched by the domain filter ──────────────
def test_non_domain_iocs_unaffected():
    text = (
        "Reach 8.8.8.8 or 1.1.1.1. Fetch http://real.example.com/x.exe. "
        "MD5 5d41402abc4b2a76b9719d911017c592 SHA1 a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 "
        "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    r = extract_iocs(text)
    assert "8.8.8.8" in r["ips"] and "1.1.1.1" in r["ips"]
    assert "real.example.com" in r["domains"]
    assert r["md5"] and r["sha1"] and r["sha256"]


# ─── 4. End-to-end chain — the exact analyst-reported payload ─────────
def test_end_to_end_chain_no_reversed_domain_leak():
    stages = [
        (
            "powershell.exe -NoProfile -WindowStyle Hidden -NonInteractive -Command "
            "\"IO.Compression.GzipStream\" "
            "$b='H4sICD12mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA=';"
            "$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));"
            "$g=New-Object IO.Compression.GzipStream($m,"
            "[IO.Compression.CompressionMode]::Decompress);"
            "$r=New-Object IO.StreamReader($g);IEX $r.ReadToEnd();"
        ),
        (
            "cmd.exe /c \"vssadmin.exe delete shadows /all /quiet && "
            "wbadmin delete systemstatebackup -keepVersions:0 -quiet && "
            "bcdedit /set {default} recoveryenabled No && "
            "wmic shadowcopy delete\""
        ),
    ]
    r = asyncio.run(analyze_chain(stages))
    doms = r.get("aggregate", {}).get("iocs", {}).get("domains", [])
    # No reversed junk of ANY shape should leak through
    for bad in ["maertspizg.noisserpmoc.oi", "exe.nimdassv", "noisserpmoc.oi"]:
        assert bad not in doms, f"leaked reversed junk: {bad} → {doms}"
    # No label in any surviving domain may equal a known reversed-TLD token
    forbidden_labels = {"moc", "ten", "gro", "ofni", "oi", "ia", "vog", "ude"}
    for d in doms:
        assert not (set(d.split(".")) & forbidden_labels), \
            f"domain {d!r} contains reversed-TLD token"


# ─── 5. Numeric-heavy junk (from ASCII-decimal decodes) ───────────────
def test_numeric_label_junk_rejected():
    # `1234567.example.com` would be a real domain by regex; but
    # `12345.6789.abc` is code artefact and must be rejected.
    r = extract_iocs("12345.6789.abc and also 987654321.789.abc")
    for d in r["domains"]:
        assert not any(lab.isdigit() and len(lab) > 3 for lab in d.split(".")[:-1]), \
            f"numeric-only label leaked: {d}"
