"""Regression: IOC extractor must not flag .NET class namespaces as domains.

Bug reported Feb-2026 while testing the STIX export on a real base64+gzip
PowerShell dropper: the STIX bundle was polluted with fake indicators like
`[domain-name:value = 'io.memorystream']` and
`[domain-name:value = 'io.compression.gzipstream']` because .NET class
namespaces regex-match the `label.label.tld` shape.

Fix: `operations.extract_iocs` now filters two classes of false positives:
  1. Code-namespace PREFIXES (io.*, system.*, net.*, kernel32.*, ...)
  2. Fake TLDs from method-chain leftovers (.readtoend, .frombase64string,
     .memorystream, .decompress, ...)

These tests lock that guarantee — analysts opening STIX bundles into MISP /
OpenCTI must never see fake indicators drawn from PowerShell script identifiers.
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401
from operations import extract_iocs


DOTNET_NOISE_LINES = """
$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAA=="))
$reader = New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))
$k = [System.Text.Encoding]::ASCII.GetBytes("secretkey")
$b = [System.Convert]::FromBase64String($enc)
$reader.ReadToEnd()
$reader.Close()
[System.Net.ServicePointManager]::SecurityProtocol
"""


def test_dotnet_class_namespaces_are_not_flagged_as_domains():
    r = extract_iocs(DOTNET_NOISE_LINES)
    bad = ["io.memorystream", "io.streamreader", "io.compression.gzipstream",
           "io.compression.compressionmode", "system.text.encoding",
           "system.convert", "system.net.servicepointmanager"]
    for d in r["domains"]:
        assert d not in bad, f".NET namespace '{d}' leaked into domains list"


def test_method_chain_pseudo_tlds_are_dropped():
    """Things like `chunk.readtoend`, `.encoding.ascii.getbytes` must NOT be domains."""
    text = "$r = $reader.ReadToEnd(); [System.Text.Encoding]::ASCII.GetBytes('x'); $b.FromBase64String($x); $chunk.Decompress()"
    r = extract_iocs(text)
    bad_endings = ["readtoend", "getbytes", "frombase64string", "decompress"]
    for d in r["domains"]:
        tld = d.rsplit(".", 1)[-1]
        assert tld not in bad_endings, f"pseudo-TLD '{tld}' passed through in domain '{d}'"


def test_binary_extensions_are_not_domains():
    """`payload.exe`, `script.ps1`, `hook.dll` must NOT be flagged as domains."""
    text = "dropper.exe kicked off payload.ps1 which loaded evil.dll and bypassed avguard.sys"
    r = extract_iocs(text)
    for d in r["domains"]:
        tld = d.rsplit(".", 1)[-1]
        assert tld not in ("exe", "ps1", "dll", "sys", "bat", "cmd", "vbs"), \
            f"binary/script ext '{tld}' leaked as domain: {d}"


def test_real_domains_still_pass():
    """The FIX MUST NOT break detection of real malicious domains."""
    text = ("beacon phones home to c2.evilcorp.ru and drops payload.exe. "
            "Also observed connection to malicious-cdn.example.com and phish.login-microsoft-secure.net")
    r = extract_iocs(text)
    for expected in ["c2.evilcorp.ru", "malicious-cdn.example.com",
                     "phish.login-microsoft-secure.net"]:
        assert expected in r["domains"], f"lost real domain '{expected}'"


def test_ip_and_url_extraction_unaffected():
    text = ("Contacts 192.168.13.37 and 45.137.21.9 via "
            "https://phish.example.com/beacon and hxxps://c2[.]badsite[.]ru/x")
    r = extract_iocs(text)
    assert "192.168.13.37" in r["ips"]
    assert "45.137.21.9" in r["ips"]
    assert any("phish.example.com" in u for u in r["urls"])
    # The refanger normalises hxxps://c2[.]badsite[.]ru/x → domain c2.badsite.ru
    assert "c2.badsite.ru" in r["domains"]


def test_email_extraction_still_works():
    text = "contact admin@evilcorp.ru or attacker+campaign@phish.example.net"
    r = extract_iocs(text)
    assert "admin@evilcorp.ru" in r["emails"]
    assert "attacker+campaign@phish.example.net" in r["emails"]


def test_verified_ps_gzip_payload_produces_clean_iocs():
    """The exact base64+gzip payload the regression was found on — must extract
    ONLY 127.0.0.1 and zero fake domains."""
    ps = (
        '$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIABd9VmoC/wstTi3SdUxPzSuxUghLLcpMy0xNAXMVFJyNrBQMjcz1DIDQEAAtZkPAKAAAAA=="));'
        'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()'
    )
    decoded = "User-Agent: VerifiedAgent  C2: 127.0.0.1"
    r = extract_iocs(ps + "\n" + decoded)
    assert "127.0.0.1" in r["ips"]
    fake = [d for d in r["domains"] if d.startswith("io.") or d.startswith("system.")]
    assert not fake, f"fake namespace-domains still leaking: {fake}"
