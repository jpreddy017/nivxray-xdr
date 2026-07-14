"""Unit tests for the Recursive Decode-and-Route pipeline upgrades.

Covers:
* XOR-key parsing from PowerShell / asm-flavoured obfuscator syntax
* Multi-stage span re-extraction (base64 → gzip → *inner* base64 → xor)
* Shellcode stop-condition + arch auto-detection
* Capstone disassembly listings
* IOC extraction from binary buffers
* API endpoint /api/analyze/shellcode round-trip
"""
import base64
import gzip
import os
import re
import pytest
import requests

# Ensure backend modules are importable when running via pytest
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import operations, ops_extended  # noqa: F401 — register operation registry
from magic_decoder import magic_decode
from payload_sanitizer import find_xor_key, find_all_base64_spans
from shellcode_analyzer import (
    analyze, detect_arch, disassemble, extract_iocs, is_shellcode,
    shannon_entropy,
)


def _load_base_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        try:
            with open("/app/frontend/.env") as f:
                for line in f:
                    if line.startswith("REACT_APP_BACKEND_URL="):
                        v = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    return (v or "").rstrip("/")


BASE_URL = _load_base_url()
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "NivXRay#2026!"


# --------------------------- XOR key parser --------------------------- #

@pytest.mark.parametrize("code, expected", [
    ("$var_code[$x] -bxor 35", 0x23),
    ("$b -bxor 0x2A", 0x2A),
    ("$char -bxor 'A'", 0x41),
    ("value ^ 0x35", 0x35),
    ("xor eax, 0x42", 0x42),
    ("xor byte ptr [rax], 0xAB", 0xAB),
    ("nothing to parse here", None),
])
def test_find_xor_key(code, expected):
    assert find_xor_key(code) == expected


# --------------------------- multi-stage spans --------------------------- #

def test_find_all_base64_spans_quoted_first():
    text = 'FromBase64String("AAAABBBBCCCCDDDDEEEE"); other = "ZZZZ";'
    spans = find_all_base64_spans(text, min_len=8)
    # Should return the quoted 20-char span, not the 4-char noise
    assert "AAAABBBBCCCCDDDDEEEE" in spans


# --------------------------- recursive decode-and-route --------------------------- #

def test_cobalt_strike_multi_stage_pipeline():
    """base64 → gzip → inner-base64 → xor(0x23) — the exact scenario from the
    'ThreatIntel' post that motivated this feature."""
    inner = b"echo COBALT_STAGER_UNMASKED"
    xored = bytes(b ^ 0x23 for b in inner)
    inner_b64 = base64.b64encode(xored).decode()
    outer_script = (
        f'$var_code = [Convert]::FromBase64String("{inner_b64}")\n'
        f'for ($x=0; $x -lt $var_code.Count; $x++) {{\n'
        f'  $var_code[$x] = $var_code[$x] -bxor 35\n'
        f'}}\n'
    )
    gz = gzip.compress(outer_script.encode())
    outer_b64 = base64.b64encode(gz).decode()
    payload = (
        f'$s = New-Object IO.MemoryStream(,'
        f'[Convert]::FromBase64String("{outer_b64}"))'
    )
    r = magic_decode(payload, max_depth=6, max_branches=4, top_n=5)
    outputs = [t.get("output") or "" for t in r["top_results"]]
    assert any("COBALT_STAGER_UNMASKED" in o for o in outputs), \
        f"pipeline did not decode down to shellcode ID. outputs: {[o[:80] for o in outputs]}"
    # And the winning chain should include the xor step with the parsed key
    winner = r["top_results"][0]
    ops = [c["op"] for c in winner["chain"]]
    assert "xor" in ops or "COBALT_STAGER_UNMASKED" in (winner.get("output") or "")


# --------------------------- entropy / shellcode --------------------------- #

def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 1000) < 0.01
    # random-ish -> entropy near 8.0
    rnd = bytes(range(256)) * 4
    assert shannon_entropy(rnd) > 7.9


def test_is_shellcode_msf_prologue():
    # MSFVenom x64 stager entry: cld; and rsp, -16; call ...
    sc = bytes.fromhex("fc4883e4f0e8c8000000415141505251564831d2")
    assert is_shellcode(sc)


def test_is_shellcode_rejects_text():
    text = ("The quick brown fox jumps over the lazy dog. " * 20).encode()
    assert not is_shellcode(text)


# --------------------------- arch detection --------------------------- #

def test_detect_arch_x86_64_prologue():
    sc = bytes.fromhex("fc4883e4f0e8c8000000")
    assert detect_arch(sc) == "x86_64"


def test_detect_arch_hint_override():
    sc = bytes.fromhex("fc4883e4f0e8c8000000")
    assert detect_arch(sc, hint="arm64") == "arm64"


def test_detect_arch_arm64_prologue():
    # stp x29, x30, [sp, #-16]!  →  fd 7b bf a9
    sc = bytes.fromhex("fd7bbfa9fd030091")
    assert detect_arch(sc) == "arm64"


# --------------------------- disassembly --------------------------- #

def test_disassemble_x86_64():
    sc = bytes.fromhex("fc4883e4f0e8c8000000")
    listing = disassemble(sc, "x86_64", max_insns=5)
    assert len(listing) >= 3
    assert listing[0]["op"] == "cld"
    assert "and" in listing[1]["op"]
    # last should be a call
    assert any(l["op"].startswith("call") for l in listing)


def test_disassemble_arm64():
    # 4 valid ARM64 insns
    sc = bytes.fromhex("fd7bbfa9fd030091e00300aac0035fd6")
    listing = disassemble(sc, "arm64", max_insns=8)
    assert len(listing) >= 3


# --------------------------- IOC extraction --------------------------- #

def test_extract_iocs_from_binary():
    blob = (
        b"\x00\x01" * 4
        + b"http://c2.evil.example.com/beacon\x00"
        + b"kernel32.dll\x00LoadLibraryA\x00GetProcAddress\x00"
        + b"192.168.1.100\x00"
        + b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        + b"\xff\xff"
    )
    r = extract_iocs(blob)
    assert "http://c2.evil.example.com/beacon" in r["urls"]
    assert "192.168.1.100" in r["ips"]
    assert any("HKLM" in k for k in r["regkeys"])
    assert "LoadLibraryA" in r["imports"]
    assert "GetProcAddress" in r["imports"]


def test_analyze_bundle():
    sc = bytes.fromhex("fc4883e4f0e8c8000000415141505251564831d2")
    r = analyze(sc)
    assert r["arch"] == "x86_64"
    assert r["is_shellcode"] is True
    assert len(r["disassembly"]) >= 3
    assert "iocs" in r


# --------------------------- API round-trip --------------------------- #

@pytest.fixture(scope="module")
def api_headers():
    if not BASE_URL:
        pytest.skip("REACT_APP_BACKEND_URL not set")
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200
    tok = r.json()["access_token"]
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def test_api_analyze_shellcode_hex(api_headers):
    r = requests.post(f"{BASE_URL}/api/analyze/shellcode", headers=api_headers,
                      json={"input": "fc4883e4f0e8c8000000415141505251"}, timeout=15)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["arch"] == "x86_64"
    assert j["is_shellcode"] is True
    assert j["input_source"] == "hex"
    assert len(j["disassembly"]) >= 3


def test_api_analyze_shellcode_base64(api_headers):
    # base64 of the same shellcode
    b64 = base64.b64encode(bytes.fromhex("fc4883e4f0e8c8000000")).decode()
    r = requests.post(f"{BASE_URL}/api/analyze/shellcode", headers=api_headers,
                      json={"input": b64}, timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert j["arch"] == "x86_64"
    assert j["input_source"] == "base64"


def test_api_analyze_shellcode_arch_override(api_headers):
    r = requests.post(f"{BASE_URL}/api/analyze/shellcode", headers=api_headers,
                      json={"input": "fd7bbfa9fd030091", "arch": "arm64"}, timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert j["arch"] == "arm64"
