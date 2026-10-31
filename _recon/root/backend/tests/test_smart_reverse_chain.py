"""Feb 2026 v1.3.1 · smart_decoder reverse-string heuristic.

Reproduces the exact shell chain the user asked about:

    echo "NivXray_Test_Payload_01" | base64 | gzip | base64 | xxd -p | rev | base64

The reverse operation makes multi-layer `rev`-based obfuscation chains
decodable end-to-end without human intervention.
"""
import base64
import gzip

import pytest

from smart_decoder import smart_decode


def _build_reversed_chain(plaintext: bytes) -> str:
    """Reproduce `base64 | gzip | base64 | xxd -p | rev | base64`."""
    s = base64.b64encode(plaintext)               # base64
    s = gzip.compress(s)                          # gzip
    s = base64.b64encode(s)                       # base64
    s = s.hex().encode()                          # xxd -p (hex)
    s = s[::-1]                                   # rev
    return base64.b64encode(s).decode()           # base64


def test_reverse_chain_end_to_end():
    """The 6-layer `rev`-based chain must decode to the original plaintext."""
    plaintext = b"NivXray_Test_Payload_01\n"
    enc = _build_reversed_chain(plaintext)

    result = smart_decode(enc)
    chain = [s["op"] for s in result.get("steps", [])]
    out = result.get("output") or ""

    assert "reverse" in chain, f"reverse step never fired · chain={chain}"
    assert "NivXray_Test_Payload_01" in out, f"plaintext never surfaced · out={out[:200]!r}"


def test_reverse_does_not_ping_pong_on_pure_hex():
    """Pure-hex payloads must not oscillate through infinite reverse steps."""
    # 64 hex chars → decodes to 32 bytes of random-shape non-magic bytes
    hex_blob = "d3d3141414141494" * 4
    result = smart_decode(hex_blob)
    chain = [s["op"] for s in result.get("steps", [])]
    n_reverse = sum(1 for op in chain if op == "reverse")
    assert n_reverse <= 1, f"reverse fired {n_reverse}× on symmetric hex · chain={chain}"


def test_reverse_skips_when_already_readable():
    """Plain readable text must not be reversed."""
    result = smart_decode("Hello World this is plain text")
    chain = [s["op"] for s in result.get("steps", [])]
    assert "reverse" not in chain, f"reverse fired on plain text · chain={chain}"


def test_reverse_chain_via_api():
    """End-to-end integration via /api/decode/smart."""
    import os
    import requests
    API = os.popen("grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d= -f2").read().strip()
    tok = requests.post(f"{API}/api/auth/login",
                        json={"email": "admin@nivxray.com",
                              "password": os.environ.get("ADMIN_PASSWORD", "")}, timeout=10).json().get("access_token")
    if not tok:
        pytest.skip("auth unavailable")
    enc = _build_reversed_chain(b"NivXray_Test_Payload_01\n")
    r = requests.post(f"{API}/api/decode/smart",
                      headers={"Authorization": f"Bearer {tok}"},
                      json={"input": enc}, timeout=60)
    assert r.status_code == 200
    d = r.json()
    assert "reverse" in (d.get("chain_ids") or []), d.get("chain_ids")
    assert "NivXray_Test_Payload_01" in (d.get("output") or "")
