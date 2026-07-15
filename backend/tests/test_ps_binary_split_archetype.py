"""Feb-2026 · PS_BINARY_SPLIT_TOINT16 archetype regression tests.

User reported a real-world Invoke-Obfuscation binary/hex-array payload that
NivXRay was decoding down to just the raw quoted string (1-step
`extract-payload`) with 45 % confidence, instead of running the underlying
`ps-binary-split-decode` op that has been in the codebase for months.

Root cause: `extract-payload` ran FIRST and stripped the `.Split(...)` and
`[Convert]::ToInt16(..., 2)` metadata that `ps-binary-split-decode` needs to
detect the base and delimiters. Making this a proper archetype guarantees
the decoder runs against the ORIGINAL wrapper text.
"""
import os

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
if BASE_URL == "http://localhost:8001":
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": "admin@nivxray.com", "password": "NivXRay#2026!"}, timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# User's exact payload fragment (from Feb 2026 screenshot)
USER_PAYLOAD = (
    "'1m1001000r1100101{1101100{1101100{1101111>100000{1010111>1101111>"
    "1110010m110110001100100a1000010100111&100000@101101&1000110<1101111"
    "a1110010&1100101&110011101110010r1101111r1110101<11011100'.Split( "
    "'l@>{r<mOa&') | ForEach-Object{ ( [Convert]::ToInt16(( [String]$_ ) "
    ", 2 ) -As[Char]) } ))"
)


class TestPsBinarySplitArchetype:
    def test_direct_archetype_matches(self):
        from wrapper_archetypes import try_archetypes
        r = try_archetypes(USER_PAYLOAD)
        assert r is not None, "archetype must match Invoke-Obfuscation binary-split"
        assert r["engine"] == "archetype:PS_BINARY_SPLIT_TOINT16"
        # Output must be predominantly printable text and start with the
        # decoded plaintext "Hello World".
        out = r["output"]
        assert "Hello Wor" in out, f"expected 'Hello Wor' in decoded output; got {out!r}"

    def test_end_to_end_via_decode_smart(self, auth):
        r = requests.post(f"{BASE_URL}/api/decode/smart",
                          json={"input": USER_PAYLOAD}, headers=auth, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["engine"] == "archetype:PS_BINARY_SPLIT_TOINT16"
        assert d["confidence"] == 100
        recipe_ops = [s["op"] for s in (d.get("recipe") or [])]
        assert recipe_ops == ["ps-binary-split-decode"]
        assert "Hello Wor" in d["output"]

    def test_recipe_does_not_collapse_to_extract_payload(self, auth):
        """The original bug was that /decode/smart returned just
        `extract-payload` with 45 % confidence. Verify that never happens
        for this payload shape."""
        r = requests.post(f"{BASE_URL}/api/decode/smart",
                          json={"input": USER_PAYLOAD}, headers=auth, timeout=30)
        recipe_ops = [s["op"] for s in (r.json().get("recipe") or [])]
        assert "extract-payload" not in recipe_ops, \
            f"regressed to extract-payload only: {recipe_ops}"

    def test_multi_byte_chunks_recovered(self):
        """When the obfuscator omits a delimiter and two bytes get glued
        into one 15-bit chunk (e.g. `110110001100100` = `l` + `d`), the
        7/8-bit re-split heuristic must recover both characters."""
        from operations import run_operation
        # `'11011000110010`0'.Split('.') → single chunk `110110001100100`
        # 8-bit R-align: 1101100(l=108) + 01100100(d=100) → "ld"
        payload = (
            "'110110001100100'.Split('.') | ForEach-Object{ "
            "[Convert]::ToInt16(([String]$_),2) -As[Char] }"
        )
        out = run_operation("ps-binary-split-decode", payload, {})
        assert "ld" in out or "l" in out and "d" in out, f"expected 'ld' in {out!r}"

    def test_case_insensitive_variant(self):
        """Attackers case-mangle keywords: `SPLIT`, `foreach-object`, `TOINT16`."""
        from wrapper_archetypes import try_archetypes
        mangled = (
            "'1001000{1100101{1101100{1101100{1101111'.sPLIT('{') | "
            "foreach-object{ ( [convert]::toInt16(([String]$_), 2) -as[char]) }"
        )
        r = try_archetypes(mangled)
        assert r is not None
        assert r["engine"] == "archetype:PS_BINARY_SPLIT_TOINT16"
        assert "Hello" in r["output"]
