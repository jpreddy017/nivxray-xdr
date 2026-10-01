"""PS ASCII XOR IEX archetype — the Feb-2026 "commercial-grade blocker" fix.

The user pasted this payload in production and NivXRay failed to decode it,
returning a bare digit run (extract-payload alone) instead of the actual
PowerShell script. This is a benign demo payload:

    Write-Host 'Hello World!' -ForegroundColor Green;
    Write-Host 'Obfuscation Rocks!' -ForegroundColor Green

The archetype PS_ASCII_XOR_IEX must:
  • Match the case-mangled `(int,int,...) | fOREACh-objEct{[ChAR]($_ -bxoR '0xNN')}
    ) -jOIn'' | InVOKE-ExpressIon` shape
  • Extract the integer list AND the XOR key
  • Return the fully-decoded PowerShell script (not a digit run)
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


# Exact payload the user reported broken (Feb 2026)
USER_PAYLOAD = (
    """powershell  -NoProfil -NonInter     "((97,68 ,95 ,66,83 , 27 , 126, 89 , 69 , 66 ,22 ,17 , """
    """126,83,90 , 90 ,89,22 , 97,89, 68 ,90 ,82 , 23 , 17 ,22 , 27 , 112, 89 ,68, 83 , 81,68 , """
    """89,67 ,88 , 82 ,117, 89 , 90,89, 68 , 22 ,113,68 , 83 ,83 ,88,13 , 22,97,68 , 95,66 , """
    """83,27,126,89 , 69 , 66 , 22 , 17 , 121,84,80,67,69,85,87, 66,95, 89, 88 , 22, 100 ,89, """
    """85, 93, 69, 23, 17 ,22,27 , 112,89 ,68 ,83 ,81 , 68 , 89, 67, 88 ,82,117, 89,90 , 89, """
    """68,22 ,113,68, 83 , 83,88 ) | fOREACh-objEct{[ChAR]($_  -bxoR'0x36' )} )-jOIn'' | InVOKE-ExpressIon" """
).strip()

EXPECTED_DECODE = (
    "Write-Host 'Hello World!' -ForegroundColor Green; "
    "Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
)


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": "admin@nivxray.com", "password": os.environ.get("ADMIN_PASSWORD", "")}, timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestPsAsciiXorIex:
    def test_direct_archetype_decode(self):
        """Direct archetype call must return the exact PowerShell script."""
        from wrapper_archetypes import try_archetypes
        r = try_archetypes(USER_PAYLOAD)
        assert r is not None, "archetype should have matched the user payload"
        assert r["engine"] == "archetype:PS_ASCII_XOR_IEX"
        assert r["output"] == EXPECTED_DECODE

    def test_end_to_end_via_decode_smart(self, auth):
        """POST /api/decode/smart on the user payload must return engine
        archetype:PS_ASCII_XOR_IEX with 100 % confidence and the plaintext script."""
        r = requests.post(
            f"{BASE_URL}/api/decode/smart",
            json={"input": USER_PAYLOAD},
            headers=auth, timeout=30,
        )
        assert r.status_code == 200
        d = r.json()
        assert d["engine"] == "archetype:PS_ASCII_XOR_IEX"
        assert d["confidence"] == 100
        assert d["output"] == EXPECTED_DECODE
        recipe_ops = [s["op"] for s in (d.get("recipe") or [])]
        assert recipe_ops == ["ascii-decimal-decode", "xor"]

    def test_case_insensitive_variants(self):
        """PowerShell keyword mangling shouldn't defeat the matcher."""
        from wrapper_archetypes import try_archetypes
        variants = [
            # All-lowercase
            "powershell \"((72,101,108,108,111) | foreach-object{[char]($_ -bxor 0)}) -join '' | invoke-expression\"",
            # All-uppercase
            "POWERSHELL \"((72,101,108,108,111) | FOREACH-OBJECT{[CHAR]($_ -BXOR 0)}) -JOIN '' | INVOKE-EXPRESSION\"",
            # IEX shorthand alias
            "powershell \"((72,101,108,108,111) | ForEach-Object{[char]($_ -bxor 0)}) -join '' | iex\"",
        ]
        for i, v in enumerate(variants):
            r = try_archetypes(v)
            assert r is not None, f"variant #{i} should match: {v!r}"
            assert r["output"] == "Hello"

    def test_no_iex_no_match(self):
        """Without the terminal `| Invoke-Expression`, don't fire the archetype
        (analyst may just be XOR-encoding data — different intent)."""
        from wrapper_archetypes import try_archetypes
        no_iex = "((72,101,108,108,111) | ForEach-Object{[char]($_ -bxor 0)}) -join ''"
        r = try_archetypes(no_iex)
        assert r is None or r.get("engine") != "archetype:PS_ASCII_XOR_IEX"

    def test_wrong_key_does_not_produce_gibberish(self):
        """If the XOR key is mis-specified and the result is unprintable,
        the handler should raise so the pipeline falls back to the next
        engine rather than emit garbage."""
        from wrapper_archetypes import _handle_ps_ascii_xor_iex
        # Same integers, wrong key (255 - would produce mostly non-printable)
        bad = "((97,68,95,66,83) | ForEach-Object{[char]($_ -bxor 255)}) -join '' | iex"
        with pytest.raises(ValueError):
            _handle_ps_ascii_xor_iex(bad)

    def test_recipe_is_two_ops_and_no_extract_payload(self, auth):
        """Recipe must be ascii-decimal-decode → xor, NOT extract-payload alone.
        This was the ORIGINAL bug — extract-payload collapsed the wrapper to a
        digit run and lost the XOR metadata."""
        r = requests.post(
            f"{BASE_URL}/api/decode/smart",
            json={"input": USER_PAYLOAD},
            headers=auth, timeout=30,
        )
        recipe_ops = [s["op"] for s in (r.json().get("recipe") or [])]
        assert "extract-payload" not in recipe_ops
        assert recipe_ops == ["ascii-decimal-decode", "xor"]

    def test_terminal_line_wrap_inside_integer_still_decodes(self, auth):
        """REGRESSION — user chat/email/terminal often line-wraps INSIDE an
        integer (e.g. `83,8\\n3` really means `83, 83`). The archetype must
        strip whitespace inside the captured int blob so this decodes
        correctly instead of falling back to a raw digit run.
        """
        from wrapper_archetypes import try_archetypes
        wrapped = (
            'powershell  -NoProfil -NonInter     "((97,68 ,95 ,66,83 , 27 , '
            '126, 89 , 69 , 66 ,22 ,17 , 126,83,90 , 90 ,89,22 , 97,89, 68 ,'
            '90 ,82 , 23 , 17 ,22 , 27 , 112, 89 ,68, 83 , 81,68 , 89,67 ,88 ,'
            ' 82 ,117, 89 , 90,89, 68 , 22 ,113,68 , 83,8\n'
            '3 ,88,13 , 22,97,68 , 95,66 , 83,27 ,126,89 , 69 , 66 , 22 , 17 ,'
            ' 121,84, 80, 67 ,69,85,87, 66,95, 89, 88 , 22, 100 ,89, 85, 93 ,'
            ' 69, 23, 17 ,22,27 , 112,89 ,68 ,83 ,81 , 68 , 89, 67, 88 ,82,117,'
            ' 89,90 , 89, 68,22 ,113,68, 83 , 83,88 )\n'
            "| fOREACh-objEct{[ChAR]($_ -bxoR'0x36' )} )-jOIn'' | InVOKE-ExpressIon\""
        )
        r = try_archetypes(wrapped)
        assert r is not None, "archetype must match even with line-wrap inside an integer"
        assert r["engine"] == "archetype:PS_ASCII_XOR_IEX"
        assert r["output"] == EXPECTED_DECODE

        # End-to-end via API for the same wrapped payload
        api_r = requests.post(
            f"{BASE_URL}/api/decode/smart",
            json={"input": wrapped},
            headers=auth, timeout=30,
        )
        assert api_r.status_code == 200
        d = api_r.json()
        assert d["engine"] == "archetype:PS_ASCII_XOR_IEX"
        assert d["output"] == EXPECTED_DECODE
        assert d["confidence"] == 100
