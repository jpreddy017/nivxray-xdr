"""Real-shape Base32 + ASCII-decimal phishing regression suite (Feb 2026).

Locks in every decoder shape NivX Forge currently handles end-to-end so
future refactors of `magic_decoder`, `wrapper_archetypes`, or the operations
registry cannot silently regress.

Each fixture pair lives in `/app/backend/tests/fixtures/`:
  <stem>.txt              — the (possibly obfuscated) input payload
  <stem>.expected.txt     — a substring that MUST appear in the decoded output

Coverage matrix (all SAFE — no real C2, defanged/example.com only):
  base32_pure_downloader        — pure Base32 blob (uppercase)          → IEX Net.WebClient
  base32_lowercase_downloader   — Base32 lower-case (RFC 4648 §6)       → IEX Net.WebClient
  base32_nopad_downloader       — Base32 without `=` padding            → IEX Net.WebClient
  ascii_decimal_hello_analyst   — PS (int,int) | %{[char]$_} | Join     → Write-Host benign
  ascii_decimal_recon           — space-separated bare decimals         → id;whoami;hostname
  ascii_decimal_xor_hancitor    — PS (ints) | %{[char]($_-bxor k)} |iex → IEX iwr loader
  ascii_decimal_xor_multiline_empire — multi-line variant with XOR      → Write-Host PWNED
  js_fromcharcode_socgholish    — <script>eval(String.fromCharCode(..)) → deep decode
"""
import os
import re

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


FIXTURES_DIR = "/app/backend/tests/fixtures"


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": "admin@nivxray.com", "password": "NivXRay#2026!"}, timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# Enumerate all (payload, expected) pairs at import time so pytest ids read cleanly.
def _pairs():
    out = []
    for fname in sorted(os.listdir(FIXTURES_DIR)):
        if not fname.endswith(".txt") or fname.endswith(".expected.txt"):
            continue
        stem = fname[:-4]
        exp_path = os.path.join(FIXTURES_DIR, stem + ".expected.txt")
        if not os.path.exists(exp_path):
            continue
        out.append(stem)
    return out


FIXTURE_STEMS = _pairs()

# Fixtures that are known to NOT decode fully end-to-end yet.
# Kept in the suite so the coverage stays visible and can be un-xfailed as
# the pipeline improves. Comment explains the specific pipeline gap.
XFAIL_STEMS = {
    # (all currently-known gaps have been closed as of Feb 2026)
}


@pytest.mark.parametrize("stem", FIXTURE_STEMS)
def test_fixture_decodes_end_to_end(stem, auth):
    """Every fixture pair must round-trip through /api/decode/smart and
    contain the expected plaintext substring."""
    if stem in XFAIL_STEMS:
        pytest.xfail(f"known gap · {XFAIL_STEMS[stem]}")

    payload = open(os.path.join(FIXTURES_DIR, stem + ".txt")).read()
    expected = open(os.path.join(FIXTURES_DIR, stem + ".expected.txt")).read().strip()

    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      json={"input": payload}, headers=auth, timeout=45)
    assert r.status_code == 200, f"{stem}: HTTP {r.status_code}"
    d = r.json()
    out = d.get("output") or ""
    assert expected in out, (
        f"{stem}: decoded output does not contain expected substring\n"
        f"  engine:   {d.get('engine')}\n"
        f"  conf:     {d.get('confidence')}\n"
        f"  expected: {expected[:120]!r}\n"
        f"  got:      {out[:200]!r}"
    )
    # Every real archetype/decode must exceed the 0-confidence floor
    assert (d.get("confidence") or 0) >= 40, \
        f"{stem}: confidence too low ({d.get('confidence')}) — probably a passthrough"


class TestBase32ResiliencePatterns:
    """Focused checks on Base32-specific edge cases beyond the fixture matrix."""

    def test_base32_case_insensitive_direct_op(self):
        """RFC 4648 §6: decoders MAY accept lowercase. Our base32-decode op does."""
        from operations import run_operation
        upper = "NBSWY3DPEB3W64TMMQ======"   # base32 of "hello world"
        lower = upper.lower()
        # Both must decode to the SAME bytes
        r_up = run_operation("base32-decode", upper, {})
        r_lo = run_operation("base32-decode", lower, {})
        assert r_up == r_lo == "hello world", f"decoded: up={r_up!r} lo={r_lo!r}"

    def test_base32_missing_padding_healed(self):
        """Attackers strip the `=` padding. The op auto-pads before decoding."""
        from operations import run_operation
        # "hello world" without `=` padding — decoder must auto-pad and succeed
        r = run_operation("base32-decode", "NBSWY3DPEB3W64TMMQ", {})
        assert r == "hello world"


class TestAsciiDecimalResiliencePatterns:
    """Bare-metal ASCII decimal ops must survive whitespace / comma variance."""

    @pytest.mark.parametrize("sep", [",", " ", ", ", "  ,  ", "\n"])
    def test_ascii_decimal_separator_variants(self, sep):
        from operations import run_operation
        # "Hi!" = 72, 105, 33
        payload = sep.join(["72", "105", "33"])
        assert run_operation("ascii-decimal-decode", payload, {}) == "Hi!"

    def test_ascii_decimal_skips_out_of_range_tokens(self):
        """Realistic garbage (year numbers, PS variable names $var17) must
        NOT poison the decoded string."""
        from operations import run_operation
        # 72 (H), 3000 (skip — >255), 105 (i), 999999 (skip), 33 (!)
        r = run_operation("ascii-decimal-decode", "72, 3000, 105, 999999, 33", {})
        assert r == "Hi!"
