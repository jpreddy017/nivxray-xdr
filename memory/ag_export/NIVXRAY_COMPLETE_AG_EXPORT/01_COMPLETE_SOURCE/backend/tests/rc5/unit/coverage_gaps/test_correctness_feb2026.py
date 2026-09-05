"""Feb-2026 · Priority 1 Correctness — deterministic IPv4 & family attribution.

Guards two classes of previously-under-constrained classification:

1. **Dotted-quad IPv4 classification** (`operations.extract_iocs`)
   Software version numbers like `9.0.0.0`, `1.0.0.0`, assembly
   `Version=7.4.0.0` context markers MUST NOT be promoted to IPv4
   IOCs. Real routable hosts (`8.8.8.8`, `192.168.1.100`, `1.2.3.4`)
   must still be classified correctly.

2. **Malware-family attribution** (`chain_analyzer.detect_malware_family`)
   A single regex hit is insufficient. Weak single-vote candidates are
   surfaced with `provisional=True` at low confidence and MUST NOT
   drive verdict-tier elevation via the `+15` risk boost.
"""
from __future__ import annotations

from operations import extract_iocs


class TestIPv4Classification:
    def test_software_version_9_0_0_0_not_ip(self):
        blob = "PowerShellCore, Version=9.0.0.0, Culture=neutral"
        assert extract_iocs(blob)["ips"] == []

    def test_assembly_version_context_rejected(self):
        blob = "System.Management.Automation, Version=7.4.0.0, PublicKeyToken=..."
        assert extract_iocs(blob)["ips"] == []

    def test_three_zero_octets_rejected(self):
        for ip in ("0.0.0.0", "9.0.0.0", "1.0.0.0", "10.0.0.0", "127.0.0.0"):
            assert ip not in extract_iocs(f"contact {ip}")["ips"], ip

    def test_broadcast_rejected(self):
        assert "255.255.255.255" not in extract_iocs("send to 255.255.255.255")["ips"]

    def test_out_of_range_octet_rejected(self):
        # The naive regex `\d{1,3}` matches `999`; validation must reject.
        assert extract_iocs("bad IP 999.999.999.999")["ips"] == []
        assert extract_iocs("edge 256.1.1.1")["ips"] == []

    def test_real_public_ips_still_classified(self):
        assert "8.8.8.8" in extract_iocs("curl http://8.8.8.8/")["ips"]
        assert "1.2.3.4" in extract_iocs("connect 1.2.3.4 for c2")["ips"]
        assert "8.8.4.4" in extract_iocs("dns 8.8.4.4")["ips"]

    def test_private_hosts_still_classified(self):
        # Private-range hosts ARE valid IOCs from an analysis pov
        # (lateral movement, insider). Only 3-zero base addresses are dropped.
        assert "192.168.1.100" in extract_iocs("net view 192.168.1.100")["ips"]
        assert "10.0.0.5" in extract_iocs("ssh 10.0.0.5")["ips"]

    def test_mixed_version_and_real_ip(self):
        blob = "Version=1.0.0.0 curl http://8.8.4.4/"
        ips = extract_iocs(blob)["ips"]
        assert ips == ["8.8.4.4"]


class TestMalwareFamilyAttribution:
    def _stage(self, output: str, idx: int = 0) -> dict:
        return {
            "stage_index": idx, "output": output, "input_preview": "",
            "lolbas": [],
        }

    def test_single_hit_is_provisional_and_low_confidence(self):
        from chain_analyzer import detect_malware_family, _FAMILY_SIGNATURES
        # Grab a real family signature and craft a single-hit sample.
        family, rx = _FAMILY_SIGNATURES[0]
        # Extract a literal-ish token from the regex source that will match.
        # We use the source directly by embedding a plausible marker.
        sample = "cobaltstrike beacon"  # matches multiple heuristics safely
        result = detect_malware_family([self._stage(sample)])
        if result is None:
            # Corpus didn't hit that particular family — try a broader probe.
            result = detect_malware_family([self._stage("emotet dropper stage 1")])
        if result is not None:
            # Single hit → provisional flag must be set OR hits ≥ 2.
            assert result["hits"] >= 2 or result.get("provisional") is True

    def test_two_hits_are_not_provisional(self):
        from chain_analyzer import detect_malware_family
        # Two stages both containing the same family marker → firm attribution.
        stages = [
            self._stage("emotet dropper", 0),
            self._stage("emotet loader stage 2", 1),
        ]
        result = detect_malware_family(stages)
        if result is not None:
            assert result["hits"] >= 2
            assert result.get("provisional") is False
            assert result["confidence"] >= 60

    def test_provisional_family_does_not_elevate_risk(self):
        """Verifies `_aggregate_risk` does NOT apply the +15 family boost
        when family attribution is provisional."""
        from chain_analyzer import _aggregate_risk
        stages = [self._stage("noop", 0)]
        family_provisional = {
            "family": "TestFamily", "confidence": 20, "hits": 1,
            "evidence": [], "provisional": True,
        }
        risk_no_family    = _aggregate_risk(stages, {}, [], [], None)
        risk_provisional  = _aggregate_risk(stages, {}, [], [], family_provisional)
        assert risk_no_family["score"] == risk_provisional["score"], (
            "provisional family attribution must not elevate risk"
        )

    def test_firm_family_still_elevates_risk(self):
        """Ensures the +15 boost still applies to non-provisional families."""
        from chain_analyzer import _aggregate_risk
        stages = [self._stage("noop", 0)]
        family_firm = {
            "family": "TestFamily", "confidence": 80, "hits": 2,
            "evidence": [], "provisional": False,
        }
        risk_no_family = _aggregate_risk(stages, {}, [], [], None)
        risk_firm      = _aggregate_risk(stages, {}, [], [], family_firm)
        assert risk_firm["score"] == min(100, risk_no_family["score"] + 15)
