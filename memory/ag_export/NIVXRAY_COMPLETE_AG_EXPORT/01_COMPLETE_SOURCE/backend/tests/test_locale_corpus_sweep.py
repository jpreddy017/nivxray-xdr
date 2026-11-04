"""Nightly Golden-Corpus locale sweep · Feb-2026.

Regression fence for the multi-locale Entity Classifier. Runs a
broad set of Cyrillic / Chinese / Arabic / Japanese / Korean threat-
intel-style snippets through ``classify_token`` and
``classify_dotted_quads`` to guarantee that:

    • Network / host / server context keywords in any of the
      supported scripts still route dotted-quads to ``ipv4``.
    • Version / build context keywords in any of the supported
      scripts still route to ``software_version`` or ``windows_build``.
    • The classifier remains deterministic across repeated calls.

The tests are runtime-cheap (< 30 ms each) so they can execute in
every pytest cycle. Added specifically to prevent the class of
regressions where a small tweak to the English keyword list
accidentally drops Cyrillic / CJK coverage.
"""
from __future__ import annotations

import pytest

from engine.entity_classifier import (
    classify_token,
    classify_dotted_quads,
    KIND_IPV4,
    KIND_SOFTWARE_VERSION,
    KIND_WINDOWS_BUILD,
)


# ─── Cyrillic (Russian) sweep ──────────────────────────────────────
CYRILLIC_NETWORK_CASES = [
    "адрес C2: 203.0.113.5",
    "хост управления 203.0.113.5",
    "порт 443 хоста 203.0.113.5",
    "сервер злоумышленника 203.0.113.5",
    "подключение к 203.0.113.5",
    "соединение с сервером 203.0.113.5",
    "загрузка полезной нагрузки с 203.0.113.5",
    "скачивание stager с 203.0.113.5",
]

CYRILLIC_VERSION_CASES = [
    "версия компонента 9.0.0.0",
    "сборка библиотеки 9.0.0.0",
]


class TestCyrillicSweep:
    @pytest.mark.parametrize("txt", CYRILLIC_NETWORK_CASES)
    def test_network_keyword_routes_to_ipv4(self, txt):
        res = classify_token("203.0.113.5", txt)
        assert res.kind == KIND_IPV4, (
            f"Cyrillic network context lost coverage: {txt!r} → {res.kind}"
        )
        assert res.confidence >= 0.8

    @pytest.mark.parametrize("txt", CYRILLIC_VERSION_CASES)
    def test_version_keyword_routes_to_software_version(self, txt):
        res = classify_token("9.0.0.0", txt)
        assert res.kind == KIND_SOFTWARE_VERSION, (
            f"Cyrillic version context lost coverage: {txt!r} → {res.kind}"
        )


# ─── Simplified Chinese sweep ──────────────────────────────────────
CHINESE_NETWORK_CASES = [
    "目标服务器地址: 203.0.113.5",
    "主机 203.0.113.5 端口 443",
    "下载文件从 203.0.113.5",
    "连接远程服务器 203.0.113.5",
    "通信到 203.0.113.5",
]

CHINESE_VERSION_CASES = [
    "组件版本 9.0.0.0",
    "版号 9.0.0.0",
]


class TestChineseSweep:
    @pytest.mark.parametrize("txt", CHINESE_NETWORK_CASES)
    def test_network_keyword_routes_to_ipv4(self, txt):
        res = classify_token("203.0.113.5", txt)
        assert res.kind == KIND_IPV4, (
            f"Chinese network context lost coverage: {txt!r} → {res.kind}"
        )

    @pytest.mark.parametrize("txt", CHINESE_VERSION_CASES)
    def test_version_keyword_routes_to_software_version(self, txt):
        res = classify_token("9.0.0.0", txt)
        assert res.kind == KIND_SOFTWARE_VERSION


# ─── Japanese sweep ────────────────────────────────────────────────
JAPANESE_NETWORK_CASES = [
    "アドレス: 203.0.113.5",
    "サーバ 203.0.113.5 に接続",
    "ホスト 203.0.113.5 との通信",
    "ポート 443 サーバ 203.0.113.5",
]

JAPANESE_VERSION_CASES = [
    "アセンブリのバージョン 9.0.0.0",
    "コンポーネントのバージョン 9.0.0.0",
]


class TestJapaneseSweep:
    @pytest.mark.parametrize("txt", JAPANESE_NETWORK_CASES)
    def test_network_keyword_routes_to_ipv4(self, txt):
        res = classify_token("203.0.113.5", txt)
        assert res.kind == KIND_IPV4, (
            f"Japanese network context lost coverage: {txt!r} → {res.kind}"
        )

    @pytest.mark.parametrize("txt", JAPANESE_VERSION_CASES)
    def test_version_keyword_routes_to_software_version(self, txt):
        res = classify_token("9.0.0.0", txt)
        assert res.kind == KIND_SOFTWARE_VERSION

    def test_windows_build_context(self):
        # Even without the well-known-prefix short-circuit, the
        # Japanese "Windowsバージョン ビルド番号" phrase should still
        # be enough to keep a Windows build classified correctly.
        res = classify_token(
            "10.0.19045.5011",
            "Windowsバージョン ビルド番号 10.0.19045.5011",
        )
        assert res.kind == KIND_WINDOWS_BUILD


# ─── Arabic sweep ──────────────────────────────────────────────────
ARABIC_NETWORK_CASES = [
    "عنوان الخادم 203.0.113.5",
    "اتصال إلى خادم 203.0.113.5",
    "منفذ 443 خادم 203.0.113.5",
    "تحميل ملف من 203.0.113.5",
]

ARABIC_VERSION_CASES = [
    "إصدار المكتبة 9.0.0.0",
    "نسخة المنتج 9.0.0.0",
]


class TestArabicSweep:
    @pytest.mark.parametrize("txt", ARABIC_NETWORK_CASES)
    def test_network_keyword_routes_to_ipv4(self, txt):
        res = classify_token("203.0.113.5", txt)
        assert res.kind == KIND_IPV4, (
            f"Arabic network context lost coverage: {txt!r} → {res.kind}"
        )

    @pytest.mark.parametrize("txt", ARABIC_VERSION_CASES)
    def test_version_keyword_routes_to_software_version(self, txt):
        res = classify_token("9.0.0.0", txt)
        assert res.kind == KIND_SOFTWARE_VERSION


# ─── Korean sweep ──────────────────────────────────────────────────
KOREAN_NETWORK_CASES = [
    "주소: 203.0.113.5",
    "서버 203.0.113.5 에 연결",
    "포트 443 호스트 203.0.113.5",
]


class TestKoreanSweep:
    @pytest.mark.parametrize("txt", KOREAN_NETWORK_CASES)
    def test_network_keyword_routes_to_ipv4(self, txt):
        res = classify_token("203.0.113.5", txt)
        assert res.kind == KIND_IPV4, (
            f"Korean network context lost coverage: {txt!r} → {res.kind}"
        )

    def test_korean_version_context(self):
        res = classify_token("9.0.0.0", "라이브러리 버전 9.0.0.0")
        assert res.kind == KIND_SOFTWARE_VERSION


# ─── Mixed-corpus deterministic sweep ──────────────────────────────
# Each dotted-quad is padded with `_PAD` filler so its ±CTX_CHARS (48)
# window never overlaps with another line's keywords — this is a
# realistic threat-intel writeup where paragraphs are separated by
# blank lines / prose, not tightly packed.
_PAD = "                                                                       "
MIXED_CORPUS = (
    f"起点 сервер 203.0.113.5 传输{_PAD}\n"
    f"Assembly сборка 9.0.0.0 loaded{_PAD}\n"
    f"ビルド番号 10.0.19045.5011 detected on host{_PAD}\n"
    f"اتصال إلى خادم 198.51.100.7 port 443{_PAD}\n"
    f"서버 주소 198.51.100.14 접속{_PAD}\n"
)


class TestMixedCorpusSweep:
    def test_mixed_locales_do_not_collide(self):
        results = classify_dotted_quads(MIXED_CORPUS)
        kinds = {r.token: r.kind for r in results}
        # IPv4 addresses picked up regardless of surrounding script.
        assert kinds.get("203.0.113.5")   == KIND_IPV4
        assert kinds.get("198.51.100.7")  == KIND_IPV4
        assert kinds.get("198.51.100.14") == KIND_IPV4
        # Version + build coverage from CJK/Cyrillic keywords.
        assert kinds.get("9.0.0.0")       == KIND_SOFTWARE_VERSION
        assert kinds.get("10.0.19045.5011") == KIND_WINDOWS_BUILD

    def test_determinism_over_ten_runs(self):
        # Determinism guarantee: the same input must produce the
        # exact same classification output across repeated calls.
        first = [r.to_dict() for r in classify_dotted_quads(MIXED_CORPUS)]
        for _ in range(9):
            again = [r.to_dict() for r in classify_dotted_quads(MIXED_CORPUS)]
            assert again == first


# ─── Negative-space guards ─────────────────────────────────────────
class TestLocaleNegativeSpace:
    def test_bare_dotted_quad_stays_generic_across_scripts(self):
        # An isolated 1.2.3.4 with only decorative CJK / Cyrillic
        # punctuation around it must NOT be misclassified as IPv4.
        for wrapper in ("· 1.2.3.4 ·", "「1.2.3.4」", "— 1.2.3.4 —"):
            res = classify_token("1.2.3.4", wrapper)
            assert res.kind != KIND_IPV4, (
                f"False-positive IPv4 for bare token in wrapper {wrapper!r}"
            )

    def test_partial_locale_word_does_not_leak(self):
        # A single character from a locale word alone should NOT be
        # enough to trigger a false network-context signal.
        res = classify_token("1.2.3.4", "接")  # first char of 接続
        assert res.kind != KIND_IPV4
