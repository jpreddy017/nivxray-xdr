"""P1-02 regression lock · Defanged IOC extraction.

Threat-intel blog posts (Talos, Sophos, Mandiant) heavily defang IPs
and URLs so the strings can't be auto-fetched. Before this fix,
`split_artifacts` missed them entirely; the C2 IP `149[.]28[.]81[.]19`
in a Sophos post surfaced only inside the chain decoder's peeled_iocs,
never at the top-level IOC panel.

This suite locks the current extractor so we can distinguish
`preserved / fixed / introduced` behavior after ADR-004 migration.
"""
from __future__ import annotations

import pytest

from services.ida.artifact_splitter import split_artifacts, _refang


# ── Refang helper ─────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("149[.]28[.]81[.]19",       "149.28.81.19"),
    ("45(.)77(.)10(.)5",         "45.77.10.5"),
    ("1 [.] 2 [.] 3 [.] 4",      "1.2.3.4"),
    ("hxxps://foo[.]com/a",      "https://foo.com/a"),
    ("hxxp://bar(.)co/x",        "http://bar.co/x"),
    ("HXXPS://EVIL[.]COM",       "https://EVIL.COM"),
    ("mail[at]evil[.]com",       "mail@evil.com"),
    ("user(at)corp(.)com",       "user@corp.com"),
    ("http[://]foo.com/x",       "http://foo.com/x"),
    ("no-defang-here",           "no-defang-here"),
])
def test_refang_helper(raw, expected):
    assert _refang(raw) == expected


# ── Defanged IPv4 extraction ──────────────────────────────────────
def test_defanged_ipv4_bracket_form():
    arts = split_artifacts("C2 IP: 149[.]28[.]81[.]19 observed.")
    ips = [a for a in arts if a.type == "ip"]
    assert len(ips) == 1
    ip = ips[0]
    assert ip.value == "149[.]28[.]81[.]19"
    assert ip.canonical == "149.28.81.19"
    assert ip.metadata["defanged"] is True
    assert ip.metadata["original_form"] == "149[.]28[.]81[.]19"
    assert ip.source["extractor"] == "ida.ipv4.defanged"


def test_defanged_ipv4_paren_form():
    arts = split_artifacts("Also seen: 45(.)77(.)10(.)5 in the report.")
    ips = [a for a in arts if a.type == "ip"]
    assert len(ips) == 1
    assert ips[0].canonical == "45.77.10.5"
    assert ips[0].metadata["defanged"] is True


def test_defanged_ipv4_mixed_form():
    arts = split_artifacts("Hybrid: 10[.]0.0[.]1 seen in transcript.")
    ips = [a for a in arts if a.type == "ip"]
    canonicals = {ip.canonical for ip in ips}
    assert "10.0.0.1" in canonicals


def test_multiple_defanged_ips_all_captured():
    text = ("Beacons to 149[.]28[.]81[.]19, 45[.]77[.]10[.]5 and "
                "185[.]220[.]101[.]45 discovered.")
    arts = split_artifacts(text)
    ips = [a for a in arts if a.type == "ip"]
    canonicals = sorted(ip.canonical for ip in ips)
    assert canonicals == ["149.28.81.19", "185.220.101.45", "45.77.10.5"]
    assert all(ip.metadata["defanged"] for ip in ips)


def test_plain_ipv4_still_works_and_not_marked_defanged():
    arts = split_artifacts("Public DNS 8.8.8.8 pinged fine.")
    ips = [a for a in arts if a.type == "ip"]
    assert len(ips) == 1
    assert ips[0].canonical == "8.8.8.8"
    assert ips[0].metadata.get("defanged") is not True
    assert ips[0].source["extractor"] == "ida.ipv4"


# ── Defanged URL extraction ───────────────────────────────────────
def test_defanged_url_hxxp_bracket():
    arts = split_artifacts("Reach out to hxxps://malicious[.]example[.]com/beacon.")
    urls = [a for a in arts if a.type == "url"]
    assert len(urls) == 1
    u = urls[0]
    assert u.canonical == "https://malicious.example.com/beacon"
    assert u.metadata["defanged"] is True
    assert u.metadata["host"] == "malicious.example.com"


def test_defanged_url_paren_form():
    arts = split_artifacts("Also: hxxp://foo(.)bar(.)co/x here.")
    urls = [a for a in arts if a.type == "url"]
    assert len(urls) == 1
    assert urls[0].canonical == "http://foo.bar.co/x"


def test_plain_url_still_works_and_not_marked_defanged():
    arts = split_artifacts("Legit link: https://microsoft.com/security here.")
    urls = [a for a in arts if a.type == "url"]
    assert len(urls) == 1
    assert urls[0].canonical == "https://microsoft.com/security"
    assert urls[0].metadata.get("defanged") is not True


# ── Real-world mini corpus (Sophos-style paragraph) ────────────────
_SOPHOS_STYLE = """
    In our incident-response engagement, the actor established
    persistence and beaconed to the following C2 servers:
        · 149[.]28[.]81[.]19   (Vultr node · US-East)
        · 45(.)77(.)10(.)5     (Vultr node · EU-West)
        · hxxps://malicious[.]example[.]com/gate.php
    A staging URL was also observed: hxxp://staging[.]evil[.]net/x.bin.
    """


def test_sophos_style_paragraph_extracts_all_defanged_iocs():
    arts = split_artifacts(_SOPHOS_STYLE)
    ips  = sorted(a.canonical for a in arts if a.type == "ip")
    urls = sorted(a.canonical for a in arts if a.type == "url")
    # Both IPs must surface (this was the P1-02 gap)
    assert "149.28.81.19" in ips
    assert "45.77.10.5"   in ips
    # Both URLs must surface
    assert any("malicious.example.com" in u for u in urls)
    assert any("staging.evil.net"      in u for u in urls)


# ── Determinism ────────────────────────────────────────────────────
def test_defanged_extraction_deterministic():
    text = "IPs: 149[.]28[.]81[.]19 and hxxps://foo[.]bar/x. Repeat: 149[.]28[.]81[.]19."
    r1 = [(a.type, a.canonical, a.source["offset"]) for a in split_artifacts(text)]
    r2 = [(a.type, a.canonical, a.source["offset"]) for a in split_artifacts(text)]
    assert r1 == r2
