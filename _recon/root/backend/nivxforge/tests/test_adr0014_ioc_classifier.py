"""ADR-0014 · Phase 2 · IOC Classifier unit tests (§1.1.16).

Locks the classification contract. Every regression here protects a
category boundary. Adding a new vendor / CA should extend the curated
list AND add a positive test.
"""
from __future__ import annotations

import pytest

from nivxforge.investigation.ioc_classifier import classify


class TestCertificateInfrastructure:
    @pytest.mark.parametrize("value", [
        "http://crl.verisign.com/ThawteTimestampingCA.crl",
        "http://csc3-2010-aia.verisign.com",
        "http://csc3-2010-crl.verisign.com",
        "http://logo.verisign.com",
        "http://www.verisign.com",
        "http://crl.digicert.com/DigiCertGlobalRoot.crl",
        "http://ocsp.sectigo.com",
        "http://letsencrypt.org",
        "http://ocsp.pki.goog",
    ])
    def test_certificate_authorities_never_primary_ioc(self, value):
        r = classify(value)
        assert r.category == "certificate_infrastructure"
        assert r.weight == 0

    def test_bare_verisign_domain_classified(self):
        r = classify("verisign.com")
        assert r.category == "certificate_infrastructure"

    def test_lookalike_not_classified_as_ca(self):
        # We must never suffix-match on substring — `verisign.attacker.com`
        # is an attacker-controlled domain, not CA infra.
        r = classify("http://verisign.attacker.com/payload")
        assert r.category == "external_ioc"


class TestVendorInfrastructure:
    @pytest.mark.parametrize("value", [
        "https://console.amp.cisco.com/incidents/123",
        "https://private.intel.amp.cisco.com",
        "https://xdr.us.security.cisco.com",
        "https://amp.cisco.com/dashboard",
        "https://falcon.crowdstrike.com/detection/1",
        "https://securitycenter.microsoft.com/alerts",
        "https://portal.azure.com",
        "https://sentinelone.com",
        "https://splunk.com",
    ])
    def test_vendor_endpoints_never_primary_ioc(self, value):
        r = classify(value)
        assert r.category == "vendor_infrastructure"
        assert r.weight == 0

    def test_microsoft_metadata_endpoint(self):
        r = classify("http://www.microsoft.com")
        assert r.category == "vendor_infrastructure"


class TestInternalAssets:
    @pytest.mark.parametrize("ip", [
        "10.0.0.5", "172.16.100.1", "192.168.1.55", "127.0.0.1",
    ])
    def test_rfc1918_ipv4(self, ip):
        r = classify(ip, ioc_kind="ip")
        assert r.category == "internal_asset"

    def test_internal_dns_suffixes(self):
        for suffix in [".local", ".lan", ".corp", ".internal"]:
            r = classify(f"host{suffix}", ioc_kind="domain")
            assert r.category == "internal_asset"


class TestExternalIOC:
    @pytest.mark.parametrize("value", [
        "http://malicious.attacker.com/payload",
        "185.159.5.55",
        "8.8.8.8",   # even legit DNS resolvers are leads until classified
    ])
    def test_external_domains_and_ips(self, value):
        r = classify(value)
        assert r.category == "external_ioc"
        assert r.weight >= 6

    def test_hash_short_circuits(self):
        r = classify("1b7eda7f" * 8, ioc_kind="sha256")
        assert r.category == "external_ioc"


class TestMaliciousOverride:
    def test_ti_labelled_beats_vendor_infra(self):
        # A hostile actor could theoretically use `microsoft.com` — if a
        # TI provider flagged it, malicious classification wins.
        r = classify("microsoft.com", ti_labelled_malicious=True)
        assert r.category == "malicious_ioc"
        assert r.weight == 10


class TestUnknown:
    @pytest.mark.parametrize("value", ["", "   ", "not://a[valid]url"])
    def test_unparseable(self, value):
        r = classify(value)
        assert r.category in ("unknown", "external_ioc")
        # Unknown must not drive verdicts
        if r.category == "unknown":
            assert r.weight == 0
