"""Tests for the Value Shape detection library.

Contracts:
  · Pure / deterministic / never raises
  · Precision over coverage — no false positives on adversarial inputs
  · No vendor identity anywhere
"""
from __future__ import annotations

import pytest

from nivxforge.investigation.pipeline.value_shape import (
    SHAPE_CONCEPT_AFFINITY,
    ShapeMatch,
    ValueShape,
    concept_boosts_for,
    detect_shapes,
)


def _shapes(value):
    return [m.shape for m in detect_shapes(value)]


class TestNetworkShapes:

    @pytest.mark.parametrize("v", [
        "10.0.0.1", "192.168.1.100", "8.8.8.8", "255.255.255.255",
    ])
    def test_ipv4(self, v):
        assert ValueShape.IPV4 in _shapes(v)

    def test_ipv4_cidr(self):
        assert ValueShape.IPV4_CIDR in _shapes("10.0.0.0/24")

    @pytest.mark.parametrize("v", [
        "2001:db8::1", "::1", "fe80::1", "2001:0db8:0000:0000:0000:ff00:0042:8329",
    ])
    def test_ipv6(self, v):
        assert ValueShape.IPV6 in _shapes(v)

    def test_mac(self):
        for v in ("00:1A:2B:3C:4D:5E", "aa-bb-cc-dd-ee-ff"):
            assert ValueShape.MAC in _shapes(v)

    def test_asn(self):
        assert ValueShape.ASN in _shapes("AS15169")
        assert ValueShape.ASN in _shapes(15169)

    def test_port(self):
        assert ValueShape.PORT in _shapes(443)
        assert ValueShape.PORT in _shapes(65535)

    def test_domain_fqdn(self):
        assert ValueShape.DOMAIN_FQDN in _shapes("example.com")
        assert ValueShape.DOMAIN_FQDN in _shapes("mail.corp.local")

    def test_url(self):
        assert ValueShape.URL in _shapes("https://example.com/path?x=1")
        assert ValueShape.URL in _shapes("smb://server/share/file")

    def test_dns_rr_type(self):
        for rr in ("A", "AAAA", "CNAME", "MX", "TXT", "SRV"):
            assert ValueShape.DNS_RR_TYPE in _shapes(rr)


class TestIdentityShapes:

    def test_email(self):
        assert ValueShape.EMAIL in _shapes("alice@example.com")

    def test_email_message_id(self):
        assert ValueShape.EMAIL_MESSAGE_ID in _shapes(
            "<abc123@mail.example.com>"
        )

    def test_windows_sid(self):
        assert ValueShape.WINDOWS_SID in _shapes(
            "S-1-5-21-1111111111-2222222222-3333333333-1001"
        )

    def test_guid_and_uuid(self):
        v = "{1B4E28BA-2FA1-11D2-883F-0016D3CCA427}"
        s = _shapes(v)
        assert ValueShape.GUID in s and ValueShape.UUID in s

    def test_jwt(self):
        # header.payload.signature — synthetic short JWT
        jwt = ("eyJhbGciOiJIUzI1NiJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        assert ValueShape.JWT in _shapes(jwt)


class TestFilesystemShapes:

    def test_windows_path(self):
        assert ValueShape.FILE_PATH_WIN in _shapes(
            r"C:\Windows\System32\cmd.exe"
        )

    def test_unc_path(self):
        assert ValueShape.FILE_PATH_WIN in _shapes(
            r"\\server\share\folder"
        )

    def test_posix_path(self):
        assert ValueShape.FILE_PATH_POSIX in _shapes(
            "/usr/local/bin/python3"
        )

    def test_registry_path(self):
        assert ValueShape.REGISTRY_PATH in _shapes(
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
        )

    def test_linux_device_id(self):
        assert ValueShape.LINUX_DEVICE_ID in _shapes("8:0")


class TestCryptographicShapes:

    def test_md5(self):
        assert ValueShape.HASH_MD5 in _shapes("d41d8cd98f00b204e9800998ecf8427e")

    def test_sha1(self):
        assert ValueShape.HASH_SHA1 in _shapes(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )

    def test_sha256(self):
        v = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert ValueShape.HASH_SHA256 in _shapes(v)

    def test_sha512(self):
        v = ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9c"
             "e47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        assert ValueShape.HASH_SHA512 in _shapes(v)

    def test_pem_certificate(self):
        v = "-----BEGIN CERTIFICATE-----\nMIID…\n-----END CERTIFICATE-----"
        assert ValueShape.PEM_CERTIFICATE in _shapes(v)


class TestThreatIdentifiers:

    def test_mitre_technique(self):
        assert ValueShape.MITRE_TECHNIQUE_ID in _shapes("T1059")
        assert ValueShape.MITRE_TECHNIQUE_ID in _shapes("T1059.001")

    def test_mitre_tactic(self):
        assert ValueShape.MITRE_TACTIC_ID in _shapes("TA0002")

    def test_mitre_software(self):
        assert ValueShape.MITRE_SOFTWARE_ID in _shapes("S0009")

    def test_cve(self):
        assert ValueShape.CVE_ID in _shapes("CVE-2024-12345")

    def test_cwe(self):
        assert ValueShape.CWE_ID in _shapes("CWE-79")

    def test_capec(self):
        assert ValueShape.CAPEC_ID in _shapes("CAPEC-63")


class TestCloudShapes:

    def test_aws_arn(self):
        assert ValueShape.AWS_ARN in _shapes(
            "arn:aws:s3:::my-bucket-name"
        )

    def test_azure_resource(self):
        assert ValueShape.AZURE_RESOURCE_ID in _shapes(
            "/subscriptions/11111111-2222-3333-4444-555555555555/"
            "resourceGroups/rg-prod"
        )

    def test_oci_sha256(self):
        v = ("sha256:"
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert ValueShape.OCI_SHA256_DIGEST in _shapes(v)


class TestDeterminismAndRobustness:

    @pytest.mark.parametrize("v", [
        None, True, False, "", "   ", "x" * 5000,
    ])
    def test_edge_cases_do_not_raise(self, v):
        # Some intentionally return [] — the point is no exception.
        assert isinstance(detect_shapes(v), list)

    def test_deterministic(self):
        v = "https://evil.example.com/malware.exe"
        assert detect_shapes(v) == detect_shapes(v)


class TestConceptAffinity:

    def test_ipv4_boosts_ip(self):
        matches = detect_shapes("10.0.0.1")
        boosts = concept_boosts_for(matches)
        assert any(c == "IP" for c, _, _ in boosts)

    def test_url_boosts_url(self):
        boosts = concept_boosts_for(detect_shapes("https://x.io/y"))
        assert any(c == "URL" for c, _, _ in boosts)

    def test_no_vendor_concept_in_affinity_table(self):
        # Extra safety — affinity table must reference only canonical
        # concepts, never vendor names.
        concepts_used = {c for pairs in SHAPE_CONCEPT_AFFINITY.values()
                         for (c, _) in pairs}
        vendor_words = {"crowdstrike", "defender", "cisco", "sysmon",
                        "microsoft", "sentinelone"}
        for c in concepts_used:
            assert c.lower() not in vendor_words
