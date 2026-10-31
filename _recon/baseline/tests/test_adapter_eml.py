"""Phase 3B · EML adapter contract tests.

Builds a small phishing-shaped RFC-822 message at test time and
validates the flagship EML pipeline:  identity + transport + content +
attachments + metadata, MIME hierarchy, structural-only relationships
(R8), graceful-degradation manifest fields (R9).
"""
from __future__ import annotations

from email.message import EmailMessage

import pytest

from models import IEP, RelationshipType
from services.adapters import EMLAdapter, adapt


def _make_eml() -> bytes:
    m = EmailMessage()
    m["From"]         = "Attacker <attacker@bad.example>"
    m["Reply-To"]     = "victim@totally-different.example"
    m["Return-Path"]  = "<bounce@bad.example>"
    m["To"]           = "victim@target.example"
    m["Cc"]           = "cfo@target.example, ceo@target.example"
    m["Subject"]      = "Invoice #4711"
    m["Message-ID"]   = "<abcd@bad.example>"
    m["Date"]         = "Wed, 10 Jul 2024 08:15:00 +0000"
    m["X-Mailer"]     = "PhishKit v6.6"
    m["Authentication-Results"] = "mx.example; spf=fail; dkim=fail; dmarc=fail"
    m["Received"]     = "from bad.example by mx.example"
    m.set_content(
        "Please pay via https://mal.example/pay\n"
        "Callback: 10.0.0.42\n"
        "CVE-2024-57727\n"
    )
    m.add_alternative(
        "<html><body>Please click "
        "<a href='https://mal.example/pay'>here</a></body></html>",
        subtype="html",
    )
    m.add_attachment(b"%PDF-1.4 malicious payload",
                     maintype="application", subtype="pdf",
                     filename="invoice.pdf")
    return m.as_bytes()


EML_BYTES = _make_eml()


def test_eml_detection():
    a = EMLAdapter()
    assert a.can_handle(EML_BYTES)
    assert not a.can_handle(b"not an email")


def test_eml_adapter_wins_routing():
    iep = adapt(EML_BYTES)
    assert iep.provenance.adapter == "adapter.eml"


def test_eml_extracts_identity_artifacts():
    iep = EMLAdapter().make_iep(EML_BYTES)
    emails = iep.values_of("email_address")
    assert "attacker@bad.example"        in emails
    assert "victim@target.example"       in emails
    assert "cfo@target.example"          in emails
    assert "ceo@target.example"          in emails


def test_eml_extracts_body_artifacts():
    iep = EMLAdapter().make_iep(EML_BYTES)
    urls = iep.values_of("url")
    ips  = iep.values_of("ip")
    cves = iep.values_of("cve")
    assert any("mal.example/pay" in u for u in urls)
    assert "10.0.0.42" in ips
    assert "CVE-2024-57727" in cves


def test_eml_attachment_surfaces_with_provenance():
    iep = EMLAdapter().make_iep(EML_BYTES)
    atts = [a for a in iep.artifacts if "eml_attachment" in (a.tags or [])]
    assert atts, "expected at least one attachment artifact"
    a = atts[0]
    assert a.value == "invoice.pdf"
    assert a.source_ref.startswith("mime.part.")
    assert (a.attributes or {}).get("mime_type") == "application/pdf"
    assert (a.attributes or {}).get("sha256")


def test_eml_relationships_are_structural_only():
    iep = EMLAdapter().make_iep(EML_BYTES)
    _ALLOWED = {RelationshipType.CONTAINS, RelationshipType.ATTACHES}
    assert iep.relationships, "no relationships emitted"
    for r in iep.relationships:
        assert r.verb in _ALLOWED, f"non-structural: {r.verb}"


def test_eml_reply_to_mismatch_warning():
    iep = EMLAdapter().make_iep(EML_BYTES)
    codes = {w.code for w in iep.warnings}
    assert "eml_reply_to_differs_from_from" in codes
    assert "eml_spf_fail"   in codes
    assert "eml_dkim_fail"  in codes
    assert "eml_dmarc_fail" in codes
    assert "eml_has_attachments" in codes


def test_eml_manifest_has_timing_and_status():
    """R9 · manifest carries execution_time_ms + adapter_status."""
    iep = EMLAdapter().make_iep(EML_BYTES)
    m = iep.metadata.data["adapter"]
    assert isinstance(m.get("execution_time_ms"), int)
    assert m["execution_time_ms"] >= 0
    assert m.get("adapter_status") in {"success", "partial"}


def test_eml_statistics_include_relationships_and_timing():
    iep = EMLAdapter().make_iep(EML_BYTES)
    s = iep.statistics
    assert s.relationships == len(iep.relationships)
    assert s.warnings      == len(iep.warnings)
    assert s.processing_time_ms >= 0


def test_r9_adapter_graceful_degradation_on_broken_input():
    """R9 · adapter must NEVER throw — corrupted input yields a
    valid IEP with `adapter_status='failed'` and an error warning."""
    class BombEMLAdapter(EMLAdapter):
        def normalize(self, content):
            raise RuntimeError("simulated normalize failure")
    iep = BombEMLAdapter().make_iep(EML_BYTES)
    assert iep.provenance.adapter == "adapter.eml"
    assert iep.metadata.data["adapter"]["adapter_status"] == "failed"
    codes = {w.code for w in iep.warnings}
    assert "adapter_exception" in codes
