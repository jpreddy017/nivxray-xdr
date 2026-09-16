"""R28.8 · Phase 0 · Universal Input Adapter acceptance suite.

Proves every adapter converts its native format into typed
artifacts AND the router picks the correct adapter deterministically."""
import base64, io, json, re, zipfile

import pytest

from services.uaie.adapters import route_input, ADAPTERS


# ══════════════════════════════════════════════════════════════════
# 1. Router smoke — at least 9 adapters registered
# ══════════════════════════════════════════════════════════════════
def test_all_expected_adapters_registered():
    names = {a.name for a in ADAPTERS}
    for expected in (
        "adapter.plain_text", "adapter.pdf", "adapter.docx",
        "adapter.eml",        "adapter.zip", "adapter.url",
        "adapter.html",       "adapter.json", "adapter.commandline",
    ):
        assert expected in names, f"missing {expected} · have {sorted(names)}"


# ══════════════════════════════════════════════════════════════════
# 2. Plain text
# ══════════════════════════════════════════════════════════════════
def test_plain_text_input_routed_to_plain_text_adapter():
    r = route_input(b"just a sentence with no special format")
    assert r.meta.get("selected_adapter") == "adapter.plain_text"
    assert len(r.artifacts) == 1
    assert r.artifacts[0].artifact_type == "text"


# ══════════════════════════════════════════════════════════════════
# 3. Empty input never explodes
# ══════════════════════════════════════════════════════════════════
def test_empty_input_returns_stub_artifact():
    r = route_input(b"")
    assert len(r.artifacts) == 1
    assert r.artifacts[0].artifact_type == "empty_input"


# ══════════════════════════════════════════════════════════════════
# 4. Commandline
# ══════════════════════════════════════════════════════════════════
def test_commandline_input_routed_to_commandline_adapter():
    payload = b"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand JABzAD0A"
    r = route_input(payload)
    assert r.meta.get("selected_adapter") == "adapter.commandline"
    assert any(a.artifact_type == "commandline" for a in r.artifacts)


# ══════════════════════════════════════════════════════════════════
# 5. URL
# ══════════════════════════════════════════════════════════════════
def test_url_input_emits_url_domain_artifacts():
    r = route_input(b"https://mal.example.com/beacon?id=42")
    assert r.meta.get("selected_adapter") == "adapter.url"
    types = [a.artifact_type for a in r.artifacts]
    assert "url" in types
    assert "domain" in types


def test_bare_ip_url_emits_ip_artifact():
    r = route_input(b"https://149.28.81.19/beacon")
    types = [a.artifact_type for a in r.artifacts]
    assert "url" in types
    assert "ip" in types


# ══════════════════════════════════════════════════════════════════
# 6. JSON
# ══════════════════════════════════════════════════════════════════
def test_json_input_extracts_urls_ips_hashes_from_leaves():
    doc = {
        "target":  "https://c2.example.net/beacon",
        "callback_ip": "203.0.113.42",
        "sample_sha256": "a" * 64,
        "notes": "harmless",
    }
    payload = json.dumps(doc).encode()
    r = route_input(payload)
    assert r.meta.get("selected_adapter") == "adapter.json"
    types = {a.artifact_type for a in r.artifacts}
    for expected in ("url", "ip", "hash", "text"):
        assert expected in types, f"missing {expected} · got {types}"


# ══════════════════════════════════════════════════════════════════
# 7. HTML
# ══════════════════════════════════════════════════════════════════
def test_html_input_extracts_text_and_urls():
    payload = (b"<!doctype html><html><body>"
                 b"<a href='https://mal.example.com/x'>bad</a>"
                 b"<p>hello world</p></body></html>")
    r = route_input(payload)
    assert r.meta.get("selected_adapter") == "adapter.html"
    types = {a.artifact_type for a in r.artifacts}
    assert "text" in types
    assert "url"  in types


# ══════════════════════════════════════════════════════════════════
# 8. EML
# ══════════════════════════════════════════════════════════════════
def test_eml_input_emits_envelope_body_and_url_artifacts():
    payload = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: hi\r\n"
        b"Date: Mon, 3 Feb 2026 10:00:00 -0500\r\n"
        b"Message-ID: <abc@example.com>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please visit https://phish.example.net/login\r\n"
    )
    r = route_input(payload)
    assert r.meta.get("selected_adapter") == "adapter.eml"
    types = [a.artifact_type for a in r.artifacts]
    assert "email_envelope" in types
    assert "text" in types
    assert "url"  in types


# ══════════════════════════════════════════════════════════════════
# 9. ZIP (generic, non-OOXML)
# ══════════════════════════════════════════════════════════════════
def test_generic_zip_expands_into_archive_entry_artifacts():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil.ps1", "$c='powershell'; Invoke-Expression $c;")
        zf.writestr("readme.txt", "hello")
    r = route_input(buf.getvalue())
    assert r.meta.get("selected_adapter") == "adapter.zip"
    entries = [a for a in r.artifacts if a.artifact_type == "archive_entry"]
    assert len(entries) == 2
    names = {a.meta.get("entry_name") for a in entries}
    assert names == {"evil.ps1", "readme.txt"}


# ══════════════════════════════════════════════════════════════════
# 10. OOXML DOCX (well-formed minimal document)
# ══════════════════════════════════════════════════════════════════
def test_ooxml_docx_extracts_document_text_and_urls():
    """Build a minimal DOCX in-memory (word/document.xml with a
    hyperlink) so we don't need a real docx sample file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml",
            "<document><body><p><r><t>Hello analyst · "
            "visit https://mal.example.com/pwn</t></r></p></body></document>")
        zf.writestr("word/_rels/document.xml.rels",
            '<Relationships><Relationship Target="https://evil.example.net/c2"/></Relationships>')
    r = route_input(buf.getvalue(), filename="report.docx")
    assert r.meta.get("selected_adapter") == "adapter.docx"
    types = {a.artifact_type for a in r.artifacts}
    assert "text" in types
    assert "url"  in types
    text_arts = [a for a in r.artifacts if a.artifact_type == "text"]
    joined = b" ".join(a.payload for a in text_arts).decode()
    assert "Hello analyst" in joined


# ══════════════════════════════════════════════════════════════════
# 11. PDF
# ══════════════════════════════════════════════════════════════════
def test_pdf_input_routed_and_urls_recovered():
    """Craft a minimal valid PDF containing a URL in a plain-text
    stream that pypdf can decode."""
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 52>>stream\nBT /F1 12 Tf 72 720 Td "
        b"(Visit https://phish.example.com/login) Tj ET\nendstream endobj\n"
        b"xref\n0 5\n0000000000 65535 f \n"
        b"trailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF"
    )
    r = route_input(pdf, filename="lure.pdf")
    assert r.meta.get("selected_adapter") == "adapter.pdf"
    # PDF adapter regex-scans embedded URLs directly from bytes, so
    # even if pypdf/pdfminer can't extract text from this handmade
    # PDF, the URL still surfaces.
    urls = [a for a in r.artifacts if a.artifact_type == "url"]
    assert urls, f"no URL surfaced · artifacts={[a.artifact_type for a in r.artifacts]}"


# ══════════════════════════════════════════════════════════════════
# 12. ARCHITECTURAL — router picks correct adapter for each family
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("payload,expected_adapter", [
    (b"plain sentence "*20,                                              "adapter.plain_text"),
    (b"%COMSPEC% /c powershell -nop -enc ABCDEFG",                       "adapter.commandline"),
    (b"https://example.com/path",                                        "adapter.url"),
    (b'{"a":1,"b":"https://x.y/z"}',                                     "adapter.json"),
    (b"<!doctype html><html><body><a href='http://x/y'>x</a></body></html>", "adapter.html"),
])
def test_router_picks_correct_adapter(payload, expected_adapter):
    r = route_input(payload)
    assert r.meta.get("selected_adapter") == expected_adapter, (
        f"expected {expected_adapter} · got {r.meta.get('selected_adapter')}"
    )
