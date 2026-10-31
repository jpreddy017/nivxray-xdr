"""R28.8 · Phase 0 · Orchestrator + Adapter integration.

Proves the Universal Input Adapter layer is wired into
``Orchestrator.run()`` so an arbitrary uploaded document ends up as
typed artifacts inside the UAIE state machine — no manual routing,
no format-specific code path in the orchestrator."""
import io, json, zipfile

from services.uaie import plugins as _p           # noqa: F401
from services.uaie.orchestrator import Orchestrator


def _new_orchestrator() -> Orchestrator:
    return Orchestrator(
        recognizers=_p.all_recognizers(),
        max_artifacts=128, max_depth=16,
    )


def test_docx_upload_produces_typed_text_and_url_artifacts():
    """A DOCX upload with an embedded hyperlink must land in the
    orchestrator as (at minimum) a ``text`` artifact + a ``url``
    artifact — proving the DOCX adapter fired and the orchestrator
    ingested its child artifacts."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml",
            "<document><body><p><r><t>Please visit our portal.</t></r></p></body></document>")
        zf.writestr("word/_rels/document.xml.rels",
            '<Relationships><Relationship Target="https://phish.example.com/x"/></Relationships>')
    orch = _new_orchestrator()
    r = orch.run(buf.getvalue(), filename="lure.docx")
    types = {a.artifact_type for a in r.artifacts.values()}
    assert "text" in types, f"text artifact never surfaced · types={types}"
    assert "url"  in types, f"url artifact never surfaced · types={types}"
    joined = b" ".join(a.payload for a in r.artifacts.values()
                          if a.artifact_type == "text").decode()
    assert "portal" in joined


def test_eml_upload_produces_envelope_body_url_artifacts():
    payload = (
        b"From: attacker@example.net\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Please review\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please open https://mal.example.com/pwn now.\r\n"
    )
    orch = _new_orchestrator()
    r = orch.run(payload)
    types = {a.artifact_type for a in r.artifacts.values()}
    assert "email_envelope" in types
    assert "url" in types
    assert "text" in types


def test_json_upload_extracts_url_ip_hash_leaves_as_artifacts():
    doc = {
        "c2":      "https://mal.example.net/beacon",
        "backup":  "203.0.113.9",
        "sample_sha256": "b" * 64,
    }
    orch = _new_orchestrator()
    r = orch.run(json.dumps(doc).encode())
    types = {a.artifact_type for a in r.artifacts.values()}
    assert "url" in types
    assert "ip"  in types
    assert "hash" in types


def test_generic_zip_expands_and_orchestrator_ingests_entries():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("suspicious.ps1",
            "Invoke-Expression ([Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String('SGVsbG8=')))")
        zf.writestr("readme.md", "just a note")
    orch = _new_orchestrator()
    r = orch.run(buf.getvalue(), filename="pack.zip")
    entries = [a for a in r.artifacts.values()
                if a.artifact_type == "archive_entry"]
    assert len(entries) >= 2


def test_root_type_declared_bypasses_adapter_router():
    """If the caller declares ``root_type='text'`` explicitly, the
    adapter router does not run (backwards-compat with capability
    wrappers and older tests that manually type the root)."""
    orch = _new_orchestrator()
    r = orch.run(b"just a sentence", root_type="text")
    types = [a.artifact_type for a in r.artifacts.values()]
    # Root came in exactly as declared, no adapter re-typing.
    assert types[0] == "text"


def test_command_line_input_typed_as_commandline_via_router():
    payload = b"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand JABzAD0A"
    orch = _new_orchestrator()
    r = orch.run(payload)
    types = {a.artifact_type for a in r.artifacts.values()}
    assert "commandline" in types
