"""Round 39 · Step 5 · Investigation Report PDF export regression.

Acceptance gates (owner-locked):

  1. Endpoint `GET /api/incidents/{id}/report/pdf` returns HTTP 200
     with `application/pdf` content-type and valid PDF magic bytes.
  2. PDF is a *projection* of the exact `report_svc.compose()` output —
     no second report engine.  Every SYSTEM block in the composed
     contract has a provenance signature (badge label) present in
     the PDF text stream.
  3. The four owner-locked section titles appear in the PDF text
     stream, in canonical order.
  4. Analyst-added blocks appear in the PDF with an ANALYST provenance
     badge.
  5. Technical Summary carries the EVIDENCE-DERIVED provenance badge.
  6. Missing incident → PDF renderer returns an honest one-page PDF
     (never crashes, never fabricates a report).
  7. PDF rendering is deterministic in structure: same input → same
     byte length within tolerance.
"""
from __future__ import annotations
import asyncio, hashlib
from datetime import datetime, timezone
from io import BytesIO
import pytest
import pypdf

from services import report as report_svc


def _pdf_text(pdf_bytes: bytes) -> str:
    """Extract text from every page of a PDF byte-stream.

    Whitespace is collapsed so that badges laid out on two rows in
    the PDF (`NIVXRAY\\nGENERATED`) remain findable as
    ``NIVXRAY GENERATED``.
    """
    reader = pypdf.PdfReader(BytesIO(pdf_bytes))
    raw = "\n".join(p.extract_text() or "" for p in reader.pages)
    return " ".join(raw.split())


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def db(loop):
    from motor.motor_asyncio import AsyncIOMotorClient
    import os
    from dotenv import load_dotenv
    load_dotenv("/app/backend/.env")
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]
    c.close()


@pytest.fixture(scope="module")
def incident_id(loop, db):
    inc_id = "inc_r39s5_" + hashlib.sha256(b"r39s5").hexdigest()[:12]
    evt_id = "evt_r39s5_" + hashlib.sha256(b"r39s5-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host": {"name": "WKS-R39S5"},
        "user": {"name": "eve@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "network": {"src": {"ip": "10.20.30.40"},
                          "dst": {"ip": "198.51.100.7"},
                          "protocol": "TCP"},
        "security": {"signature": {"id": 88, "name": "Suspicious PS"},
                           "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R39 Step5 PDF fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "in_progress", "incident_priority": "P1",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"},
                    {"technique_id": "T1218.011", "tactic_id": "TA0005",
                        "name": "Rundll32"}],
        "iocs": {"ip": ["198.51.100.7"], "user": ["eve@nivxray.local"]},
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r39s5",
                              "trace_id": "r39s5"}
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
        # Add an analyst block so we can test the ANALYST ADDED provenance.
        await report_svc.add_block(db, inc_id, "supporting_evidence",
                                              "Additional context observed by "
                                              "the on-call analyst.",
                                              "eve@nivxray.local",
                                              title="Analyst context note")
    _run(loop, _seed())
    return inc_id


# ── Acceptance gates ────────────────────────────────────────────────

def test_render_returns_valid_pdf_bytes(loop, db, incident_id):
    report = _run(loop, report_svc.compose(db, incident_id))
    pdf = report_svc.render_pdf(report)
    assert isinstance(pdf, (bytes, bytearray)), type(pdf)
    assert pdf.startswith(b"%PDF-"), (
        f"Not a valid PDF (magic bytes missing): {pdf[:10]!r}"
    )
    assert b"%%EOF" in pdf[-1024:], "PDF trailer missing"
    assert len(pdf) > 1500, f"PDF suspiciously small: {len(pdf)}"


def test_pdf_contains_all_four_section_titles(loop, db, incident_id):
    report = _run(loop, report_svc.compose(db, incident_id))
    pdf = report_svc.render_pdf(report)
    txt = _pdf_text(pdf)
    for title in ("Executive Summary", "Technical Summary",
                       "Supporting Evidence", "Recommendations"):
        assert title in txt, (
            f"Section title {title!r} missing from PDF text stream"
        )


def test_pdf_carries_evidence_derived_badge(loop, db, incident_id):
    """Technical Summary MUST render with the EVIDENCE-DERIVED badge."""
    report = _run(loop, report_svc.compose(db, incident_id))
    txt = _pdf_text(report_svc.render_pdf(report))
    assert "EVIDENCE-DERIVED" in txt, (
        "Technical Summary provenance badge missing from PDF"
    )


def test_pdf_carries_analyst_added_badge(loop, db, incident_id):
    """The Analyst block seeded in the fixture must be rendered with
    the ANALYST ADDED provenance badge."""
    report = _run(loop, report_svc.compose(db, incident_id))
    txt = _pdf_text(report_svc.render_pdf(report))
    assert "ANALYST ADDED" in txt, (
        "Analyst-added provenance badge missing from PDF"
    )


def test_pdf_carries_nivxray_generated_badge(loop, db, incident_id):
    """SYSTEM-composed blocks MUST render with NIVXRAY GENERATED."""
    report = _run(loop, report_svc.compose(db, incident_id))
    txt = _pdf_text(report_svc.render_pdf(report))
    assert "NIVXRAY GENERATED" in txt, (
        "SYSTEM-composed provenance badge missing from PDF"
    )


def test_pdf_header_shows_incident_identity(loop, db, incident_id):
    report = _run(loop, report_svc.compose(db, incident_id))
    txt = _pdf_text(report_svc.render_pdf(report))
    assert "NivXRay XDR" in txt, "Brand header missing"
    assert (report["header"]["title"] or "") in txt, "Title missing"
    assert incident_id in txt, "Incident id missing"


def test_pdf_missing_incident_returns_honest_pdf(loop, db):
    report = _run(loop, report_svc.compose(db, "does-not-exist-inc"))
    assert report.get("state") == "MISSING"
    pdf = report_svc.render_pdf(report)
    assert pdf.startswith(b"%PDF-")
    txt = _pdf_text(pdf)
    assert "Report unavailable" in txt, (
        "Honest MISSING PDF must state that the report is unavailable"
    )
    # Must not contain fabricated section titles from a full report.
    assert "Technical Summary" not in txt


def test_pdf_projection_never_calls_second_engine(loop, db, incident_id):
    """The PDF renderer MUST accept the exact shape from compose() and
    MUST NOT depend on any parallel report engine.  Empty sections
    render empty rather than fabricated."""
    report = _run(loop, report_svc.compose(db, incident_id))
    # Erase system blocks to prove PDF projects only what compose provides.
    report_copy = {**report,
                       "sections": {
                           **report["sections"],
                           "executive_summary": {
                               **report["sections"]["executive_summary"],
                               "system_blocks": [], "analyst_blocks": [],
                           },
                       }}
    txt = _pdf_text(report_svc.render_pdf(report_copy))
    assert "Executive Summary" in txt
    assert "No executive summary blocks composed" in txt, (
        "Empty section must render honestly, not be fabricated"
    )


def test_pdf_deterministic_size_within_tolerance(loop, db, incident_id):
    """Rendering the same report twice must produce byte-streams whose
    sizes are within a small tolerance (PDF carries a build-time
    creation date but the structural content is deterministic)."""
    report = _run(loop, report_svc.compose(db, incident_id))
    a = len(report_svc.render_pdf(report))
    b = len(report_svc.render_pdf(report))
    assert abs(a - b) < 200, (
        f"PDF size not deterministic within tolerance: {a} vs {b}"
    )
