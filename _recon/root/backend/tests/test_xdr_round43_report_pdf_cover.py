"""Round 43 · Report PDF Cover Art — regression.

Presentation enhancement only.  The existing four-section report
contract is untouched.  Every acceptance gate here is directly
traceable to the owner brief.

  Cover ON
    ├── page 1  = branded NivXRay XDR cover page
    ├── pages 2+ = existing four-section report
    └── every page footer = "Page X of Y"

  Cover OFF
    ├── page 1  = existing four-section report (Step 5 export)
    └── every page footer = "Page X of Y"

  MISSING incident
    └── honest one-page PDF (no fabricated cover, regardless of flag)
"""
from __future__ import annotations
import asyncio, hashlib, re
from datetime import datetime, timezone
from io import BytesIO
import pytest
import pypdf

from services import report as report_svc


def _pdf_text(pdf_bytes: bytes) -> str:
    reader = pypdf.PdfReader(BytesIO(pdf_bytes))
    raw = "\n".join(p.extract_text() or "" for p in reader.pages)
    return " ".join(raw.split())


def _pdf_page_count(pdf_bytes: bytes) -> int:
    return len(pypdf.PdfReader(BytesIO(pdf_bytes)).pages)


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
    inc_id = "inc_r43_" + hashlib.sha256(b"r43").hexdigest()[:12]
    evt_id = "evt_r43_" + hashlib.sha256(b"r43-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host": {"name": "WKS-R43"},
        "user": {"name": "ivy@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "security": {"signature": {"id": 43, "name": "PS"}, "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R43 cover-art fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "in_progress", "incident_priority": "P1",
        "verdict_card": {"verdict": "malicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r43",
                              "trace_id": "r43"},
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
        await report_svc.add_block(db, inc_id, "supporting_evidence",
                                              "Analyst-added test note.",
                                              "ivy@nivxray.local",
                                              title="Analyst context note")
    _run(loop, _seed())
    return inc_id


# ── Acceptance gates ────────────────────────────────────────────────

def test_cover_enabled_prepends_cover_page(loop, db, incident_id):
    report = _run(loop, report_svc.compose(db, incident_id))
    pdf_with    = report_svc.render_pdf(report, cover=True)
    pdf_without = report_svc.render_pdf(report, cover=False)
    n_with    = _pdf_page_count(pdf_with)
    n_without = _pdf_page_count(pdf_without)
    assert n_with == n_without + 1, (
        f"cover=True must add exactly one page: with={n_with}, "
        f"without={n_without}"
    )


def test_cover_page_carries_required_fields(loop, db, incident_id):
    """The cover MUST include: brand, incident title/ID,
    verdict/severity, investigation status, generated timestamp,
    and the provenance notice."""
    report = _run(loop, report_svc.compose(db, incident_id))
    txt = _pdf_text(report_svc.render_pdf(report, cover=True))
    hdr = report["header"]
    assert "NivXRay XDR" in txt
    assert (hdr.get("title") or "") in txt
    assert incident_id in txt
    # verdict is rendered upper-cased on the cover
    assert (hdr.get("verdict") or "").upper() in txt
    # priority + investigation state present
    assert (hdr.get("priority") or "") in txt
    assert (hdr.get("state") or "") in txt
    assert "Generated at" in txt
    # Provenance notice paragraph explicitly names the four badges.
    for badge in ("EVIDENCE-DERIVED", "NIVXRAY GENERATED",
                        "ANALYST ADDED", "ANALYST EDITED"):
        assert badge in txt, f"cover must name badge {badge!r}"


def test_cover_disabled_returns_step5_layout(loop, db, incident_id):
    """cover=False MUST NOT introduce cover-only text into the PDF —
    the export falls back to the exact Step 5 layout."""
    report = _run(loop, report_svc.compose(db, incident_id))
    txt = _pdf_text(report_svc.render_pdf(report, cover=False))
    # The cover-only provenance notice mentions "Generated at" as a
    # bold field label — the Step 5 header uses "Generated at" too,
    # so we assert on cover-only KPIs instead.
    assert "INVESTIGATION STATE" not in txt, (
        "cover-only 'INVESTIGATION STATE' KPI must not appear when "
        "cover=False"
    )
    assert "VERDICT" not in txt, (
        "cover-only 'VERDICT' KPI must not appear when cover=False"
    )
    # Body still fully renders.
    for title in ("Executive Summary", "Technical Summary",
                        "Supporting Evidence", "Recommendations"):
        assert title in txt, f"body section {title!r} missing"


def test_footer_page_numbers_present_both_modes(loop, db, incident_id):
    """Every page footer MUST carry a "Page X of Y" stamp in both
    cover-on and cover-off exports."""
    report = _run(loop, report_svc.compose(db, incident_id))
    for cover in (True, False):
        pdf = report_svc.render_pdf(report, cover=cover)
        txt = _pdf_text(pdf)
        total = _pdf_page_count(pdf)
        for n in range(1, total + 1):
            assert f"Page {n} of {total}" in txt, (
                f"page footer 'Page {n} of {total}' missing "
                f"(cover={cover})"
            )


def test_sections_ordering_preserved_both_modes(loop, db, incident_id):
    """The four sections MUST appear in canonical order regardless
    of the cover flag."""
    report = _run(loop, report_svc.compose(db, incident_id))
    canonical = ["Executive Summary", "Technical Summary",
                       "Supporting Evidence", "Recommendations"]
    for cover in (True, False):
        txt = _pdf_text(report_svc.render_pdf(report, cover=cover))
        positions = [txt.index(t) for t in canonical]
        assert positions == sorted(positions), (
            f"section order broken (cover={cover}): {positions}"
        )


def test_all_provenance_badges_preserved_both_modes(loop, db, incident_id):
    """All four provenance badges MUST appear in both exports."""
    report = _run(loop, report_svc.compose(db, incident_id))
    for cover in (True, False):
        txt = _pdf_text(report_svc.render_pdf(report, cover=cover))
        for badge in ("EVIDENCE-DERIVED", "NIVXRAY GENERATED",
                            "ANALYST ADDED"):
            assert badge in txt, (
                f"badge {badge!r} missing in body (cover={cover})"
            )


def test_missing_incident_no_cover_regardless_of_flag(loop, db):
    """MISSING incidents MUST NOT fabricate a cover page under any
    flag setting."""
    report = _run(loop, report_svc.compose(db, "does-not-exist"))
    assert report.get("state") == "MISSING"
    for cover in (True, False):
        pdf = report_svc.render_pdf(report, cover=cover)
        assert pdf.startswith(b"%PDF-")
        txt = _pdf_text(pdf)
        assert "Report unavailable" in txt
        # No cover-only KPIs leaked.
        assert "INVESTIGATION STATE" not in txt
        assert "VERDICT" not in txt


def test_missing_incident_still_page_numbered(loop, db):
    """Even the one-page MISSING error PDF should still carry the
    Page 1 of 1 footer (consistent presentation)."""
    report = _run(loop, report_svc.compose(db, "does-not-exist"))
    pdf = report_svc.render_pdf(report, cover=True)
    txt = _pdf_text(pdf)
    assert "Page 1 of 1" in txt


def test_render_signature_backwards_compatible(loop, db, incident_id):
    """The default ``render_pdf(report)`` call (no ``cover`` kwarg)
    MUST default to cover-on so callers who upgraded from Step 5
    without changes see the new presentation immediately."""
    report = _run(loop, report_svc.compose(db, incident_id))
    default_pdf = report_svc.render_pdf(report)                 # implicit
    explicit    = report_svc.render_pdf(report, cover=True)     # explicit
    # Same structural page count.
    assert _pdf_page_count(default_pdf) == _pdf_page_count(explicit)
    # And the cover-only KPI headers are present in the default
    # (proving the default is cover-on).
    txt = _pdf_text(default_pdf)
    assert "INVESTIGATION STATE" in txt


def test_no_second_report_engine_introduced(loop, db, incident_id):
    """Round 43 is presentation-only.  The public ``report_svc``
    module must still expose exactly one report composer + one
    renderer.  No parallel engine, no cover composer, no separate
    cover-data model."""
    forbidden = {"compose_cover", "render_cover", "cover_pdf",
                    "compose_v2", "render_pdf_v2", "compose_pdf",
                    "compose_report_pdf"}
    leaked = forbidden & set(dir(report_svc))
    assert not leaked, (
        f"Round 43 must remain presentation-only; leaked engine "
        f"symbols: {sorted(leaked)}"
    )
