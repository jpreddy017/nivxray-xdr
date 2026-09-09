"""Determinism CI Gate · ADR-0008 §5.5 · Session-8.

Locks NivXRay's report-determinism contract as a testable, byte-level
property:

    Same canonical ReportEnvelope
                    │
        ┌───────────┴───────────┐
        │                       │
    render #1              render #2
        │                       │
        └───────  ==  ──────────┘   (byte-identical)
                    │
                    ▼
        Same signature.sha256

Scope
-----
- **Markdown**: byte-identical output for two calls on the same envelope.
- **STIX 2.1 bundle**: byte-identical canonical-JSON output for two calls.
- **Envelope signature**: `sign_report(env)` produces the same
  `signature.sha256` across two independent signings.
- **PDF**: intentionally not part of this gate. `reportlab` embeds a
  creation timestamp / xref table that is non-deterministic without a
  normalisation step; a follow-up ADR will define the PDF normaliser.
  This test declares that gap explicitly so we do NOT silently claim
  PDF determinism.

Non-goals
---------
- We do NOT re-run the whole pipeline; the input envelope is constructed
  directly. That isolates the renderers from any upstream nondeterminism
  (LLM narrate, clock, random) and makes THIS test a pure determinism
  contract test.
- We do NOT modify report semantics. If a future change to the schema
  regresses byte-stability, this test fails loud.

Reference: /app/memory/adr/0008-execution-plan-from-audit.md §5.5, §6, §10.
"""
from __future__ import annotations

import copy

import pytest


# Deferred so pytest can collect this file even when v2 module import
# chain is heavy on cold start.
def _make_envelope():
    from v2.report.schema import ReportEnvelope, ReportSection

    # Body shapes below match the concrete Markdown / STIX / PDF
    # renderer expectations (v2/report/markdown.py, stix.py, pdf.py).
    # Any drift here will fail this determinism gate loud — which is
    # exactly the CI contract we want.
    sections = [
        ReportSection(
            id="executive_summary",
            title="Executive Summary",
            order=1,
            narrative="Deterministic canonical report test envelope.",
            body={
                "verdict_counts": {"malicious": 0, "suspicious": 1, "benign": 0},
                "event_total": 1,
                "tactics": ["execution", "defense_evasion"],
            },
        ),
        ReportSection(
            id="case_metadata",
            title="Case Metadata",
            order=2,
            narrative="",
            body={
                "case_id": "det-case-001",
                "name": "Determinism gate case",
                "status": "closed",
                "created_at": "2026-08-11T00:00:00Z",
                "first_observed": "2026-08-11T00:00:00Z",
                "last_observed": "2026-08-11T00:00:00Z",
                "observation_count": 1,
                "tags": ["determinism", "gate"],
            },
        ),
        ReportSection(
            id="verdict_rollup",
            title="Verdict Rollup",
            order=3,
            narrative="Aggregate verdict derived from canonical evidence.",
            body={
                "counts": {"malicious": 0, "suspicious": 1, "benign": 0},
                "percentages": {"malicious": 0, "suspicious": 100, "benign": 0},
            },
        ),
        ReportSection(
            id="mitre_coverage",
            title="MITRE Coverage",
            order=4,
            narrative="",
            body={
                "tactics": [
                    {"id": "execution", "count": 2},
                    {"id": "defense_evasion", "count": 1},
                ],
                "techniques": [
                    {"id": "T1059.001", "count": 3},
                    {"id": "T1027", "count": 1},
                    {"id": "T1105", "count": 2},
                ],
            },
        ),
        ReportSection(
            id="process_ancestry",
            title="Process Ancestry",
            order=5,
            narrative="",
            body={
                "top_processes": [
                    {"process": "powershell.exe", "event_count": 3},
                ],
                "spawn_edges": [
                    {"parent": "explorer.exe", "children": ["powershell.exe"]},
                ],
            },
        ),
        ReportSection(
            id="top_entities",
            title="Top Entities",
            order=6,
            narrative="",
            body={
                "file":    [{"iid": "file:evil.dll", "count": 2}],
                "network": [{"iid": "net:1.2.3.4", "count": 1}],
            },
        ),
        ReportSection(
            id="chronological_timeline",
            title="Chronological Timeline",
            order=7,
            narrative="",
            body={
                "rows": [
                    {
                        "ts": "2026-08-11T00:00:00Z",
                        "lane": "process",
                        "action": "invoke",
                        "process": "powershell.exe",
                        "verdict": "SUSPICIOUS",
                        "mitre": ["T1059.001"],
                    }
                ]
            },
        ),
        ReportSection(
            id="commandline_decoding",
            title="Command-Line Decoding",
            order=8,
            narrative="",
            body={"decoded": [], "chain": []},
        ),
        ReportSection(
            id="enrichment",
            title="Enrichment",
            order=9,
            narrative="",
            body={"iocs": [], "reputation": {}},
        ),
        ReportSection(
            id="signature",
            title="Signature",
            order=10,
            narrative="",
            body={},
        ),
    ]

    # `generated_at` is FIXED here — the schema requires this to be
    # derived from observation timestamps, and the whole determinism
    # contract depends on that being a stable input.
    return ReportEnvelope(
        case_id="det-case-001",
        generated_at="2026-08-11T00:00:00Z",
        sections=sections,
    )


# ─── Tests ────────────────────────────────────────────────────────


def test_determinism_markdown_byte_identical():
    """Same envelope → same Markdown bytes across two calls."""
    from v2.report.markdown import render_markdown

    env1 = _make_envelope()
    env2 = _make_envelope()
    md1 = render_markdown(env1)
    md2 = render_markdown(env2)
    assert md1 == md2, "Markdown render is non-deterministic across two calls"
    assert isinstance(md1, str) and len(md1) > 0


def test_determinism_markdown_stable_across_deepcopy():
    """Deep-copying the envelope must not change the output bytes."""
    from v2.report.markdown import render_markdown

    env = _make_envelope()
    md1 = render_markdown(env)
    md2 = render_markdown(copy.deepcopy(env))
    assert md1 == md2


def test_determinism_stix_byte_identical():
    """Canonical STIX JSON bytes are byte-identical across two calls."""
    from v2.report.stix import render_stix_bytes

    env1 = _make_envelope()
    env2 = _make_envelope()
    b1 = render_stix_bytes(env1)
    b2 = render_stix_bytes(env2)
    assert b1 == b2, "STIX render is non-deterministic across two calls"
    assert b1.startswith(b"{") and b1.endswith(b"}")


def test_determinism_stix_deterministic_ids():
    """STIX ids are derived from stable seeds (case_id + generated_at)."""
    from v2.report.stix import render_stix

    b1 = render_stix(_make_envelope())
    b2 = render_stix(_make_envelope())
    ids1 = sorted(obj["id"] for obj in b1["objects"])
    ids2 = sorted(obj["id"] for obj in b2["objects"])
    assert ids1 == ids2


def test_determinism_signature_sha256_stable():
    """`sign_report` produces the same signature.sha256 across two signings."""
    from v2.report.hashing import canonical_json, report_hash, sign_report

    env1 = _make_envelope()
    env2 = _make_envelope()
    h1 = report_hash(env1)
    h2 = report_hash(env2)
    assert h1 == h2, "report_hash is non-deterministic"
    signed1 = sign_report(_make_envelope())
    signed2 = sign_report(_make_envelope())
    assert signed1.signature["sha256"] == signed2.signature["sha256"]
    # Canonical JSON is also byte-stable.
    assert canonical_json(env1) == canonical_json(env2)


def test_determinism_signature_matches_canonical_hash():
    """Signature must equal SHA-256 of canonical JSON with signature blanked."""
    import hashlib

    from v2.report.hashing import canonical_json, sign_report

    signed = sign_report(_make_envelope())
    # Rebuild the canonical JSON view of the signed envelope (signature
    # blanked per the contract) and hash it — must match.
    canonical = canonical_json(signed)
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert signed.signature["sha256"] == expected


def test_determinism_pdf_declared_out_of_scope():
    """PDF byte-determinism is deliberately excluded from this gate.

    reportlab embeds a creation timestamp / xref table; without a
    normaliser those bytes drift. This test documents the exclusion
    so no future contributor silently starts claiming PDF determinism.
    """
    # Sanity: importable, callable, produces bytes; we do NOT assert
    # byte-identity across renders.
    from v2.report.pdf import render_pdf

    env = _make_envelope()
    b1 = render_pdf(env)
    assert isinstance(b1, (bytes, bytearray)) and len(b1) > 0
    # Explicit contract of THIS gate — record it in the test:
    pytest.skip(
        "PDF byte-determinism intentionally out of scope for ADR-0008 "
        "determinism gate — needs a PDF normaliser (deferred to follow-up ADR)."
    )
