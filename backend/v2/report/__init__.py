"""v2/report · Deterministic Investigation Report Generator (R4).

Given a `case_id`, this module composes a canonical, hash-stable
investigation report from the shared CEM store. Same inputs always
produce the same output — the report SHA-256 is deterministic.

The report is the CANONICAL OUTPUT of the platform. Every Mode B UI
screen is a projection of it; every Mode A egress payload is a
serialisation of it. See /app/memory/ARCHITECTURE_v2.md appendix.

Public API:
    - build_report(db, case_id) -> ReportEnvelope   # async
    - render_markdown(report)  -> str               # pure
    - report_hash(report)       -> str               # pure

Zero RC5 imports. All I/O is scoped to v2_* collections.
"""
from __future__ import annotations
from .schema import ReportEnvelope, ReportSection, REPORT_SCHEMA_VERSION
from .builder import build_report
from .markdown import render_markdown
from .hashing import report_hash

__all__ = [
    "ReportEnvelope", "ReportSection", "REPORT_SCHEMA_VERSION",
    "build_report", "render_markdown", "report_hash",
]
