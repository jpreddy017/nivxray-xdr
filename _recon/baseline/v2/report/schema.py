"""v2/report/schema.py · Deterministic Investigation Report envelope.

Frozen at R4 tag — see /app/memory/ARCHITECTURE_v2.md · Shared Contracts.
Every future adapter or egress consumer reads this envelope.
"""
from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "r4.0"

# Ten canonical section IDs. Adding a new section BUMPS the schema
# version; consumers pin to a schema major.
SectionId = Literal[
    "executive_summary",
    "case_metadata",
    "verdict_rollup",
    "mitre_coverage",
    "process_ancestry",
    "top_entities",
    "chronological_timeline",
    "commandline_decoding",
    "enrichment",
    "signature",
]


class ReportSection(BaseModel):
    """A single section of the investigation report."""
    id: SectionId
    title: str
    order: int
    body: dict[str, Any] = Field(default_factory=dict)
    # Text summary for humans — Markdown rendering uses this as the
    # human-readable prose above the JSON block.
    narrative: str = ""


class ReportEnvelope(BaseModel):
    """The canonical, hash-stable report envelope.

    `signature.sha256` is computed by hashing the CANONICAL JSON of
    every field EXCEPT `signature` itself, so two runs on identical
    inputs produce byte-identical `sha256` values.
    """
    schema_version: str = REPORT_SCHEMA_VERSION
    case_id: str
    generated_at: str            # ISO-8601 · derived from observation timestamps only
    generator: str = "nivxray.v2.report"
    generator_version: str = "1.0.0"
    sections: list[ReportSection]
    signature: dict[str, str] = Field(default_factory=dict)
