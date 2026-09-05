"""
IDA · Intelligent Document Analyzer
────────────────────────────────────
Frozen 2026-03-01 as the P0 investigation-pipeline engine (see
`/app/memory/IDA_ARCHITECTURE.md`).

IDA is the universal Content Acquisition + Document Intelligence
engine.  It sits on the same tier as DIE — where DIE decodes
encoded payloads, IDA acquires and interprets external / structured
/ human-readable content and writes every artifact into the
Canonical Investigation Object (SSOT).

Slice 1 (2026-03-01) landed in this package:
  · `input_classifier`   IDA-1 · extended input-type recognition
  · `artifact_splitter`  IDA-2 · mixed-artifact decomposition

Later slices (IDA-3 URL Fetcher, IDA-3.5 Content Understanding,
IDA-4 Threat Report Extractor, …) plug in alongside these modules
and continue to write only into the SSOT — never into the UI
directly (Rule R14).
"""
from .artifact_splitter import split_artifacts, Artifact  # noqa: F401
from .input_classifier import classify_artifact_input     # noqa: F401
from .url_intent import classify_url_intent                # noqa: F401
from .acquisition import acquire_url, AcquiredResource     # noqa: F401
from .report_extractors import understand_document, extract_all  # noqa: F401
from .artifact_router import (
    investigate_all as investigate_all_artifacts,           # noqa: F401
    merge_into_ssot as merge_artifact_investigations,       # noqa: F401
)
