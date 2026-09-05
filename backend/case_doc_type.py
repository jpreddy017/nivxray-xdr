"""NivXRay XDR · `workspace_cases` document-type discriminator.

P0-1 (owner-authorised 2026-09-05).  `workspace_cases` is the ratified
authoritative case/incident store.  It carries two legitimate document
kinds that were previously distinguished only implicitly, per-reader:

    DOC_TYPE_XDR_INCIDENT   — created by the canonical XDR pipeline
                              (`detection_content/xdr_incident.py`)
    DOC_TYPE_ANALYSIS_CASE  — created by the artifact-analysis path
                              (`routers/cases.py::save_case`)

Classification is DETERMINISTIC and evaluated in strict order.  A document
that satisfies no rule is NOT guessed at — it resolves to
`DOC_TYPE_UNCLASSIFIED`, which is an honest admission, not a claim.

Census at ratification time (live, 484 docs):
    R1 xdr_incident    198
    R2 analysis_case   209
    R3 analysis_case    76
    R4 unclassified      1   (`inc_r381_empty` — a test fixture)
                       ---
                       484
"""
from __future__ import annotations

from typing import Any, Mapping

DOC_TYPE_FIELD = "doc_type"
DOC_TYPE_REASON_FIELD = "doc_type_reason"

DOC_TYPE_XDR_INCIDENT = "xdr_incident"
DOC_TYPE_ANALYSIS_CASE = "analysis_case"
DOC_TYPE_UNCLASSIFIED = "unclassified"


def classify(doc: Mapping[str, Any]) -> tuple[str, str]:
    """Return `(doc_type, rule_id)` for a `workspace_cases` document.

    Rules are mutually exclusive and evaluated in order.  Pure function:
    no I/O, no clock, no randomness — the same document always yields the
    same answer.
    """
    if "xdr_pipeline" in doc:
        # Only `xdr_incident.materialise_incident` writes this envelope.
        return DOC_TYPE_XDR_INCIDENT, "R1:xdr_pipeline"
    if "ssot" in doc:
        # SSOT bundle is written only by the artifact-analysis save path.
        return DOC_TYPE_ANALYSIS_CASE, "R2:ssot"
    if "input" in doc:
        # Pre-SSOT analysis case: carries the analysed artifact itself.
        return DOC_TYPE_ANALYSIS_CASE, "R3:input"
    return DOC_TYPE_UNCLASSIFIED, "R4:no-discriminating-field"


def is_ambiguous(doc: Mapping[str, Any]) -> bool:
    """True when classification is undecidable from the document alone."""
    return classify(doc)[0] == DOC_TYPE_UNCLASSIFIED
