"""Canonical Phase 1 investigation pipeline (locked 2026-08-01).

Every stage below the Investigation Graph consumes ONLY the graph —
never raw vendor payloads, never decoded strings.

Pipeline order (see ADR-2026-08-01_addendum_B_revised_pipeline.md):

    Input Classification → Parser → Vendor Detection → Vendor
    Normalization → CEM → Artifact Discovery → Recursive Decoder →
    Evidence Extraction → Investigation Graph → Evidence Validation
"""
