"""IUE — Input Understanding Engine package (Stage 1 · Lane A only).

Design authority:
  - `/app/memory/NivXRay_Stage1_STEP3_Compatibility.md`
  - `/app/memory/NivXRay_Stage1_STEP4_DataFlows.md`
  - `/app/memory/NivXRay_Stage1_STEP5_Regression.md`

This package is an orchestration seam, not a platform.  Every capability
delegates to an existing NivXRay owner (session/adapter, UAIE ledger,
canonical SSOT Provenance, DIE input_understanding, IDA input_classifier).

Feature flag
------------
`IUE_STRUCTURED_LANE=off` (default) — Lane A code paths are inert.  When
flipped `on`, structured logs (JSON/NDJSON/CSV/XML) walk the Collection
→ Parsing → Normalization → Aggregation → IUE chain.
"""
