"""v2/ingestion — Investigation Ingestion Engine (Phase 4.1).

Pipeline (per operator spec, 2026-02):

    Upload
       │
       ▼
    Format Detection    (EVTX / JSON / CSV / XML / ZIP)
       │
       ▼
    Source Detection    (Sysmon / Windows Security / Generic)
       │
       ▼
    Normalizer          → Canonical Event Schema (CES)
       │
       ▼
    Evidence Store      (v2_shadow_observations · CEM v1 dict)
       │
       ▼
    Correlation → IKG → Investigation Workspace + Report

The Canonical Event Schema (CES) is the contract between ingestion
and every downstream investigation component. Everything downstream
consumes CES only — never a Sysmon XML, never a Win-Sec CSV, never
raw JSON. Add a new source by writing one normalizer.
"""
from .canonical import (
    CanonicalEventRecord, IngestionProvenance,
    CES_FIELDS, ces_to_cem_dict,
)
from .metrics import IngestionMetrics
from .pipeline import ingest_bytes, IngestionResult

__all__ = [
    "CanonicalEventRecord", "IngestionProvenance", "CES_FIELDS",
    "ces_to_cem_dict",
    "IngestionMetrics",
    "ingest_bytes", "IngestionResult",
]
