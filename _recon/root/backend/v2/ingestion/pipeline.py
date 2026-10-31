"""v2/ingestion/pipeline.py · Orchestrator.

Wires: FormatDetector → SourceDetector → Normalizer → CES → CEM →
Mongo persist → IngestionMetrics. One entry point:

    result = await ingest_bytes(db, data, filename, case_id)

Also exposes a synchronous helper `normalize_bytes(...)` used by
tests and the golden-corpus round-trip.
"""
from __future__ import annotations

import io
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .canonical import CanonicalEventRecord, IngestionProvenance, ces_to_cem_dict
from .format_detector import detect_format
from .source_detector import (
    detect_source,
    SOURCE_SYSMON, SOURCE_WINDOWS_SECURITY,
    SOURCE_CANONICAL_JSON, SOURCE_GENERIC_CSV, SOURCE_UNKNOWN,
)
from .metrics import IngestionMetrics
from . import normalizers as N
from v2.case_engine.schema import COLLECTIONS


@dataclass
class IngestionResult:
    ok: bool = True
    ingest_job_id: str = ""
    case_id: str = ""
    metrics: IngestionMetrics = field(default_factory=IngestionMetrics)
    workspace_url: str = ""       # relative path for the frontend to jump to
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "ingest_job_id": self.ingest_job_id,
            "case_id": self.case_id,
            "workspace_url": self.workspace_url,
            "error": self.error,
            "metrics": self.metrics.to_dict(),
        }


# ─── Pure sync layer (unit-testable) ─────────────────────────────────
def _pick_normalizer(source: str, fmt: str):
    """Return the normalize() function for a given (source, format)."""
    if source == SOURCE_SYSMON and fmt == "xml":
        return N.normalize_sysmon_xml
    if source == SOURCE_WINDOWS_SECURITY and fmt == "xml":
        return N.normalize_winsec_xml
    if source in (SOURCE_CANONICAL_JSON,) and fmt in ("json", "ndjson"):
        return N.normalize_json
    if fmt in ("json", "ndjson"):
        # Fall back to canonical JSON normalizer for unknown JSON sources
        return N.normalize_json
    if fmt == "csv":
        return N.normalize_csv
    if fmt == "xml":
        # Windows Security is the safer default for unknown Win-event XML.
        return N.normalize_winsec_xml
    return None


def normalize_bytes(data: bytes, filename: str, *,
                    metrics: IngestionMetrics,
                    ingest_job_id: str) -> list[CanonicalEventRecord]:
    """Detect format+source, run the appropriate normalizer, and return
    a list of CES records. Pure — no I/O."""
    if not data:
        return []
    fmt = detect_format(data, filename=filename)
    metrics.detected_formats[fmt] = metrics.detected_formats.get(fmt, 0) + 1

    if fmt == "zip":
        return _normalize_zip(data, filename, metrics=metrics,
                              ingest_job_id=ingest_job_id)

    src = detect_source(data, fmt=fmt, filename=filename)
    metrics.detected_sources[src] = metrics.detected_sources.get(src, 0) + 1

    normalizer = _pick_normalizer(src, fmt)
    if normalizer is None:
        metrics.note_parse_error(f"no-normalizer:format={fmt}:source={src}")
        metrics.files_failed += 1
        return []

    prov = IngestionProvenance(
        origin="customer-upload",
        format=fmt, source=src, filename=filename,
        ingest_job_id=ingest_job_id,
        ingested_at=datetime.now(timezone.utc).isoformat(),
    )

    out: list[CanonicalEventRecord] = []
    for rec in normalizer(data, provenance=prov, metrics=metrics):
        out.append(rec)
        metrics.events_parsed += 1
        if rec.timestamp:
            metrics.events_normalized += 1
    metrics.files_parsed += 1
    return out


def _normalize_zip(data: bytes, filename: str, *,
                   metrics: IngestionMetrics,
                   ingest_job_id: str) -> list[CanonicalEventRecord]:
    """Extract every member of a ZIP archive and dispatch to normalize_bytes."""
    records: list[CanonicalEventRecord] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.infolist():
                if member.is_dir() or member.file_size <= 0:
                    continue
                try:
                    sub_data = zf.read(member.filename)
                except Exception as ex:
                    metrics.note_parse_error(f"zip:{member.filename}:{ex!s:.80}")
                    continue
                metrics.file_names.append(member.filename)
                records.extend(normalize_bytes(sub_data, member.filename,
                                               metrics=metrics,
                                               ingest_job_id=ingest_job_id))
    except zipfile.BadZipFile as ex:
        metrics.note_parse_error(f"zip:BadZipFile:{ex!s:.80}")
    return records


# ─── Async persist layer (Mongo) ─────────────────────────────────────
async def _persist_case(db: Any, case_id: str, name: str) -> None:
    await db[COLLECTIONS["cases"]].update_one(
        {"_id": case_id},
        {"$setOnInsert": {
            "_id":         case_id,
            "case_id":     case_id,
            "name":        name,
            "status":      "open",
            "tags":        ["ingested", "phase4"],
            "created_at":  datetime.now(timezone.utc),
            "created_by":  "ingestion-pipeline",
            "event_count": 0,
            "entity_count":0,
        }},
        upsert=True,
    )


async def _persist_events(db: Any, case_id: str,
                          records: Iterable[CanonicalEventRecord],
                          *, ingest_job_id: str) -> int:
    """Bulk insert CES → CEM v1 dicts into v2_shadow_observations.

    Returns the count actually inserted.
    """
    coll = db[COLLECTIONS["shadow_observations"]]
    await coll.create_index([("input_sha256", 1)], name="shadow_input_sha")
    await coll.create_index([("adapter", 1), ("captured_at", -1)],
                             name="shadow_adapter_ts")

    docs: list[dict[str, Any]] = []
    for idx, rec in enumerate(records):
        ev = ces_to_cem_dict(rec, case_id=case_id, sequence=idx)
        docs.append({
            "adapter":       ev["adapter"],
            "cem_version":   "v1",
            "case_id":       case_id,
            "captured_at":   ev["ts"],
            "kind":          ev["kind"],
            "process_iid":   ev.get("process_iid"),
            "artefacts_iids":list(ev.get("artefacts_iids") or ()),
            "input_sha256":  (ev.get("raw") or {}).get("sha256"),
            "event":         ev,
            "ingest_job_id": ingest_job_id,
        })
    if not docs:
        return 0
    # Insert in chunks to keep the payload reasonable
    inserted = 0
    for i in range(0, len(docs), 500):
        chunk = docs[i:i+500]
        res = await coll.insert_many(chunk, ordered=False)
        inserted += len(res.inserted_ids)
    return inserted


async def ingest_bytes(db: Any, data: bytes, filename: str, *,
                       case_id: str | None = None,
                       case_name: str | None = None) -> IngestionResult:
    """Full pipeline: bytes → CES → Mongo → IngestionResult."""
    job_id = f"ing_{uuid.uuid4().hex[:12]}"
    cid = case_id or f"case_ingested_{uuid.uuid4().hex[:12]}"
    name = case_name or f"Ingested · {filename or 'upload'}"

    metrics = IngestionMetrics(ingest_job_id=job_id, case_id=cid, started_at=time.time())
    metrics.files_uploaded = 1
    metrics.file_names.append(filename or "upload")

    try:
        records = normalize_bytes(data, filename or "upload",
                                   metrics=metrics, ingest_job_id=job_id)
        await _persist_case(db, cid, name)
        persisted = await _persist_events(db, cid, records, ingest_job_id=job_id)
        metrics.events_persisted = persisted
    except Exception as ex:
        metrics.note_parse_error(f"pipeline:{type(ex).__name__}:{ex!s:.120}")
        metrics.finish()
        return IngestionResult(ok=False, ingest_job_id=job_id, case_id=cid,
                               metrics=metrics, error=str(ex))

    metrics.finish()
    return IngestionResult(
        ok=True,
        ingest_job_id=job_id,
        case_id=cid,
        metrics=metrics,
        workspace_url=f"/v2/case/{cid}",
    )
