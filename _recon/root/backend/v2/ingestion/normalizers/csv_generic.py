"""v2/ingestion/normalizers/csv_generic.py · CSV → CES.

Accepts any CSV with a header row. The header names are matched against
the CES aliases from the JSON normalizer (case-insensitive, whitespace-
trimmed). Rows that do not carry at least a `timestamp` are counted as
`unsupported_fields` and skipped.
"""
from __future__ import annotations
import csv
import io
from typing import Iterator

from ..canonical import CanonicalEventRecord, IngestionProvenance
from .json_canonical import _FIELD_ALIASES, _TS_ALIASES, _PROVIDER_ALIASES, _EID_ALIASES

NORMALIZER_ID = "csv_generic@1.0"


def _pick(row: dict, aliases: tuple[str, ...]) -> str:
    for k in aliases:
        for cand in (k, k.lower(), k.upper()):
            v = row.get(cand)
            if v not in (None, ""):
                return str(v).strip()
    return ""


def _pick_int(row: dict, aliases: tuple[str, ...]) -> int | None:
    s = _pick(row, aliases)
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def normalize(data: bytes, *,
              provenance: IngestionProvenance,
              metrics=None) -> Iterator[CanonicalEventRecord]:
    text = data.decode("utf-8", errors="ignore")
    if not text:
        return
    prov = IngestionProvenance(**{**provenance.to_dict(),
                                   "normalizer": NORMALIZER_ID,
                                   "format": "csv",
                                   "source": provenance.source or "generic_csv"})
    reader = csv.DictReader(io.StringIO(text))
    # Normalise headers → strip whitespace + lower-case
    if reader.fieldnames:
        reader.fieldnames = [(fn or "").strip() for fn in reader.fieldnames]
    for row in reader:
        try:
            # Normalise keys — accept any case
            lc_row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            ts = _pick(lc_row, _TS_ALIASES)
            if not ts:
                if metrics is not None:
                    metrics.note_unsupported_field("timestamp")
                continue
            r = CanonicalEventRecord(
                timestamp=ts,
                provider=_pick(lc_row, _PROVIDER_ALIASES),
                event_id=_pick_int(lc_row, _EID_ALIASES),
                raw_event=dict(lc_row),
                provenance=prov,
            )
            for target, aliases in _FIELD_ALIASES.items():
                setattr(r, target, _pick(lc_row, aliases))
            yield r
        except Exception as ex:
            if metrics is not None:
                metrics.note_parse_error(f"csv:{type(ex).__name__}:{ex!s:.80}")
