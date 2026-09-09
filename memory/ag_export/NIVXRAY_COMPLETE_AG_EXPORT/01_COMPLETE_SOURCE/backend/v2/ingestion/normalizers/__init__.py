"""v2/ingestion/normalizers · One module per source type.

Every normalizer is a pure function:
    normalize(data: bytes, *, provenance, metrics) -> Iterator[CanonicalEventRecord]

`data` is the RAW file bytes. Normalizers must:
    · Never raise on a single bad record — instead call
      `metrics.note_parse_error("…")` and skip it.
    · Never persist. Persistence happens in `pipeline.py`.
    · Never mutate `provenance`.
"""
from .sysmon_xml import normalize as normalize_sysmon_xml
from .windows_security import normalize as normalize_winsec_xml
from .json_canonical import normalize as normalize_json
from .csv_generic import normalize as normalize_csv

__all__ = [
    "normalize_sysmon_xml",
    "normalize_winsec_xml",
    "normalize_json",
    "normalize_csv",
]
