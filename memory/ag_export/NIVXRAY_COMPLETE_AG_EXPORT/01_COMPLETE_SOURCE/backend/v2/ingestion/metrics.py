"""v2/ingestion/metrics.py · Ingestion Quality Metrics.

Every upload produces one IngestionMetrics record so operators can see
exactly how faithfully the source normalized into CES.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class IngestionMetrics:
    ingest_job_id: str = ""
    case_id: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    files_uploaded: int = 0
    file_names: list[str] = field(default_factory=list)
    files_parsed: int = 0
    files_failed: int = 0
    detected_formats: dict[str, int] = field(default_factory=dict)  # {"xml": 3, "csv": 1}
    detected_sources: dict[str, int] = field(default_factory=dict)  # {"sysmon": 3, "windows_security": 1}
    events_parsed: int = 0
    events_normalized: int = 0
    events_persisted: int = 0
    unknown_event_ids: list[int] = field(default_factory=list)
    unsupported_fields: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    # Populated post-persist by the pipeline caller
    ikg_nodes: int = 0
    ikg_edges: int = 0
    workspace_generation_ms: float = 0.0

    def finish(self) -> "IngestionMetrics":
        self.finished_at = time.time()
        return self

    @property
    def duration_ms(self) -> float:
        end = self.finished_at or time.time()
        return round((end - self.started_at) * 1000.0, 2)

    @property
    def normalization_coverage(self) -> float:
        if self.events_parsed == 0:
            return 0.0
        return round(self.events_normalized / self.events_parsed * 100.0, 2)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["duration_ms"] = self.duration_ms
        d["normalization_coverage"] = self.normalization_coverage
        return d

    def note_unknown_event_id(self, eid: int) -> None:
        if eid not in self.unknown_event_ids:
            self.unknown_event_ids.append(eid)

    def note_unsupported_field(self, field_name: str) -> None:
        if field_name not in self.unsupported_fields:
            self.unsupported_fields.append(field_name)

    def note_parse_error(self, err: str) -> None:
        # Keep the collection tight — one entry per unique error string.
        if err not in self.parse_errors and len(self.parse_errors) < 50:
            self.parse_errors.append(err)
