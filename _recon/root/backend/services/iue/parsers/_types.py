"""ParsedRecord — shared shape emitted by every Lane-A parser."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, List, Mapping

from canonical.ssot.models import Provenance
from .._prov import parse_prov


@dataclass(frozen=True)
class ParsedRecord:
    record_id: str
    source_file_id: str
    input_id: str
    tenant_id: str
    offset: int
    raw_fields: Mapping[str, Any]
    parser_name: str
    parse_status: str = "ok"           # ok | partial | malformed
    parse_errors: List[str] = field(default_factory=list)
    provenance: Provenance = field(
        default_factory=lambda: parse_prov("unknown"))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["raw_fields"] = dict(self.raw_fields)
        return d
