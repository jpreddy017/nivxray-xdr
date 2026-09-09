"""Shared parser-error helpers.

Consolidates the ~5 malformed-record branches each parser had into a
single ``malformed_record()`` factory that also stamps the correct
Provenance for the parser.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from canonical.ssot.models import Provenance
from ._types import ParsedRecord
from .._prov import parse_prov


def record_id(source_file_id: str, offset: int) -> str:
    return hashlib.sha256(
        f"{source_file_id}:{offset}".encode()).hexdigest()[:24]


def malformed_record(*, raw, parser_name: str, offset: int,
                       error: str,
                       upstream: Optional[Provenance] = None
                       ) -> ParsedRecord:
    """Return a ParsedRecord with parse_status='malformed' carrying
    ``error`` in ``parse_errors``.  Every parser MUST use this helper
    so failure-envelope shape is uniform."""
    rid = record_id(raw.source_file_id, offset)
    return ParsedRecord(
        record_id=rid,
        source_file_id=raw.source_file_id,
        input_id=raw.input_id,
        tenant_id=raw.tenant_id,
        offset=offset,
        raw_fields={},
        parser_name=parser_name,
        parse_status="malformed",
        parse_errors=[error],
        provenance=parse_prov(parser_name,
                               upstream=upstream or raw.provenance,
                               own_id=rid),
    )


def ok_record(*, raw, parser_name: str, offset: int,
                raw_fields: dict,
                parse_errors: Optional[list] = None) -> ParsedRecord:
    """Return a well-formed ParsedRecord with the parser's provenance."""
    rid = record_id(raw.source_file_id, offset)
    return ParsedRecord(
        record_id=rid,
        source_file_id=raw.source_file_id,
        input_id=raw.input_id,
        tenant_id=raw.tenant_id,
        offset=offset,
        raw_fields=raw_fields,
        parser_name=parser_name,
        parse_errors=list(parse_errors or []),
        provenance=parse_prov(parser_name,
                               upstream=raw.provenance,
                               own_id=rid),
    )
