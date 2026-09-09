"""Lane-C artifact parser — one artifact envelope → 1+ ParsedRecord.

Contract:
  - Emits exactly ONE PRIMARY record (offset=0) carrying the artifact
    identity (artifact_type, display_name, sha256/md5/sha1, filename,
    size, detected_by, confidence).
  - Emits ZERO or more CHILD records (offset=1..N) for embedded IOCs
    or high-value static-analysis fields surfaced by the artifact
    analyser (e.g. embedded URLs from a PDF, hashes from an OLE file).
    Each child record still carries the parent's source_file_id so
    aggregation & correlation see the lineage.

Every raw_field dict uses vendor-neutral keys.  The dictionary layer
in ``services.iue.normalizers.field_map`` maps these keys onto the
canonical.artifact.* / canonical.file.* namespace.
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, List

from ._errors import malformed_record, ok_record
from ._types import ParsedRecord


# Fields inside AnalysisResult.analysis that carry IOC-flavoured
# child evidence worth surfacing as separate records.
_ANALYSIS_CHILD_KEYS = (
    "urls",
    "domains",
    "ips",
    "hashes",           # embedded hashes discovered inside the artifact
    "embedded_files",
    "macros",
    "js_actions",
    "javascript",
    "openaction",
    "shellcodes",
)


def _primary_record_fields(raw) -> Dict[str, Any]:
    """Build the raw_fields dict for the artifact's primary record."""
    disp = raw.artifact_dispatch or {}
    hashes = disp.get("hashes") or {}
    fields: Dict[str, Any] = {
        "artifact_type":        disp.get("artifact_type") or "unknown",
        "artifact_display_name": disp.get("display_name") or "Unknown Artifact",
        "confidence":           disp.get("confidence") or 0,
        "detected_by":          disp.get("detected_by") or "",
        "capability_available": bool(disp.get("capability_available")),
        "file_name":            raw.filename or "",
        "file_size":            disp.get("size") or len(raw.bytes_ or b""),
        "file_mime":            raw.mime or "application/octet-stream",
        "file_sha256":          (hashes.get("sha256") or "").lower(),
        "file_md5":             (hashes.get("md5") or "").lower(),
        "file_sha1":            (hashes.get("sha1") or "").lower(),
    }
    fallback = disp.get("fallback_reason")
    if fallback:
        fields["fallback_reason"] = fallback
    # Preserve a bounded copy of the static analysis for the wire.
    # NOTE: this stays SMALL — heavy fields (raw macros / disassembly)
    # are the analyser's responsibility to trim.
    analysis = disp.get("analysis") or {}
    if isinstance(analysis, dict):
        fields["analysis_available"] = bool(analysis.get("available", True))
        for k, v in analysis.items():
            if k in ("available",):
                continue
            if k in _ANALYSIS_CHILD_KEYS:
                continue
            # Keep only small scalars / short strings — the parser
            # does not need to carry every last field the analyser
            # emitted.  The full dispatch dict is still on the raw
            # payload envelope for anyone who needs the detail.
            if isinstance(v, (bool, int, float)):
                fields[f"analysis.{k}"] = v
            elif isinstance(v, str) and len(v) <= 512:
                fields[f"analysis.{k}"] = v
    return fields


def _child_records(raw, offset_start: int) -> List[Dict[str, Any]]:
    """Extract child raw_fields dicts for embedded IOCs / high-value
    static-analysis surfaces.  Deterministic ordering (kind then value).
    """
    disp = raw.artifact_dispatch or {}
    analysis = disp.get("analysis") or {}
    if not isinstance(analysis, dict):
        return []

    children: List[Dict[str, Any]] = []
    for key in _ANALYSIS_CHILD_KEYS:
        vals = analysis.get(key)
        if not vals:
            continue
        if not isinstance(vals, (list, tuple, set)):
            continue
        # Deterministic order.
        for v in sorted({x for x in vals if isinstance(x, (str, int, float))},
                        key=lambda x: str(x)):
            fields: Dict[str, Any] = {
                "artifact_child_kind": key,
                "artifact_child_value": v,
                "parent_artifact_type": disp.get("artifact_type") or "unknown",
                "parent_file_sha256":  (disp.get("hashes") or {}).get("sha256") or "",
            }
            # Route the value into a canonical bucket the field-map
            # dictionary already understands.
            if key in ("urls",):
                fields["url"] = v
            elif key in ("domains",):
                fields["domain"] = v
            elif key in ("ips",):
                fields["src_ip"] = v          # dictionary alias for canonical.source.ip
            elif key == "hashes":
                sv = str(v)
                if len(sv) == 64:
                    fields["sha256"] = sv
                elif len(sv) == 40:
                    fields["sha1"] = sv
                elif len(sv) == 32:
                    fields["md5"] = sv
            children.append(fields)
    return children


def iter_records(raw) -> Iterator[ParsedRecord]:
    """Yield exactly ONE primary + N child ParsedRecords for a
    FileRawPayload.  Never raises — malformed dispatch → single
    malformed record so the failure envelope is uniform.
    """
    if raw is None or not getattr(raw, "artifact_dispatch", None):
        yield malformed_record(raw=raw, parser_name="artifact",
                                 offset=0,
                                 error="empty artifact dispatch")
        return

    # PRIMARY
    yield ok_record(raw=raw, parser_name="artifact", offset=0,
                     raw_fields=_primary_record_fields(raw))

    # CHILDREN
    for i, cfields in enumerate(_child_records(raw, offset_start=1), start=1):
        yield ok_record(raw=raw, parser_name="artifact",
                         offset=i, raw_fields=cfields)
