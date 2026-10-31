"""v2/ingestion/normalizers/json_canonical.py · JSON / NDJSON → CES.

Two accepted shapes:
    1. Canonical CES — a JSON object or array whose keys exactly match
       CES_FIELDS. This is the recommended interchange format.
    2. Loose JSON — any dict that carries a `timestamp` (or `ts`/`@timestamp`)
       key plus a `provider` (or `channel`) hint. Missing fields default
       to empty strings — the pipeline downstream degrades gracefully.

Both shapes accept an outer `{"events": [...]}` wrapper (as many EDR
exports use it).
"""
from __future__ import annotations
import json
from typing import Iterator, Any

from ..canonical import CanonicalEventRecord, IngestionProvenance, CES_FIELDS

NORMALIZER_ID = "json_canonical@1.0"

_TS_ALIASES = ("timestamp", "ts", "@timestamp", "utcTime", "eventTime")
_PROVIDER_ALIASES = ("provider", "channel", "provider_name", "source_name")
_EID_ALIASES = ("event_id", "eventID", "EventID", "id")

_FIELD_ALIASES = {
    "computer":            ("computer", "hostname", "host", "endpoint_name"),
    "user":                ("user", "userName", "user_name", "TargetUserName", "SubjectUserName"),
    "sid":                 ("sid", "userSid", "user_sid", "TargetUserSid"),
    "logon_id":            ("logon_id", "logonId", "TargetLogonId"),
    "process_guid":        ("process_guid", "ProcessGuid", "processGuid"),
    "process_id":          ("process_id", "ProcessId", "processId", "pid"),
    "parent_process_guid": ("parent_process_guid", "ParentProcessGuid"),
    "parent_process_id":   ("parent_process_id", "ParentProcessId", "ppid"),
    "parent_image":        ("parent_image", "ParentImage", "parentImage"),
    "image":               ("image", "Image", "processImage", "path"),
    "command_line":        ("command_line", "CommandLine", "commandLine", "cmdline"),
    "current_directory":   ("current_directory", "CurrentDirectory", "cwd"),
    "file_path":           ("file_path", "TargetFilename", "targetFilename", "file"),
    "file_hash_sha256":    ("file_hash_sha256", "sha256", "SHA256"),
    "file_hash_md5":       ("file_hash_md5", "md5", "MD5"),
    "file_hash_sha1":      ("file_hash_sha1", "sha1", "SHA1"),
    "registry_key":        ("registry_key", "TargetObject", "registryKey"),
    "registry_value":      ("registry_value", "Details"),
    "src_ip":              ("src_ip", "SourceIp", "sourceIp"),
    "src_port":            ("src_port", "SourcePort", "sourcePort"),
    "dst_ip":              ("dst_ip", "DestinationIp", "destinationIp"),
    "dst_port":            ("dst_port", "DestinationPort", "destinationPort"),
    "protocol":            ("protocol", "Protocol"),
    "dns_query":           ("dns_query", "QueryName", "queryName"),
    "dns_answer":          ("dns_answer", "QueryResults"),
    "url":                 ("url", "URL", "Uri"),
    "service":             ("service", "Service", "ServiceName"),
    "task_name":           ("task_name", "TaskName"),
    "logon_type":          ("logon_type", "LogonType"),
}


def _first(record: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = record.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def _first_int(record: dict, keys: tuple[str, ...]) -> int | None:
    for k in keys:
        v = record.get(k)
        if v in (None, ""):
            continue
        try:
            return int(v)
        except (ValueError, TypeError):
            return None
    return None


def _iter_records(data: bytes) -> Iterator[dict]:
    text = data.decode("utf-8", errors="ignore").strip()
    if not text:
        return
    # NDJSON path (line-delimited)
    if "\n" in text and not text.startswith("["):
        # Skip if it's a single JSON object spread over multiple lines
        first_line = text.splitlines()[0].strip()
        if first_line.endswith("}") or first_line.endswith("]"):
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, list):
                    yield from (o for o in obj if isinstance(o, dict))
                elif isinstance(obj, dict):
                    yield obj
            return
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return
    if isinstance(parsed, list):
        yield from (o for o in parsed if isinstance(o, dict))
    elif isinstance(parsed, dict):
        # Common wrappers
        for k in ("events", "records", "data", "batch"):
            v = parsed.get(k)
            if isinstance(v, list):
                yield from (o for o in v if isinstance(o, dict))
                return
        yield parsed


def normalize(data: bytes, *,
              provenance: IngestionProvenance,
              metrics=None) -> Iterator[CanonicalEventRecord]:
    prov = IngestionProvenance(**{**provenance.to_dict(),
                                   "normalizer": NORMALIZER_ID,
                                   "format": "json",
                                   "source": provenance.source or "canonical"})
    for rec in _iter_records(data):
        try:
            r = CanonicalEventRecord(
                timestamp=_first(rec, _TS_ALIASES),
                provider=_first(rec, _PROVIDER_ALIASES),
                event_id=_first_int(rec, _EID_ALIASES),
                channel=str(rec.get("channel", "")),
                raw_event=rec,
                provenance=prov,
            )
            for target, aliases in _FIELD_ALIASES.items():
                setattr(r, target, _first(rec, aliases))
            yield r
        except Exception as ex:
            if metrics is not None:
                metrics.note_parse_error(f"json:{type(ex).__name__}:{ex!s:.80}")
