"""Read-only, bounded file observations; reuse the canonical file identity adapter.

The cursor walks source records by Mongo _id, NOT by event time. Time and
file filters are evaluated after the bounded scan to tolerate historical
timestamp dialects without reclassifying a process image as a file.
No writes, collection migrations, sensor changes or invented prevalence.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone

from edr_plane.file_identity import from_observation

STORE = "v2_shadow_observations"
SCAN_LIMIT = 1000
MAX_WINDOW_MS = 31 * 86400000
HASH_LENGTHS = {"sha256": 64, "sha1": 40, "md5": 32}


class InvalidFileQuery(ValueError):
    pass


def validate_query(endpoint_id, time_start, time_end, key_type="path", key="", limit=100):
    if not isinstance(endpoint_id, str) or not endpoint_id.strip() or len(endpoint_id) > 512:
        raise InvalidFileQuery("An endpoint identifier is required")
    if (type(time_start) is not int or type(time_end) is not int
            or not 0 <= time_start < time_end <= 253402300799000
            or time_end - time_start > MAX_WINDOW_MS):
        raise InvalidFileQuery("Use an increasing UTC window of at most 31 days")
    if type(limit) is not int or not 1 <= limit <= 200:
        raise InvalidFileQuery("limit must be between 1 and 200")
    if key_type not in ("path", "name", "sha256") or not isinstance(key, str) or len(key) > 4096:
        raise InvalidFileQuery("Invalid file filter")
    if key_type == "sha256" and key and not re.fullmatch(r"[a-fA-F0-9]{64}", key):
        raise InvalidFileQuery("SHA-256 must contain exactly 64 hexadecimal characters")
    return dict(endpoint_id=endpoint_id.strip(), time_start=time_start,
                time_end=time_end, key_type=key_type, key=key, limit=limit)


def _context(query, tenant_id):
    # Binding is a consistency check, NOT authorization. Every read still
    # uses the authoritative endpoint resolver and tenant predicate.
    return hashlib.sha256(json.dumps([tenant_id, query], sort_keys=True).encode()).hexdigest()


def encode_cursor(after, query, tenant_id):
    return base64.urlsafe_b64encode(json.dumps(
        {"v": 1, "after": str(after), "context": _context(query, tenant_id)},
        separators=(",", ":")).encode()).decode().rstrip("=")


def decode_cursor(cursor, query, tenant_id):
    if not cursor:
        return None
    try:
        if not isinstance(cursor, str) or len(cursor) > 512:
            raise ValueError()
        obj = json.loads(base64.b64decode(cursor + "=" * (-len(cursor) % 4),
                                        altchars=b"-_", validate=True))
        if (obj.get("v") != 1 or obj.get("context") != _context(query, tenant_id)
                or not re.fullmatch(r"[a-f0-9]{24}", obj.get("after", ""))):
            raise ValueError()
        return obj["after"]
    except (ValueError, TypeError, AttributeError, UnicodeError) as exc:
        raise InvalidFileQuery("Cursor is invalid or belongs to a different query") from exc


def _millis(value):
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError, OverflowError):
        return None


def project(doc, query):
    try:
        obs = from_observation(doc)
    except (AttributeError, TypeError, ValueError):
        return None, "FILE_RECORD_UNREADABLE"
    if obs is None:
        return None, None
    stamp = _millis(obs.observed_at)
    if stamp is None:
        return None, "FILE_TIME_UNRESOLVED"
    if not query["time_start"] <= stamp < query["time_end"]:
        return None, None
    row = asdict(obs)
    # Discard malformed source digests; never substitute event.raw.sha256
    # (payload integrity) or process-image hashes.
    original_hashes = row["hashes"]
    row["hashes"] = {k: v for k, v in original_hashes.items()
                     if k in HASH_LENGTHS and re.fullmatch(
                         r"[a-fA-F0-9]{%d}" % HASH_LENGTHS[k], v)}
    if row["hashes"] != original_hashes:
        row["file_key"] = None  # never keep a key derived from a rejected digest
    if row["hashes"].get("sha256"):
        row["identity_basis"] = "CONTENT_IDENTITY_SHA256"
    elif row["hashes"]:
        row["identity_basis"] = "CONTENT_IDENTITY_NON_SHA256_ONLY"
    else:
        row["identity_basis"] = "PATH_IDENTITY_ONLY"
        row["file_key"] = None  # do not retain a key derived from an invalid hash
    row["hash_state"] = "HASH_OBSERVED" if row["hashes"] else "HASH_NOT_OBSERVED"
    key = query["key"]
    if key:
        field = row["hashes"].get("sha256", "") if query["key_type"] == "sha256" else row[query["key_type"]]
        if query["key_type"] == "sha256":
            field, key = field.lower(), key.lower()
        if field != key:
            return None, None
    row["record_id"] = str(doc["_id"])
    row["observed_at"] = datetime.fromtimestamp(stamp / 1000, timezone.utc).isoformat()
    row["assessment"] = "NOT_ASSESSED"  # absence of a finding is never a clean verdict
    return row, None


def scan_page(documents, query, tenant_id):
    """Consume at most SCAN_LIMIT records; resume at the last CONSUMED row.

    A page can contain zero file matches and still have a next cursor.
    That is an incomplete scan, never an empty-evidence conclusion.
    """
    rows, issues, last = [], {}, None
    consumed = 0
    more = False
    iterator = iter(documents)
    for doc in iterator:
        if consumed >= SCAN_LIMIT or len(rows) >= query["limit"]:
            more = True
            break
        last = doc["_id"]
        consumed += 1
        row, issue = project(doc, query)
        if issue:
            issues[issue] = issues.get(issue, 0) + 1
        if row:
            rows.append(row)
    return {
        "state": "FILE_OBSERVATIONS" if rows else ("SCAN_INCOMPLETE" if more else "NO_MATCHING_FILE_OBSERVATIONS"),
        "observations": rows, "scanned_records": consumed,
        "next_cursor": encode_cursor(last, query, tenant_id) if more else None,
        "complete": not more, "issues": issues,
        "coverage": "NOT_PROVEN", "order": "SOURCE_RECORD_ID_DESC",
        "window": {"start_ms": query["time_start"], "end_ms": query["time_end"], "end_exclusive": True},
        "note": "Recorded file observations, not a live disk inventory. Empty results do not prove no file activity. Name/path matches do not prove identical content. Earliest loaded observation is not the origin of a threat.",
    }


def read_page(collection, resolution, query, tenant_id, cursor=None):
    from bson import ObjectId
    after = decode_cursor(cursor, query, tenant_id)
    predicate = resolution.predicate(STORE)
    # Defensive: the resolver must bind THIS customer, not another tenant.
    if str(resolution.identity.get("tenant_id") or "") != tenant_id:
        raise InvalidFileQuery("Endpoint customer could not be established")
    if after:
        predicate = {"$and": [predicate, {"_id": {"$lt": ObjectId(after)}}]}
    projection = {"_id": 1, "event": 1, "captured_at": 1,
                  "tenant_id": 1, "connector_id": 1, "collector_id": 1,
                  "observation_id": 1, "canonical_event_id": 1}
    docs = collection.find(predicate, projection).sort("_id", -1).limit(SCAN_LIMIT + 1).max_time_ms(3000)
    try:
        result = scan_page(docs, query, tenant_id)
    finally:
        docs.close()
    from services.edr.file_context import enrich
    enrich(collection, resolution.predicate(STORE), result["observations"], query)
    result["identity"] = resolution.descriptor()
    for row in result["observations"]:
        # The adapter may name a historical collector alias. The resolved
        # platform endpoint, rather than that source alias, owns this view.
        row["endpoint_id"] = resolution.identity.get("endpoint_id")
    return result

