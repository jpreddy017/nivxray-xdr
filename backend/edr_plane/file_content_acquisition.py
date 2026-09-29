"""B3 · FILE CONTENT ACQUISITION — the SERVER-SIDE contract.

Three digests exist on this platform and they are never interchangeable:

```
PROCESS_IMAGE_SHA256        the bytes of the executable that RAN
FILE_CONTENT_SHA256         the bytes of a file on disk at ACQUISITION time
RAW_PAYLOAD_CONTENT_DIGEST  the digest of the telemetry payload itself
```

A sensor may only contribute a `FILE_CONTENT_SHA256`, and only inside a
CONTENT ACQUISITION RECORD that states when the bytes were read and
whether they were stable. A bare digest whose subject and version are
unknown is refused here, at the boundary, because once it is stored
nothing downstream can tell what it identified.

`UNKNOWN` never becomes `BENIGN`: every refusal carries the cause.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from v2.ingestion.canonical import HASH_NOT_OBSERVED, HASH_OBSERVED

#: WHICH bytes a digest identifies. Never merged, never substituted.
PROCESS_IMAGE_SHA256 = "PROCESS_IMAGE_SHA256"
FILE_CONTENT_SHA256 = "FILE_CONTENT_SHA256"
RAW_PAYLOAD_CONTENT_DIGEST = "RAW_PAYLOAD_CONTENT_DIGEST"
DIGEST_CLASSES = frozenset({PROCESS_IMAGE_SHA256, FILE_CONTENT_SHA256,
                            RAW_PAYLOAD_CONTENT_DIGEST})

ACQUIRED = "ACQUIRED"
#: Every attempted acquisition resolves to exactly one of these.
ACQUISITION_STATES = frozenset({
    ACQUIRED, "NOT_ELIGIBLE_BY_POLICY", "FILE_ABSENT_AT_ACQUISITION",
    "ACCESS_DENIED", "LOCKED_OR_SHARING_VIOLATION", "SIZE_LIMIT_EXCEEDED",
    "TIMEOUT", "IO_ERROR", "RATE_LIMITED", "HASH_NOT_ATTEMPTED",
    "DROPPED_QUEUE_FULL", "CAPABILITY_DISABLED",
})
CONTENT_VERSION_STATES = frozenset({
    "STABLE_DURING_ACQUISITION", "CHANGED_DURING_ACQUISITION",
    "CHANGED_SINCE_EVENT", "CONSISTENT_WITH_EVENT",
})
#: Admissible content versions for a digest. A torn read is not one.
ADMISSIBLE_VERSIONS = frozenset({"STABLE_DURING_ACQUISITION",
                                 "CHANGED_SINCE_EVENT",
                                 "CONSISTENT_WITH_EVENT"})

#: Acquisition states this server MINTS when a record is absent or unusable.
NO_RECORD = "HASH_NOT_ATTEMPTED"
SOURCE_STATED = "SOURCE_STATED_NO_ACQUISITION_RECORD"
RECORD_REFUSED = "ACQUISITION_RECORD_REFUSED"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CARRIED = ("path", "acquisition_state", "content_version_state",
            "hash_algorithm", "hash_algorithm_version", "size_bytes",
            "event_observed_at", "acquired_at", "acquisition_latency_ms",
            "mtime_at_acquisition", "ctime_at_acquisition", "acquirer",
            "sensor_version", "policy_id", "cache_state", "renamed_from",
            "coalesced_event_refs", "file_id", "volume_guid",
            "refusal_reason")
PROVENANCE_ACQUIRED = "sensor:content_acquisition(SHA-256)"
PROVENANCE_SOURCE_STATED = "source:file_event.sha256"


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _refuse(record: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "hashes": {},
        "hash_state": HASH_NOT_OBSERVED,
        "hash_class": FILE_CONTENT_SHA256,
        "hash_reason": reason,
        "acquisition": {**record, "admitted": False,
                        "refused_by": "server_contract",
                        "refusal_reason": reason},
        "field_provenance": {},
    }


def admit(*, sha256: Optional[str] = None,
          record: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Decide what a FILE event's content identity actually is.

    `sha256` is whatever digest the event stated bare. `record` is the
    sensor's content acquisition record. Neither is trusted blindly: a
    digest is admitted only when its SUBJECT (these bytes) and its
    VERSION (when they were read, and whether they moved) are stated.
    """
    stated = _s(sha256).lower()
    if not isinstance(record, dict) or not record:
        if stated and _SHA256.match(stated):
            # Backward compatible: a source that hashed the file itself and
            # said so on the event. Admitted, but explicitly NOT a
            # contracted acquisition — its content VERSION is unknown.
            return {
                "hashes": {"sha256": stated},
                "hash_state": HASH_OBSERVED,
                "hash_class": FILE_CONTENT_SHA256,
                "hash_reason": ("the source stated a content digest on the "
                                "file event itself; no acquisition record "
                                "accompanied it, so when the bytes were "
                                "read and whether they were stable is "
                                "UNKNOWN"),
                "acquisition": {"acquisition_state": SOURCE_STATED,
                                "content_version_state": "UNKNOWN",
                                "admitted": True},
                "field_provenance": {
                    "hashes.sha256": PROVENANCE_SOURCE_STATED},
            }
        return {
            "hashes": {},
            "hash_state": HASH_NOT_OBSERVED,
            "hash_class": FILE_CONTENT_SHA256,
            "hash_reason": ("no content digest and no acquisition record "
                            "accompanied this file event. The process image "
                            "hash on the same event identifies the "
                            "EXECUTABLE THAT RAN and is never promoted "
                            "here"),
            "acquisition": {"acquisition_state": NO_RECORD,
                            "content_version_state": "UNKNOWN",
                            "admitted": False},
            "field_provenance": {},
        }

    kept = {k: record[k] for k in _CARRIED if k in record}
    state = _s(record.get("acquisition_state")).upper()
    version = _s(record.get("content_version_state")).upper()
    digest = _s(record.get("sha256") or stated).lower()
    kept["acquisition_state"] = state or "UNKNOWN"
    kept["content_version_state"] = version or "UNKNOWN"

    declared_class = _s(record.get("hash_class")).upper()
    if declared_class and declared_class != FILE_CONTENT_SHA256:
        return _refuse(kept, (
            f"the record declares digest class {declared_class}; only "
            f"{FILE_CONTENT_SHA256} may identify a file's content and a "
            f"process image digest is never substituted for it"))
    if state not in ACQUISITION_STATES:
        return _refuse(kept, ("acquisition_state "
                              f"{state or 'ABSENT'!r} is not a declared "
                              "acquisition outcome"))
    if state != ACQUIRED:
        return {
            "hashes": {},
            "hash_state": HASH_NOT_OBSERVED,
            "hash_class": FILE_CONTENT_SHA256,
            "hash_reason": (f"content acquisition did not complete: {state}. "
                            "This is a STATED cause, not an unknown gap, and "
                            "it is not an absence of the file event"),
            "acquisition": {**kept, "admitted": False},
            "field_provenance": {},
        }
    if version not in CONTENT_VERSION_STATES:
        return _refuse(kept, ("an ACQUIRED record must state a declared "
                              "content_version_state; "
                              f"{version or 'ABSENT'!r} is not one"))
    if version not in ADMISSIBLE_VERSIONS:
        return _refuse(kept, ("the content changed DURING acquisition, so "
                              "the digest describes a torn read and is "
                              "discarded rather than presented as the "
                              "file's identity"))
    if not _SHA256.match(digest):
        return _refuse(kept, ("an ACQUIRED record must carry a lowercase "
                              "64-hex SHA-256 of the bytes that were read"))
    if not _s(record.get("acquired_at")):
        return _refuse(kept, ("an ACQUIRED record must state acquired_at; a "
                              "digest without a read time has no content "
                              "version"))
    return {
        "hashes": {"sha256": digest},
        "hash_state": HASH_OBSERVED,
        "hash_class": FILE_CONTENT_SHA256,
        "hash_reason": (
            "the sensor read these bytes to completion and hashed them; the "
            "digest is the identity of the content AT ACQUISITION TIME"
            + (", which is NOT provably the content the event described"
               if version == "CHANGED_SINCE_EVENT" else "")),
        "acquisition": {**kept, "sha256": digest,
                        "hash_algorithm": _s(record.get("hash_algorithm"))
                        or "SHA-256",
                        "admitted": True},
        "field_provenance": {"hashes.sha256": PROVENANCE_ACQUIRED},
    }
