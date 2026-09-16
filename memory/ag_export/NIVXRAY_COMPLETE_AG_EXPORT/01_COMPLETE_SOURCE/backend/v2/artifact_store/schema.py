"""v2/artifact_store/schema.py · Artifact + CustodyEvent models.

Field set per DFIR requirements (see /app/memory/ROADMAP.md · R2):
    - artifact_iid       Immutable, deterministic ID (SHA-256 + kind).
    - sha256             Content hash (hex, lowercase).
    - kind               One of `command_line | file | url | ip |
                         domain | hash | process | binary | text | blob`.
    - value              Text payload for inline artifacts (command
                         lines, URLs, IOCs). Empty for binary blobs
                         where `blob_ref` points at external storage.
    - mime_type          e.g. `text/x-command-line`, `application/pdf`.
    - size               Payload byte length.
    - acquisition_time   When the evidence was CAPTURED at the sensor
                         (adapter-supplied when known; otherwise the
                         write time).
    - created_at         When we first PERSISTED it (server clock).
    - source             Adapter name / uploader identifier — e.g.
                         `json`, `syslog`, `webhook`, `manual`.
    - provenance         Rule / engine metadata (rule_id, confidence,
                         engine_version, ingest_run_id, ...).
    - related_case_ids   Cases this artifact appears in.
    - related_entity_iids
    - related_observation_iids
    - chain_of_custody   Append-only list[CustodyEvent].
    - schema_version     Frozen at r2.0. Additions bump the major.

All timestamps are ISO-8601 UTC strings — never datetime objects on
the wire (per project convention).
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field

ARTIFACT_SCHEMA_VERSION = "r2.0"

ArtifactKind = Literal[
    "command_line", "file", "url", "ip", "domain", "hash",
    "process", "binary", "text", "blob",
]

CustodyAction = Literal[
    "acquired",       # sensor / adapter captured the evidence
    "ingested",       # persisted into the artifact store
    "linked",         # attached to a case / entity / observation
    "reviewed",       # analyst opened / examined
    "annotated",      # analyst added a note
    "exported",       # released to an egress channel (SIEM / ITSM)
    "sealed",         # marked immutable — no further mutations allowed
]


class CustodyEvent(BaseModel):
    """One line in the chain-of-custody log."""
    ts: str                                    # ISO-8601 UTC
    actor: str                                 # user email OR system name
    action: CustodyAction
    detail: str = ""                           # free-form (e.g. "attached to case=X")
    signature: str | None = None               # optional HMAC/SHA over prior chain (R2.1+)


class Artifact(BaseModel):
    """Immutable evidence object with full DFIR provenance."""
    schema_version: str = ARTIFACT_SCHEMA_VERSION
    artifact_iid: str                          # Immutable ID (deterministic)
    sha256: str                                # Content hash (hex lowercase)
    kind: ArtifactKind
    value: str = ""                            # Inline text (empty for binary blob refs)
    mime_type: str = "text/plain"
    size: int = 0                              # Payload bytes
    acquisition_time: str = ""                 # Captured at sensor
    created_at: str = ""                       # Persisted at server
    source: str = "manual"                     # Adapter name / uploader
    provenance: dict[str, Any] = Field(default_factory=dict)
    related_case_ids: list[str] = Field(default_factory=list)
    related_entity_iids: list[str] = Field(default_factory=list)
    related_observation_iids: list[str] = Field(default_factory=list)
    chain_of_custody: list[CustodyEvent] = Field(default_factory=list)
    # Only populated when kind == "blob" / "binary" and external storage is used.
    blob_ref: str | None = None                # e.g. "gridfs://<oid>" (R2.1+)


def build_artifact_iid(sha256: str, kind: str) -> str:
    """Deterministic artifact IID.

    Two properties matter:
        1. Identical (sha, kind) always yields the same ID → idempotent
           upserts across ingest pipeline retries.
        2. Different `kind` on the same content still yields different
           IIDs (a URL string and a command_line string CAN share bytes).

    Format: `art_<12-hex-of-sha256(kind|sha256)>` — 12 hex is 48-bit,
    ≈2.8e14 space, collision-safe at the DFIR volumes NivXRay targets.
    """
    digest = hashlib.sha256(f"{kind}|{sha256}".encode("utf-8")).hexdigest()
    return f"art_{digest[:12]}"


def compute_sha256(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
