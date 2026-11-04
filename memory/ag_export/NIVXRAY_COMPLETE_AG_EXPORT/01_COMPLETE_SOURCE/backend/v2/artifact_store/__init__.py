"""v2/artifact_store · R2 · Immutable Evidence Object Store.

Public surface:
    Artifact                — pydantic model of an evidence object
    CustodyEvent            — one entry in the chain-of-custody log
    build_artifact_iid      — deterministic ID from (sha256, kind)
    create_or_update        — idempotent write into v2_artifact_store
    get_by_iid, get_by_sha  — read helpers
    list_by_case            — filter/list
    append_custody          — appends a custody event atomically
    link_observation        — attaches an observation iid
    link_entity             — attaches an entity iid
    link_case               — attaches a case_id

Storage:
    Mongo collection `v2_artifact_store` (declared in
    v2/case_engine/schema.py with existing (case_id, sha256) and
    (sha256) indexes). All writes are additive; no destructive updates.

Zero RC5 imports. Feature-flag gated on ARTIFACT_STORE.
"""
from .schema import (
    Artifact, CustodyEvent, CustodyAction, ArtifactKind,
    ARTIFACT_SCHEMA_VERSION, build_artifact_iid,
)
from .store import (
    create_or_update, get_by_iid, get_by_sha, list_by_case,
    append_custody, link_observation, link_entity, link_case,
)

__all__ = [
    "Artifact", "CustodyEvent", "CustodyAction", "ArtifactKind",
    "ARTIFACT_SCHEMA_VERSION", "build_artifact_iid",
    "create_or_update", "get_by_iid", "get_by_sha", "list_by_case",
    "append_custody", "link_observation", "link_entity", "link_case",
]
