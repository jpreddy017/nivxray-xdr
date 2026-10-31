"""JSON Schema (draft 2020-12) view over CEM v1.

Consumers that don't run Python (e.g. TypeScript UI, external
integrations) can validate against this schema. Kept in sync with
`schema.py` by construction — the two live side-by-side and any
change would land as a v2 addition.
"""
from __future__ import annotations

from typing import Any

from v2.cem.v1.schema import (
    ENTITY_KINDS,
    EVENT_KINDS,
    RELATIONSHIP_KINDS,
    VERSION,
)

_PROVENANCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "origin":         {"type": "string"},
        "adapter":        {"type": "string"},
        "parser":         {"type": "string"},
        "normalization":  {"type": "string"},
        "correlation":    {"type": "array", "items": {"type": "string"}},
        "evidence_source":{"type": "array", "items": {"type": "string"}},
        "confidence":     {"type": "number", "minimum": 0, "maximum": 1},
        "transformations":{"type": "array"},
        "observed_at":    {"type": ["string", "null"]},
        "ingested_at":    {"type": ["string", "null"]},
        "derived_at":     {"type": ["string", "null"]},
        "engine_versions":{"type": "object"},
    },
    "required": ["origin", "adapter"],
    "additionalProperties": False,
}

CANONICAL_EVENT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": f"nivxray-cem-{VERSION}",
    "title": f"NivXRay Canonical Event Model {VERSION}",
    "type": "object",
    "properties": {
        "iid":             {"type": "string"},
        "case_id":         {"type": "string"},
        "adapter":         {"type": "string"},
        "adapter_version": {"type": "string"},
        "ts":              {"type": "string"},
        "sequence":        {"type": "integer", "minimum": 0},
        "kind":            {"enum": list(EVENT_KINDS)},
        "device_iid":      {"type": ["string", "null"]},
        "actor_iid":       {"type": ["string", "null"]},
        "session_iid":     {"type": ["string", "null"]},
        "process_iid":     {"type": ["string", "null"]},
        "artefacts_iids":  {"type": "array", "items": {"type": "string"}},
        "labels":          {"type": "array", "items": {"type": "string"}},
        "mitre":           {"type": "array", "items": {"type": "string"}},
        "raw":             {"type": "object"},
        "trust":           {"type": "object"},
        "provenance":      _PROVENANCE_SCHEMA,
    },
    "required": ["iid", "case_id", "adapter", "adapter_version", "ts", "sequence", "kind"],
    "additionalProperties": False,
}

ENTITY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": f"nivxray-cem-entity-{VERSION}",
    "type": "object",
    "properties": {
        "iid":             {"type": "string"},
        "case_id":         {"type": "string"},
        "kind":            {"enum": list(ENTITY_KINDS)},
        "attrs":           {"type": "object"},
        "first_seen":      {"type": ["string", "null"]},
        "last_seen":       {"type": ["string", "null"]},
        "correlation_key": {"type": ["string", "null"]},
        "provenance":      _PROVENANCE_SCHEMA,
    },
    "required": ["iid", "case_id", "kind"],
    "additionalProperties": False,
}

RELATIONSHIP_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": f"nivxray-cem-relationship-{VERSION}",
    "type": "object",
    "properties": {
        "iid":         {"type": "string"},
        "case_id":     {"type": "string"},
        "src_iid":     {"type": "string"},
        "dst_iid":     {"type": "string"},
        "kind":        {"enum": list(RELATIONSHIP_KINDS)},
        "confidence":  {"type": "number", "minimum": 0, "maximum": 1},
        "evidence_ids":{"type": "array", "items": {"type": "string"}},
        "created_at":  {"type": ["string", "null"]},
        "provenance":  _PROVENANCE_SCHEMA,
    },
    "required": ["iid", "case_id", "src_iid", "dst_iid", "kind", "confidence"],
    "additionalProperties": False,
}
