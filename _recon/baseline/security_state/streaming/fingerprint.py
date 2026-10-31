"""Canonical event identity generation (Dual Tier Strategy) for streaming telemetry.

Tier A: Native source UUID.
Tier B: Content-deterministic semantic fingerprint with 1-second timestamp quantization.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..contracts import canonical_json, sha256_digest

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_valid_uuid(val: str) -> bool:
    """Check if string is a valid UUID4/UUID format."""
    if not val or not isinstance(val, str):
        return False
    return bool(UUID_REGEX.match(val.strip()))


def quantize_timestamp_1s(iso_ts: str) -> str:
    """Quantize ISO-8601 timestamp to 1-second resolution to neutralize microsecond transport jitter."""
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        # Strip microseconds
        dt_1s = dt.replace(microsecond=0)
        return dt_1s.isoformat()
    except Exception:
        # Fallback to prefix if parsing fails
        if "T" in iso_ts and len(iso_ts) >= 19:
            return iso_ts[:19] + "Z"
        return iso_ts


def generate_event_fingerprint(
    tenant_id: str,
    event_id: Optional[str],
    source_kind: str,
    action: str,
    actor: Dict[str, Any],
    target: Dict[str, Any],
    event_timestamp: str,
    payload_body: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate deterministic event fingerprint using Tier A or Tier B strategy.

    Tier A (Native UUID):
    If event_id is a valid UUID, returns 'uuid:{tenant_id}:{event_id}'.

    Tier B (Content-Deterministic Semantic Fingerprint):
    Computes SHA-256 over:
    - tenant_id
    - source_kind
    - action
    - normalized actor (id, name, domain, ip)
    - normalized target (id, name, path, hash)
    - 1-second quantized event_timestamp
    
    Transport metadata (collector PID, Kafka partition/offset, ingest_timestamp)
    is strictly excluded.
    """
    # 1. Tier A: Valid Native UUID
    if event_id and is_valid_uuid(event_id):
        return f"tier_a:{tenant_id}:{event_id.strip().lower()}"

    # 2. Tier B: Semantic Normalization
    norm_actor = {
        "id": actor.get("id") or actor.get("user_id") or actor.get("process_id") or "",
        "name": actor.get("name") or actor.get("user_name") or actor.get("process_name") or "",
        "ip": actor.get("ip") or actor.get("src_ip") or "",
    }
    norm_target = {
        "id": target.get("id") or target.get("file_id") or target.get("dest_host") or "",
        "name": target.get("name") or target.get("file_path") or target.get("dest_ip") or "",
        "hash": target.get("hash") or target.get("sha256") or "",
    }

    # If payload body has core action fields, extract deterministic attributes
    core_payload = {}
    if payload_body:
        for k in ("command_line", "process_name", "parent_process_name", "technique_id", "service_name"):
            if k in payload_body:
                core_payload[k] = str(payload_body[k])

    quantized_ts = quantize_timestamp_1s(event_timestamp)

    semantic_payload = {
        "tenant_id": tenant_id,
        "source_kind": source_kind.lower().strip(),
        "action": action.lower().strip(),
        "actor": norm_actor,
        "target": norm_target,
        "core": core_payload,
        "quantized_ts": quantized_ts,
    }

    digest = sha256_digest(canonical_json(semantic_payload))
    return f"tier_b:{tenant_id}:{digest}"
