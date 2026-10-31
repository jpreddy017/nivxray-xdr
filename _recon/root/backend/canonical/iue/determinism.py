"""Deterministic serialisation + fingerprinting for IUEDecision."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


def _default(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"non-serialisable: {type(obj).__name__}")


def canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, deterministic separators, no whitespace."""
    return json.dumps(
        obj,
        default=_default,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def fingerprint(obj: Any) -> str:
    """sha256 of the canonical JSON serialisation."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
