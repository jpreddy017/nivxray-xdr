"""v2/report/hashing.py · Deterministic report signing.

The signature is a SHA-256 of the CANONICAL JSON of the entire
envelope with `signature` blanked. Canonical JSON = sorted keys,
no whitespace, ensure_ascii=False. Same inputs → same hash.
"""
from __future__ import annotations
import hashlib
import json
from .schema import ReportEnvelope


def canonical_json(env: ReportEnvelope | dict) -> str:
    """Dump the envelope to canonical JSON with the signature blanked."""
    data = env.model_dump() if isinstance(env, ReportEnvelope) else dict(env)
    data["signature"] = {}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def report_hash(env: ReportEnvelope | dict) -> str:
    """SHA-256 of the canonical envelope (signature blanked)."""
    return hashlib.sha256(canonical_json(env).encode("utf-8")).hexdigest()


def sign_report(env: ReportEnvelope) -> ReportEnvelope:
    """Return a copy of the envelope with signature populated."""
    h = report_hash(env)
    env.signature = {
        "algorithm": "sha256",
        "sha256": h,
        "canonical_json_bytes": str(len(canonical_json(env).encode("utf-8"))),
    }
    return env
