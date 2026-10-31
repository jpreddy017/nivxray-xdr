"""Deterministic clustering of past investigations into KB archetypes.

Fingerprint strategy (rev.1):
  key = ( top-3 MITRE technique IDs, sorted+deduped )
      ∪ ( verdict.verdict OR "unknown" )
      ∪ ( "shellcode" if reached_shellcode else "no-shellcode" )

This groups semantically-equivalent investigations together without any LLM
involvement — the clustering itself is pure math and stable across runs.
"""
from __future__ import annotations
import hashlib
import re
from typing import Any, Dict, List


def top_mitre_ids(inv: Dict[str, Any], k: int = 3) -> List[str]:
    """Return the k unique MITRE IDs from the investigation's mitre list."""
    seen: List[str] = []
    for m in (inv.get("mitre") or []):
        mid = (m or {}).get("id")
        if not mid or not isinstance(mid, str):
            continue
        if mid not in seen:
            seen.append(mid)
        if len(seen) >= k:
            break
    return sorted(seen)


def verdict_bucket(inv: Dict[str, Any]) -> str:
    v = ((inv.get("verdict") or {}).get("verdict") or "unknown").strip().lower()
    if v in {"malicious", "suspicious", "benign"}:
        return v
    return "unknown"


def shellcode_marker(inv: Dict[str, Any]) -> str:
    return "shellcode" if bool(inv.get("reached_shellcode")) else "no-shellcode"


def compute_fingerprint(inv: Dict[str, Any]) -> str:
    """Deterministic sha1-based fingerprint for one investigation."""
    parts = [
        "|".join(top_mitre_ids(inv, k=3)) or "no-mitre",
        verdict_bucket(inv),
        shellcode_marker(inv),
    ]
    key = "::".join(parts)
    h = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
    return f"kb-{h}"


def slug_for(inv: Dict[str, Any], fingerprint: str) -> str:
    """Human-readable slug (safe for URLs)."""
    tops = top_mitre_ids(inv, k=2)
    prefix = "-".join(t.lower().replace(".", "_") for t in tops) or "generic"
    prefix = re.sub(r"[^a-z0-9_\-]", "", prefix)[:32]
    verdict = verdict_bucket(inv)
    return f"{prefix}-{verdict}-{fingerprint.split('-')[-1]}"
