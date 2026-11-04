"""Immutable SSOT Store · R27.1 · R28.1.

Content-addressable Single-Source-Of-Truth persistence layer.

Design (frozen · see /app/memory/NIVXRAY_ARCHITECTURE_V1.md R27/R28):
  • Every investigation writes to ``investigation_ssot`` — one canonical
    document keyed by ``investigation_id`` (UUID) with a
    ``checksum = sha256(canonical_json(ssot))`` content address.
  • Duplicates are deduplicated by checksum — re-saving an identical
    bundle returns the existing ``investigation_id``.
  • Callers persist a lightweight ``ssot_ref = {id, checksum, version}``
    pointer on their own docs (workspace_cases, investigations,
    reports, exports…) and dereference at read time.
  • Progressive migration (R28.1 option c): write-through keeps the
    legacy inline ``ssot`` copy on ``workspace_cases`` until the
    Phase 3 compatibility gate has been clean for 7 consecutive days.
  • The Artifact Trace projection lifts the persisted ``decode_trace``
    into the canonical Artifact → Recognizer → Capability → Evidence
    → Child-Artifact shape (works for PowerShell / PE / PDF / Office /
    Shellcode / Memory / PCAP — no rename needed post-UAIE).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from deps import sync_collection

# Content-addressable immutable SSOT collection.
_ssot_col = sync_collection("investigation_ssot")


# ═════════════════════════════════════════════════════════════════════════
# VERSION STAMPING — compound stamp so every SSOT records which pipeline
# (schema / engine / uaie / baseline) produced it.  ``version`` is left
# as an object; legacy string ``"1.0"`` restores by coercion.
# ═════════════════════════════════════════════════════════════════════════
_SCHEMA_VERSION   = "1.0"
_ENGINE_VERSION   = "legacy"        # → "uaie-plugin" after R26 Phase 3
_UAIE_VERSION     = "phase1"        # phase1 · phase2 · phase3
_BASELINE_VERSION = "R27"           # R27 · R27.1 · R28 · …


def build_version_stamp(
    *,
    engine: Optional[str] = None,
    uaie: Optional[str] = None,
    baseline: Optional[str] = None,
) -> Dict[str, str]:
    """Return the compound version stamp attached to every persisted SSOT."""
    return {
        "schema":   _SCHEMA_VERSION,
        "engine":   engine   or _ENGINE_VERSION,
        "uaie":     uaie     or _UAIE_VERSION,
        "baseline": baseline or _BASELINE_VERSION,
    }


def coerce_version(v: Any) -> Dict[str, str]:
    """Normalise a persisted ``version`` back to the compound shape.

    Legacy R27 cases stored the string ``"1.0"`` — treat those as
    ``{schema: "1.0", engine: "legacy", uaie: "phase0", baseline: "R27"}``
    so restore code can rely on a single shape.
    """
    if isinstance(v, dict):
        return {
            "schema":   str(v.get("schema")   or _SCHEMA_VERSION),
            "engine":   str(v.get("engine")   or "legacy"),
            "uaie":     str(v.get("uaie")     or "phase0"),
            "baseline": str(v.get("baseline") or "R27"),
        }
    return {
        "schema":   str(v) if v else _SCHEMA_VERSION,
        "engine":   "legacy",
        "uaie":     "phase0",
        "baseline": "R27",
    }


# ═════════════════════════════════════════════════════════════════════════
# CONTENT ADDRESSING — sha256 of the canonical JSON of the SSOT payload
# (with sorted keys + stable primitives).  Two identical investigations
# collapse to one immutable row.
# ═════════════════════════════════════════════════════════════════════════
def canonical_bytes(ssot: Dict[str, Any]) -> bytes:
    """Deterministic canonical JSON — used exclusively for content hashing.

    We strip ``persisted_at`` and any pointer/version fields so that two
    identical investigations produce the same checksum regardless of
    save time.
    """
    scrub_keys = {"persisted_at", "checksum", "investigation_id", "ssot_ref"}
    payload = {k: v for k, v in ssot.items() if k not in scrub_keys}
    return json.dumps(payload, sort_keys=True, default=str,
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def compute_checksum(ssot: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(ssot)).hexdigest()


# ═════════════════════════════════════════════════════════════════════════
# STORE — write-through + content-addressed dedupe
# ═════════════════════════════════════════════════════════════════════════
def store_ssot(
    ssot: Dict[str, Any],
    *,
    user_email: Optional[str] = None,
    case_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist ``ssot`` into ``investigation_ssot`` and return a
    lightweight ``ssot_ref`` pointer that callers should embed in their
    own documents.

    Idempotent by content-hash: identical bundles collapse to one row.
    Never mutates the input dict.
    """
    if not isinstance(ssot, dict):
        raise TypeError("ssot must be a dict")
    checksum = compute_checksum(ssot)
    # Content-address dedupe: if a doc with this checksum already exists
    # reuse its investigation_id.
    existing = _ssot_col.find_one({"checksum": checksum}, {"_id": 0})
    now      = datetime.now(timezone.utc).isoformat()
    version  = coerce_version(ssot.get("version"))
    if existing:
        # Update reference-count / last-seen only; content is immutable.
        _ssot_col.update_one(
            {"checksum": checksum},
            {"$inc": {"ref_count": 1},
             "$set": {"last_seen_at": now}},
        )
        return {
            "id":       existing["investigation_id"],
            "checksum": checksum,
            "version":  version,
        }
    investigation_id = str(uuid.uuid4())
    doc = {
        "investigation_id": investigation_id,
        "checksum":         checksum,
        "version":          version,
        "user_email":       user_email,
        "case_name":        case_name,
        "created_at":       now,
        "last_seen_at":     now,
        "ref_count":        1,
        "ssot":             ssot,
    }
    _ssot_col.insert_one(doc)
    return {
        "id":       investigation_id,
        "checksum": checksum,
        "version":  version,
    }


def load_ssot(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Dereference an ``ssot_ref`` — returns the canonical SSOT or None."""
    if not investigation_id:
        return None
    doc = _ssot_col.find_one(
        {"investigation_id": investigation_id},
        {"_id": 0, "ssot": 1, "checksum": 1, "version": 1,
         "created_at": 1, "investigation_id": 1},
    )
    if not doc:
        return None
    ssot = dict(doc.get("ssot") or {})
    # Stamp the pointer info back into the returned payload so the
    # frontend can display checksum + version + investigation_id.
    ssot["investigation_id"] = doc["investigation_id"]
    ssot["checksum"]         = doc["checksum"]
    if "version" in doc and "version" not in ssot:
        ssot["version"] = doc["version"]
    return ssot


# ═════════════════════════════════════════════════════════════════════════
# ARTIFACT TRACE PROJECTION — Artifact → Recognizer → Capability →
# Evidence → Child Artifact.  Future-proof for UAIE (PDF / PE / Office
# / Shellcode / Memory / PCAP), not just decoding.
# ═════════════════════════════════════════════════════════════════════════
def project_artifact_trace(ssot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Lift a persisted ``decode_trace`` into the canonical
    Artifact → Recognizer → Capability → Evidence shape.

    Contract:
      • Zero business logic.  Pure projection.
      • Idempotent — calling twice returns the same list.
      • Safe on legacy SSOTs — returns [] if no decode_trace.
    """
    trace: List[Dict[str, Any]] = list(ssot.get("decode_trace") or [])
    if not trace:
        return []
    iocs = ((ssot.get("analysis") or {}).get("iocs")) or {}
    verdict_card = ssot.get("verdict_card") or {}
    out: List[Dict[str, Any]] = []
    for idx, layer in enumerate(trace):
        # Layer may be a str ("gzip") or a dict.  Normalize.
        if isinstance(layer, str):
            op = layer
            reason = ""
            out_preview = ""
            out_len = 0
        else:
            op          = str(layer.get("op") or layer.get("engine") or f"layer-{idx}")
            reason      = str(layer.get("reason") or layer.get("why") or "")
            out_preview = str(layer.get("output_preview") or "")
            out_len     = int(layer.get("out_len") or layer.get("output_len") or 0)
        artifact_uri = f"uaie://artifact/decode-layer-{idx:03d}/{op}"
        # Evidence bindings come from the ssot's canonical inventory:
        # last-layer artifacts inherit the case-level IOCs.
        evidence: List[Dict[str, Any]] = []
        if idx == len(trace) - 1:
            for kind, values in iocs.items():
                for v in (values or []):
                    evidence.append({
                        "kind": kind,
                        "value": v,
                        "confidence": verdict_card.get("confidence"),
                    })
        out.append({
            "artifact_uri": artifact_uri,
            "layer_index":  idx,
            "recognizer": {
                "name":   op,
                "reason": reason,
            },
            "capability": {
                "name":       op,
                "out_len":    out_len,
                "out_preview": out_preview[:200],
            },
            "evidence":       evidence,
            "child_artifact": (f"uaie://artifact/decode-layer-{idx+1:03d}"
                               if idx < len(trace) - 1 else None),
        })
    return out


__all__ = [
    "build_version_stamp",
    "coerce_version",
    "canonical_bytes",
    "compute_checksum",
    "store_ssot",
    "load_ssot",
    "project_artifact_trace",
]
