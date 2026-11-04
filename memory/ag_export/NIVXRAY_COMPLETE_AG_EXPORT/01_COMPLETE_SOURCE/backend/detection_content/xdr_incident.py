"""
P0.4 · Round 11 · XDR Incident Materialiser
───────────────────────────────────────────

Creates a real record in the SSOT collection ``workspace_cases``
(already the authoritative case store per ``routers/incidents.py``)
**only** when the verdict qualifies.  Otherwise honestly returns
``created=False`` with the exact reason.

Gate (§37 · no fabricated incidents):
  * VEEE.label must be MALICIOUS or SUSPICIOUS.
  * VEEE.score must be ≥ INCIDENT_MIN_SCORE (default 55).

Provenance (§P3): every incident carries the full chain
  trace_id ← integration ← collector ← dsm ← parser ← normalizer
           ← canonical_event_id ← iue_id ← detection_rule_id
           ← ice_match_ids ← veee_engine_id
"""
from __future__ import annotations
import os
import uuid
from datetime import datetime, timezone
from typing import Any


INCIDENT_COLLECTION   = "workspace_cases"
INCIDENT_MIN_SCORE    = int(os.environ.get("INCIDENT_MIN_SCORE", "55"))
INCIDENT_ENGINE_ID    = "nivxray::xdr::incident"
INCIDENT_ENGINE_VERSION = "1.0.0"

# Same lifecycle vocabulary used by routers/incidents.py (§4 · reuse).
_INITIAL_STATE = "new"


def _priority(verdict: dict) -> tuple[str, str]:
    label = (verdict.get("label") or "").upper()
    score = int(verdict.get("score") or 0)
    if label == "MALICIOUS" and score >= 80:
        return "P1", "Critical"
    if label == "MALICIOUS":
        return "P2", "High"
    if label == "SUSPICIOUS":
        return "P3", "Medium"
    return "P4", "Low"


async def materialise_incident(db, canonical: dict, iue: dict,
                                    ice: dict, detection: dict | None,
                                    verdict: dict, trace_id: str,
                                    tenant_id: str = "default") -> dict:
    """
    Round 11 · Incident materialisation.  Deterministic gate;
    provenance-preserving.
    """
    label = (verdict or {}).get("label") or "INCONCLUSIVE"
    score = int((verdict or {}).get("score") or 0)

    if label not in ("MALICIOUS", "SUSPICIOUS") or score < INCIDENT_MIN_SCORE:
        return {
            "created":    False,
            "engine_id":  INCIDENT_ENGINE_ID,
            "reason":     f"verdict.label={label} score={score} below gate "
                            f"(min_score={INCIDENT_MIN_SCORE}, "
                            f"required_labels=MALICIOUS|SUSPICIOUS)",
            "honesty_note":
                "No fabricated incident: gate honestly refused this verdict.",
        }

    incident_id = f"inc_{uuid.uuid4().hex[:20]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    priority_code, priority_label = _priority(verdict)

    doc = {
        # Core fields consumed by routers/incidents.py projection.
        "id":                incident_id,
        "tenant_id":         tenant_id,
        "created_at":        now_iso,
        "updated_at":        now_iso,
        "incident_state":    _INITIAL_STATE,
        "incident_state_history": [{
            "state":     _INITIAL_STATE,
            "at":        now_iso,
            "actor":     INCIDENT_ENGINE_ID,
            "reason":    "auto-created by XDR pipeline (Round 11 VEEE gate)",
        }],
        "incident_priority": priority_code,
        "priority_label":    priority_label,
        # Additive verdict record (compatible with verdict_stage2 shape).
        "verdict_card": {
            "verdict":     label.lower(),
            "confidence":  score,
            "reason":      verdict.get("reason"),
            "engine":      verdict.get("engine_id"),
        },
        # Round 11 XDR-native provenance envelope.
        "xdr_pipeline": {
            "engine_id":         INCIDENT_ENGINE_ID,
            "engine_version":    INCIDENT_ENGINE_VERSION,
            "trace_id":          trace_id,
            "canonical_event_id": canonical.get("event_id"),
            "iue_id":            (iue or {}).get("iue_id"),
            "detection_rule_id": (detection or {}).get("rule_id"),
            "ice_matches":       [m.get("match_id")
                                    for m in (ice or {}).get("matches") or []],
            "veee":              verdict,
            "source_provenance": (canonical.get("provenance") or {}),
        },
        "title": (
            f"{label.title()} — sig {(canonical.get('security') or {}).get('signature', {}).get('id')} "
            f"→ {(canonical.get('network') or {}).get('dst', {}).get('ip')}"
        ),
    }

    await db[INCIDENT_COLLECTION].insert_one(dict(doc))
    return {
        "created":     True,
        "incident_id": incident_id,
        "priority":    priority_code,
        "priority_label": priority_label,
        "state":       _INITIAL_STATE,
        "engine_id":   INCIDENT_ENGINE_ID,
        "collection":  INCIDENT_COLLECTION,
        "honesty_note":
            "Incident materialised only because verdict passed the gate. "
            "Full provenance chain preserved in xdr_pipeline sub-document.",
    }
