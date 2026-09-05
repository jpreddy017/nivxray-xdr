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
import hashlib
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

# ── P0-3 · Canonical verdict representation ─────────────────────────
# Owner ratification 2026-09-05: `verdict_stage2` is the CANONICAL verdict
# representation; `verdict_card` is retained as a compatibility projection
# of the SAME VEEE result.  There is NO second verdict engine and NO
# independent scoring here — every row below is a re-shape of VEEE's own
# `contributors[]` (see xdr_veee.compute_verdict).
_STAGE2_LABEL_MAP = {
    "MALICIOUS":     "malicious",
    "SUSPICIOUS":    "suspicious",
    "LIKELY_BENIGN": "benign",
    "INCONCLUSIVE":  "unknown",
}

_STAGE2_FIELD_MAP = {
    "detection":         "detection.rule_id",
    "iue.severity_hint": "iue.severity_hint",
    "ice.matches":       "ice.matches",
}


def _stage2_from_veee(verdict: dict, canonical: dict) -> dict:
    """Project the VEEE verdict into the canonical `verdict_stage2` shape.

    Deterministic and evidence-only: one evidence row per VEEE contributor,
    no row without a contributor, empty `evidence` when VEEE found none.
    The confidence *bucket* is taken from the existing Stage-2 banding
    function (reused, never re-derived); the *label* remains VEEE's.
    """
    contributors = list((verdict or {}).get("contributors") or [])
    score = int((verdict or {}).get("score") or 0)
    label = _STAGE2_LABEL_MAP.get(
        str((verdict or {}).get("label") or "").upper(), "unknown")

    # Reuse the owner-locked Stage-2 banding; keep only its confidence
    # component so VEEE remains the sole authority on the label.
    from services.verdict_stage2.engine import _label_and_confidence
    _, bucket = _label_and_confidence(score, len(contributors),
                                        bool(contributors))

    event_id = (canonical or {}).get("event_id")
    engine_id = (verdict or {}).get("engine_id")

    rows: list[dict] = []
    signals: list[dict] = []
    for c in contributors:
        source = str(c.get("source") or "")
        weight = int(c.get("weight") or 0)
        detail = c.get("detail")
        detail_s = "" if detail is None else str(detail)[:240]
        row_id = hashlib.sha256(
            f"{event_id}|{source}|{detail_s}|{weight}".encode()
        ).hexdigest()[:24]
        rows.append({
            "row_id":                  row_id,
            "rule_id":                 detail_s if source == "detection" else source,
            "canonical_field_matched": _STAGE2_FIELD_MAP.get(source, source),
            "matched_value":           detail_s,
            "weight_contribution":     weight,
            "lane":                    "log",
            "event_ids":               [event_id] if event_id else [],
            "provenance_chain":        [engine_id] if engine_id else [],
            "display_summary":         f"{source} contributed +{weight}",
        })
        signals.append({
            "rule_id":      detail_s if source == "detection" else source,
            "rule_name":    source,
            "weight":       weight,
            "hits":         1,
            "label_effect": label,
            "description":  f"VEEE contributor {source} (+{weight})",
        })

    return {
        "label":              label,
        "confidence":         bucket,
        # Readers filter on `confidence_bucket`; the Stage-2 engine names the
        # same value `confidence`.  Both are published to avoid a divergence.
        "confidence_bucket":  bucket,
        "risk_score":         score,
        "engine":             engine_id,
        "contributing_signals": signals,
        # `evidence` is the reader-facing name; `evidence_rows` is the
        # Stage-2 engine contract name.  Identical content, no divergence.
        "evidence":           rows,
        "evidence_rows":      rows,
        # VEEE caps its score at 100, so the row weights can legitimately
        # sum higher than `risk_score`.  Stated explicitly so the numbers
        # are never read as inconsistent.
        "weight_sum":         sum(r["weight_contribution"] for r in rows),
        "score_cap_applied":  sum(r["weight_contribution"] for r in rows) > score,
        "provenance_chain":   [engine_id, INCIDENT_ENGINE_ID] if engine_id
                                else [INCIDENT_ENGINE_ID],
        "version":            "stage2.v1-veee-projection",
        "honesty_note":
            "Projection of the VEEE verdict — no second engine, no "
            "independent scoring. One evidence row per VEEE contributor; "
            "an empty evidence[] means VEEE found no contributors.",
    }


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
        # P0-1 · explicit document-type discriminator (workspace_cases is
        # the ratified authoritative store and carries two doc kinds).
        "doc_type":          "xdr_incident",
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
        # Additive verdict record (compatibility projection of the same
        # VEEE result — see _stage2_from_veee).
        "verdict_card": {
            "verdict":     label.lower(),
            "confidence":  score,
            "reason":      verdict.get("reason"),
            "engine":      verdict.get("engine_id"),
        },
        # P0-3 · CANONICAL verdict representation (owner-ratified).
        "verdict_stage2": _stage2_from_veee(verdict, canonical),
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
