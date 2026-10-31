"""
P0.4 · Round 11 · XDR VEEE (Verdict & Evidence Evaluation Engine)
────────────────────────────────────────────────────────────────

**Boundary**:
  Detection = capability match (a rule fired).
  IUE       = understanding of the evidence (entities, severity_hint).
  ICE       = correlation evidence.
  VEEE      = *combined* deterministic verdict projection.

Determinism (§3): Same canonical + IUE + ICE inputs → byte-identical
verdict.  No clock reads, no random, no LLM.

HONEST STATE (§37):
  * `label ∈ {MALICIOUS, SUSPICIOUS, LIKELY_BENIGN, INCONCLUSIVE}`
  * `confidence` is a bounded integer 0..100.
  * `reason` never falls back to a generic template — if there is
    zero evidence, we say so.
"""
from __future__ import annotations
from typing import Any


VEEE_ENGINE_ID = "nivxray::xdr::veee"
VEEE_ENGINE_VERSION = "1.0.0"


# ── Deterministic scoring (documented) ───────────────────────────
_WEIGHT_DETECTION_MATCH   = 45   # rule fired
_WEIGHT_CORRELATION_MATCH = 20   # each ICE match, capped at 3
_WEIGHT_SEVERITY = {
    "CRITICAL":      35,
    "HIGH":          25,
    "MEDIUM":        15,
    "LOW":            5,
    "INFORMATIONAL":  0,
}
_MAX_SCORE = 100

# Bands — allow-listed, mirrors canonical.projections.verdict.
_LABEL_BANDS = [
    (80, "MALICIOUS"),
    (55, "SUSPICIOUS"),
    (25, "LIKELY_BENIGN"),
    (0,  "INCONCLUSIVE"),
]


def _score(detection: dict | None, iue: dict, ice: dict) -> tuple[int, list[dict]]:
    contributors: list[dict] = []
    score = 0
    if detection and detection.get("matched"):
        score += _WEIGHT_DETECTION_MATCH
        contributors.append({"source": "detection",
                              "weight": _WEIGHT_DETECTION_MATCH,
                              "detail": detection.get("rule_id")})
    sev = (iue or {}).get("severity_hint") or "INFORMATIONAL"
    sev_w = _WEIGHT_SEVERITY.get(sev, 0)
    if sev_w > 0:
        score += sev_w
        contributors.append({"source": "iue.severity_hint",
                              "weight": sev_w, "detail": sev})
    n_matches = len((ice or {}).get("matches") or [])
    if n_matches:
        w = min(n_matches, 3) * _WEIGHT_CORRELATION_MATCH
        score += w
        contributors.append({"source": "ice.matches",
                              "weight": w, "detail": f"{n_matches} match(es)"})
    return min(score, _MAX_SCORE), contributors


def _label(score: int) -> str:
    for threshold, label in _LABEL_BANDS:
        if score >= threshold:
            return label
    return "INCONCLUSIVE"


def compute_verdict(canonical: dict, detection: dict | None,
                     iue: dict, ice: dict) -> dict:
    """
    Round 11 · XDR VEEE entry point.  Deterministic + reproducible.
    """
    score, contributors = _score(detection, iue, ice)
    label = _label(score)

    if not contributors:
        reason = "no evidence supported a verdict"
    else:
        parts = [f"{c['source']}(+{c['weight']})" for c in contributors]
        reason = "verdict derived from " + " + ".join(parts)

    return {
        "engine_id":      VEEE_ENGINE_ID,
        "engine_version": VEEE_ENGINE_VERSION,
        "label":          label,
        "score":          score,
        "confidence":     score,        # bounded 0..100
        "reason":         reason,
        "contributors":   contributors,
        "inputs": {
            "canonical_event_id": canonical.get("event_id"),
            "iue_id":              (iue or {}).get("iue_id"),
            "detection_rule_id":  (detection or {}).get("rule_id"),
            "ice_state":          (ice or {}).get("state"),
        },
        "honesty_note":
            "Score is derived from the enumerated contributors only. "
            "An empty contributors[] MUST yield label=INCONCLUSIVE.",
    }
