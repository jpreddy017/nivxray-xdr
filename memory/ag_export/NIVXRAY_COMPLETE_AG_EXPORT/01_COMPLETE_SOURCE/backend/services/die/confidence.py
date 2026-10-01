"""
DIE · Investigation Confidence Engine (Phase B.6 · 2026-02-16 evening)
──────────────────────────────────────────────────────────────────────
Deterministic scoring across the 8 canonical investigation
dimensions (owner-locked ordering, never change):

    Decoder · Artifacts · MITRE · DKP · Intent · Fingerprint ·
    Narrative · Overall

Every score is derived DETERMINISTICALLY from the DIE envelope —
same input → same score.  No probabilistic models, no LLM.

Bucket legend (owner-locked 2026-02-16 evening):
    95-100%   High confidence
    80-94%    Moderate confidence
    < 80%     Requires analyst validation
"""
from __future__ import annotations
from typing import Any, Dict

DIMENSIONS = ["Decoder", "Artifacts", "MITRE", "DKP",
              "Intent", "Fingerprint", "Narrative", "Overall"]

CONFIDENCE_LEGEND = [
    {"range": "95–100%", "label": "High confidence"},
    {"range": "80–94%",  "label": "Moderate confidence"},
    {"range": "< 80%",   "label": "Requires analyst validation"},
]


def _bucket(score: int) -> str:
    if score >= 95: return "High"
    if score >= 80: return "Moderate"
    return "Requires validation"


def score_investigation(env: Dict[str, Any]) -> Dict[str, Any]:
    """Return per-dimension + overall confidence for a DIE envelope.

    ``env`` is the object returned by ``services.die.api.analyze``.
    """
    ast     = env.get("ast") or {}
    chain   = env.get("chain") or {}
    intent  = env.get("attack_intent") or (chain.get("attack_intent") or {})
    dkp     = env.get("dkp_matches") or []
    tech    = env.get("techniques") or []

    # ── Decoder: high when parser produced structured output ─────
    decoder = 100 if ast else (80 if env.get("language") != "unknown" else 60)

    # ── Artifacts: derived from LOLBAS + IOC count (proxy for
    #    recovered structural signals — deeper analyzer telemetry
    #    plumbs in when Artifact Analyzer wires into the envelope). ─
    lolbins = env.get("lolbins") or []
    iocs    = env.get("iocs") or []
    signal  = min(20, len(lolbins) * 4) + min(20, len(iocs) * 2)
    artifacts = 60 + signal        # baseline 60 → up to 100

    # ── MITRE: proportional to hit count (capped) ─────────────────
    mitre = 60 + min(40, len(tech) * 10)

    # ── DKP: highest-confidence match wins ────────────────────────
    if dkp:
        dkp_score = int(round(max(m.get("confidence", 0) for m in dkp) * 100))
        dkp_score = max(60, dkp_score)
    else:
        dkp_score = 55

    # ── Intent: engine's own confidence ───────────────────────────
    intent_score = int(round((intent.get("confidence") or 0.0) * 100))
    if intent_score == 0 and (ast or tech):
        intent_score = 55  # a floor when we have signal but no intent

    # ── Fingerprint: not evaluated by DIE — assume stable when the
    #    engine produced any output.  Wired into real fingerprint
    #    telemetry in a later milestone. ────────────────────────────
    fingerprint = 100 if (ast or chain) else 70

    # ── Narrative: quality proxy — high when structured chain or
    #    single-step AST is present. ───────────────────────────────
    narrative = 100 if chain else (90 if ast else 70)

    scores = {
        "Decoder":     min(100, decoder),
        "Artifacts":   min(100, artifacts),
        "MITRE":       min(100, mitre),
        "DKP":         min(100, dkp_score),
        "Intent":      min(100, intent_score),
        "Fingerprint": min(100, fingerprint),
        "Narrative":   min(100, narrative),
    }

    # Overall = weighted average (deterministic weights).
    weights = {"Decoder":1.5, "Artifacts":1.0, "MITRE":1.2, "DKP":1.0,
               "Intent":1.5, "Fingerprint":0.8, "Narrative":1.0}
    ws = sum(weights.values())
    overall = int(round(sum(scores[k] * w for k, w in weights.items()) / ws))
    scores["Overall"] = overall

    return {
        "dimensions": [
            {"name": d, "score": scores[d], "bucket": _bucket(scores[d])}
            for d in DIMENSIONS
        ],
        "overall":  overall,
        "bucket":   _bucket(overall),
        "legend":   CONFIDENCE_LEGEND,
    }
