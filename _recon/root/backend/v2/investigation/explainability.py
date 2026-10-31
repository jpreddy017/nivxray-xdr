"""v2/investigation/explainability.py · Deterministic reasoning engine.

Answers analyst questions with pure evidence-based logic:

    "Why is this <band>?"                       (positive)
    "Why isn't this ransomware?"                (negative — required behaviours missing)
    "Why isn't this credential theft?"
    "Why isn't this lateral movement?"
    "Why isn't this persistence?"
    "Why isn't this beaconing?"

Read-only. Reads directly from the correlation output + IKG. No LLM.
Same evidence → same explanation string.
"""
from __future__ import annotations
from typing import Any


# ─── Attack pattern definitions (deterministic) ─────────────────────
#
# For each pattern we declare the *required* behaviours as a set of
# signal keys — the analyst is told exactly which required signals are
# missing.
ATTACK_PATTERNS: dict[str, dict[str, Any]] = {
    "ransomware": {
        "label":    "Ransomware",
        "required": {
            "BACKUP_DESTRUCTION":   "backup destruction / shadow-copy deletion",
            "MASS_FILE_ENCRYPTION": "mass file encryption",
            "RANSOM_NOTE_CREATION": "ransom note dropped",
        },
        "supporting": {
            "SHADOW_COPY_DELETE": "shadow-copy deletion",
        },
        "min_required":      2,   # need at least this many required signals
        "min_supporting":    0,
    },
    "credential_theft": {
        "label":    "Credential Theft",
        "required": {
            "CREDENTIAL_DUMPING": "credential dumping (mimikatz-style)",
            "LSASS_ACCESS":       "LSASS process memory access",
        },
        "supporting": {
            "SAM_ACCESS": "SAM database access",
        },
        "min_required":    1,
        "min_supporting":  0,
    },
    "lateral_movement": {
        "label":    "Lateral Movement",
        "required": {
            "NETWORK_BEACONING":  "network beaconing to remote host",
            "SUSPICIOUS_PARENT":  "remotely-launched process",
        },
        "supporting": {
            "CREDENTIAL_DUMPING": "credential access (required to move laterally)",
        },
        "min_required":    1,
        "min_supporting":  1,
    },
    "persistence": {
        "label":    "Persistence",
        "required": {
            "REGISTRY_PERSISTENCE":  "registry Run-key modification",
            "SCHEDULED_TASK_CREATE": "scheduled task created",
            "WMI_PERSISTENCE":       "WMI event subscription",
            "SERVICE_INSTALL":       "Windows service installed",
        },
        "supporting":     {},
        "min_required":   1,
        "min_supporting": 0,
    },
    "beaconing": {
        "label":    "C2 Beaconing",
        "required": {
            "EXTERNAL_C2":       "external command-and-control",
            "NETWORK_BEACONING": "periodic beacon traffic",
        },
        "supporting":     {},
        "min_required":   1,
        "min_supporting": 0,
    },
}


# ─── Positive explanation (Why is this <band>?) ─────────────────────

def why_is_this(dev_verdict: dict, ikg_stats: dict) -> dict[str, Any]:
    """Deterministic explanation of the current classification."""
    if not dev_verdict:
        return {"band": "unknown", "reasons": [], "stats": ikg_stats or {}}
    band = dev_verdict.get("band", "benign")
    reasons: list[dict] = []

    # Top-3 evidence signals by effective weight.
    top = sorted(dev_verdict.get("evidence_breakdown", []),
                 key=lambda e: e.get("effective_weight", 0), reverse=True)[:3]
    for e in top:
        reasons.append({
            "kind":   "evidence",
            "weight": e.get("effective_weight", 0),
            "text":   f"{e.get('signal', '').replace('_', ' ').lower()} detected",
            "detail": e.get("reason", ""),
        })

    # Correlation bonuses.
    for b in dev_verdict.get("correlation_bonuses", []):
        reasons.append({
            "kind":   "bonus",
            "weight": b.get("weight", 0),
            "text":   b.get("signal", "").replace("_", " ").lower(),
            "detail": b.get("reason", ""),
        })

    # Progressions.
    for p in dev_verdict.get("progressions", []):
        reasons.append({
            "kind":   "progression",
            "weight": p.get("effective_weight", p.get("weight", 0)),
            "text":   p.get("label", p.get("id", "")),
            "detail": p.get("reason", ""),
        })

    # Tactic coverage headline.
    n_tac = len(dev_verdict.get("tactic_coverage", {}))
    if n_tac > 0:
        reasons.append({
            "kind":   "coverage",
            "weight": 0,
            "text":   f"{n_tac} MITRE tactic{'s' if n_tac > 1 else ''} covered",
            "detail": ", ".join(sorted((dev_verdict.get("tactic_coverage") or {}).keys())),
        })

    return {
        "band":          band,
        "score":         dev_verdict.get("score", 0),
        "confidence":    dev_verdict.get("confidence", 0),
        "reasons":       reasons,
        "stats":         ikg_stats or {},
    }


# ─── Negative explanation ("Why isn't this <pattern>?") ─────────────

def why_is_this_not(pattern_id: str, dev_verdict: dict) -> dict[str, Any]:
    """Return a deterministic explanation of what would be required to
    reclassify the case as `pattern_id`. Used for every "Why isn't this
    ransomware/credential-theft/persistence/…" question.
    """
    pat = ATTACK_PATTERNS.get(pattern_id)
    if pat is None:
        return {"pattern": pattern_id, "matches": False,
                "reasons": [{"kind": "error", "text": f"unknown pattern: {pattern_id}"}]}

    fired = set(dev_verdict.get("signals", [])) if dev_verdict else set()

    have_required = {k: v for k, v in pat["required"].items()   if k in fired}
    miss_required = {k: v for k, v in pat["required"].items()   if k not in fired}
    have_support  = {k: v for k, v in pat["supporting"].items() if k in fired}
    miss_support  = {k: v for k, v in pat["supporting"].items() if k not in fired}

    n_req_met = len(have_required)
    n_sup_met = len(have_support)
    classified = (n_req_met >= pat["min_required"]) and \
                 (n_sup_met >= pat["min_supporting"])

    reasons: list[dict] = []
    for _sig, human in have_required.items():
        reasons.append({"kind": "present",  "text": human})
    for _sig, human in have_support.items():
        reasons.append({"kind": "present",  "text": human + " (supporting)"})
    for _sig, human in miss_required.items():
        reasons.append({"kind": "missing",  "text": human + " — required behaviour absent"})
    for _sig, human in miss_support.items():
        reasons.append({"kind": "missing",  "text": human + " — supporting evidence absent"})

    verdict_msg = ("Classification matches: this DOES exhibit "
                   + pat["label"].lower() + " behaviour.") if classified else \
                  ("Classification remains as-is: not enough "
                   + pat["label"].lower() + "-specific evidence.")

    return {
        "pattern":       pattern_id,
        "label":         pat["label"],
        "matches":       classified,
        "have_required": sorted(have_required.keys()),
        "missing_required": sorted(miss_required.keys()),
        "have_supporting": sorted(have_support.keys()),
        "missing_supporting": sorted(miss_support.keys()),
        "reasons":       reasons,
        "verdict_line":  verdict_msg,
    }


def list_patterns() -> list[dict[str, str]]:
    """List every attack pattern the explainability engine can answer for."""
    return [{"id": k, "label": v["label"]} for k, v in ATTACK_PATTERNS.items()]
