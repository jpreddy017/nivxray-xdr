"""
P0 · Round 18 · Mitigation & Exclusion Intelligence
────────────────────────────────────────────────────

**KNOWLEDGE LAYER — NOT AN ENGINE.**

This module feeds the existing `xdr_recommendation_synthesis.py`
synthesizer.  It never fabricates recommendations, never executes
anything, and never produces verdicts.  It ONLY enriches recommendations
whose `suggested_action` is an *exclusion / allow-list / suppression*
with:

    RISK_BAND · VISIBILITY_IMPACT · SAFER_ALTERNATIVE ·
    APPROVAL_POLICY · ANALYST_WARNING

Non-exclusion recommendations (ISOLATE_ENDPOINT, IP_BLOCK,
COLLECT_FORENSIC_SNAPSHOT, OSINT_ENRICH_IP, etc.) are returned
unchanged — the risk model does NOT apply to ordinary mitigations
per Round 18 architectural guardrail.

Alignment: Cisco Secure Endpoint exclusion documentation — an
exclusion's real risk depends on
    (a) which security engine it disables/narrows
    (b) how broad its scope is
    (c) whether the detection was signature-based, behavioral,
        ML/cloud, or heuristic
Broad path/threat/wildcard exclusions have HIGH-to-CRITICAL security
risk and REQUIRE a safer alternative before the analyst can accept.

Owner-locked (§Round 18, PRD lines 21-28):
  * SHA256 Cloud Lookup → Application Allow List  → MEDIUM
  * Behavioral Protection → Process Exclusion     → HIGH
  * Path exclusion (subtree)                       → HIGH
  * Threat exclusion (future TP suppression)       → CRITICAL
"""
from __future__ import annotations
from typing import Any


INTEL_ENGINE_ID = "nivxray::xdr::mitigation_intelligence"
INTEL_VERSION   = "1.0.0"


# ── Risk bands ──────────────────────────────────────────────────
LOW      = "LOW"
MEDIUM   = "MEDIUM"
HIGH     = "HIGH"
CRITICAL = "CRITICAL"


# ── Exclusion action identifiers ───────────────────────────────
# Any suggested_action ∈ this set is treated as an exclusion.
# Ordinary mitigations (IP_BLOCK, ISOLATE_ENDPOINT, etc.) are NOT
# in this set and are returned unchanged by enrich_recommendation.
EXCLUSION_ACTIONS: set[str] = {
    "APPLICATION_ALLOW_LIST_ADD",
    "PROCESS_EXCLUSION_ADD",
    "PATH_EXCLUSION_ADD",
    "THREAT_EXCLUSION_ADD",
    "WILDCARD_EXCLUSION_ADD",
}


# ── Exclusion Risk Model (locked in PRD §Round 18) ─────────────
#
# Every entry must declare:
#   exclusion_type      · human-readable category
#   scope               · single-hash / process / subtree / threat-name
#   detection_method    · signature / behavioral / ml_cloud / heuristic
#   affected_engine     · Cloud IOC / TETRA / SPP / Behavioural Protection
#   visibility_impact   · what NivXRay stops seeing
#   security_risk       · LOW / MEDIUM / HIGH / CRITICAL band
#   safer_alternative   · narrower option to propose instead
#   approval_policy     · APPROVAL_REQUIRED / DUAL_APPROVAL
#   warning_banner      · unmistakable text shown when band ≥ HIGH
#
# Ordered from narrowest / safest to broadest / riskiest.

_RISK_MODEL: dict[str, dict[str, Any]] = {
    "APPLICATION_ALLOW_LIST_ADD": {
        "exclusion_type":    "Application Allow List",
        "scope":             "single_hash",
        "detection_method":  "SHA256 Cloud Lookup",
        "affected_engine":   "Cloud IOC · ML classifier",
        "visibility_impact":
            "ML + cloud reputation is bypassed for exactly this hash. "
            "Behavioural Protection, TETRA and network telemetry remain "
            "fully in scope.",
        "security_risk":     MEDIUM,
        "safer_alternative":
            "Confirm the sample is a legitimate signed build (verify "
            "publisher + signature + originating team) before allow-listing.",
        "approval_policy":   "APPROVAL_REQUIRED",
        "warning_banner":    None,
    },
    "PROCESS_EXCLUSION_ADD": {
        "exclusion_type":    "Process Exclusion",
        "scope":             "entire_process",
        "detection_method":  "Behavioural Protection · SPP",
        "affected_engine":   "Behavioural Protection · System Process "
                             "Protection · Exploit Prevention",
        "visibility_impact":
            "All behavioural telemetry for this process is silenced — "
            "process-tree evidence, injection, credential-dumping and "
            "living-off-the-land patterns will no longer trigger.",
        "security_risk":     HIGH,
        "safer_alternative":
            "Narrow to a specific parent → child chain or a specific "
            "command-line pattern instead of allow-listing the entire "
            "process image.",
        "approval_policy":   "APPROVAL_REQUIRED",
        "warning_banner":
            "HIGH RISK — This exclusion may reduce security "
            "visibility/detection coverage. Consider the narrower "
            "alternative before accepting.",
    },
    "PATH_EXCLUSION_ADD": {
        "exclusion_type":    "Path Exclusion",
        "scope":             "filesystem_subtree",
        "detection_method":  "TETRA · file scanning",
        "affected_engine":   "TETRA on-access scan · Cloud IOC file "
                             "reputation · scheduled scan",
        "visibility_impact":
            "All files and sub-directories under the path are excluded "
            "from scanning — new droppers or side-loaded DLLs placed in "
            "the excluded subtree will not be inspected.",
        "security_risk":     HIGH,
        "safer_alternative":
            "Exclude the specific file hash(es) of the known-good "
            "installer instead of the entire directory tree.",
        "approval_policy":   "APPROVAL_REQUIRED",
        "warning_banner":
            "HIGH RISK — Broad path exclusions disable file scanning "
            "across the entire subtree. Consider hash-scoped exclusion "
            "instead.",
    },
    "WILDCARD_EXCLUSION_ADD": {
        "exclusion_type":    "Wildcard Exclusion",
        "scope":             "pattern_match",
        "detection_method":  "TETRA · Behavioural Protection · Exploit "
                             "Prevention",
        "affected_engine":   "TETRA on-access scan · Behavioural "
                             "Protection · Exploit Prevention",
        "visibility_impact":
            "Any file or process matching the wildcard pattern is "
            "silently ignored. Broad Exploit Prevention wildcards "
            "require extensive testing (Cisco guidance).",
        "security_risk":     HIGH,
        "safer_alternative":
            "Replace the wildcard with the concrete literal path or "
            "hash — never keep unbounded * or ? patterns in production "
            "exclusions.",
        "approval_policy":   "APPROVAL_REQUIRED",
        "warning_banner":
            "HIGH RISK — Wildcard exclusions can silence detections "
            "across many unrelated files/processes. Replace with a "
            "narrower literal scope.",
    },
    "THREAT_EXCLUSION_ADD": {
        "exclusion_type":    "Threat Name Exclusion",
        "scope":             "future_detections",
        "detection_method":  "Signature · Cloud IOC · Behavioural "
                             "Protection · ML classifier",
        "affected_engine":   "All engines that emit this threat name",
        "visibility_impact":
            "FUTURE true-positive detections of this threat name across "
            "every endpoint may be suppressed. A single true positive "
            "elsewhere in the estate can be silently missed.",
        "security_risk":     CRITICAL,
        "safer_alternative":
            "Do NOT suppress by threat name. Investigate why this "
            "sample was flagged, verify legitimacy, and — if genuinely "
            "benign — allow-list the specific SHA256 only.",
        "approval_policy":   "DUAL_APPROVAL",
        "warning_banner":
            "CRITICAL RISK — Threat-name exclusions can silence future "
            "true positives across the entire estate. Dual approval "
            "required. Prefer hash-scoped Application Allow List.",
    },
}


# ── Public API ──────────────────────────────────────────────────

def is_exclusion(action_id: str) -> bool:
    """
    Round 18 architectural guardrail: the risk model activates ONLY
    when the recommendation's suggested_action is an exclusion /
    allow-list / suppression.  Ordinary mitigations (ISOLATE_ENDPOINT,
    COLLECT_FORENSIC_SNAPSHOT, IP_BLOCK, OSINT_ENRICH_*, etc.) are
    NOT exclusions and MUST NOT receive a risk block.
    """
    return action_id in EXCLUSION_ACTIONS


def risk_model_for(action_id: str) -> dict[str, Any] | None:
    """Return a deep copy of the risk model for an exclusion action,
    or None if the action is not an exclusion."""
    entry = _RISK_MODEL.get(action_id)
    return dict(entry) if entry else None


def enrich_recommendation(reco: dict) -> dict:
    """
    Attach `risk_analysis` to a synthesized recommendation IF and
    ONLY IF its `suggested_action` is in EXCLUSION_ACTIONS.  Return
    the reco unchanged otherwise — this is the architectural guardrail
    (ISOLATE_ENDPOINT, IP_BLOCK etc. remain risk-free).

    The enriched shape (added fields):
        risk_analysis: {
            engine_id, engine_version,
            exclusion_type, scope, detection_method, affected_engine,
            visibility_impact, security_risk, safer_alternative,
            approval_policy, warning_banner, analyst_decision
        }
        risk_band   · shortcut for UI inline badge (LOW/MEDIUM/HIGH/CRITICAL)
    """
    action_id = reco.get("suggested_action")
    if not is_exclusion(action_id):
        return reco

    model = risk_model_for(action_id)
    if not model:
        # Defensive: action is in EXCLUSION_ACTIONS but has no model.
        # Return the reco with an honest empty risk block rather than
        # fabricating a band.
        reco["risk_analysis"] = {
            "engine_id":       INTEL_ENGINE_ID,
            "engine_version":  INTEL_VERSION,
            "security_risk":   "UNKNOWN",
            "note":
                f"action {action_id} declared as exclusion but no risk "
                f"model registered — honest UNKNOWN state.",
        }
        reco["risk_band"] = "UNKNOWN"
        return reco

    # Analyst decision starts empty — Round 18 records it when the
    # analyst accepts / rejects / defers via the existing decision
    # endpoint.
    reco["risk_analysis"] = {
        "engine_id":         INTEL_ENGINE_ID,
        "engine_version":    INTEL_VERSION,
        "exclusion_type":    model["exclusion_type"],
        "scope":             model["scope"],
        "detection_method":  model["detection_method"],
        "affected_engine":   model["affected_engine"],
        "visibility_impact": model["visibility_impact"],
        "security_risk":     model["security_risk"],
        "safer_alternative": model["safer_alternative"],
        "approval_policy":   model["approval_policy"],
        "warning_banner":    model["warning_banner"],
        "analyst_decision":  None,
    }
    reco["risk_band"] = model["security_risk"]
    return reco


def enrich_all(recos: list[dict]) -> list[dict]:
    """Enrich every reco in a list; ordinary mitigations pass through
    unchanged."""
    return [enrich_recommendation(dict(r)) for r in recos]


def summary() -> dict:
    """Read-only introspection endpoint helper."""
    return {
        "engine_id":       INTEL_ENGINE_ID,
        "engine_version":  INTEL_VERSION,
        "role":            "KNOWLEDGE_LAYER",
        "not_an_engine":   True,
        "exclusion_actions": sorted(EXCLUSION_ACTIONS),
        "risk_model": {
            aid: {
                "exclusion_type":  m["exclusion_type"],
                "security_risk":   m["security_risk"],
                "approval_policy": m["approval_policy"],
            }
            for aid, m in _RISK_MODEL.items()
        },
        "guardrail":
            "risk_analysis is attached ONLY when suggested_action is an "
            "exclusion.  Ordinary mitigations (ISOLATE_ENDPOINT, IP_BLOCK, "
            "COLLECT_FORENSIC_SNAPSHOT, OSINT_ENRICH_*) are returned "
            "unchanged.",
    }
