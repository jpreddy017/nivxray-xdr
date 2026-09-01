"""
P0.7 · Round 13 · Response Decision Engine + Recommendation Intelligence
──────────────────────────────────────────────────────────────────────

The decision engine consumes the full Response Context and emits ONE
of six deterministic outcomes:

  NO_RESPONSE_JUSTIFIED       — evidence does not warrant a response
  ANALYST_INVESTIGATION_REQ   — humans must investigate first
  DIRECT_ACTION_AVAILABLE     — capability + low-risk auto-approve
  PLAYBOOK_AVAILABLE          — orchestration needed
  APPROVAL_REQUIRED           — capability present, risk gate blocks
  CAPABILITY_UNAVAILABLE      — no integration wired for the required action

Owner-locked rules (§37, §42):
  * A decision is authorized only when supporting evidence is present.
  * Recommendations are guidance; a Response Decision authorizes intent.
  * No decision may be produced without both a verdict AND at least
    one entity to act on.
"""
from __future__ import annotations
from typing import Any

from .xdr_action_registry import (
    list_actions, action_entry, ApprovalPolicy,
)


DECISION_ENGINE_ID     = "nivxray::xdr::response_decision"
RECO_ENGINE_ID         = "nivxray::xdr::recommendation_intel"
DECISION_VERSION       = "1.0.0"


# ── Response Context Builder ────────────────────────────────────

async def build_response_context(db, incident_id: str) -> dict:
    """
    Pure projector: gather everything an evidence-first decision needs.
    Never fabricates missing inputs.  Missing pieces stay `null`.
    """
    inc = await db["workspace_cases"].find_one(
        {"id": incident_id}, {"_id": 0})
    if not inc:
        return {"state": "MISSING",
                    "reason": f"incident {incident_id} not found"}

    prov = inc.get("xdr_pipeline") or {}
    canonical_id = prov.get("canonical_event_id")
    canonical = None
    if canonical_id:
        canonical = await db["xdr_canonical_evidence"].find_one(
            {"event_id": canonical_id}, {"_id": 0})

    ice_matches: list[dict] = []
    for mid in (prov.get("ice_matches") or []):
        m = await db["xdr_correlation_matches"].find_one(
            {"match_id": mid}, {"_id": 0})
        if m:
            ice_matches.append(m)

    # Previous response executions on this incident.
    previous: list[dict] = []
    async for r in db["xdr_response_executions"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        previous.append(r)

    entities: list[dict] = []
    if canonical:
        net = canonical.get("network") or {}
        src = (net.get("src") or {}).get("ip")
        dst = (net.get("dst") or {}).get("ip")
        if src:
            entities.append({"kind": "ipv4", "value": src, "role": "source",
                                    "origin": "network.src.ip"})
        if dst:
            entities.append({"kind": "ipv4", "value": dst, "role": "destination",
                                    "origin": "network.dst.ip"})
        # Round 18 · additional entities for Mitigation Intelligence.
        # Threat name: taken from the triggering signature name (honest —
        # derived from evidence, not fabricated).
        sig = (canonical.get("security") or {}).get("signature") or {}
        if sig.get("name"):
            entities.append({"kind":   "threat_name",
                                    "value":  sig["name"],
                                    "role":   "trigger",
                                    "origin": "security.signature.name"})
        # File hash: only when present in evidence.
        file_obj = canonical.get("file") or {}
        fh = file_obj.get("hash") or file_obj.get("sha256")
        if fh:
            entities.append({"kind":   "hash",
                                    "value":  fh,
                                    "role":   "artifact",
                                    "origin": "file.hash"})
        # Process image / path: only when present in evidence.
        proc = canonical.get("process") or {}
        if proc.get("image"):
            entities.append({"kind":   "process",
                                    "value":  proc["image"],
                                    "role":   "artifact",
                                    "origin": "process.image"})
        if file_obj.get("path"):
            entities.append({"kind":   "path",
                                    "value":  file_obj["path"],
                                    "role":   "artifact",
                                    "origin": "file.path"})

    veee = prov.get("veee") or {}
    return {
        "state":            "READY",
        "incident_id":      incident_id,
        "incident_state":   inc.get("incident_state"),
        "incident_priority": inc.get("incident_priority"),
        "verdict": {
            "label":      veee.get("label"),
            "score":      veee.get("score"),
            "reason":     veee.get("reason"),
        },
        "entities":         entities,
        "ice_matches":      len(ice_matches),
        "previous_actions": len(previous),
        "provenance": {
            "trace_id":         prov.get("trace_id"),
            "canonical_event_id": canonical_id,
            "iue_id":           prov.get("iue_id"),
        },
        # Round 23.5 · Provenance & Evidence-State Lock-in.
        # Every downstream synthesized recommendation inherits this
        # chain so the analyst can traverse Canonical → IUE →
        # Correlation → Framework → Recommendation from any reco card
        # — same shape the attack-graph node exposes.
        "traversal_chain": {
            "canonical_event_id":     canonical_id,
            "iue_ref":                f"iue:{incident_id}"
                                                if prov.get("iue_id") else None,
            "correlation_match_ids":  list(prov.get("ice_matches") or []),
            "incident_id":            incident_id,
        },
        "honesty_note":
            "Response Context is a projection of persisted evidence. "
            "Missing pieces stay null — no fabrication.",
    }


# ── Recommendation Intelligence ─────────────────────────────────

def recommend(context: dict) -> list[dict]:
    """
    Emit guidance based on the honest context.  Recommendations are
    guidance ONLY — they do not authorise execution.  A Recommendation
    remains valid even when no capability exists.
    """
    if context.get("state") != "READY":
        return []
    verdict = context.get("verdict") or {}
    label   = (verdict.get("label") or "").upper()
    entities = context.get("entities") or []
    ice_n   = context.get("ice_matches") or 0

    recos: list[dict] = []

    if label == "MALICIOUS":
        for e in entities:
            if e["role"] == "source" and e["kind"].startswith("ipv"):
                recos.append({
                    "id":     f"reco-block-src-{e['value']}",
                    "text":   f"Block traffic from source IP {e['value']} "
                                 f"at the network edge",
                    "confidence":    "HIGH",
                    "supported_by":  ["verdict.label", "network.src.ip"],
                    "suggested_action": "IP_BLOCK",
                    "engine_id":     RECO_ENGINE_ID,
                })
    if label in ("MALICIOUS", "SUSPICIOUS"):
        # OSINT enrichment BEFORE any destructive action — deterministic
        # low-risk step that lifts investigation confidence.
        for e in entities:
            if e["kind"].startswith("ipv"):
                recos.append({
                    "id":     f"reco-osint-ip-{e['value']}",
                    "text":   f"Enrich {e['role']} IP {e['value']} across "
                                 f"public OSINT (Talos, DShield, URLhaus, VT, AbuseIPDB)",
                    "confidence":    "HIGH",
                    "supported_by":  [f"network.{e['role']}.ip"],
                    "suggested_action": "OSINT_ENRICH_IP",
                    "engine_id":     RECO_ENGINE_ID,
                })
        # Watch-list every source/dest IP — deterministic guidance.
        for e in entities:
            recos.append({
                "id":     f"reco-watchlist-{e['role']}-{e['value']}",
                "text":   f"Add {e['role']} {e['kind']} {e['value']} to "
                             f"NivXRay internal watchlist",
                "confidence":    "MEDIUM",
                "supported_by":  [f"network.{e['role']}.ip"],
                "suggested_action": "IOC_ADD_WATCHLIST",
                "engine_id":     RECO_ENGINE_ID,
            })
    if label == "SUSPICIOUS" and ice_n == 0:
        recos.append({
            "id":     "reco-analyst-triage",
            "text":   "Analyst triage required — single-signal alert with "
                        "no correlation lift; investigate before responding",
            "confidence":    "HIGH",
            "supported_by":  ["verdict.label", "ice.matches"],
            "suggested_action": None,       # human step, not automatable
            "engine_id":     RECO_ENGINE_ID,
        })
    return recos


# ── Response Decision Engine ────────────────────────────────────

_VALID_DECISIONS = {
    "NO_RESPONSE_JUSTIFIED",
    "ANALYST_INVESTIGATION_REQUIRED",
    "DIRECT_ACTION_AVAILABLE",
    "PLAYBOOK_AVAILABLE",
    "APPROVAL_REQUIRED",
    "CAPABILITY_UNAVAILABLE",
}


def decide(context: dict, recommendations: list[dict]) -> dict:
    """
    Deterministic decision — same context + recos → byte-identical.
    Returns a decision record with `decision`, `reason`,
    `required_action`, `policy_status`, `evidence_refs`.
    """
    if context.get("state") != "READY":
        return _bail("NO_RESPONSE_JUSTIFIED",
                          "response context is not READY",
                          context, None, None)

    verdict = context.get("verdict") or {}
    label   = (verdict.get("label") or "").upper()

    # Bail: verdict is INCONCLUSIVE / LIKELY_BENIGN — no action.
    if label not in ("MALICIOUS", "SUSPICIOUS"):
        return _bail("NO_RESPONSE_JUSTIFIED",
                          f"verdict.label={label} does not authorise response",
                          context, None, None)

    # SUSPICIOUS with zero correlation → OSINT enrichment first (LOW-RISK
    # auto-approve), then require analyst review.
    if label == "SUSPICIOUS" and (context.get("ice_matches") or 0) == 0:
        # If we have an OSINT recommendation, promote it — enrichment is
        # non-destructive and lifts investigation before analyst triage.
        osint_reco = next((r for r in recommendations
                                    if r.get("suggested_action", "").startswith("OSINT_")),
                                   None)
        if osint_reco:
            entry = action_entry(osint_reco["suggested_action"])
            if entry:
                actions = {a["action_id"]: a for a in list_actions()}
                live = actions.get(osint_reco["suggested_action"]) or {}
                if live.get("capability_available"):
                    return _mk("DIRECT_ACTION_AVAILABLE",
                                   entry["approval_policy"],
                                   f"OSINT enrichment authorised before analyst "
                                   f"review — {osint_reco['suggested_action']} is "
                                   "non-destructive and auto-approvable",
                                   context, osint_reco["suggested_action"], entry)
        return _bail("ANALYST_INVESTIGATION_REQUIRED",
                          "SUSPICIOUS with no correlation lift — analyst must "
                          "validate before authorising response",
                          context, None, None)

    # Choose the strongest recommendation with a suggested_action.
    reco = next((r for r in recommendations if r.get("suggested_action")),
                    None)
    if not reco:
        return _bail("ANALYST_INVESTIGATION_REQUIRED",
                          "no recommendation carries an actionable "
                          "suggested_action",
                          context, None, None)

    action_id = reco["suggested_action"]
    entry     = action_entry(action_id)
    if not entry:
        return _bail("CAPABILITY_UNAVAILABLE",
                          f"action '{action_id}' is not in the registry",
                          context, action_id, None)

    # Runtime capability check — HONEST.
    actions = {a["action_id"]: a for a in list_actions()}
    live = actions.get(action_id) or {}
    if not live.get("capability_available"):
        return _bail("CAPABILITY_UNAVAILABLE",
                          live.get("capability_reason")
                             or f"integration '{entry['required_integration']}'"
                                 " is not configured",
                          context, action_id, entry)

    # Approval routing.
    policy = entry["approval_policy"]
    if policy in (ApprovalPolicy.APPROVAL_REQUIRED.value,
                        ApprovalPolicy.DUAL_APPROVAL.value):
        return _mk("APPROVAL_REQUIRED", policy,
                       f"action {action_id} requires {policy}",
                       context, action_id, entry)

    return _mk("DIRECT_ACTION_AVAILABLE", policy,
                   f"action {action_id} is auto-approvable and its "
                   "capability is configured",
                   context, action_id, entry)


def _bail(decision: str, reason: str, ctx: dict,
             action_id: str | None, entry: dict | None) -> dict:
    return _mk(decision, "NOT_APPLICABLE", reason, ctx, action_id, entry)


def _mk(decision: str, policy_status: str, reason: str,
          ctx: dict, action_id: str | None, entry: dict | None) -> dict:
    assert decision in _VALID_DECISIONS, decision
    return {
        "engine_id":        DECISION_ENGINE_ID,
        "engine_version":   DECISION_VERSION,
        "decision":         decision,
        "reason":           reason,
        "policy_status":    policy_status,
        "incident_id":      ctx.get("incident_id"),
        "required_action":  action_id,
        "action_entry":     entry,
        "evidence_refs":    ctx.get("provenance") or {},
        "verdict":          ctx.get("verdict") or {},
        "honesty_note":
            "Deterministic decision.  No fabrication.  If a capability "
            "isn't wired, the decision is CAPABILITY_UNAVAILABLE.",
    }
