"""
DIE · Attack Intent Engine (Phase B.7 · 2026-02-16 pm-late)
────────────────────────────────────────────────────────────
Deterministic synthesis of a chain envelope into a single
**Primary Objective** answer.  SOC analysts think in objectives
("Ransomware Deployment") not techniques ("T1490").  This module
closes that gap without any LLM.

Rules — evaluated in priority order.  The first matching rule wins;
subsequent rules do NOT override.  Every rule declares:

    - name (Primary Objective label)
    - tactic_gates (ATT&CK tactics that MUST all be present)
    - dkp_boosts  (DKP pattern ids that add confidence when present)
    - contra      (tactics that DISQUALIFY when their weight beats
                   the gate weight — e.g. Reconnaissance-only chains
                   must not upgrade to Ransomware Deployment)

Output shape:

    {
      "objective":       "Ransomware Deployment",
      "confidence":      0.96,
      "evidence":        [ "Shadow Copy Removal", ...],
      "mitre":           ["T1490","T1059.001",...],
      "observed_phases": ["Discovery","Execution","Impact",...],
      "missing_phases":  ["Exfiltration","Lateral Movement"],
      "progress":        0.66,   # % of the standard 12 ATT&CK tactics
      "rule":            "ransomware_deployment"
    }
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

# ── canonical ATT&CK tactic set (deterministic order) ─────────────
TACTICS: List[str] = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "Impair Defenses",
]


# ── objective rules (priority-ordered) ────────────────────────────
# `weight` blends the rule's own confidence; `dkp_boosts` add on top
# when the specified DKP id appears in the chain match set.
_RULES = [
    # ── Double-Extortion Ransomware (2026-08-26) ──────────────────
    # Modern ransomware TTP: steal data first, then encrypt.  Fires
    # when BOTH Impact AND Exfiltration tactics are observed — this
    # is the "leak-site + encryption" pattern (LockBit, BlackCat,
    # Play, Akira, Rhysida etc.).  Declared BEFORE the plain
    # ransomware_deployment rule so double-extortion always wins
    # when the evidence supports it.
    {
        "id":   "double_extortion_ransomware",
        "name": "Double-Extortion Ransomware",
        "categories": ["Impact", "Exfiltration", "Collection",
                        "Command and Control"],
        "requires": ["Impact", "Exfiltration"],
        "supports": ["Collection", "Command and Control", "Discovery",
                     "Credential Access", "Lateral Movement",
                     "Defense Evasion", "Impair Defenses"],
        "dkp_boosts": {
            "dkp.shadow_copy_removal":     0.20,
            "dkp.rclone_exfil":            0.15,
            "dkp.mega_upload":             0.10,
            "dkp.schtasks_persistence":    0.03,
            "dkp.reflective_loader":       0.03,
        },
        "base": 0.70,
    },
    {
        "id":   "ransomware_deployment",
        "name": "Ransomware Deployment",
        "categories": ["Impact", "Execution", "Defense Evasion"],
        "requires": ["Impact"],
        "supports": ["Discovery", "Execution", "Defense Evasion",
                     "Persistence", "Impair Defenses"],
        "dkp_boosts": {
            "dkp.shadow_copy_removal":     0.35,
            "dkp.schtasks_persistence":    0.05,
            "dkp.ps_encoded_command":      0.03,
            "dkp.reflective_loader":       0.05,
        },
        "base": 0.55,
    },
    {
        "id":   "credential_theft",
        "name": "Credential Theft",
        "categories": ["Credential Access", "Discovery", "Defense Evasion"],
        "requires": ["Credential Access"],
        "supports": ["Discovery", "Defense Evasion", "Execution",
                     "Impair Defenses"],
        "dkp_boosts": {
            "dkp.amsi_bypass":             0.05,
        },
        "base": 0.60,
    },
    {
        "id":   "lateral_movement",
        "name": "Lateral Movement",
        "categories": ["Lateral Movement", "Discovery", "Execution"],
        "requires": ["Lateral Movement"],
        "supports": ["Discovery", "Execution", "Credential Access"],
        "dkp_boosts": {},
        "base": 0.65,
    },
    {
        "id":   "data_exfiltration",
        "name": "Data Exfiltration",
        "categories": ["Exfiltration", "Collection", "Command and Control"],
        "requires": ["Exfiltration"],
        "supports": ["Collection", "Command and Control"],
        "dkp_boosts": {},
        "base": 0.70,
    },
    {
        "id":   "c2_beaconing",
        "name": "Command & Control Beaconing",
        "categories": ["Command and Control", "Execution", "Defense Evasion"],
        "requires": ["Command and Control"],
        "supports": ["Execution", "Persistence", "Defense Evasion"],
        "dkp_boosts": {
            "dkp.ps_download_cradle":      0.10,
            "dkp.reflective_loader":       0.08,
            "dkp.amsi_bypass":             0.05,
            "dkp.regsvr32_squiblydoo":     0.10,
            "dkp.mshta_remote":            0.10,
        },
        "base": 0.55,
    },
    {
        "id":   "persistence_establishment",
        "name": "Persistence Establishment",
        "categories": ["Persistence", "Defense Evasion", "Execution"],
        "requires": ["Persistence"],
        "supports": ["Defense Evasion", "Execution", "Privilege Escalation"],
        "dkp_boosts": {
            "dkp.schtasks_persistence":    0.10,
            "dkp.cron_persistence":        0.10,
        },
        "base": 0.55,
    },
    # ── Deployment & Execution Workflow (2026-03-01) ──
    # Matches multi-stage installer / loader / launcher chains that
    # combine deployment (archive extraction, portable runtime setup)
    # with execution (browser launch, script execution) and defense
    # evasion (headless, cleanup, execution-policy bypass).  Common
    # in modern data-theft / infostealer deployment scripts and
    # portable-installer trojans.  Does NOT require Impact.  Declared
    # before the "reconnaissance" fallback so multi-behavior chains
    # win over pure-discovery classification.
    {
        "id":   "deployment_and_execution",
        "name": "Deployment and Execution Workflow",
        "categories": ["Execution", "Deployment", "Defense Evasion", "Discovery"],
        "requires": ["Execution"],
        "supports": ["Defense Evasion", "Discovery", "Persistence"],
        "dkp_boosts": {
            "dkp.ps_execution_policy_bypass":   0.05,
            "dkp.headless_browser_launch":      0.05,
        },
        "base": 0.60,
    },
    # ── Multi-Stage Intrusion (2026-08-26) ────────────────────────
    # Broad-coverage advisory fallback for reports that walk through
    # ≥5 distinct ATT&CK tactics (typical ransomware / APT advisory
    # narratives) but do NOT yet trigger the impact/exfil-gated rules
    # above.  Fires BEFORE the pure-reconnaissance fallback so
    # investigator-facing summaries show a meaningful objective
    # rather than "Reconnaissance / Discovery".  Requires no single
    # tactic — the ``requires`` gate is empty; a separate breadth
    # gate inside classify_intent() enforces the ≥5 threshold.
    {
        "id":   "multi_stage_intrusion",
        "name": "Multi-Stage Intrusion",
        "categories": ["Multi-tactic"],
        "requires": [],                   # breadth gate handled below
        "supports": ["Initial Access", "Execution", "Persistence",
                     "Privilege Escalation", "Defense Evasion",
                     "Credential Access", "Discovery",
                     "Lateral Movement", "Collection",
                     "Command and Control", "Exfiltration",
                     "Impact", "Impair Defenses"],
        "dkp_boosts": {},
        "base": 0.55,
        # Minimum distinct-tactics count required for the rule to
        # apply.  Kept as an attribute (not a gate list) so existing
        # rule-evaluation code stays untouched.
        "min_tactics_breadth": 5,
    },
    {
        "id":   "reconnaissance",
        "name": "Reconnaissance / Discovery",
        "categories": ["Discovery"],
        "requires": ["Discovery"],
        "supports": [],
        # Reconnaissance is the *fallback* interpretation — only
        # picked when nothing else matches.
        "dkp_boosts": {},
        "base": 0.55,
    },
]


# ── public API ────────────────────────────────────────────────────
def classify_intent(chain_env: Dict[str, Any]) -> Dict[str, Any]:
    """Return the Attack Intent record for a chain envelope.

    ``chain_env`` is the object returned by
    ``services.die.chain.analyze_chain``.  For non-chain inputs the
    caller can wrap a single-step envelope in the same shape (see
    ``classify_intent_from_analyze``).
    """
    if not chain_env or not chain_env.get("steps"):
        return _empty()

    tactics_seen: Dict[str, int] = {}
    for s in chain_env["steps"]:
        t = s.get("intent")
        if t:
            tactics_seen[t] = tactics_seen.get(t, 0) + 1

    observed = sorted(tactics_seen.keys())
    missing  = [t for t in TACTICS if t not in tactics_seen]
    # Standard 12 tactics (drop Impair Defenses from the progress
    # denominator — it doubles up with Defense Evasion for scoring).
    denom = 12
    progress = round(min(1.0, len(observed) / denom), 3)

    dkp_ids = {m["id"] for m in (chain_env["aggregate"]["dkp_matches"] or [])}
    mitre_ids = sorted({t["id"] for t in
                        (chain_env["aggregate"]["techniques"] or [])})

    # Evaluate rules in priority order.  First rule whose `requires`
    # tactics are all present wins.  Confidence = base + DKP boosts.
    for rule in _RULES:
        if not all(gate in tactics_seen for gate in rule["requires"]):
            continue
        # Breadth gate — rules with no `requires` list (e.g. the
        # broad-coverage "multi_stage_intrusion") declare a minimum
        # distinct-tactics count instead.  Skip when unmet.
        min_breadth = rule.get("min_tactics_breadth", 0)
        if min_breadth and len(tactics_seen) < min_breadth:
            continue
        confidence = rule["base"]
        support_hits = sum(1 for s in rule["supports"] if s in tactics_seen)
        confidence += 0.05 * support_hits
        for dkp_id, boost in rule["dkp_boosts"].items():
            if dkp_id in dkp_ids:
                confidence += boost
        confidence = min(0.99, round(confidence, 3))

        evidence = _build_evidence(chain_env, rule, tactics_seen)

        return {
            "objective":       rule["name"],
            "rule":             rule["id"],
            "categories":      list(rule.get("categories") or []),
            "confidence":      confidence,
            "evidence":        evidence,
            "mitre":           mitre_ids,
            "observed_phases": observed,
            "missing_phases":  missing,
            "progress":        progress,
        }

    # Nothing fired — return a low-confidence "Uncategorised" record
    # so consumers always get a shape.
    return {
        "objective":       "Uncategorised",
        "rule":            "none",
        "categories":      [],
        "confidence":      0.30,
        "evidence":        [],
        "mitre":           mitre_ids,
        "observed_phases": observed,
        "missing_phases":  missing,
        "progress":        progress,
    }


def classify_intent_from_analyze(env: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience wrapper that reads the top-level ``analyze()``
    envelope (which may or may not be a chain)."""
    if env.get("chain"):
        return classify_intent(env["chain"])
    # Synthesize a chain from a flat envelope so the same rules
    # apply.  We build ONE synthetic step per unique tactic present
    # in the technique list so a rich, augmented ``techniques[]``
    # (see investigation_results.render) contributes ALL its
    # tactics to ``tactics_seen`` — not just the classic PS-AST
    # verdict.  This is what lets multi-behavior chains (deployment
    # + execution + defense-evasion + discovery) match the correct
    # objective rule.
    tactics_from_techniques: List[str] = []
    seen: set = set()
    for t in env.get("techniques") or []:
        tac = (t.get("tactic") or "").strip()
        if tac and tac not in seen:
            seen.add(tac)
            tactics_from_techniques.append(tac)
    if not tactics_from_techniques:
        # Fall back to the classic single-tactic guess for backwards
        # compatibility with simple flat envelopes.
        tactics_from_techniques = [_flat_step_tactic(env)]
    fake_steps = [{"intent": tac} for tac in tactics_from_techniques]
    synthesized = {
        "steps": fake_steps,
        "aggregate": {
            "techniques":  env.get("techniques") or [],
            "dkp_matches": env.get("dkp_matches") or [],
        },
    }
    return classify_intent(synthesized)


# ── helpers ───────────────────────────────────────────────────────
def _flat_step_tactic(env: Dict[str, Any]) -> str:
    """Best-effort tactic for a flat (non-chain) envelope."""
    from .chain import classify_intent as step_intent  # avoid cycle
    text = ""
    ast = env.get("ast") or {}
    for c in ast.get("cmdlets", []) or []:
        text += " " + c.get("name","")
    for c in ast.get("commands", []) or []:
        text += " " + c.get("text","")
    return step_intent(env, text)


def _build_evidence(chain_env: Dict[str, Any], rule: Dict[str, Any],
                    tactics_seen: Dict[str, int]) -> List[str]:
    """Turn the matched signals into a small, human-readable evidence
    list the frontend can render as bullet points."""
    ev: List[str] = []
    # DKP hits that contributed a boost — highest signal first.
    for m in chain_env["aggregate"]["dkp_matches"] or []:
        if m["id"] in rule["dkp_boosts"]:
            ev.append(m["name"])
    # Tactic-based evidence — deterministic ordering.
    for gate in rule["requires"]:
        ev.append(f"{gate} observed ({tactics_seen[gate]} step(s))")
    for sup in rule["supports"]:
        if sup in tactics_seen:
            ev.append(f"{sup} observed ({tactics_seen[sup]} step(s))")
    # Deduplicate while preserving order.
    seen = set(); out = []
    for e in ev:
        if e in seen: continue
        seen.add(e); out.append(e)
    return out[:12]


def _empty() -> Dict[str, Any]:
    return {
        "objective":       "Uncategorised",
        "rule":            "none",
        "confidence":      0.0,
        "evidence":        [],
        "mitre":           [],
        "observed_phases": [],
        "missing_phases":  list(TACTICS),
        "progress":        0.0,
    }
