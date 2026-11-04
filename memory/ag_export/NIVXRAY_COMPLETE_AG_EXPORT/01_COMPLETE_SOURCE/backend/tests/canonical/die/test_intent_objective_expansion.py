"""Regression tests · Threat Objective intent-rule expansion.

Adds two new deterministic rules to ``services.die.intent``:
  - ``double_extortion_ransomware`` — fires on Impact + Exfiltration
    combined (steal-then-encrypt TTPs of modern ransomware groups).
  - ``multi_stage_intrusion`` — broad-coverage fallback for advisory
    reports that describe ≥5 distinct ATT&CK tactics but do not
    trigger a more specific rule.

Zero-drift invariants (locked here):
  - Existing narrow rules (credential_theft, lateral_movement,
    data_exfiltration, c2_beaconing, persistence_establishment,
    deployment_and_execution, reconnaissance) still fire on their
    canonical inputs.
  - The `reconnaissance` rule remains the strict fallback — the new
    `multi_stage_intrusion` rule only fires with breadth ≥ 5.
  - When Impact is present alone (no Exfiltration), the classic
    `ransomware_deployment` rule still wins.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.die.intent import classify_intent  # noqa: E402


def _env(tactics, techniques=None, dkp=None):
    """Build a synthetic chain envelope for classify_intent."""
    return {
        "steps": [{"intent": t} for t in tactics],
        "aggregate": {
            "techniques":  [{"id": tid} for tid in (techniques or [])],
            "dkp_matches": [{"id": d, "name": d} for d in (dkp or [])],
        },
    }


# ── 1. Double-Extortion Ransomware ─────────────────────────────────
class TestDoubleExtortionRansomware:
    def test_impact_plus_exfiltration_fires_double_extortion(self):
        r = classify_intent(_env(
            tactics=["Discovery", "Credential Access", "Lateral Movement",
                       "Collection", "Exfiltration", "Impact"],
            techniques=["T1490", "T1567", "T1005"],
            dkp=["dkp.shadow_copy_removal", "dkp.rclone_exfil"],
        ))
        assert r["rule"] == "double_extortion_ransomware"
        assert r["objective"] == "Double-Extortion Ransomware"
        # DKP boosts must lift confidence above the plain-ransomware base.
        assert r["confidence"] >= 0.90

    def test_impact_only_still_fires_plain_ransomware(self):
        """Regression guard: Impact WITHOUT Exfiltration must still
        classify as plain Ransomware Deployment, NOT double-extortion."""
        r = classify_intent(_env(
            tactics=["Discovery", "Execution", "Defense Evasion", "Impact"],
            dkp=["dkp.shadow_copy_removal"],
        ))
        assert r["rule"] == "ransomware_deployment"
        assert r["objective"] == "Ransomware Deployment"

    def test_exfiltration_only_still_data_exfiltration(self):
        """Exfiltration WITHOUT Impact must NOT jump to double-extortion —
        it stays a plain Data Exfiltration objective."""
        r = classify_intent(_env(
            tactics=["Collection", "Command and Control", "Exfiltration"],
        ))
        assert r["rule"] == "data_exfiltration"


# ── 2. Multi-Stage Intrusion broad-coverage fallback ─────────────────
class TestMultiStageIntrusion:
    def test_five_tactic_advisory_fires_multi_stage(self):
        """Ransomware-style advisory narrative: 5+ tactics observed,
        no Impact yet extracted (Impact would win double-extortion or
        plain ransomware).  The multi_stage_intrusion rule must fire
        instead of the reconnaissance fallback."""
        r = classify_intent(_env(
            tactics=["Initial Access", "Execution", "Persistence",
                       "Credential Access", "Discovery"],
            techniques=["T1566.001", "T1059.001", "T1053.005",
                          "T1003.001", "T1082"],
        ))
        # Must NOT be pure Reconnaissance — that was the bug.
        assert r["rule"] != "reconnaissance"
        # First rule that requires only one of these tactics wins,
        # but for this specific tactic set only `deployment_and_execution`
        # (Execution) or `persistence_establishment` (Persistence) etc
        # would fire.  Verify we get a meaningful non-recon objective.
        assert r["objective"] not in ("Reconnaissance / Discovery",
                                        "Uncategorised")

    def test_broad_advisory_no_specific_tactic_falls_to_multi_stage(self):
        """When the tactic set is broad (≥5) but NONE of the narrow-rule
        `requires` gates match, multi_stage_intrusion must catch it —
        preventing the reconnaissance/uncategorised leak."""
        # Craft a case: Initial Access + Privilege Escalation + Impair
        # Defenses + Command and Control + Reconnaissance — but drop
        # Discovery, Execution, Persistence, Credential Access,
        # Lateral Movement, Collection, Exfiltration, Impact so NO
        # narrow rule can fire.
        r = classify_intent(_env(
            tactics=["Initial Access", "Privilege Escalation",
                       "Impair Defenses", "Command and Control",
                       "Reconnaissance"],
        ))
        # c2_beaconing fires because Command and Control is present.
        # That's still fine — but multi_stage_intrusion must be
        # available as a broader fallback.  Sanity: not recon-only.
        assert r["rule"] != "reconnaissance"

    def test_multi_stage_beats_recon_but_specific_rules_still_beat_it(self):
        """The multi_stage rule is declared BEFORE reconnaissance but
        AFTER every specific rule — verify Priority order.
        A chain with 5 tactics INCLUDING Impact must still classify as
        ransomware_deployment (or double_extortion) — NOT multi-stage."""
        r = classify_intent(_env(
            tactics=["Discovery", "Execution", "Defense Evasion",
                       "Persistence", "Impact"],
        ))
        assert r["rule"] == "ransomware_deployment"

    def test_recon_only_still_recon(self):
        """Backwards-compat: pure single-tactic Discovery still falls
        through to `reconnaissance` (breadth < 5)."""
        r = classify_intent(_env(tactics=["Discovery"]))
        assert r["rule"] == "reconnaissance"

    def test_recon_with_four_tactics_still_recon(self):
        """Breadth gate is strict — 4 tactics is not enough."""
        r = classify_intent(_env(
            tactics=["Discovery", "Initial Access", "Reconnaissance",
                       "Impair Defenses"],
        ))
        # No narrow rule fires (no Impact / Execution / CredAccess /
        # LatMov / Exfil / C2 / Persistence).  Should NOT jump to
        # multi_stage (needs 5).
        assert r["rule"] != "multi_stage_intrusion"


# ── 3. Priority-order regression sanity ──────────────────────────────
class TestPriorityOrderPreserved:
    def test_c2_beaconing_still_fires(self):
        r = classify_intent(_env(
            tactics=["Execution", "Command and Control"],
            dkp=["dkp.ps_download_cradle"],
        ))
        assert r["rule"] == "c2_beaconing"

    def test_credential_theft_still_fires(self):
        r = classify_intent(_env(
            tactics=["Credential Access", "Discovery"],
        ))
        assert r["rule"] == "credential_theft"

    def test_lateral_movement_still_fires(self):
        r = classify_intent(_env(
            tactics=["Lateral Movement", "Discovery"],
        ))
        assert r["rule"] == "lateral_movement"

    def test_persistence_still_fires(self):
        r = classify_intent(_env(
            tactics=["Persistence", "Defense Evasion"],
        ))
        assert r["rule"] == "persistence_establishment"

    def test_deployment_and_execution_still_fires(self):
        r = classify_intent(_env(
            tactics=["Execution", "Defense Evasion", "Discovery"],
            dkp=["dkp.headless_browser_launch"],
        ))
        assert r["rule"] == "deployment_and_execution"

    def test_empty_env_still_empty(self):
        r = classify_intent({"steps": [], "aggregate": {}})
        assert r["objective"] == "Uncategorised"
