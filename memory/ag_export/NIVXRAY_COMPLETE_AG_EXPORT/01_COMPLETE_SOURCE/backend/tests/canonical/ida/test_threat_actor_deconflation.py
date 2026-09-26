"""Regression tests · Threat-Actor de-conflation from MITRE tactic IDs.

Bug: the extractor's generic actor regex ``_RE_GENERIC_ACTOR`` matched
`TA-?\\d{2,4}` and captured MITRE ATT&CK tactic identifiers such as
`TA0001`..`TA0043` (Enterprise), `TA0027`..`TA0038` (Mobile), and
`TA0100`..`TA0111` (ICS) as if they were threat actors, contaminating
investigator-facing intelligence.

Fix: `_extract_actors` now filters matches through:
  1. An authoritative `_MITRE_TACTIC_IDS` deny-list.
  2. A shape guard ``TA0\\d{3}`` catching any 4-digit zero-padded id.

Real Proofpoint TA-numbered actors (TA505, TA544, TA577, …) use `TA`
+ 3 digits without a leading zero — the filter is precise enough to
keep them.

Zero-drift invariant: none of the previously-known actors (APT41,
FIN7, Storm-1811, TA505, …) may be dropped by this fix.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.ida.report_extractors import _extract_actors  # noqa: E402


# ── 1. MITRE tactic IDs MUST NEVER appear as threat actors ──────────
class TestMitreTacticExclusion:
    def test_enterprise_tactic_ids_are_not_actors(self):
        text = (
            "Reconnaissance (TA0043) preceded Initial Access (TA0001) then "
            "Execution (TA0002), Persistence (TA0003), Privilege Escalation "
            "(TA0004), Defense Evasion (TA0005), Credential Access (TA0006), "
            "Discovery (TA0007), Lateral Movement (TA0008), Collection (TA0009), "
            "C2 (TA0011), Exfiltration (TA0010) and Impact (TA0040)."
        )
        actors = [a["name"] for a in _extract_actors(text)]
        assert actors == [], f"MITRE tactic ids leaked as actors: {actors}"

    def test_ics_tactic_range_not_actors(self):
        text = "The ICS attack traversed TA0100, TA0104, TA0105 and TA0111."
        actors = [a["name"] for a in _extract_actors(text)]
        assert actors == [], f"ICS tactic ids leaked as actors: {actors}"

    def test_mobile_tactic_range_not_actors(self):
        text = "Mobile tactics observed: TA0027, TA0033, TA0038."
        actors = [a["name"] for a in _extract_actors(text)]
        assert actors == [], f"Mobile tactic ids leaked as actors: {actors}"

    def test_unlisted_ta0_shape_still_blocked(self):
        """Even if MITRE adds new TA0-prefixed ids we haven't listed,
        the shape guard (`TA0\\d{3}`) must still drop them."""
        text = "Future tactic TA0999 mentioned in a research paper."
        actors = [a["name"] for a in _extract_actors(text)]
        assert actors == [], f"future TA0-shape id leaked: {actors}"


# ── 2. Real threat actors MUST still be extracted ───────────────────
class TestKnownActorsPreserved:
    def test_curated_apt_actors_preserved(self):
        text = "APT29 and APT41 collaborated with FIN7 on the operation."
        actors = {a["name"] for a in _extract_actors(text)}
        for expected in ("APT29", "APT41", "FIN7"):
            assert expected in actors, f"missing curated actor {expected}"

    def test_proofpoint_ta_actors_preserved(self):
        """Real Proofpoint TA-numbered actors (3-digit, no leading zero)
        must survive the fix — this is the classic false-negative trap."""
        text = "TA505 delivered TA544 payloads via TA551 infrastructure. TA577 followed."
        actors = {a["name"] for a in _extract_actors(text)}
        for expected in ("TA505", "TA544", "TA551", "TA577"):
            assert expected in actors, f"real threat actor {expected} dropped"

    def test_storm_actors_preserved(self):
        text = "Storm-1811 leveraged Storm-0303 tooling in the Q4 incident."
        actors = {a["name"] for a in _extract_actors(text)}
        assert "Storm-1811" in actors
        assert "Storm-0303" in actors

    def test_unc_generic_actors_preserved(self):
        text = "UNC4841 activity attributed to UNC2452 later this year."
        actors = {a["name"] for a in _extract_actors(text)}
        assert "UNC4841" in actors
        assert "UNC2452" in actors


# ── 3. Mixed narratives — the exact investigator scenario ───────────
class TestMixedNarratives:
    def test_ransomware_report_with_tactics_and_actors(self):
        """The exact scenario that triggered the bug: a ransomware report
        that references BOTH tactic ids and a real actor.  Only the actor
        must appear."""
        text = (
            "APT29 executed the intrusion via Initial Access (TA0001) → "
            "Execution (TA0002) → Persistence (TA0003) → Impact (TA0040). "
            "TA505 tooling was also observed in the lateral movement phase (TA0008)."
        )
        actors = {a["name"] for a in _extract_actors(text)}
        # Real actors present
        assert "APT29" in actors
        assert "TA505" in actors
        # Tactic ids absent
        for tid in ("TA0001", "TA0002", "TA0003", "TA0040", "TA0008"):
            assert tid not in actors, f"tactic id {tid} leaked into actor list"

    def test_hyphenated_tactic_shape_not_actor(self):
        """`TA-0001` is not a common form but the generic regex accepts a
        hyphen after `TA`.  The de-hyphenated form must still match the
        tactic id filter."""
        text = "Analysts noted TA-0001 activity on day one."
        actors = [a["name"] for a in _extract_actors(text)]
        assert actors == []
