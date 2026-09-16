"""Stage-2 Verdict Engine — acceptance-locked contract tests.

Locks every rule the owner declared on 2026-08-26:

  1a Additive — verdict_stage2 sibling; v3.x untouched.
  2c Compute on-demand + idempotent auto-compute.
  3a Strict deterministic — no LLM.  No invented events / IOCs /
     techniques / actors / families / process ancestry.
  4c Vocab preserved + confidence bucket layered on top.
  5c Rich, collapsible evidence rows with full citation.
  6  Fingerprint excludes ``generated_at``.

Additional locks:
  - Same canonical input → BYTE-identical output (fingerprint match).
  - Two runs at different times → same fingerprint.
  - Every evidence row carries event_id[] + lane + provenance_chain +
    canonical_field_matched + rule_id + weight_contribution.
  - v3.x label/vocabulary vocabulary preserved.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.verdict_stage2.engine import compute_stage2, build_inputs  # noqa: E402
from services.verdict_stage2.model import (VERDICT_LABELS,  # noqa: E402
                                              CONFIDENCE_BUCKETS,
                                              EvidenceRow)
from services.verdict_stage2.fingerprint import verdict_fingerprint  # noqa: E402


# ── deterministic fixtures ───────────────────────────────────────
def _ev(event_id, action=None, ts="2026-08-26T10:00:00+00:00",
         process=None, parent=None, cmd=None, file_ref=None,
         dest=None, lane="log", canonical_fields=None):
    return {
        "event_id":         event_id,
        "lane":             lane,
        "input_id":         "i-1",
        "tenant_id":        "t1",
        "source_file_id":   "sf-1",
        "timestamp":        ts,
        "timestamp_source": "canonical",
        "first_seen":       ts,
        "last_seen":        ts,
        "count":            1,
        "action":           action,
        "process":          process,
        "parent_process":   parent,
        "command_line":     cmd,
        "file_ref":         file_ref,
        "destination":      dest,
        "provenance_chain": [f"iue.intake:{event_id}",
                              f"iue.aggregator:{event_id}"],
        "canonical_fields": canonical_fields or {},
    }


def _tl(events):
    return {"events": events, "untimed_events": [],
            "lanes": sorted({e["lane"] for e in events})}


# ── 1. Additive-only contract ────────────────────────────────────
class TestAdditiveContract:
    def test_verdict_stage2_shape_is_additive(self):
        v = compute_stage2(build_inputs())
        d = v.to_dict()
        expected_keys = {"label", "confidence", "risk_score",
                          "contributing_signals", "evidence_rows",
                          "provenance_chain", "fingerprint",
                          "inputs_hash", "generated_at", "version"}
        assert set(d.keys()) == expected_keys, \
            f"unexpected shape: {sorted(d.keys())}"

    def test_engine_never_reads_or_writes_v3x_keys(self):
        # A v3.x card handed in as input MUST NOT be mutated.
        v3x = {"verdict": "suspicious", "risk_score": 42,
                "interpreter": [{"step": 1}]}
        original = copy.deepcopy(v3x)
        inp = build_inputs(v3x_verdict_card=v3x)
        _ = compute_stage2(inp)
        assert v3x == original, "v3.x verdict_card was mutated by Stage-2"


# ── 2. Deterministic vocabulary (labels + confidence) ────────────
class TestVocabulary:
    def test_label_is_in_canonical_vocab(self):
        v = compute_stage2(build_inputs())
        assert v.label in VERDICT_LABELS

    def test_confidence_is_in_canonical_vocab(self):
        v = compute_stage2(build_inputs())
        assert v.confidence in CONFIDENCE_BUCKETS

    def test_empty_evidence_returns_unknown_insufficient(self):
        v = compute_stage2(build_inputs())
        assert v.label == "unknown"
        assert v.confidence == "insufficient"


# ── 3. Deterministic fingerprint (rule 6) ────────────────────────
class TestDeterministicFingerprint:
    def _sample_scenario(self):
        events = [
            _ev("e1", action="execute", process="powershell.exe",
                 parent="winword.exe",
                 cmd="powershell.exe -enc SQBFAFgAKAA..."),
            _ev("e2", action="create",
                 file_ref={"path": "C:\\Users\\Public\\AppData\\Temp\\payload.dll",
                            "name": "payload.dll"}),
            _ev("e3", action="connect", process="powershell.exe",
                 dest="http://evil.example.com/x"),
        ]
        return build_inputs(
            case_id="case-A",
            timeline=_tl(events),
            intent={"rule": "double_extortion_ransomware",
                     "objective": "Double-Extortion Ransomware",
                     "confidence": 0.9,
                     "steps": [{"intent": "Impact"},
                                {"intent": "Exfiltration"}]},
            v3x_verdict_card={"verdict": "malicious", "risk_score": 80},
        )

    def test_two_computes_same_input_same_fingerprint(self):
        inp = self._sample_scenario()
        v1 = compute_stage2(inp, now_iso="2026-08-26T10:00:00+00:00")
        v2 = compute_stage2(inp, now_iso="2027-01-01T00:00:00+00:00")
        assert v1.fingerprint == v2.fingerprint
        # generated_at differs; fingerprint doesn't.
        assert v1.generated_at != v2.generated_at

    def test_fingerprint_excludes_generated_at(self):
        v = compute_stage2(self._sample_scenario())
        d = v.to_dict()
        # Manually recompute — should match the envelope's fingerprint.
        assert verdict_fingerprint(d) == v.fingerprint

    def test_inputs_hash_stable_across_runs(self):
        inp = self._sample_scenario()
        v1 = compute_stage2(inp)
        v2 = compute_stage2(inp)
        assert v1.inputs_hash == v2.inputs_hash

    def test_different_inputs_different_fingerprint(self):
        v1 = compute_stage2(self._sample_scenario())
        # Alter one event's process — must change fingerprint.
        events2 = [
            _ev("e1", action="execute", process="cmd.exe",
                 parent="winword.exe", cmd="cmd.exe /c whoami"),
        ]
        inp2 = build_inputs(timeline=_tl(events2))
        v2 = compute_stage2(inp2)
        assert v1.fingerprint != v2.fingerprint


# ── 4. Evidence citation (rule 5c) ───────────────────────────────
class TestEvidenceCitation:
    def test_each_row_carries_full_citation_metadata(self):
        events = [_ev("e1", action="execute", process="powershell.exe",
                        parent="winword.exe", cmd="-enc XYZ")]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        assert v.evidence_rows, "no evidence rows produced"
        for row in v.evidence_rows:
            # Owner rule 5c required fields.
            assert row.rule_id
            assert row.canonical_field_matched
            assert row.matched_value
            assert row.weight_contribution != 0
            assert row.lane in {"log", "url", "file", "narrative"}
            # event_ids or narrative-only rules (v3x carry / mitre)
            if row.rule_id not in {"MITRE-IMPACT",
                                     "MITRE-EXFILTRATION",
                                     "OBJECTIVE-DOUBLE-EXTORTION",
                                     "V3X-VERDICT-CARRY"}:
                assert row.event_ids, f"{row.rule_id} missing event_ids"

    def test_row_ids_are_deterministic(self):
        events = [_ev("e1", action="execute", process="powershell.exe",
                        parent="winword.exe", cmd="-enc AAA")]
        v1 = compute_stage2(build_inputs(timeline=_tl(events)))
        v2 = compute_stage2(build_inputs(timeline=_tl(events)))
        assert [r.row_id for r in v1.evidence_rows] == \
               [r.row_id for r in v2.evidence_rows]


# ── 5. Rule-engine behaviour ─────────────────────────────────────
class TestRuleEngine:
    def test_proc_suspicious_parent_fires(self):
        events = [_ev("e1", action="execute", process="powershell.exe",
                        parent="outlook.exe", cmd="Get-ChildItem")]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        ids = {r.rule_id for r in v.evidence_rows}
        assert "PROC-SUSPICIOUS-PARENT" in ids

    def test_cmd_obfuscation_fires_on_enc_flag(self):
        events = [_ev("e1", action="execute", process="powershell.exe",
                        parent="explorer.exe",
                        cmd="powershell.exe -enc SQBFAFgA")]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        assert "CMD-OBFUSCATION" in {r.rule_id for r in v.evidence_rows}

    def test_file_drop_executable_fires(self):
        events = [_ev("e1", action="create",
                        file_ref={"path": "C:\\Users\\Public\\Temp\\p.dll",
                                    "name": "p.dll"})]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        assert "FILE-DROP-EXECUTABLE" in {r.rule_id for r in v.evidence_rows}

    def test_network_suspicious_requires_scripting_host_source(self):
        # A whitelisted destination from a scripting host: NO fire.
        events = [_ev("e1", process="powershell.exe",
                        dest="https://update.microsoft.com/x")]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        assert "NETWORK-SUSPICIOUS" not in {r.rule_id for r in v.evidence_rows}
        # A non-whitelisted destination FROM a scripting host: FIRE.
        events2 = [_ev("e1", process="powershell.exe",
                         dest="http://evil.example.com/x")]
        v2 = compute_stage2(build_inputs(timeline=_tl(events2)))
        assert "NETWORK-SUSPICIOUS" in {r.rule_id for r in v2.evidence_rows}

    def test_mitre_impact_fires_from_intent(self):
        inp = build_inputs(
            intent={"steps": [{"intent": "Impact"}]})
        v = compute_stage2(inp)
        assert "MITRE-IMPACT" in {r.rule_id for r in v.evidence_rows}

    def test_double_extortion_objective_lifts_score(self):
        events = [_ev("e1", action="execute", process="powershell.exe",
                        parent="winword.exe", cmd="-enc AAA")]
        base = compute_stage2(build_inputs(timeline=_tl(events)))
        elevated = compute_stage2(build_inputs(
            timeline=_tl(events),
            intent={"rule": "double_extortion_ransomware",
                     "objective": "Double-Extortion Ransomware",
                     "confidence": 0.9,
                     "steps": [{"intent": "Impact"},
                                {"intent": "Exfiltration"}]}))
        assert elevated.risk_score > base.risk_score

    def test_signed_benign_reduces_score(self):
        events = [_ev("e1", action="execute", process="powershell.exe",
                        parent="winword.exe", cmd="-enc BBB",
                        canonical_fields={"canonical.file.signer":
                                            "Microsoft Corporation"})]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        signers = {r.rule_id for r in v.evidence_rows}
        assert "SIGNED-BENIGN-COUNTERWEIGHT" in signers
        # Sum of weights should be lower than the same events unsigned.
        events_unsigned = [_ev("e1", action="execute",
                                 process="powershell.exe",
                                 parent="winword.exe", cmd="-enc BBB")]
        v_unsigned = compute_stage2(build_inputs(timeline=_tl(events_unsigned)))
        assert v.risk_score <= v_unsigned.risk_score


# ── 6. Label & confidence mapping ─────────────────────────────────
class TestLabelMapping:
    def test_high_risk_score_maps_to_malicious_high(self):
        events = [
            _ev("e1", action="execute", process="powershell.exe",
                 parent="winword.exe", cmd="-enc AAA"),
            _ev("e2", action="create",
                 file_ref={"path": "C:\\Users\\Public\\Temp\\p.dll",
                            "name": "p.dll"}),
            _ev("e3", action="connect", process="powershell.exe",
                 dest="http://evil.example.com/x"),
        ]
        v = compute_stage2(build_inputs(
            timeline=_tl(events),
            intent={"rule": "double_extortion_ransomware",
                     "objective": "Double-Extortion Ransomware",
                     "confidence": 0.9,
                     "steps": [{"intent": "Impact"},
                                {"intent": "Exfiltration"}]},
            v3x_verdict_card={"verdict": "malicious"}))
        assert v.label == "malicious"
        assert v.confidence in ("high", "medium")
        assert v.risk_score >= 60

    def test_single_signal_returns_insufficient_confidence(self):
        events = [_ev("e1", process="powershell.exe",
                        dest="http://one.example.com")]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        assert v.confidence == "insufficient"


# ── 7. No-invention guardrails (rule 3a) ─────────────────────────
class TestNoInvention:
    def test_no_events_returned_when_no_input(self):
        v = compute_stage2(build_inputs())
        assert v.evidence_rows == []
        assert v.contributing_signals == []

    def test_engine_does_not_add_event_ids_that_dont_exist(self):
        events = [_ev("real-1", action="execute", process="powershell.exe",
                        parent="winword.exe", cmd="-enc AAA")]
        v = compute_stage2(build_inputs(timeline=_tl(events)))
        all_ids = set()
        for r in v.evidence_rows:
            all_ids.update(r.event_ids)
        allowed = {"real-1", ""}
        assert all_ids.issubset(allowed), \
            f"engine invented event_ids: {all_ids - allowed}"

    def test_engine_does_not_produce_actors_or_families(self):
        v = compute_stage2(build_inputs())
        d = v.to_dict()
        # Owner rule 3a — verdict envelope must not carry actor / family.
        for k in ("threat_actor", "malware_family", "invented",
                  "predicted", "inferred_ioc"):
            assert k not in d, f"forbidden top-level key: {k}"
