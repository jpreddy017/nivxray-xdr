"""ADR-0009 · Canonical Investigation Model (CIM) · Pinned regression suite.

Locks the CIM composer's contract:
  - Schema shape (top-level fields, section models)
  - Merge-gate invariants (Assessment.evidence non-empty, Recommendation.evidence non-empty)
  - No-orphan-evidence invariant
  - AttackTechnique dedup invariant
  - Composer determinism (same FactSubstrate → identical CIM modulo id/timestamps)
  - Deterministic Unknowns (rules produce identical output for identical substrate)
  - Additive contract on both endpoints
  - schema_version pinned at "1.0"

Governance source of truth: /app/memory/adr/0009-canonical-investigation-model.md
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import pytest

from nivxforge.cim import compose
from nivxforge.cim.fact_substrate import (
    FactSubstrate, DecoderLayer, IOCRecord, TIHitRecord, MITREHit, StageRecord,
    VerdictRecord, from_analysis_result,
)
from nivxforge.cim.models import (
    Investigation, Assessment, Recommendation, CIMValidationError,
)
from nivxforge.cim.unknowns import generate_unknowns
from nivxforge.cim import validators


# ─── Fixtures ─────────────────────────────────────────────────────────────

def _emotet_facts() -> FactSubstrate:
    """Rich FactSubstrate for the Emotet downloader case (spans every section)."""
    return FactSubstrate(
        input_text="powershell.exe -w hidden -enc SQBFAFgAKAA...",
        input_kind="ps_encoded",
        decoder_chain=[
            DecoderLayer(idx=0, op="b64-decode", input_kind="b64",
                         output_kind="text", output_preview="IEX(New-Object Net.WebClient)..."),
            DecoderLayer(idx=1, op="ps-normalize", input_kind="text",
                         output_kind="text",
                         output_preview="Invoke-Expression((New-Object Net.WebClient)...)"),
        ],
        iocs=[
            IOCRecord(kind="url", value="http://mal.com/a.ps1",
                      normalized_value="http://mal.com/a.ps1",
                      stage_passed=["syntactic", "context"]),
            IOCRecord(kind="domain", value="mal.com",
                      normalized_value="mal.com",
                      stage_passed=["syntactic", "context"]),
        ],
        ti_hits=[TIHitRecord(provider="virustotal", label="Emotet", subject="mal.com")],
        mitre_hits=[
            MITREHit(technique_id="T1059.001", name="PowerShell", tactic="execution"),
            MITREHit(technique_id="T1105", name="Ingress Tool Transfer",
                     tactic="command-and-control"),
        ],
        verdict=VerdictRecord(label="Confirmed Malicious", confidence_pct=92,
                              reasons=["known family (Emotet)", "encoded PowerShell"]),
        reasoning_notes=["PowerShell downloader chain resolves to a known Emotet C2."],
        source_surface="test",
    )


# ─── Schema & construction ────────────────────────────────────────────────

def test_composer_produces_valid_investigation():
    inv = compose.from_facts(_emotet_facts())
    assert isinstance(inv, Investigation)
    assert inv.schema_version == "1.0"
    assert inv.executive.verdict == "Confirmed Malicious"
    assert inv.executive.family == "Emotet"


def test_investigation_has_all_top_level_sections():
    inv = compose.from_facts(_emotet_facts())
    required = {"executive", "assessments", "evidence", "timeline", "entities",
                "relationships", "threat_intel", "attack", "stages_executed",
                "decode_chain", "unknowns", "recommendations"}
    for section in required:
        assert hasattr(inv, section), f"Missing top-level section: {section}"


def test_schema_version_is_pinned():
    inv = compose.from_facts(_emotet_facts())
    assert inv.schema_version == "1.0", (
        "schema_version drifted — bump the major and add a new ADR."
    )


# ─── Merge-gate invariants (§2.1.b / §2.1.d) ──────────────────────────────

def test_every_assessment_has_at_least_one_evidence_ref():
    inv = compose.from_facts(_emotet_facts())
    assert inv.assessments, "Composer must emit at least one Assessment"
    for a in inv.assessments:
        assert len(a.evidence) >= 1, (
            f"Assessment {a.id} lacks evidence — merge-gate violated."
        )


def test_every_recommendation_has_at_least_one_evidence_ref():
    inv = compose.from_facts(_emotet_facts())
    for r in inv.recommendations:
        assert len(r.evidence) >= 1, (
            f"Recommendation {r.id} lacks evidence — merge-gate violated."
        )


def test_unsupported_assessment_at_pydantic_layer():
    """Pydantic min_length=1 enforces the invariant at model-construction time."""
    with pytest.raises(Exception):  # pydantic ValidationError
        Assessment(id="A-001", statement="unbacked", kind="verdict",
                   confidence="Unknown", evidence=[])


def test_unsupported_recommendation_at_pydantic_layer():
    with pytest.raises(Exception):
        Recommendation(id="R-001", kind="hunt", text="hunt for x", evidence=[])


# ─── No-orphan-evidence invariant (§2.8 #5) ───────────────────────────────

def test_composer_never_emits_orphan_evidence():
    inv = compose.from_facts(_emotet_facts())
    referenced = set()
    for a in inv.assessments:
        referenced.update(a.evidence)
    for r in inv.recommendations:
        referenced.update(r.evidence)
    for u in inv.unknowns:
        referenced.update(u.evidence)
    for rel in inv.relationships:
        referenced.update(rel.evidence)
    for th in inv.threat_intel:
        referenced.update(th.evidence)
    for at in inv.attack:
        referenced.update(at.evidence)
    for ent in inv.entities:
        referenced.update(ent.evidence)
    for st in inv.stages_executed:
        referenced.update(st.evidence_produced)
    for t in inv.timeline:
        referenced.update(t.evidence)
    orphans = [e.id for e in inv.evidence if e.id not in referenced]
    assert not orphans, f"Composer emitted orphan evidence: {orphans}"


def test_validators_reject_synthetic_orphan_evidence():
    """Feed the validator an Investigation with an injected orphan → raises."""
    inv = compose.from_facts(_emotet_facts())
    # Inject an orphan Evidence
    from nivxforge.cim.models import Evidence, EvidenceSource
    inv.evidence.append(Evidence(
        id="EV-999",
        type="reasoning.inference",
        source=EvidenceSource(producer="test"),
        raw_value="orphan probe",
    ))
    with pytest.raises(CIMValidationError) as exc:
        validators.validate(inv)
    assert exc.value.code == "CIM-VALID-ORPHAN-EVIDENCE"


# ─── AttackTechnique dedup invariant (§2.8 #6) ────────────────────────────

def test_attack_technique_list_is_deduplicated():
    fs = _emotet_facts()
    # Duplicate the technique in the substrate — composer must dedup.
    fs.mitre_hits.append(MITREHit(technique_id="T1059.001", name="PowerShell",
                                   tactic="execution"))
    inv = compose.from_facts(fs)
    ids = [a.id for a in inv.attack]
    assert len(ids) == len(set(ids)), (
        f"Composer did not dedup AttackTechnique: {ids}"
    )


# ─── Deterministic Unknowns (§2.2) ────────────────────────────────────────

def test_unknowns_are_deterministic_across_two_invocations():
    fs = _emotet_facts()
    u1 = generate_unknowns(fs)
    u2 = generate_unknowns(fs)
    assert [(u.rule_id, u.text) for u in u1] == [(u.rule_id, u.text) for u in u2]


def test_unknowns_have_stable_rule_ids():
    fs = _emotet_facts()
    unknowns = generate_unknowns(fs)
    rule_ids = [u.rule_id for u in unknowns]
    # No duplicate rule_ids in a single run.
    assert len(rule_ids) == len(set(rule_ids)), (
        f"A rule fired twice: {rule_ids}"
    )
    # Every id follows the U-RULE-* naming convention.
    for rid in rule_ids:
        assert rid.startswith("U-RULE-"), f"malformed rule_id: {rid}"


def test_unknowns_shrink_when_telemetry_is_supplied():
    """Add telemetry → some rules must stop firing (deterministic response)."""
    fs = _emotet_facts()
    baseline = len(generate_unknowns(fs))
    fs.telemetry_network = [{"src": "10.0.0.1", "dst": "1.2.3.4"}]
    fs.telemetry_processes = [{"pid": 4400, "name": "powershell.exe"}]
    after = len(generate_unknowns(fs))
    assert after < baseline, (
        f"Adding telemetry did not shrink unknowns: {baseline} → {after}"
    )


# ─── AnalysisStage status enum ────────────────────────────────────────────

def test_stages_executed_contains_at_least_one_completed():
    inv = compose.from_facts(_emotet_facts())
    assert any(s.status == "completed" for s in inv.stages_executed)


def test_stages_executed_uses_fixed_status_enum():
    inv = compose.from_facts(_emotet_facts())
    for s in inv.stages_executed:
        assert s.status in {"completed", "skipped", "failed", "error"}


# ─── Composer determinism · id/timestamps ignored ─────────────────────────

def test_composer_determinism_modulo_id_and_timestamps():
    """Same substrate → same CIM sections (structural equivalence)."""
    fs = _emotet_facts()
    inv1 = compose.from_facts(fs)
    inv2 = compose.from_facts(fs)
    # ID/created_at differ; everything else structural should match.
    assert inv1.executive == inv2.executive
    assert [a.statement for a in inv1.assessments] == [a.statement for a in inv2.assessments]
    assert [e.raw_value for e in inv1.evidence] == [e.raw_value for e in inv2.evidence]
    assert [t.id for t in inv1.attack] == [t.id for t in inv2.attack]
    assert [u.rule_id for u in inv1.unknowns] == [u.rule_id for u in inv2.unknowns]


# ─── Adapter · from_analysis_result on real endpoint-shaped dict ──────────

def test_from_analysis_result_maps_iocs_correctly():
    """The adapter maps the /api/decode/smart response dict → FactSubstrate
    without importing HTTP libraries."""
    result_dict = {
        "iocs": {
            "urls": ["http://mal.com/x"],
            "domains": ["mal.com"],
            "ips": ["1.2.3.4"],
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
        },
        "layer_trace": [
            {"op": "b64-decode", "input_kind": "b64", "output_kind": "text", "preview": "IEX..."},
        ],
        "verdict_card": {"verdict": "Malicious", "confidence": 75, "reasons": ["ps-encoded"]},
        "mitre": {"techniques": [{"id": "T1059.001", "tactic": "execution"}]},
    }
    fs = from_analysis_result(result_dict, input_text="x", source_endpoint="/test")
    ioc_kinds = sorted(rec.kind for rec in fs.iocs)
    assert ioc_kinds == sorted(["url", "domain", "ip", "hash"])
    assert fs.verdict is not None
    assert fs.verdict.label == "Malicious"
    assert fs.verdict.confidence_pct == 75
    assert fs.decoder_chain and fs.decoder_chain[0].op == "b64-decode"
    assert fs.mitre_hits and fs.mitre_hits[0].technique_id == "T1059.001"


# ─── End-to-end · composer + validator on adapter output ──────────────────

def test_end_to_end_from_endpoint_shaped_dict_produces_valid_cim():
    result_dict = {
        "iocs": {
            "urls": ["http://mal.com/x"],
            "domains": ["mal.com"],
            "ips": [],
            "md5": [], "sha1": [], "sha256": [], "emails": [], "bitcoin_addresses": [],
        },
        "layer_trace": [{"op": "b64-decode", "preview": "IEX..."}],
        "verdict_card": {"verdict": "Suspicious", "confidence": 55,
                         "reasons": ["encoded ps"]},
        "mitre": {"techniques": [{"id": "T1059.001"}]},
        "ti_shield": {"layers": [
            {"ti_hits": [{"provider": "virustotal", "label": "Downloader"}]}
        ]},
    }
    fs = from_analysis_result(result_dict, input_text="powershell -enc XYZ",
                              source_endpoint="/api/decode/smart")
    inv = compose.from_facts(fs)  # validator runs internally
    assert inv.schema_version == "1.0"
    assert inv.executive.verdict == "Suspicious"


# ─── §2.8 · schema_version enforcement ────────────────────────────────────

def test_composer_output_passes_validators():
    """Every composer output has already passed validators.validate()."""
    inv = compose.from_facts(_emotet_facts())
    validators.validate(inv)  # must not raise


def test_validators_reject_wrong_schema_version():
    inv = compose.from_facts(_emotet_facts())
    # Force an unsupported version — pydantic doesn't block since it's Literal.
    # We bypass Pydantic to prove the validator's guard.
    object.__setattr__(inv, "schema_version", "2.0")
    with pytest.raises(CIMValidationError) as exc:
        validators.validate(inv)
    assert exc.value.code == "CIM-VALID-SCHEMA"


# ─── §2.8 · dangling relationship endpoint ────────────────────────────────

def test_validators_reject_dangling_relationship():
    inv = compose.from_facts(_emotet_facts())
    from nivxforge.cim.models import Relationship
    inv.relationships.append(Relationship(
        id="REL-999", source="E-nope", target=inv.entities[0].id, kind="test",
    ))
    with pytest.raises(CIMValidationError) as exc:
        validators.validate(inv)
    assert exc.value.code == "CIM-VALID-DANGLING-REL-SOURCE"


# ─── Transport-independence (§2.7) ────────────────────────────────────────

def test_composer_does_not_import_from_routers():
    """`compose.py` must NOT import from routers/* — CIM is transport-independent."""
    import ast
    import nivxforge.cim.compose as c
    tree = ast.parse(open(c.__file__).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert not mod.startswith("routers"), (
                f"compose.py imports from routers.{mod} — §2.7 transport independence"
            )
            assert mod != "fastapi", (
                "compose.py depends on fastapi — §2.7 transport independence"
            )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("routers"), (
                    f"compose.py imports routers.{alias.name} — §2.7"
                )
                assert alias.name != "fastapi", (
                    "compose.py imports fastapi — §2.7"
                )
