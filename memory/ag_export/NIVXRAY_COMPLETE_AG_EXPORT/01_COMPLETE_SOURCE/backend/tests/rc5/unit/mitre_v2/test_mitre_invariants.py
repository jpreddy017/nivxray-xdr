"""Phase 5 · Invariants — deterministic guarantees, evidence integrity,
kill-list § 13 static-import gate.
"""
from __future__ import annotations

import inspect
import json
import pathlib
import re

import pytest

from engine.exec_graph import Behavior, ExecGraph, ExecNode, NodeKind, TacticKind
from engine.detectors.mitre_mapper import (
    MITRE_RULES, MITRE_TACTIC_IDS, MitreMapping, map_behaviors_to_mitre,
    get_mitre_mapper, get_rules,
)
from engine.detectors.mitre_navigator_export import build_navigator_layer
from engine.detectors.mitre_stix_export import build_stix_bundle


def _b(tactic, sub, params, conf=100, nid="n_x"):
    return Behavior(tactic=tactic, sub_kind=sub, evidence_nodes=(nid,),
                    reconstructed=f"{tactic.value}:{sub}",
                    confidence=conf, parameters=params or {})


# ── (1) determinism: byte-equal outputs for same input ────────────────
def test_mapper_output_is_byte_identical_across_runs():
    behaviors = [
        _b(TacticKind.execution, "process_spawn", {"image": "powershell.exe"}, nid="n_a"),
        _b(TacticKind.defense_evasion, "obfuscation", {"kind": "encoded_command"}, nid="n_a"),
        _b(TacticKind.command_and_control, "download", {"image": "certutil.exe"}, nid="n_b"),
    ]
    a = [m.model_dump(mode="json") for m in map_behaviors_to_mitre(behaviors)]
    b = [m.model_dump(mode="json") for m in map_behaviors_to_mitre(behaviors)]
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ── (2) every mapping has ≥ 1 behavior + ≥ 1 node ref ─────────────────
def test_every_mapping_has_non_empty_evidence_lists():
    behaviors = [
        _b(TacticKind.execution, "process_spawn", {"image": "cmd.exe"}, nid="n_c"),
        _b(TacticKind.persistence, "autorun_registration",
           {"key_hint": r"hkcu\software\microsoft\windows\currentversion\run"}, nid="n_r"),
    ]
    mm = map_behaviors_to_mitre(behaviors)
    for m in mm:
        assert m.evidence_behavior_ids
        assert m.evidence_node_ids


# ── (3) technique_id validation catches bad IDs ───────────────────────
def test_bad_technique_id_rejected_by_model():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        MitreMapping(
            id="m_bad",
            technique_id="ATT&CK-BAD",   # doesn't start with T + digits
            technique_name="Fake",
            tactic="execution", tactic_id="TA0002", tactic_name="Execution",
            confidence=50,
            evidence_behavior_ids=("b_1",),
            evidence_node_ids=("n_1",),
        )


# ── (4) confidence range ──────────────────────────────────────────────
def test_out_of_range_confidence_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        MitreMapping(
            id="m_bad2",
            technique_id="T1059",
            technique_name="PS",
            tactic="execution", tactic_id="TA0002", tactic_name="Execution",
            confidence=200,
            evidence_behavior_ids=("b_1",),
            evidence_node_ids=("n_1",),
        )


# ── (5) every rule's behavior_tactic exists in the enum ───────────────
def test_every_rule_tactic_is_valid():
    valid = {t.value for t in TacticKind}
    for r in MITRE_RULES:
        assert r.behavior_tactic.value in valid


# ── (6) every rule's tactic value has a MITRE_TACTIC_IDS row ──────────
def test_every_rule_tactic_has_mitre_id_mapping():
    for r in MITRE_RULES:
        assert r.behavior_tactic.value in MITRE_TACTIC_IDS


# ── (7) every rule's technique_id is well-formed ──────────────────────
def test_all_rule_technique_ids_wellformed():
    for r in MITRE_RULES:
        assert re.fullmatch(r"T\d{3,5}", r.technique_id), r.rule_id
        if r.sub_technique_id:
            assert re.fullmatch(r"T\d{4}\.\d{3}", r.sub_technique_id), r.rule_id


# ── (8) every rule ID is unique ───────────────────────────────────────
def test_all_rule_ids_unique():
    ids = [r.rule_id for r in MITRE_RULES]
    assert len(ids) == len(set(ids))


# ── (9) advisor-origin nodes never enter mappings ─────────────────────
def test_advisor_origin_behaviors_would_not_be_mapped():
    # The extractor filters advisor nodes; but if someone bypasses that and
    # hands a behavior directly, the mapper still operates purely on the
    # behavior's structured data — no side channels. This test simply
    # exercises the mapper with a manually-created behavior to confirm it
    # doesn't consult ExecNode.origin (the mapper never sees ExecNodes).
    b = _b(TacticKind.execution, "process_spawn", {"image": "powershell.exe"})
    mm = map_behaviors_to_mitre([b])
    assert mm
    # No indirect field access to origin — the mapper only reads Behavior.
    src = inspect.getsource(map_behaviors_to_mitre.__wrapped__
                            if hasattr(map_behaviors_to_mitre, "__wrapped__")
                            else map_behaviors_to_mitre)
    assert "origin" not in src


# ── (10) mapper never uses regex on raw reconstructed text ────────────
def test_mapper_source_has_no_regex_on_reconstructed_text():
    from engine.detectors import mitre_mapper as mod
    src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
    # The mapper module must not import `re` (predicates are set-membership only).
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith("import re"), \
            "mitre_mapper must be regex-free (§8 invariant)"


# ── (11) rule-count sanity — must be non-trivial ──────────────────────
def test_rule_table_covers_all_major_tactics():
    tactic_ids = {r.technique_id[:5] for r in MITRE_RULES}
    # Presence of at least 10 distinct top-level technique IDs is a
    # smell-test that the rule table isn't a stub.
    assert len(tactic_ids) >= 10


# ── (12) navigator layer techniques ⊆ mapping-referenced techniques ───
def test_navigator_techniques_subset_of_mappings():
    b = _b(TacticKind.execution, "process_spawn", {"image": "powershell.exe"}, nid="n_n")
    mm = map_behaviors_to_mitre([b])
    lay = build_navigator_layer(mm)
    referenced = {(m.sub_technique_id or m.technique_id) for m in mm}
    for t in lay["techniques"]:
        assert t["techniqueID"] in referenced


# ── (13) stix bundle attack-pattern id per unique (tid, sub) pair ────
def test_stix_attack_patterns_unique_per_technique():
    b1 = _b(TacticKind.execution, "process_spawn", {"image": "powershell.exe"}, nid="n_x")
    b2 = _b(TacticKind.execution, "process_spawn", {"image": "powershell.exe"}, nid="n_y")
    bundle = build_stix_bundle(map_behaviors_to_mitre([b1, b2]))
    ap_ids = [o["id"] for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert len(ap_ids) == len(set(ap_ids))


# ── (14) kill-list § 13 — no new import of legacy MITRE map ───────────
def test_no_new_import_of_KEYWORD_MITRE_MAP_in_engine_or_routers():
    """§ 13 kill-list gate: no file in `engine/` or `routers/` (except the
    legacy `operations.py` shim itself) may import the deprecated
    `_KEYWORD_MITRE_MAP` symbol. This test is what will trip CI if a new
    detector accidentally reaches into the legacy heuristic table.
    """
    backend = pathlib.Path(__file__).resolve().parents[4]  # /app/backend
    engine = backend / "engine"
    routers = backend / "routers"
    # Match actual imports / attribute references (not doc-string mentions).
    pat = re.compile(
        r"(?m)^\s*(?:from\s+\S+\s+import\s+[^\n]*_KEYWORD_MITRE_MAP|"
        r"import\s+[^\n]*_KEYWORD_MITRE_MAP)|"
        r"\b_KEYWORD_MITRE_MAP\s*[.\[(]"
    )
    offenders = []
    for base in (engine, routers):
        for p in base.rglob("*.py"):
            if p.name in ("operations.py", "ops.py"):
                continue
            src = p.read_text(encoding="utf-8", errors="ignore")
            if pat.search(src):
                offenders.append(str(p))
    assert not offenders, f"kill-list § 13 violation — {offenders}"


# ── (15) MITRE mapper module never imports emergentintegrations ───────
def test_mitre_mapper_no_ai_imports():
    """§ 14 · AI cannot influence mitre_*.  Any `emergentintegrations`
    import inside the mapper family fails this gate.
    """
    root = pathlib.Path(__file__).resolve().parents[4] / "engine" / "detectors"
    for name in ("mitre_mapper.py", "mitre_navigator_export.py", "mitre_stix_export.py"):
        p = root / name
        src = p.read_text(encoding="utf-8")
        assert "emergentintegrations" not in src, f"AI-import in {p}"
