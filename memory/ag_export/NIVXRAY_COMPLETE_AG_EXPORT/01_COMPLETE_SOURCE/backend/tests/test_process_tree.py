"""Pytest for the Process-Tree pipeline (schema, formats, validator, dataset)."""
from __future__ import annotations
import json
import pytest

from training.schema import ProcessTree, ProcessNode, ProcessEvidence, SocRationale
from training.seed_dataset import all_archetypes, stats as ds_stats
from training.tree_formats import to_edge_list, edge_list_to_tree, to_ascii_tree
from training.validator import validate_and_prune
from training.exporter import (
    to_jsonl, to_openai_chat_jsonl, to_anthropic_jsonl, to_csv, to_edge_list_jsonl,
    FORMATS,
)


# ─── Dataset sanity ──────────────────────────────────────────────────────
def test_dataset_has_100_plus_archetypes():
    n = len(all_archetypes())
    assert n >= 100, f"Expected 100+ archetypes, got {n}"


def test_dataset_covers_all_target_platforms():
    plats = ds_stats()["by_platform"]
    assert set(plats.keys()) >= {"windows", "linux", "macos", "container"}


def test_dataset_covers_key_categories():
    cats = ds_stats()["by_category"]
    # At least these categories must be represented
    required = {"powershell","cmd","lolbin","bash","office-macro","wmi",
                "ransomware","cron","systemd","osascript","docker","cloud-cli"}
    missing = required - set(cats.keys())
    assert not missing, f"Missing categories: {missing}"


def test_every_archetype_has_verdict_and_mitre():
    for r in all_archetypes():
        assert r.predicted_process_tree.rationale.verdict, f"{r.training_id}: no verdict"
        assert r.predicted_process_tree.rationale.mitre_ids, f"{r.training_id}: no mitre"
        assert r.predicted_process_tree.root.process, f"{r.training_id}: no root process"


def test_every_node_has_citation_or_inferred_flag():
    def walk(n):
        # Every node must have a citation OR be marked inferred
        assert n.evidence.citation or n.evidence.inferred, \
            f"Node {n.process} has neither citation nor inferred flag"
        for c in n.children:
            walk(c)
    for r in all_archetypes():
        walk(r.predicted_process_tree.root)


# ─── Format round-trip ───────────────────────────────────────────────────
def test_edge_list_roundtrip_preserves_root_and_kids():
    for r in all_archetypes()[:20]:
        t = r.predicted_process_tree
        rebuilt = edge_list_to_tree(to_edge_list(t))
        assert rebuilt.root.process == t.root.process
        assert len(rebuilt.root.children) == len(t.root.children)


def test_ascii_tree_renders_root_and_verdict():
    t = all_archetypes()[0].predicted_process_tree
    txt = to_ascii_tree(t)
    assert t.root.process in txt
    assert t.rationale.verdict in txt
    assert t.rationale.severity in txt


# ─── Exporters ───────────────────────────────────────────────────────────
def test_jsonl_export_valid_lines():
    records = all_archetypes()[:5]
    body = to_jsonl(records)
    lines = body.splitlines()
    assert len(lines) == 5
    for ln in lines:
        d = json.loads(ln)
        assert "training_id" in d and "predicted_process_tree" in d


def test_openai_export_has_messages():
    body = to_openai_chat_jsonl(all_archetypes()[:2])
    for ln in body.splitlines():
        d = json.loads(ln)
        assert "messages" in d
        roles = [m["role"] for m in d["messages"]]
        assert roles == ["system", "user", "assistant"]


def test_anthropic_export_has_conversations():
    body = to_anthropic_jsonl(all_archetypes()[:2])
    for ln in body.splitlines():
        d = json.loads(ln)
        assert "system" in d and "conversations" in d
        roles = [c["role"] for c in d["conversations"]]
        assert roles == ["user", "assistant"]


def test_csv_export_has_header():
    body = to_csv(all_archetypes()[:3])
    header = body.splitlines()[0]
    for col in ("training_id","platform","category","verdict","mitre_ids","ascii_tree"):
        assert col in header


def test_all_formats_registered():
    assert set(FORMATS.keys()) == {"jsonl","openai","anthropic","csv","edge-list"}


# ─── Validator ───────────────────────────────────────────────────────────
def test_validator_prunes_uncited_nodes():
    tree = ProcessTree(
        root=ProcessNode(process="powershell.exe", command_line="powershell -c IEX(...)",
                         evidence=ProcessEvidence(citation="powershell -c IEX", inferred=False),
                         children=[
                             ProcessNode(process="calc.exe", command_line="calc.exe",
                                         evidence=ProcessEvidence(citation="calc.exe", inferred=False)),
                             ProcessNode(process="notepad.exe", command_line="notepad.exe",
                                         evidence=ProcessEvidence(citation="NOT_IN_DECODED", inferred=False)),
                         ]),
    )
    decoded = "powershell -c IEX(...); calc.exe /c stuff"
    pruned, warnings = validate_and_prune(tree, decoded, "")
    assert pruned.root.process == "powershell.exe"
    # notepad.exe pruned because "NOT_IN_DECODED" absent from decoded
    kids = [c.process for c in pruned.root.children]
    assert "calc.exe" in kids and "notepad.exe" not in kids
    assert any("pruned" in w or "uncited" in w for w in warnings)


def test_validator_marks_insufficient_when_root_uncited():
    tree = ProcessTree(
        root=ProcessNode(process="fake.exe", command_line="fake",
                         evidence=ProcessEvidence(citation="NON_EXISTENT_CITATION")),
    )
    pruned, _ = validate_and_prune(tree, "some unrelated text", "")
    assert pruned.evidence_source == "insufficient"


def test_validator_prunes_uncited_iocs():
    tree = ProcessTree(
        root=ProcessNode(process="curl", command_line="curl http://real.io",
                         evidence=ProcessEvidence(citation="curl http://real.io")),
        rationale=SocRationale(
            iocs={"urls": ["http://real.io", "http://fake.example"]},
        ),
    )
    pruned, _ = validate_and_prune(tree, "curl http://real.io", "")
    assert pruned.rationale.iocs["urls"] == ["http://real.io"]
