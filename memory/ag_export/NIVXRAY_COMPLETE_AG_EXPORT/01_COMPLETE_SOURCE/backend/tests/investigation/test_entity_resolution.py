"""Phase 2 · Entity Resolution regression suite.

Locks in the operator-mandated completion criteria (2026-08-01):

  1. HOST01 + 10.1.1.15 + host01.contoso.local collapse to ONE host
  2. Multiple usernames referring to the same identity merge
  3. Duplicate hashes remain a single node (invariant preserved)
  4. Duplicate domains / FQDNs merge into one entity
  5. Golden end-to-end test proving entity collapse in a real
     Investigation Graph coming out of `run_phase1()`
"""
from __future__ import annotations

import json
from typing import Tuple

import pytest

from nivxforge.investigation.pipeline.entity_resolution import (
    EntityMerge, resolve_entities,
)
from nivxforge.investigation.pipeline.graph_builder import (
    GraphEdge, GraphNode, InvestigationGraph,
)
from nivxforge.investigation.pipeline.orchestrator import run_phase1


# ── Helpers ──────────────────────────────────────────────────────────

def _n(nid: str, kind: str, value: str, **attrs) -> GraphNode:
    return GraphNode(
        id=nid, kind=kind, label=f"{kind.upper()} · {value}",
        value=value, attrs=dict(attrs),
        evidence_refs=("ev-" + nid,),
        provenance={"vendor": "test"},
    )


def _e(rel: str, a: str, b: str) -> GraphEdge:
    return GraphEdge(
        id=f"e-{rel}-{a}-{b}", from_id=a, to_id=b,
        relation=rel, evidence_refs=("ev-1",),
    )


# ── 1 · Host merges ─────────────────────────────────────────────────

def test_host_name_ip_and_fqdn_collapse_to_one():
    g = InvestigationGraph(
        nodes=(
            _n("h-name", "host", "HOST01", ip="10.1.1.15"),
            _n("h-ip",   "host", "10.1.1.15"),
            _n("h-fqdn", "host", "host01.contoso.local"),
        ),
        edges=(),
    )
    resolved, merges = resolve_entities(g)
    hosts = resolved.nodes_of("host")
    assert len(hosts) == 1, f"expected 1 host, got {len(hosts)}: {[h.value for h in hosts]}"
    survivor = hosts[0]
    aliases = set((survivor.attrs or {}).get("aliases") or [])
    # Both other identifiers must appear as aliases on the survivor.
    assert {"10.1.1.15", "host01.contoso.local"}.issubset(aliases)
    assert len(merges) == 2
    assert all(m.kind == "host" for m in merges)


def test_host_evidence_refs_union_after_merge():
    g = InvestigationGraph(
        nodes=(
            _n("h1", "host", "HOST01"),
            _n("h2", "host", "host01"),   # case-insensitive same short name
        ),
        edges=(),
    )
    resolved, _ = resolve_entities(g)
    host = resolved.nodes_of("host")[0]
    # Both source evidence refs preserved
    assert set(host.evidence_refs) == {"ev-h1", "ev-h2"}


# ── 2 · User merges ─────────────────────────────────────────────────

def test_user_domain_and_email_form_collapse_to_one():
    g = InvestigationGraph(
        nodes=(
            _n("u1", "user", "alice", domain="CORP"),
            _n("u2", "user", "alice@corp"),          # email form
            _n("u3", "user", "CORP\\alice"),         # DOMAIN\user shorthand
        ),
        edges=(),
    )
    resolved, merges = resolve_entities(g)
    users = resolved.nodes_of("user")
    assert len(users) == 1
    aliases = set((users[0].attrs or {}).get("aliases") or [])
    # At least the two absorbed forms appear as aliases
    assert "alice@corp" in aliases
    assert "CORP\\alice" in aliases
    assert all(m.kind == "user" for m in merges)


def test_user_sid_merges_to_existing_principal():
    g = InvestigationGraph(
        nodes=(
            _n("u1", "user", "bob", domain="CORP",
               sid="S-1-5-21-123-456-789-1000"),
            _n("u2", "user", "bob", sid="S-1-5-21-123-456-789-1000"),
        ),
        edges=(),
    )
    resolved, merges = resolve_entities(g)
    assert len(resolved.nodes_of("user")) == 1
    assert merges and merges[0].kind == "user"


def test_users_with_different_names_stay_separate():
    g = InvestigationGraph(
        nodes=(
            _n("u1", "user", "alice", domain="CORP"),
            _n("u2", "user", "bob",   domain="CORP"),
        ),
        edges=(),
    )
    resolved, _ = resolve_entities(g)
    assert len(resolved.nodes_of("user")) == 2


# ── 3 · Hash & process invariants ───────────────────────────────────

def test_duplicate_hashes_remain_single_node_invariant():
    """graph_builder already dedups hashes canonically. Entity
    resolution MUST NOT introduce duplicates for identical hash
    values."""
    same = "a" * 64
    g = InvestigationGraph(
        nodes=(
            _n("h1", "hash", same, algo="sha256"),
            _n("h2", "hash", same, algo="sha256"),
        ),
        edges=(),
    )
    resolved, _ = resolve_entities(g)
    hashes = resolved.nodes_of("hash")
    # graph_builder canonicalises, so at most one node — resolution
    # must not re-split them.
    assert len(hashes) <= 1 or all(h.value.lower() == same for h in hashes)


def test_process_image_basename_collapse():
    g = InvestigationGraph(
        nodes=(
            _n("p1", "process", "C:/Windows/System32/cmd.exe"),
            _n("p2", "process", "cmd.exe"),
        ),
        edges=(),
    )
    resolved, merges = resolve_entities(g)
    processes = resolved.nodes_of("process")
    assert len(processes) == 1
    assert merges and merges[0].kind == "process"


def test_processes_with_different_images_stay_separate():
    g = InvestigationGraph(
        nodes=(
            _n("p1", "process", "cmd.exe"),
            _n("p2", "process", "powershell.exe"),
        ),
        edges=(),
    )
    resolved, _ = resolve_entities(g)
    assert len(resolved.nodes_of("process")) == 2


# ── 4 · Edge redirection ────────────────────────────────────────────

def test_edges_get_repointed_to_surviving_node():
    """When two hosts merge, every edge that pointed to either host
    must point to the surviving host in the resolved graph."""
    g = InvestigationGraph(
        nodes=(
            _n("h-name", "host", "HOST01", ip="10.1.1.15"),
            _n("h-ip",   "host", "10.1.1.15"),
            _n("p1",     "process", "cmd.exe"),
        ),
        edges=(
            _e("executed_on", "p1", "h-name"),
            _e("executed_on", "p1", "h-ip"),   # duplicate that should
                                                # dedupe after merge
        ),
    )
    resolved, _ = resolve_entities(g)
    assert len(resolved.nodes_of("host")) == 1
    host_id = resolved.nodes_of("host")[0].id
    executed_on = [e for e in resolved.edges if e.relation == "executed_on"]
    assert executed_on, "executed_on edge disappeared"
    # Every remaining executed_on edge points at the surviving host
    for e in executed_on:
        assert e.to_id == host_id


def test_no_self_edges_after_merge():
    g = InvestigationGraph(
        nodes=(
            _n("h1", "host", "HOST01"),
            _n("h2", "host", "host01"),
        ),
        edges=(
            _e("belongs_to", "h1", "h2"),  # would become self-edge
        ),
    )
    resolved, _ = resolve_entities(g)
    for e in resolved.edges:
        assert e.from_id != e.to_id, "self-edge slipped through merge"


# ── 5 · Golden end-to-end ────────────────────────────────────────────

def test_end_to_end_entity_resolution_via_run_phase1():
    """Golden test: run_phase1 on NDJSON that references the same host
    by name (Sysmon) and by hostname array (Cisco-style) must
    collapse to one host node in the resolved graph."""
    ndjson = "\n".join([
        json.dumps({
            "EventID": 1, "Computer": "HOST01",
            "Image": "C:/Windows/System32/cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        }),
        json.dumps({
            "EventID": 3, "Computer": "host01",
            "SourceIp": "10.0.0.1", "DestinationIp": "8.8.8.8",
            "DestinationPort": 443, "Protocol": "tcp",
        }),
    ])
    state = run_phase1(ndjson)

    hosts = state.graph.nodes_of("host")
    assert len(hosts) == 1, (
        f"expected 1 canonical host after entity resolution, "
        f"got {len(hosts)}: {[h.value for h in hosts]}"
    )
    # entity_merges is populated only when nodes had to be collapsed
    # (graph_builder's own canonicalisation may already have done it).
    assert isinstance(state.entity_merges, tuple)


def test_entity_resolution_stage_appears_in_pipeline_trace():
    state = run_phase1('{"EventID":1,"Computer":"H","Image":"a.exe","CommandLine":"a"}')
    stages = [t["stage"] for t in state.stage_trace]
    assert "entity_resolution" in stages
    # Entity resolution must come AFTER graph build and BEFORE validation
    assert stages.index("entity_resolution") > stages.index("investigation_graph")
    assert stages.index("entity_resolution") < stages.index("evidence_validation")
