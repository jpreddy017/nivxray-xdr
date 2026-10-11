"""Malformed ancestry must remain visible and cannot hang a trajectory pivot."""
from edr_trajectory.contracts import ID_GUID, PROVEN_CAUSAL, UNRESOLVED, event
from edr_trajectory.lineage import build_graph, isolate, lanes


def start(index, parent=None):
    key = f"pg:t:d:{index}"
    return event(event_id=f"e{index}", tenant_id="t", device_id="d",
                 kind="PROCESS_START", observed_ms=index + 1000,
                 process={"pid": index, "guid": str(index), "image": f"p{index}.exe"},
                 process_key=key, process_identity=ID_GUID,
                 parent={"guid": str(parent)} if parent is not None else {},
                 parent_key=f"pg:t:d:{parent}" if parent is not None else None,
                 parent_identity=ID_GUID if parent is not None else None)


def test_cyclic_parent_records_stay_visible_and_are_not_proven():
    events = [start(1, 2), start(2, 1), start(3, 2)]
    graph = build_graph(events)["nodes"]
    for key in ("pg:t:d:1", "pg:t:d:2"):
        assert graph[key]["causal_state"] == UNRESOLVED
        assert "cycle" in graph[key]["causal_basis"]
        assert graph[graph[key]["parent_key"]]["synthetic"]
    assert graph["pg:t:d:3"]["causal_state"] == PROVEN_CAUSAL
    assert {"pg:t:d:1", "pg:t:d:2", "pg:t:d:3"} <= {
        lane["lane_id"] for lane in lanes(events, 0, 5000)["lanes"]}
    assert isolate(events, process_key="pg:t:d:1")["lane_ids"] == ["pg:t:d:1"]
    assert isolate(events, process_key="pg:t:d:3")["lane_ids"] == ["pg:t:d:2", "pg:t:d:3"]
    # Input delivery order cannot decide which contradictory edge is hidden.
    assert build_graph(list(reversed(events))) == build_graph(events)


def test_self_parent_is_unresolved_and_lineage_pivot_terminates():
    events = [start(1, 1)]
    assert build_graph(events)["nodes"]["pg:t:d:1"]["causal_state"] == UNRESOLVED
    assert isolate(events, process_key="pg:t:d:1")["lane_ids"] == ["pg:t:d:1"]


def test_deep_process_tree_does_not_exhaust_python_recursion():
    events = [start(i, i - 1 if i else None) for i in range(1500)]
    rows = lanes(events, 0, 5000)["lanes"]
    processes = [r for r in rows if r["lane_type"] == "PROCESS"]
    assert len(processes) == 1500
    assert len({r["lane_id"] for r in processes}) == 1500
    assert processes[-1]["lane_id"] == "pg:t:d:1499"
    assert processes[-1]["depth"] == 1500
