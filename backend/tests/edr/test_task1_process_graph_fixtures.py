"""Task 1 · process graph honesty, against the EXISTING projection.

No second correlation engine: these tests drive
`routers.edr._project_endpoint_process_tree`, the projection the graph UI
consumes, and assert the three failure modes the owner called out —
PID reuse, a missing process-start event, and incomplete telemetry — are
represented as UNKNOWN rather than as confirmed edges.
"""
import importlib
import os

import pytest
from pymongo import MongoClient


class _StubResolution:
    """Stands in for the real endpoint-identity resolution so the test
    exercises the GRAPH projection, not the identity service (which has
    its own suite). The predicate it returns is the real tenant+collector
    scoping, so tenant isolation is still genuinely asserted."""

    def __init__(self, tenant, endpoint):
        self.identity = {"tenant_id": tenant, "endpoint_id": endpoint}
        self.refs = [endpoint]

    def predicate(self, store, fields=None):
        return {"tenant_id": self.identity["tenant_id"],
                "collector_id": self.identity["endpoint_id"]}


@pytest.fixture()
def edr(monkeypatch):
    mod = importlib.import_module("routers.edr")
    client = MongoClient(os.environ["MONGO_URL"])
    db = client["edr_task1_graph_fixtures"]
    client.drop_database("edr_task1_graph_fixtures")
    yield_db = db
    monkeypatch.setattr(mod, "sync_collection", lambda name: db[name],
                        raising=False)
    monkeypatch.setattr(mod.eq, "resolve_endpoint",
                        lambda supplied, scope: _StubResolution(TENANT, EP),
                        raising=False)
    monkeypatch.setattr(mod, "_window_honesty",
                        lambda *a, **k: {"window_hours": 24,
                                         "state": "WINDOW_COVERED",
                                         "oldest": None, "newest": None},
                        raising=False)
    yield mod, yield_db
    client.drop_database("edr_task1_graph_fixtures")
    client.close()


def _obs(tenant, endpoint, iid, name, pid, parent_iid=None, ppid=None,
         captured="2026-10-20T10:00:00Z", rules=None, state="PARENT_OBSERVED"):
    return {
        "tenant_id": tenant, "collector_id": endpoint, "kind": "process",
        "origin": "collector-live",
        "captured_at": captured,
        "event": {
            "iid": f"ev_{iid}_{pid}",
            "process": {"iid": iid, "name": name, "parent_iid": parent_iid},
            "rule_ids": rules or [],
            "raw": {"pid": pid, "ppid": ppid, "command_line": f"{name} --run",
                    "user": "CORP\\analyst", "image_path": f"C:\\\\Windows\\\\{name}",
                    "parent_lookup_state": state},
        },
    }


TENANT = "ten_fixture"
EP = "ep_fixture_1"


def _tree(edr, docs):
    mod, db = edr
    if docs:
        db["v2_shadow_observations"].insert_many(docs)
    return mod._project_endpoint_process_tree(EP, 24, TENANT)


def test_lineage_is_identity_linked_not_pid_linked(edr):
    """Same pid reused by a different process identity must NOT merge."""
    tree = _tree(edr, [
        _obs(TENANT, EP, "proc_parent", "explorer.exe", 4321),
        _obs(TENANT, EP, "proc_child_a", "cmd.exe", 9999,
             parent_iid="proc_parent", ppid=4321),
        # pid 9999 recycled minutes later by an unrelated identity
        _obs(TENANT, EP, "proc_child_b", "notepad.exe", 9999,
             parent_iid="proc_parent", ppid=4321,
             captured="2026-10-20T10:30:00Z"),
    ])
    ids = {n["process_iid"] for n in tree["nodes"]}
    assert {"proc_parent", "proc_child_a", "proc_child_b"} <= ids
    names = {n["process_iid"]: n["process"] for n in tree["nodes"]}
    assert names["proc_child_a"] == "cmd.exe"
    assert names["proc_child_b"] == "notepad.exe"


def test_missing_parent_becomes_an_explicit_ghost_not_a_dropped_edge(edr):
    tree = _tree(edr, [
        _obs(TENANT, EP, "proc_orphan", "powershell.exe", 7001,
             parent_iid="proc_never_seen", ppid=6000,
             state="PARENT_NOT_OBSERVED"),
    ])
    ghost = [n for n in tree["nodes"] if n["process_iid"] == "proc_never_seen"]
    assert ghost, "a referenced-but-unobserved parent must still appear"
    assert ghost[0]["observed"] is False
    assert ghost[0]["lineage_state"] == "GHOST_PARENT_NOT_OBSERVED"
    # and nothing is claimed about it
    assert ghost[0]["process"] is None
    assert ghost[0]["command_line"] is None


def test_incomplete_telemetry_yields_nulls_not_invented_fields(edr):
    mod, db = edr
    db["v2_shadow_observations"].insert_one({
        "tenant_id": TENANT, "collector_id": EP, "kind": "process",
        "origin": "collector-live",
        "captured_at": "2026-10-20T11:00:00Z",
        "event": {"iid": "ev_thin", "process": {"iid": "proc_thin",
                                                "name": "svchost.exe"},
                  "raw": {}},
    })
    tree = mod._project_endpoint_process_tree(EP, 24, TENANT)
    node = next(n for n in tree["nodes"] if n["process_iid"] == "proc_thin")
    assert node["pid"] is None and node["command_line"] is None
    assert node["user"] is None and node["sha256"] is None
    assert node["process_iid"] in tree["roots"]


def test_tenant_isolation(edr):
    tree = _tree(edr, [
        _obs(TENANT, EP, "proc_mine", "cmd.exe", 1001),
        _obs("ten_other", EP, "proc_theirs", "cmd.exe", 1002),
    ])
    assert {n["process_iid"] for n in tree["nodes"]} == {"proc_mine"}


def test_empty_window_draws_nothing(edr):
    tree = _tree(edr, [])
    assert tree["nodes"] == [] and tree["roots"] == []
