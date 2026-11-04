"""``/api/uaie/catalog`` acceptance tests.

Locks the response shape callers are allowed to depend on plus the
derived dependency-graph invariants.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from server import app


def _client() -> TestClient:
    return TestClient(app)


def test_catalog_returns_stable_shape():
    r = _client().get("/api/uaie/catalog")
    assert r.status_code == 200
    body = r.json()
    for k in ("count", "capabilities", "graph"):
        assert k in body, f"missing top-level key: {k}"
    assert isinstance(body["count"], int)
    assert isinstance(body["capabilities"], dict)
    assert isinstance(body["graph"], dict)
    for k in ("edges", "orphans"):
        assert k in body["graph"]
        assert isinstance(body["graph"][k], list)


def test_catalog_capability_metadata_shape():
    """Every capability entry must carry the full metadata block —
    downstream planner / UI / CI consumers depend on this shape."""
    body = _client().get("/api/uaie/catalog").json()
    for cap_id, meta in body["capabilities"].items():
        for key in ("id", "category", "requires", "produces",
                     "deterministic", "cost", "contract_registered"):
            assert key in meta, (
                f"capability {cap_id!r} missing required key {key!r}")
        assert isinstance(meta["requires"], list)
        assert isinstance(meta["produces"], list)


def test_catalog_dependency_edges_reference_existing_capabilities():
    body = _client().get("/api/uaie/catalog").json()
    known = set(body["capabilities"].keys())
    for edge in body["graph"]["edges"]:
        assert edge["from"] in known, f"edge.from unknown: {edge['from']}"
        assert edge["to"]   in known, f"edge.to unknown: {edge['to']}"
        assert edge["via_artifact_types"], (
            f"edge without artifact types: {edge}")


def test_catalog_orphan_report_covers_only_registry_capabilities():
    body = _client().get("/api/uaie/catalog").json()
    known = set(body["capabilities"].keys())
    for o in body["graph"]["orphans"]:
        assert o["capability"] in known
        assert o["unsatisfied_requires"], (
            f"orphan without unsatisfied requires: {o}")
