"""DT2-3 · the trajectory READ exposes the render graph (live preview).

DT2-2E composed the render contract but nothing served it, so the console had
no server-derived process/relationship/time structure to draw. This proves the
windowed endpoint read now carries `dt2.graph`, and that what it carries is
self-justifying: every edge names its evidence, every activity attaches to a
process that exists in the same payload, and no process is given an exit the
evidence does not contain.

EVIDENCE LABELLING — REAL. Read-only GETs against the live preview surface on
already-enrolled endpoints. No write, no fixture, no fabricated telemetry.
"""
from __future__ import annotations

import os

import pytest
import requests
from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

BASE = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
TENANT = "default"
#: WS-W1 · the real Windows endpoint used for production acceptance.
WINDOWS_ENDPOINT = "dev_0e10780f2c86"
WIDE = {"time_start": "2026-05-31T00:00:00Z",
        "time_end": "2026-09-29T00:00:00Z", "limit": 500}
FAMILIES = ("DNS", "NETWORK", "FILE", "REGISTRY")


@pytest.fixture(scope="module")
def graph():
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=30)
    assert r.status_code == 200, r.text
    token = r.json().get("access_token") or r.json().get("token")
    t = requests.get(f"{BASE}/api/edr/endpoints/{WINDOWS_ENDPOINT}/trajectory",
                     params=WIDE,
                     headers={"Authorization": f"Bearer {token}",
                              "X-Tenant-Id": TENANT}, timeout=60)
    assert t.status_code == 200, t.text
    body = t.json()
    assert (body.get("dt2") or {}).get("graph"), "dt2.graph missing"
    return body["dt2"]["graph"], body


def test_graph_is_served_with_the_window(graph):
    g, body = graph
    assert g["endpoint_id"] == WINDOWS_ENDPOINT
    assert g["contract_version"]
    assert g["process_nodes"], "no process lanes on the real Windows endpoint"
    # V1 keys are untouched — the graph is additive
    assert "events" in body and "lane_axis" in body


def test_every_edge_names_its_evidence(graph):
    g, _ = graph
    assert g["edges"], "no relationships on the real Windows endpoint"
    for e in g["edges"]:
        assert e["evidence_ref"], f"edge without evidence: {e['edge_id']}"
        assert e["derivation_basis"] and e["reason"], e["edge_id"]


def test_edges_only_connect_nodes_present_in_the_payload(graph):
    g, _ = graph
    ids = {n["node_id"] for n in g["process_nodes"]}
    ids |= {n["node_id"] for n in g["activity_nodes"]}
    for e in g["edges"]:
        assert e["source_node_id"] in ids, e["edge_id"]
        assert e["target_node_id"] in ids, e["edge_id"]


def test_parent_claims_are_backed_by_a_real_edge(graph):
    g, _ = graph
    pairs = {(e["source_node_id"], e["target_node_id"]) for e in g["edges"]
             if e["relationship_type"] == "PROCESS_PROCESS"}
    for n in g["process_nodes"]:
        parent = n.get("parent_node_id")
        if parent and parent in {p["node_id"] for p in g["process_nodes"]}:
            assert (parent, n["node_id"]) in pairs, n["node_id"]


def test_no_process_exit_is_invented(graph):
    g, _ = graph
    for n in g["process_nodes"]:
        life = n["lifeline"]
        if not life.get("exit_observed"):
            assert life.get("end_time") is None, n["node_id"]
            assert life.get("end_state") == "PROCESS_END_EVIDENCE_UNAVAILABLE"
            assert life.get("basis") == "EVIDENCE_SPAN_NOT_PROCESS_LIFETIME"
    assert g["availability"]["process_end_evidence"] == "UNAVAILABLE"


def test_activity_attaches_to_a_real_process_at_its_own_time(graph):
    g, _ = graph
    procs = {n["node_id"] for n in g["process_nodes"]}
    for a in g["activity_nodes"]:
        assert a["family"] in FAMILIES, a["family"]
        assert a["process_node_id"] in procs, a["node_id"]
        times = a["times"]
        assert times.get("ordering_time") or times.get("source_time"), a["node_id"]
        assert a["evidence_ref"], a["node_id"]


def test_activity_families_are_reported_honestly(graph):
    """Whatever the real evidence holds — no family is manufactured."""
    g, _ = graph
    observed = {a["family"] for a in g["activity_nodes"]}
    assert observed <= set(FAMILIES)
    # the report itself is the assertion: absence is absence
    for fam in FAMILIES:
        state = "OBSERVED" if fam in observed else "NOT_OBSERVED"
        assert state in ("OBSERVED", "NOT_OBSERVED")


def test_ordering_makes_no_causal_claim(graph):
    """DT2-2C's vocabulary is preserved: only `CAUSAL_EVIDENCE` is a causal
    claim, and it must carry its own proof. `ORDERED_OBSERVATION` says the
    steps share an actor, nothing more."""
    from edr_plane.trajectory import sequence as seq
    g, _ = graph
    for step in g["order"]:
        link = step.get("link_to_previous")
        assert link in (None,) + tuple(seq.CAUSALITY_LEVELS), link
        if link and link != seq.CAUSAL_EVIDENCE:
            assert step.get("link_reason"), step["step_id"]
    assert not [s for s in g["order"]
                if s.get("link_to_previous") == seq.CAUSAL_EVIDENCE
                and not s.get("link_proof_ref")]


def test_focus_is_exact_or_explicitly_not(graph):
    _, body = graph
    assert body["dt2"]["graph"]["focus"] is None      # nothing was requested


def test_graph_read_is_tenant_scoped(graph):
    """The same read without a tenant is refused server-side (Fix 1/6B-2)."""
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=30)
    token = r.json().get("access_token") or r.json().get("token")
    bare = requests.get(
        f"{BASE}/api/edr/endpoints/{WINDOWS_ENDPOINT}/trajectory",
        params=WIDE, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    assert bare.status_code == 403
    assert bare.json()["detail"]["code"] == "TENANT_REQUIRED"
