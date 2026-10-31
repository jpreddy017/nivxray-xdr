"""DT-I1D causal context: relationship contract, PID safety, UNKNOWN preservation, tenancy, bounds, JS parity."""
import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from edr_investigation import causal as C

ROOT = Path(__file__).resolve().parents[3]
FIX = json.loads((Path(__file__).parent / "fixtures" / "dt_causal_frames.json").read_text())
JS = ROOT / "frontend" / "src" / "v2" / "investigation" / "causalView.mjs"
REQUIRED = {"relationship_id", "relationship_type", "source_entity", "target_entity", "relationship_state",
            "evidence_refs", "timestamp", "window", "linkage", "reason", "resolver", "resolver_version", "provenance"}


def ctx(fid, frames=FIX, tenant="t1"):
    return C.build_causal_context(frames, tenant_id=tenant, subject_frame_iid=fid)


def test_proven_parent_child():
    e = ctx("c_b")["groups"]["caused_by"]
    assert [x["relationship_state"] for x in e] == ["PROVEN_CAUSAL"]
    assert e[0]["linkage"] == "SOURCE_PROCESS_GUID" and e[0]["source_entity"] == "proc_A"
    assert e[0]["evidence_refs"] == ["cev_c_b", "c_b", "raw_c_b"]


def test_process_to_file_and_network_supported():
    f, n = ctx("c_f")["groups"]["caused_by"][0], ctx("c_n")["groups"]["caused_by"][0]
    assert (f["relationship_type"], f["relationship_state"], f["source_entity"]) == ("wrote", "SUPPORTED_RELATIONSHIP", "proc_B")
    assert (n["relationship_type"], n["target_entity"]) == ("connected_to", "198.51.100.7")


def test_proximity_is_never_a_chain():
    q = ctx("c_q")["groups"]
    assert q["caused_by"] == [] and q["unknown"][0]["reason"] == C.ACTOR_UNKNOWN
    b = ctx("c_b")["groups"]
    corr = [e for e in b["correlated"] if e["provenance"]["frame_iid"] == "c_q"][0]
    assert corr["relationship_state"] == "CORRELATED" and corr["reason"] == C.NET_CORRELATED and corr["window"]
    bare = [{"frame_iid": x, "ts": f"2026-09-05T09:0{i}:00.000Z", "lane": lane, "label": x, "remote_ip": "203.0.113.1"}
            for i, (x, lane) in enumerate(zip("abcd", ("process", "process", "file", "network")))]
    for f in bare:
        assert {e["relationship_state"] for e in ctx(f["frame_iid"], bare)["edges"]} <= {"UNKNOWN", "CORRELATED"}


def test_missing_parent_unknown_and_mixed_chain():
    w = ctx("c_w")["groups"]
    assert w["caused_by"] == [] and w["unknown"][0]["reason"] == C.PARENT_UNKNOWN
    u = ctx("c_u")["groups"]
    assert u["unknown"][0]["reason"] == C.PARENT_PID_ONLY
    assert [(e["relationship_state"], e["target_entity"]) for e in u["produced"]] == [("PROVEN_CAUSAL", "proc_V")]


def test_pid_equality_never_establishes_identity():
    frames = [{"frame_iid": "p1", "ts": "2026-09-05T09:00:00Z", "lane": "process", "entity": {"pid": 100}},
              {"frame_iid": "p2", "ts": "2026-09-05T09:00:01Z", "lane": "process", "entity": {"iid": "proc_C"},
               "parent": {"pid": 100}}]
    assert C.identity_of({"iid": "x", "identity_basis": C.BASIS_PID_ONLY})["id"] is None
    for f in frames:
        assert all(e.relationship_state == "UNKNOWN" for e in C.frame_edges(f))


def test_supported_when_identity_not_guid_backed():
    f = {"frame_iid": "s", "ts": "2026-09-05T09:00:00Z", "lane": "process", "entity": {"iid": "proc_C"},
         "parent": {"iid": "proc_P"}, "canonical_evidence_id": "cev_s"}
    assert C.frame_edges(f)[0].relationship_state == "SUPPORTED_RELATIONSHIP"


def _edge(**kw):
    base = dict(relationship_id="r", relationship_type="spawned", source_entity="a", target_entity="b",
                relationship_state="PROVEN_CAUSAL", evidence_refs=("e",), timestamp=None, window=None,
                linkage="SOURCE_PROCESS_GUID", reason="x", resolver=C.RESOLVER, resolver_version=C.CAUSAL_VERSION,
                provenance={"identity_basis": {"source": C.BASIS_GUID, "target": C.BASIS_GUID}})
    base.update(kw)
    return C.CausalEdge(**base)


def test_contract_invariants():
    _edge()
    with pytest.raises(ValueError):
        _edge(provenance={"identity_basis": {"source": "PROCESS_IID", "target": C.BASIS_GUID}})
    with pytest.raises(ValueError):
        _edge(linkage=None)
    with pytest.raises(ValueError):
        _edge(relationship_state="SUPPORTED_RELATIONSHIP", evidence_refs=())
    with pytest.raises(ValueError):
        _edge(relationship_state="CORRELATED", window={"start": "a", "end": "b"})
    with pytest.raises(ValueError):
        _edge(relationship_type="co_occurred", relationship_state="SUPPORTED_RELATIONSHIP")
    with pytest.raises(ValueError):
        _edge(relationship_state="CORRELATED", relationship_type="co_occurred", window=None)
    with pytest.raises(ValueError):
        _edge(relationship_type="guessed")


def test_every_edge_has_full_contract_and_provenance():
    for f in FIX:
        for e in ctx(f["frame_iid"])["edges"]:
            assert set(e) == REQUIRED
            assert e["resolver_version"] == C.CAUSAL_VERSION and e["provenance"]["frame_iid"]
            assert e["relationship_state"] == "UNKNOWN" or e["evidence_refs"]


def test_tenant_isolation():
    with pytest.raises(ValueError):
        ctx("c_b", tenant="")
    with pytest.raises(ValueError):
        ctx("c_b", [dict(FIX[0], tenant_id="other")] + FIX[1:])
    assert ctx("c_b", [dict(f, tenant_id="t1") for f in FIX])["tenant_id"] == "t1"


def test_deterministic_and_bounded():
    shuffled = FIX[:]
    random.Random(7).shuffle(shuffled)
    assert ctx("c_b", shuffled) == ctx("c_b")
    many = [{"frame_iid": f"n{i:03d}", "ts": "2026-09-05T09:01:00.000Z", "lane": "network", "remote_ip": "203.0.113.2",
             "canonical_evidence_id": f"cev_n{i}"} for i in range(200)]
    out = ctx("c_b", FIX + many)
    assert len(out["groups"]["correlated"]) == C.MAX_ITEMS and len(out["edges"]) <= C.MAX_ITEMS
    assert len(out["groups"]["preceded_by"]) <= C.MAX_PRECEDING


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_parity_with_frontend_view_model():
    script = (f"import {{ buildCausalContext }} from {json.dumps(JS.as_uri())};"
              "const F = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "console.log(JSON.stringify(F.map((f) => buildCausalContext(F, f.frame_iid))));")
    script = script.replace("require('fs')", "(await import('node:fs'))")
    js = json.loads(subprocess.run(["node", "--input-type=module", "-e", script], input=json.dumps(FIX),
                                   capture_output=True, text=True, check=True).stdout)
    py = [ctx(f["frame_iid"]) for f in FIX]
    for p in py:
        p.pop("tenant_id")
    assert js == py
