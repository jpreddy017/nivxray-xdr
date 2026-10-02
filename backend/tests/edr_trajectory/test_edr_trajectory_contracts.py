"""E3 DT server contracts: paging, identity, causality, dedup, TI, retro, coverage, late, aggregation,
lanes, approvals, cross-tenant, UTC/DST, KUSHU-shaped, adapters, read-only, API."""
import asyncio
import copy
import random
from itertools import pairwise

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from edr_trajectory.actions import AppendOnlyViolation, ApprovalStore, StatusLog, pivot
from edr_trajectory.api import build_router
from edr_trajectory.contracts import (
    CORRELATED,
    ID_GUID,
    ID_PID_ONLY,
    ID_START_TIME,
    PROVEN_CAUSAL,
    SHAPE_FAITHFUL,
    SYNTHETIC,
    UNRESOLVED,
    TenantRequired,
    parse_instant,
)
from edr_trajectory.fixtures import H_PS, H_UPD
from edr_trajectory.identity import process_key
from edr_trajectory.lineage import build_graph, isolate, lanes
from edr_trajectory.paging import PAGE_MAX, BadCursor, page_newest_first
from edr_trajectory.providers import (
    STORE_CANONICAL,
    STORE_SHADOW,
    ListCollection,
    MongoStoreProvider,
    from_canonical,
    from_shadow,
)
from edr_trajectory.service import load, scenario
from edr_trajectory.ti import ProviderFailure, file_status, reputation
from edr_trajectory.timeline import coverage, density, lateness, viewport

H, M, D = 3_600_000, 60_000, 86_400_000


def _by_image(evs, name, kind="PROCESS_START"):
    return [e for e in evs if e["kind"] == kind and (e["process"].get("image") or "").lower().endswith(name)]


def _walk(evs, size):
    seen, cur, pages = [], None, 0
    while True:
        pg = page_newest_first(evs, size, cur, as_of_ms=None)
        seen += [e["event_id"] for e in pg["items"]]
        pages += 1
        if not pg["has_more"]:
            return seen, pages
        cur = pg["next_cursor"]


# ── 1 newest-first paging ─────────────────────────────────────────────
def test_first_page_is_newest_even_when_window_exceeds_cap(ev):
    evs = ev("bulk_process")["events"]
    assert len(evs) == 12_001
    pg = page_newest_first(evs, 2500)
    assert len(pg["items"]) == PAGE_MAX
    assert pg["items"][0]["observed_ms"] == max(e["observed_ms"] for e in evs)   # RC8 impossible
    assert pg["order"] == "NEWEST_FIRST" and pg["has_more"]


def test_full_walk_no_loss_no_duplication(ev):
    evs = ev("bulk_process")["events"]
    seen, pages = _walk(evs, 499)
    assert len(seen) == len(set(seen)) == len(evs) and pages == 25


def test_page_boundary_ties_on_same_observed_ms(ev):
    base = copy.deepcopy(ev("benign_tree")["events"][:1])[0]
    tied = [{**base, "event_id": f"t{i:02d}", "observed_ms": 1000} for i in range(7)]
    seen, _ = _walk(tied, 3)
    assert seen == [f"t{i:02d}" for i in range(6, -1, -1)]


def test_late_event_during_session_is_frozen_out_then_seen_by_new_session(ev):
    evs = copy.deepcopy(ev("benign_tree")["events"])
    as_of = max(e["ingested_ms"] for e in evs)
    p1 = page_newest_first(evs, 5, as_of_ms=as_of)
    late = {**evs[0], "event_id": "late-x", "observed_ms": p1["items"][-1]["observed_ms"] - 1, "ingested_ms": as_of + 1}
    rest = page_newest_first(evs + [late], 500, p1["next_cursor"])
    assert "late-x" not in [e["event_id"] for e in rest["items"]]
    fresh = page_newest_first(evs + [late], 500, as_of_ms=as_of + 1)
    assert "late-x" in [e["event_id"] for e in fresh["items"]]


def test_bad_cursor_and_bounded_size(ev):
    with pytest.raises(BadCursor):
        page_newest_first([], 10, "not-a-cursor")
    assert page_newest_first(ev("bulk_process")["events"], 10_000)["page_size"] == PAGE_MAX


# ── 2 identity / PID reuse / spoof ───────────────────────────────────
def test_pid_reuse_gives_two_instances(ev):
    keys = {e["process_key"] for e in _by_image(ev("edge_cases")["events"], "notepad.exe")}
    assert len(keys) == 2 and all(k.startswith("pi:ten_syn_a:SYN-EDGE-04:4242:") for k in keys)


def test_identity_states():
    assert process_key("t", "d", {"pid": 1, "start_time": "2026-10-01T00:00:00Z"})[1] == ID_START_TIME
    assert process_key("t", "d", {"pid": 1, "guid": "{AB}"})[1] == ID_GUID
    assert process_key("t", "d", {"pid": 1})[1] == ID_PID_ONLY
    k1 = process_key("t", "d", {"pid": 1, "start_time": 5}, boot_id="b1")[0]
    assert k1 != process_key("t", "d", {"pid": 1, "start_time": 5}, boot_id="b2")[0]


def test_parent_spoof_flagged(ev):
    ln = lanes(ev("lateral_dump")["events"], REF_ - D, REF_)["lanes"]
    sp = [x for x in ln if x.get("parent_spoof")]
    assert len(sp) == 1 and sp[0]["pid"] == 6000 and sp[0]["parent_spoof"]["creator"]["pid"] == 5300


REF_ = scenario("office_chain")["reference_ms"]


# ── 3 causality ──────────────────────────────────────────────────────
def test_office_chain_proven_lineage(ev):
    nodes = build_graph(ev("office_chain")["events"])["nodes"]
    chain = ["winword.exe", "wscript.exe", "powershell.exe", "upd.exe"]
    by = {n["image"].lower().rsplit("\\", 1)[-1]: n for n in nodes.values() if n["image"]}
    for parent, child in zip(["explorer.exe"] + chain, chain):
        assert by[child]["causal_state"] == PROVEN_CAUSAL and by[child]["parent_key"] == by[parent]["key"]
    assert by["explorer.exe"]["causal_state"] == UNRESOLVED and nodes[by["explorer.exe"]["parent_key"]]["synthetic"]


def test_pid_only_parent_is_correlated_never_proven(ev):
    nodes = build_graph(ev("lateral_dump")["events"])["nodes"]
    cmd = next(n for n in nodes.values() if n["pid"] == 5100)
    wmi = next(n for n in nodes.values() if n["pid"] == 2800 and not n["synthetic"])
    assert cmd["causal_state"] == CORRELATED and cmd["candidate_parent"] == wmi["key"]
    assert nodes[cmd["parent_key"]]["synthetic"]                       # not nested under the candidate


def test_missing_parents(ev):
    nodes = build_graph(ev("edge_cases")["events"])["nodes"]
    orphan = next(n for n in nodes.values() if n["pid"] == 4100)
    assert orphan["causal_state"] == PROVEN_CAUSAL and not nodes[orphan["parent_key"]]["observed"]
    nop = next(n for n in nodes.values() if n["pid"] == 4150)
    assert nop["causal_state"] == UNRESOLVED and nodes[nop["parent_key"]]["label"] == "Parent not observed"


def test_temporal_proximity_never_creates_an_edge(ev):
    evs = copy.deepcopy(ev("edge_cases")["events"])
    nop = next(e for e in evs if e["process"].get("pid") == 4150)
    orphan = next(e for e in evs if e["process"].get("pid") == 4100 and e["kind"] == "PROCESS_START")
    assert nop["observed_ms"] - orphan["observed_ms"] == M
    n = next(x for x in build_graph(evs)["nodes"].values() if x["pid"] == 4150)
    assert n["causal_state"] == UNRESOLVED and n["candidate_parent"] is None


# ── 4 dedup across stores ────────────────────────────────────────────
def test_duplicate_suppressed_across_both_stores(ev):
    d = ev("edge_cases")
    dups = [e for e in d["events"] if e["process"].get("pid") == 4300]
    assert len(dups) == 1 and dups[0]["sources"] == sorted([STORE_CANONICAL, STORE_SHADOW])
    assert d["suppressed_duplicates"] >= 1
    sh, ca = ev("edge_cases", source="shadow")["events"], ev("edge_cases", source="canonical")["events"]
    assert len(d["events"]) == len({e["event_id"] for e in sh} | {e["event_id"] for e in ca})


# ── 5 TI states ──────────────────────────────────────────────────────
def test_ti_states_distinguishable_and_never_clean_by_default():
    def bad(state):
        def f(_):
            raise ProviderFailure(state, state.lower())
        return f
    provs = {"a": bad("RATE_LIMITED"), "b": bad("OUTAGE"), "c": bad("PROVIDER_ERROR"),
             "d": lambda h: {"state": "NO_HIT"}, "e": lambda h: {"state": "CLEAN"},
             "f": lambda h: {"state": "MALICIOUS"}, "g": lambda h: 1 / 0,
             "h": lambda h: {"state": "CLEAN", "evidence": [{"kind": "KNOWN_GOOD_CATALOG", "ref": "syn"}]}}
    st = {r["provider"]: r["state"] for r in file_status("x" * 64, detections=[], providers=provs, now_iso="t")["reputation"]}
    assert st == {"a": "RATE_LIMITED", "b": "OUTAGE", "c": "PROVIDER_ERROR", "d": "NO_HIT", "e": "UNKNOWN",
                  "f": "UNKNOWN", "g": "PROVIDER_ERROR", "h": "CLEAN"}
    none = file_status("x" * 64, detections=[], providers={}, now_iso="t")
    assert none["reputation"][0]["state"] == "UNKNOWN" and not none["reputation"][0]["is_clean"]
    assert none["detection_state"] == "NO_DETECTION" and none["assessment"]["state"] == "UNASSESSED"
    assert reputation("MALICIOUS", provider="p", at="t", evidence=[{"k": 1}])["provenance"] == {"provider": "p", "timestamp": "t"}


def test_detection_is_not_a_verdict():
    fs = file_status(H_PS, detections=scenario("office_chain")["detections"][H_PS], providers={}, now_iso="t")
    assert fs["detection_state"] == "DETECTED" and fs["detections"][0]["is_verdict"] is False
    assert all(r["state"] != "MALICIOUS" for r in fs["reputation"])


# ── 6 adapters (both stores) + read-only ─────────────────────────────
def test_both_store_shapes_normalize_to_the_same_core():
    s = scenario("office_chain")
    sh = {d["activity_identity"]: from_shadow(d) for d in s["shadow"]}
    ca = {d["additional_fields"]["activity_identity"]: from_canonical(d) for d in s["canonical"]}
    both = set(sh) & set(ca)
    assert both
    for k in both:
        a, b = sh[k], ca[k]
        assert (a["kind"], a["observed_ms"], a["process"]["pid"], a["process"]["guid"], a["parent"]["guid"]) == \
               (b["kind"], b["observed_ms"], b["process"]["pid"], b["process"]["guid"], b["parent"]["guid"])


class _NoWrite(ListCollection):
    def __getattr__(self, name):
        if name in ("insert_one", "insert_many", "update_one", "update_many", "delete_one", "delete_many", "replace_one"):
            raise AssertionError(f"adapter attempted {name}")
        raise AttributeError(name)


def test_adapters_are_read_only_and_tenant_filtered():
    s = scenario("edge_cases")
    p = MongoStoreProvider(_NoWrite(s["shadow"]), STORE_SHADOW)
    a = asyncio.run(p.events("ten_syn_a", "SYN-EDGE-04"))
    b = asyncio.run(p.events("ten_syn_b", "SYN-EDGE-04"))
    assert a and b and {e["tenant_id"] for e in a} == {"ten_syn_a"} and {e["tenant_id"] for e in b} == {"ten_syn_b"}
    with pytest.raises(TenantRequired):
        asyncio.run(p.events("", "SYN-EDGE-04"))


# ── 7 retrospective status ───────────────────────────────────────────
def test_status_log_append_only_and_references_original(ev):
    log = StatusLog()
    orig = next(e for e in ev("office_chain")["events"] if e["process"].get("sha256") == H_UPD)
    snapshot = copy.deepcopy(orig)
    a = log.append(tenant_id="ten_syn_a", subject=H_UPD, kind="RETRO_DETECTION", state="DETECTED", recorded_at="t1",
                   references_event_id=orig["event_id"], provenance={"source": "own"})
    b = log.append(tenant_id="ten_syn_a", subject=H_UPD, kind="STATUS_CHANGE", state="ANALYST_REVIEWED",
                   recorded_at="t2", references_event_id=orig["event_id"], provenance={"source": "analyst"})
    assert b["supersedes"] == a["status_event_id"] and len(log.history("ten_syn_a", H_UPD)) == 2
    assert log.history("ten_syn_b", H_UPD) == [] and orig == snapshot
    with pytest.raises(AppendOnlyViolation):
        log.update(a["status_event_id"], state="CLEAN")
    with pytest.raises(ValueError):
        log.append(tenant_id="ten_syn_a", subject=H_UPD, kind="STATUS_CHANGE", state="X", recorded_at="t",
                   references_event_id=None, provenance={})


# ── 8 coverage / 9 late + backlog replay ─────────────────────────────
def test_gaps_are_explicit_and_not_inactivity(ev):
    s = scenario("edge_cases")
    cv = coverage(ev("edge_cases")["events"], s["reference_ms"] - D, s["reference_ms"], declared_gaps=s["declared_gaps"])
    states = {i["state"] for i in cv["intervals"]}
    assert {"NO_TELEMETRY_RECEIVED", "SENSOR_DECLARED_GAP"} <= states and "not 'no activity'" in cv["statement"]


def test_late_event_placed_by_observed_and_flagged(ev):
    late = _by_image(ev("edge_cases")["events"], "late.exe")[0]
    assert late["lateness"]["state"] == "LATE" and late["lateness"]["lateness_ms"] == 3 * H
    assert late["observed_ms"] == REF_ - 4 * H
    assert lateness({"observed_ms": 1, "ingested_ms": None})["state"] == "UNKNOWN"


def test_backlog_replay_order_independent(ev):
    evs = ev("edge_cases")["events"]
    shuffled = copy.deepcopy(evs)
    random.Random(3).shuffle(shuffled)
    a, b = lanes(evs, REF_ - D, REF_)["lanes"], lanes(shuffled, REF_ - D, REF_)["lanes"]
    assert a == b
    bk = [e for e in evs if e["kind"] == "FILE_WRITE" and (e["file"].get("path") or "").endswith("journal.log")]
    assert len(bk) == 20 and all(e["lateness"]["late"] for e in bk)
    assert [e["event_id"] for e in page_newest_first(evs, 500)["items"]] == \
           [e["event_id"] for e in page_newest_first(shuffled, 500)["items"]]


# ── 10 aggregation ───────────────────────────────────────────────────
def test_bulk_process_viewport_bounded_and_expandable(ev):
    evs = ev("bulk_process")["events"]
    ids = [x["lane_id"] for x in lanes(evs, REF_ - 3 * H, REF_)["lanes"]]
    vp = viewport(evs, ids, REF_ - 3 * H, REF_, 1200, 8, 50)
    lane = next(x for x in vp["lanes"] if x["mode"] == "BUCKETS")
    assert vp["n_buckets"] == 150 and len(lane["buckets"]) <= 150
    assert sum(b["count"] for b in lane["buckets"]) == lane["count"] >= 12_000
    b0 = lane["buckets"][0]
    zoom = viewport(evs, ids, b0["from_ms"], b0["from_ms"] + 30_000, 1200, 8, 50)
    assert any(x["mode"] == "EVENTS" and x["count"] > 0 for x in zoom["lanes"])
    assert viewport(evs, ids, REF_ - 3 * H, REF_, 10**6, 1, 10**4)["n_buckets"] == 400
    files = [x for x in viewport(evs, ids, REF_ - 3 * H, REF_, 1200, 8, 200)["lanes"] if x["lane_id"].startswith("file:")]
    assert len(files) == 97 and sum(x["count"] for x in files) == 12_000   # file rows carry their own activity


def test_density_30d_with_events_of_interest(ev):
    dn = density(ev("office_chain")["events"], REF_)
    assert len(dn["days"]) == 30 and dn["days"][-1]["day"] == "2026-10-02"
    assert any(i["detection"] for i in dn["events_of_interest"])


# ── 11 lanes + isolation ─────────────────────────────────────────────
def test_lane_model(ev):
    ln = {x["lane_id"]: x for x in lanes(ev("edge_cases")["events"], REF_ - D, REF_)["lanes"]}
    sql = next(x for x in ln.values() if x.get("pid") == 1800)
    assert sql["continues_before"] and sql["continues_after"]
    assert ln["net:unattributed"]["lane_type"] == "UNATTRIBUTED_NETWORK"
    assert any(x["lane_type"] == "FILE" for x in ln.values())
    office = lanes(ev("office_chain")["events"], REF_ - D, REF_)["lanes"]
    assert [x["depth"] for x in office if x["lane_type"] == "PROCESS"][:5] == [1, 2, 3, 4, 5]


def test_lineage_isolation(ev):
    evs = ev("office_chain")["events"]
    iso_ = isolate(evs, sha256=H_UPD)
    imgs = {(n["image"] or "").rsplit("\\", 1)[-1].lower() for k, n in build_graph(evs)["nodes"].items()
            if k in iso_["lane_ids"]}
    assert {"explorer.exe", "winword.exe", "wscript.exe", "powershell.exe", "upd.exe"} <= imgs
    assert isolate(evs, filename="upd.exe")["seeds"]
    cmd_iso = isolate(ev("lateral_dump")["events"], filename="cmd.exe")
    wmi = [n for n in build_graph(ev("lateral_dump")["events"])["nodes"].values() if n["pid"] == 2800 and not n["synthetic"]]
    assert wmi[0]["key"] not in cmd_iso["lane_ids"]                      # correlated parent not followed


# ── 12 approvals ─────────────────────────────────────────────────────
def test_approval_only_idempotent_tenant_scoped():
    st = ApprovalStore()
    a, c1 = st.request(tenant_id="ten_syn_a", action="QUARANTINE_FILE", target={"sha256": H_UPD}, requested_by="u",
                       idempotency_key="k1", reason="r", at="t")
    b, c2 = st.request(tenant_id="ten_syn_a", action="QUARANTINE_FILE", target={"sha256": H_UPD}, requested_by="u",
                       idempotency_key="k1", reason="r", at="t2")
    assert c1 and not c2 and a["request_id"] == b["request_id"]
    assert a["state"] == "APPROVAL_REQUESTED" and a["executed"] is False
    assert [h["state"] for h in a["state_history"]] == ["APPROVAL_REQUESTED"]
    assert st.list("ten_syn_b") == [] and len(st.list("ten_syn_a")) == 1
    assert [x["event"] for x in st.audit] == ["APPROVAL_REQUESTED", "IDEMPOTENT_REPLAY"]
    for bad in ({"action": "RUN_SCRIPT"}, {"tenant_id": ""}):
        with pytest.raises((ValueError, TenantRequired)):
            st.request(**{"tenant_id": "ten_syn_a", "action": "ISOLATE_DEVICE", "target": {}, "requested_by": "u",
                          "idempotency_key": "k", "reason": "", "at": "t", **bad})
    p = pivot("SEARCH_HASH", H_UPD)
    assert p["read_only"] and not p["approval_required"] and st.list("ten_syn_a") == [a]


# ── 13 cross-tenant ──────────────────────────────────────────────────
def test_cross_tenant_isolation(ev):
    a = ev("edge_cases", tenant="ten_syn_a", device="SYN-EDGE-04")["events"]
    b = ev("edge_cases", tenant="ten_syn_b", device="SYN-EDGE-04")["events"]
    assert not any("secret.txt" in (e["file"].get("path") or "") for e in a)
    assert b and all(e["tenant_id"] == "ten_syn_b" for e in b)
    assert not ({e["process_key"] for e in a} & {e["process_key"] for e in b})
    with pytest.raises(TenantRequired):
        asyncio.run(load("edge_cases", "  ", "SYN-EDGE-04"))


# ── UTC / DST ────────────────────────────────────────────────────────
def test_utc_dst_boundaries(ev):
    dst = sorted(e["observed_ms"] for e in ev("edge_cases")["events"] if (e["file"].get("path") or "").endswith("dst.txt"))
    assert [b - a for a, b in pairwise(dst)][::2] == [120_000, 2000]   # instants: no phantom DST hour
    assert parse_instant("2026-03-29 00:59:59") == parse_instant("2026-03-29T00:59:59Z") == 1774745999000
    assert parse_instant("2026-03-29T02:59:59+02:00") == 1774745999000
    assert all(e["observed_at"].endswith("Z") for e in ev("edge_cases")["events"])


# ── KUSHU-shaped ─────────────────────────────────────────────────────
def test_kushu_shape_labelled_and_honest(ev):
    d = ev("kushu_shape")
    assert d["provenance"]["label"] == SHAPE_FAITHFUL and scenario("kushu_shape")["label"] == SHAPE_FAITHFUL
    assert all(e["provenance"]["label"] == SHAPE_FAITHFUL for e in d["events"])
    msi = _by_image(d["events"], "msiexec.exe")[0]
    assert msi["process_identity"] == ID_PID_ONLY
    n = next(x for x in build_graph(d["events"])["nodes"].values() if x["pid"] == 9120)
    assert n["causal_state"] == CORRELATED
    fc = next(e for e in d["events"] if e["kind"] == "FILE_CREATE")
    assert fc["file"]["sha256"] is None                                 # never invented
    assert all(e["lateness"]["late"] for e in d["events"])
    assert scenario("office_chain")["label"] == SYNTHETIC


# ── API ──────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(build_router(), prefix="/api")
    return TestClient(app)


def test_api_openapi_and_endpoints(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in ("/api/e3/trajectory/devices/{device_id}/events", "/api/e3/trajectory/devices/{device_id}/lanes",
              "/api/e3/trajectory/devices/{device_id}/viewport", "/api/e3/trajectory/approvals",
              "/api/e3/trajectory/files/{sha256}/status", "/api/e3/trajectory/devices/{device_id}/coverage"):
        assert p in paths
    q = "scenario=office_chain&tenant=ten_syn_a"
    r = client.get(f"/api/e3/trajectory/devices/SYN-WS-01/events?{q}&page_size=5").json()
    assert r["order"] == "NEWEST_FIRST" and len(r["items"]) == 5 and r["provenance"]["label"] == SYNTHETIC
    r2 = client.get(f"/api/e3/trajectory/devices/SYN-WS-01/events?{q}&page_size=5&cursor={r['next_cursor']}").json()
    assert r2["items"][0]["observed_ms"] <= r["items"][-1]["observed_ms"]
    assert client.get("/api/e3/trajectory/devices/SYN-WS-01/events?scenario=office_chain").status_code == 400
    assert client.get(f"/api/e3/trajectory/devices/SYN-WS-01/events?{q}&cursor=zzz").status_code == 400
    fs = client.get(f"/api/e3/trajectory/files/{H_UPD}/status?{q}").json()
    assert fs["status_events"][0]["kind"] == "RETRO_DETECTION" and fs["reputation"][0]["state"] == "UNKNOWN"
    ap = client.post("/api/e3/trajectory/approvals", json={"tenant_id": "ten_syn_a", "action": "ISOLATE_DEVICE",
                                                           "target": {"device": "SYN-WS-01"}, "requested_by": "t",
                                                           "idempotency_key": "api-1", "reason": "test"})
    assert ap.status_code == 201 and ap.json()["request"]["state"] == "APPROVAL_REQUESTED"
    assert client.get("/api/e3/trajectory/approvals?tenant=ten_syn_b").json()["requests"] == []
    assert client.get("/api/e3/trajectory/devices/SYN-EDGE-04/lineage?scenario=edge_cases&tenant=ten_syn_a").status_code == 400


def test_preview_mount_off_by_default(monkeypatch):
    from edr_trajectory.preview_mount import mount_if_enabled

    monkeypatch.delenv("E3_TRAJECTORY_ROUTER", raising=False)
    app = FastAPI()
    assert mount_if_enabled(app, lambda: None) is False
    assert not [r for r in app.routes if "/e3/" in getattr(r, "path", "")]
    monkeypatch.setenv("E3_TRAJECTORY_ROUTER", "1")
    assert mount_if_enabled(app, lambda: None) is True
    assert TestClient(app).get("/api/openapi.json").json()["paths"].get("/api/e3/trajectory/contracts")
