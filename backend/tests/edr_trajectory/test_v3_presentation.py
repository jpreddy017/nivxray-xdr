"""V3 PRESENTATION CONTRACT — hermetic acceptance gates (§5, §6, §8, §10, §12, §16).

These pin the invariants the V3 surface DEPENDS ON. V3 silently de-duplicates rows that repeat
`event_iid` (`trajectory_v3/amp/model.js`), so a presentation-identity defect does not look like a
bug — it looks like evidence that was never collected. Every test here exists because of that.

The real-endpoint proof is a SEPARATE gate and is reported as BLOCKED_ENVIRONMENT: this
environment holds no authorized real endpoint for validation (owner decision). Nothing below
substitutes for it, and nothing below reaches a fixture database, a seeder or a preview route.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from edr_trajectory import production_adapter as pa
from edr_trajectory import production_service as ps
from edr_trajectory import v3_presentation as v3

from test_sd_production_adapter import DEV, T, FakeDB, shadow_doc

REFS = [DEV]


def canonical_doc(event_time: str | None, pid: int, *, tenant: str = T, device: str = DEV,
                  activity_identity: str | None = None) -> dict[str, Any]:
    return {"_id": f"cid_{pid}_{event_time}", "tenant_id": tenant,
            "event_id": f"cev_{pid}_{event_time}", "event_time": event_time,
            "ingest_time": "2030-01-01T00:00:00+00:00",
            "host": {"hostname": device, "host_id": device},
            "provenance": {"collector_id": device},
            "additional_fields": {"activity_type": "PROCESS", "operation": "create",
                                  "activity_identity": activity_identity,
                                  "severity": "NONE"},
            "process": {"pid": pid, "executable_path": f"C:\\p{pid}.exe",
                        "command_line": f"p{pid} run", "start_time": event_time}}


async def _v3(db, **kw) -> dict[str, Any]:
    e3 = await ps.device_trajectory(db, tenant_id=T, refs=REFS, endpoint_id="ep_1", **kw)
    return v3.build(e3, computer={"hostname": DEV}, identity={"tenant_id": T})


# ---------------------------------------------------------------- §5 event identity


def test_presentation_identity_is_a_bijection_of_evidence_identity():
    for raw in ("act_1_x", "ce_deadbeef", "obs/with+odd=chars", "urn:a:b", "活動"):
        iid = v3.encode_iid(raw)
        assert iid.startswith(v3.IID_PREFIX)
        assert v3.decode_iid(iid) == raw, "a presentation identity must round-trip exactly"


def test_presentation_identity_is_url_safe():
    iid = v3.encode_iid("a/b+c=d e")
    assert all(c.isalnum() or c in "-_" for c in iid), "a deep link must survive a URL unchanged"


def test_presentation_identity_does_not_own_the_v1_namespace():
    # A V1 iid must be handed back to the V1 resolver untouched, or the existing contract breaks.
    assert v3.decode_iid("obs_123#abcdef0123") is None
    assert v3.decode_iid("") is None
    assert v3.decode_iid(None) is None


def test_presentation_identity_is_stable_across_repeated_reads():
    db = FakeDB(shadow=[shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(5)])
    a = asyncio.run(_v3(db))
    b = asyncio.run(_v3(db))
    assert [r["event_iid"] for r in a["events"]] == [r["event_iid"] for r in b["events"]]


def test_presentation_identity_does_not_depend_on_page_position_or_page_size():
    docs = [shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(9)]
    db = FakeDB(shadow=docs)
    big = asyncio.run(_v3(db, page_size=9))
    small = asyncio.run(_v3(db, page_size=2))
    by_small = {r["event_iid"] for r in small["events"]}
    assert by_small, "the small page must return rows"
    assert by_small <= {r["event_iid"] for r in big["events"]}


def test_presentation_identity_is_unique_on_every_page():
    docs = [shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(9)]
    out = asyncio.run(_v3(FakeDB(shadow=docs), page_size=9))
    iids = [r["event_iid"] for r in out["events"]]
    assert len(iids) == len(set(iids)), "V3 silently drops a repeated event_iid — it DELETES evidence"


def test_one_activity_in_two_stores_is_one_presentation_event():
    ts = "2026-01-01T00:00:01.000000+00:00"
    sd = shadow_doc(ts, 1)
    cd = canonical_doc(ts, 1, activity_identity=sd["activity_identity"])
    out = asyncio.run(_v3(FakeDB(shadow=[sd], canonical=[cd])))
    assert len(out["events"]) == 1
    assert set(out["events"][0]["evidence_stores"]) == {pa.STORE_SHADOW, pa.STORE_CANONICAL}


def test_same_millisecond_distinct_microseconds_remain_distinct_presentation_events():
    a = shadow_doc("2026-01-01T00:00:01.219438+00:00", 1)
    b = shadow_doc("2026-01-01T00:00:01.219516+00:00", 2)
    out = asyncio.run(_v3(FakeDB(shadow=[a, b])))
    assert len({r["event_iid"] for r in out["events"]}) == 2
    assert out["events"][0]["timestamp_instant_ms"] == out["events"][1]["timestamp_instant_ms"], \
        "both truncate to the same millisecond — that is exactly why ms must not be the identity"


def test_distinct_evidence_identity_is_never_collapsed_by_identical_rendering():
    a = shadow_doc("2026-01-01T00:00:01.000000+00:00", 1)
    b = dict(a, _id="other", activity_identity="act_other", observation_id="obs_other")
    out = asyncio.run(_v3(FakeDB(shadow=[a, b])))
    assert len({r["event_iid"] for r in out["events"]}) == 2


# ---------------------------------------------------------------- §6 ordering / paging


def test_initial_page_is_newest_first():
    docs = [shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(6)]
    out = asyncio.run(_v3(FakeDB(shadow=docs)))
    ms = [r["timestamp_instant_ms"] for r in out["events"]]
    assert ms == sorted(ms, reverse=True)


def test_rendering_millisecond_is_never_the_ordering_authority():
    out = asyncio.run(_v3(FakeDB(shadow=[shadow_doc("2026-01-01T00:00:01.000000+00:00", 1)])))
    assert "observed_us" not in out["events"][0], "source precision stays server-side"
    assert "RENDERING coordinate only" in out["ordering_authority"]


def test_pages_do_not_overlap_and_do_not_lose_events():
    docs = [shadow_doc(f"2026-01-01T00:00:{i:02d}.000000+00:00", i) for i in range(12)]
    db = FakeDB(shadow=docs)
    reference = asyncio.run(_v3(db, page_size=50))
    seen: list[str] = []
    cursor = None
    for _ in range(12):
        out = asyncio.run(_v3(db, page_size=5, cursor=cursor))
        page = [r["event_iid"] for r in out["events"]]
        assert not (set(page) & set(seen)), "page boundary repeated an event"
        seen += page
        cursor = out["e3_preview"]["older_cursor"]
        if not cursor:
            break
    assert seen == [r["event_iid"] for r in reference["events"]], \
        "the ordered union of pages must equal the bounded reference result"


def test_older_cursor_is_opaque():
    docs = [shadow_doc(f"2026-01-01T00:00:{i:02d}.000000+00:00", i) for i in range(6)]
    out = asyncio.run(_v3(FakeDB(shadow=docs), page_size=2))
    cursor = out["e3_preview"]["older_cursor"]
    assert cursor and "2026-01-01" not in cursor, "a cursor must not leak its ordering value"


# ---------------------------------------------------------------- §8 deep links


def test_deep_link_round_trip_resolves_to_the_same_event():
    docs = [shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(5)]
    db = FakeDB(shadow=docs)
    out = asyncio.run(_v3(db))
    wanted = out["events"][2]
    got = asyncio.run(pa.resolve_evidence(db, tenant_id=T, refs=REFS,
                                          event_id=v3.decode_iid(wanted["event_iid"])))
    assert got["state"] == "FOCUS_RESOLVED"
    assert v3.encode_iid(got["event"]["event_id"]) == wanted["event_iid"]
    assert got["event"]["observed_at"] == wanted["timestamp"]


def test_deep_link_by_observation_id_resolves_exactly():
    docs = [shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(5)]
    db = FakeDB(shadow=docs)
    wanted = docs[3]["observation_id"]
    got = asyncio.run(pa.resolve_evidence(
        db, tenant_id=T, refs=REFS,
        match=lambda ev: (ev.get("provenance") or {}).get("ref") == wanted))
    assert got["state"] == "FOCUS_RESOLVED"
    assert (got["event"]["provenance"] or {})["ref"] == wanted


def test_unresolvable_deep_link_never_substitutes_a_neighbour():
    docs = [shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(5)]
    got = asyncio.run(pa.resolve_evidence(FakeDB(shadow=docs), tenant_id=T, refs=REFS,
                                          event_id="ce_does_not_exist"))
    assert got["state"] == "FOCUS_NOT_RESOLVED"
    assert got["event"] is None


def test_deep_link_cannot_cross_a_customer():
    docs = [shadow_doc("2026-01-01T00:00:01.000000+00:00", 1)]
    out = asyncio.run(_v3(FakeDB(shadow=docs)))
    wanted = v3.decode_iid(out["events"][0]["event_iid"])
    got = asyncio.run(pa.resolve_evidence(FakeDB(shadow=docs), tenant_id="ten_other",
                                          refs=REFS, event_id=wanted))
    assert got["state"] == "FOCUS_NOT_RESOLVED", "another customer must not resolve this identity"


def test_v3_build_fails_closed_without_a_production_contract():
    out = v3.build({"state": "E3_PRODUCTION_CONTRACT_UNAVAILABLE"}, computer=None, identity=None)
    assert out["state"] == "V3_CONTRACT_UNAVAILABLE"
    assert out["events"] == []
    assert out["mock_data_reachable"] is False


# ---------------------------------------------------------------- §10/§12 truthful absence


def test_no_detection_is_not_rendered_as_benign():
    out = asyncio.run(_v3(FakeDB(shadow=[shadow_doc("2026-01-01T00:00:01+00:00", 1)])))
    row = out["events"][0]
    assert "e3_detection" not in row, "no detection must mean NO claim, not a benign claim"
    assert "e3_assessment" not in row, "E1 holds no disposition authority for a raw observation"
    assert "NOT been evaluated as benign" in out["e3_preview"]["detections_basis"]


def test_unavailable_fields_are_omitted_rather_than_emptied():
    doc = shadow_doc("2026-01-01T00:00:01+00:00", 1)
    doc["event"]["process"].pop("user")
    out = asyncio.run(_v3(FakeDB(shadow=[doc])))
    assert "user" not in out["events"][0]
    assert out["events"][0]["image"] == "C:\\p1.exe"


def test_file_execute_is_not_promoted_to_an_observed_process_start():
    assert v3.EVENT_TYPE["FILE_EXECUTE"] == "file_execute"
    assert v3.EVENT_TYPE["PROCESS_START"] == "process_create"


def test_findings_join_is_by_exact_reference_never_by_time():
    docs = [shadow_doc(f"2026-01-01T00:00:0{i}.000000+00:00", i) for i in range(3)]
    out = asyncio.run(_v3(FakeDB(shadow=docs)))
    target = out["events"][1]
    report = v3.apply_findings(out["events"], [{
        "evidence_refs": [target["observation_id"]], "rule_name": "BHV-TEST-001",
        "rule_id": "BHV-TEST-001", "severity": "HIGH", "finding_id": "f1",
        "detection_source": "DETERMINISTIC_RULE", "attck": ["T1059.001"],
        "attck_basis": "RULE_DECLARED"}])
    assert report["joined"] == 1
    assert target["e3_detection"]["name"] == "BHV-TEST-001"
    assert target["e3_detection"]["authority"] == "E1_DURABLE_FINDINGS"
    assert target["e3_attack"]["techniques"][0]["technique"] == "T1059.001"
    assert all("e3_detection" not in r for r in out["events"] if r is not target), \
        "a neighbouring observation must never inherit a detection"


def test_findings_without_attck_attach_no_technique():
    out = asyncio.run(_v3(FakeDB(shadow=[shadow_doc("2026-01-01T00:00:01+00:00", 1)])))
    row = out["events"][0]
    v3.apply_findings([row], [{"evidence_refs": [row["observation_id"]], "rule_id": "R2",
                               "rule_name": "R2", "detection_source": "DETERMINISTIC_RULE"}])
    assert "e3_attack" not in row, "a technique badge is never minted where none was declared"


# ---------------------------------------------------------------- §15/§16 isolation


def test_a_capped_deep_link_search_is_not_reported_as_an_absence():
    # 2 pages of evidence, 1 page of budget: the resolver must say it RAN OUT OF BUDGET, not that
    # the endpoint never held the identifier. Those are different claims.
    docs = [shadow_doc(f"2026-01-01T00:00:{i:02d}.000000+00:00", i) for i in range(12)]
    db = FakeDB(shadow=docs)
    import unittest.mock as mock
    with mock.patch.object(pa, "PAGE_MAX", 4):
        got = asyncio.run(pa.resolve_evidence(db, tenant_id=T, refs=REFS,
                                              event_id="ce_nope", max_pages=1))
    assert got["state"] == "FOCUS_NOT_RESOLVED"
    assert got["reason"] == "SEARCH_BUDGET_REACHED_BEFORE_EXHAUSTING_RETAINED_EVIDENCE"
    assert got["search"]["state"] == "PAGE_BUDGET_REACHED_1"
    assert "NOT proof" in got["meaning"]


def test_an_exhausted_deep_link_search_says_so():
    docs = [shadow_doc("2026-01-01T00:00:01.000000+00:00", 1)]
    got = asyncio.run(pa.resolve_evidence(FakeDB(shadow=docs), tenant_id=T, refs=REFS,
                                          event_id="ce_nope"))
    assert got["search"]["state"] == "EXHAUSTED_SEARCH_COMPLETED"
    assert got["reason"] == "EVIDENCE_IDENTITY_NOT_FOUND_FOR_THIS_ENDPOINT"


def test_hours_bounds_the_day_on_the_stored_time_field():
    # Regression guard for a defect found during this phase: matching the endpoint and filtering
    # the day in Python fetched an unordered prefix of a 279,554-observation history, never
    # reached the requested day, and returned 0 for every hour of a day holding 6,643
    # observations. The day MUST be a range on the store's own observation-time field.
    import inspect
    from routers import edr_trajectory_v3 as rv3
    src = inspect.getsource(rv3.trajectory_hours)
    assert 'tkey: {"$gte": lo, "$lt": hi}' in src, "the day must bound the QUERY, not the result"
    assert ".sort(tkey, -1)" in src, "the read must be ordered by the same field it ranges on"
    assert "truncation_meaning" in src, "a truncated count must declare itself a lower bound"


def test_an_analyst_window_bounds_the_read_on_the_ordering_field():
    # Without this, the toolbar claims a range the page did not read, and a deep link to an
    # observation older than the newest page resolves correctly and then never appears.
    docs = [shadow_doc(f"2026-01-01T0{h}:00:00.000000+00:00", h) for h in range(1, 8)]
    db = FakeDB(shadow=docs)
    out = asyncio.run(_v3(db, time_start="2026-01-01T03:00:00+00:00",
                          time_end="2026-01-01T05:00:00+00:00"))
    stamps = [r["timestamp"] for r in out["events"]]
    assert len(stamps) == 3, stamps
    assert all("T03" in s or "T04" in s or "T05" in s for s in stamps), stamps


def test_an_unwindowed_read_is_still_the_newest_evidence_unbounded():
    docs = [shadow_doc(f"2026-01-01T0{h}:00:00.000000+00:00", h) for h in range(1, 8)]
    out = asyncio.run(_v3(FakeDB(shadow=docs)))
    assert len(out["events"]) == 7, "absent window must mean unbounded, not empty"


def test_a_window_boundary_is_inclusive_and_decided_on_microseconds():
    a = shadow_doc("2026-01-01T03:00:00.000000+00:00", 1)
    b = shadow_doc("2026-01-01T03:00:00.000001+00:00", 2)
    out = asyncio.run(_v3(FakeDB(shadow=[a, b]),
                          time_start="2026-01-01T03:00:00.000000+00:00",
                          time_end="2026-01-01T03:00:00.000000+00:00"))
    # one microsecond past the ceiling is OUTSIDE — the decision is not made on a string
    assert len(out["events"]) == 1
    assert out["events"][0]["timestamp"].endswith("00.000Z") or "03:00:00" in out["events"][0]["timestamp"]


def test_an_empty_window_is_reported_as_an_absence_not_as_nothing_happened():
    docs = [shadow_doc("2026-01-01T01:00:00.000000+00:00", 1)]
    e3 = asyncio.run(ps.device_trajectory(FakeDB(shadow=docs), tenant_id=T, refs=REFS,
                                          endpoint_id="ep_1",
                                          time_start="2026-06-01T00:00:00+00:00",
                                          time_end="2026-06-02T00:00:00+00:00"))
    assert e3["evidence_state"] == "NO_REAL_EVIDENCE_FOR_THIS_ENDPOINT"
    assert "IN THE REQUESTED WINDOW" in e3["meaning"]
    assert "not evidence that nothing happened" in e3["meaning"]


def test_windowed_pages_do_not_overlap_and_do_not_lose_events():
    docs = [shadow_doc(f"2026-01-01T02:{i:02d}:00.000000+00:00", i) for i in range(10)]
    db = FakeDB(shadow=docs)
    kw = {"time_start": "2026-01-01T02:00:00+00:00", "time_end": "2026-01-01T02:09:00+00:00"}
    reference = asyncio.run(_v3(db, page_size=50, **kw))
    seen: list[str] = []
    cursor = None
    for _ in range(10):
        out = asyncio.run(_v3(db, page_size=3, cursor=cursor, **kw))
        page = [r["event_iid"] for r in out["events"]]
        assert not (set(page) & set(seen)), "windowed page boundary repeated an event"
        seen += page
        cursor = out["e3_preview"]["older_cursor"]
        if not cursor:
            break
    assert seen == [r["event_iid"] for r in reference["events"]]


def test_the_deep_link_resolver_is_never_limited_by_the_analyst_window():
    # The window is a VIEW. A deep link must be able to find evidence outside it, or "resolve
    # exactly" would mean "resolve exactly, within whatever happens to be on screen".
    docs = [shadow_doc(f"2026-01-01T0{h}:00:00.000000+00:00", h) for h in range(1, 8)]
    db = FakeDB(shadow=docs)
    everything = asyncio.run(_v3(db))
    oldest = everything["events"][-1]
    got = asyncio.run(pa.resolve_evidence(db, tenant_id=T, refs=REFS,
                                          event_id=v3.decode_iid(oldest["event_iid"])))
    assert got["state"] == "FOCUS_RESOLVED"
    assert got["event"]["observed_at"] == oldest["timestamp"]


def test_a_populated_window_is_never_emptied_by_the_fetch_limit():
    # Regression guard for a defect found during this phase against real evidence: the query
    # bound was widened by an hour, so on a busy endpoint the per-branch limit was consumed by
    # rows ABOVE the ceiling and a ten-minute window holding evidence returned ZERO rows while
    # reporting 138 rows excluded. A limit applied outside the window is not a window.
    busy = [shadow_doc(f"2026-01-01T05:{m:02d}:{s:02d}.000000+00:00", m * 60 + s)
            for m in range(30, 60) for s in (0, 30)]           # 60 rows ABOVE the window
    inside = [shadow_doc(f"2026-01-01T05:0{m}:00.000000+00:00", 900 + m) for m in range(1, 6)]
    out = asyncio.run(_v3(FakeDB(shadow=busy + inside), page_size=5,
                          time_start="2026-01-01T05:00:00+00:00",
                          time_end="2026-01-01T05:10:00+00:00"))
    assert out["returned"] == 5, (out["returned"], [r["timestamp"] for r in out["events"]])


def test_the_query_bound_stays_inside_the_analyst_window():
    docs = [shadow_doc("2026-01-01T05:05:00.000000+00:00", 1)]
    db = FakeDB(shadow=docs)
    asyncio.run(_v3(db, time_start="2026-01-01T05:00:00+00:00",
                    time_end="2026-01-01T05:10:00+00:00"))
    tkey = pa.OBSERVATION_TIME_KEY[pa.STORE_SHADOW]
    for q in db[pa.STORE_SHADOW].queries:
        rng = q[tkey]
        assert rng["$gte"] >= "2026-01-01T04:59:59", rng
        assert rng["$lte"] <= "2026-01-01T05:10:01", rng


def test_the_window_is_pushed_into_the_query_not_applied_afterwards():
    docs = [shadow_doc(f"2026-01-01T0{h}:00:00.000000+00:00", h) for h in range(1, 8)]
    db = FakeDB(shadow=docs)
    asyncio.run(_v3(db, time_start="2026-01-01T03:00:00+00:00",
                    time_end="2026-01-01T05:00:00+00:00"))
    issued = db[pa.STORE_SHADOW].queries
    assert issued, "no query was issued"
    tkey = pa.OBSERVATION_TIME_KEY[pa.STORE_SHADOW]
    for q in issued:
        rng = q.get(tkey)
        assert isinstance(rng, dict) and "$gte" in rng and "$lte" in rng, (
            "a window applied after the read leaves the read unbounded: " + repr(q))


def test_the_resume_bound_still_wins_when_it_is_stricter_than_the_window():
    docs = [shadow_doc(f"2026-01-01T02:{i:02d}:00.000000+00:00", i) for i in range(10)]
    db = FakeDB(shadow=docs)
    kw = {"time_start": "2026-01-01T02:00:00+00:00", "time_end": "2026-01-01T02:09:00+00:00"}
    first = asyncio.run(_v3(db, page_size=3, **kw))
    cursor = first["e3_preview"]["older_cursor"]
    db[pa.STORE_SHADOW].queries.clear()
    second = asyncio.run(_v3(db, page_size=3, cursor=cursor, **kw))
    tkey = pa.OBSERVATION_TIME_KEY[pa.STORE_SHADOW]
    ceilings = {q[tkey]["$lte"] for q in db[pa.STORE_SHADOW].queries}
    assert ceilings, "no resumed query was issued"
    # the resume bound is inside the window, so it — not the window ceiling — must be the ceiling
    assert all(c < "2026-01-01T02:09" for c in ceilings), ceilings
    assert not ({r["event_iid"] for r in second["events"]}
                & {r["event_iid"] for r in first["events"]})


def test_no_preview_or_fixture_path_is_reachable_from_the_v3_contract():
    import inspect
    src = inspect.getsource(v3)
    for forbidden in ("fixtures", "e1_shape_preview", "kushu_import", "platform_seed",
                      "preview_mount", "artifacts_overlay", "E3_PREVIEW_DB"):
        assert forbidden not in src, f"{forbidden} must never be reachable from a production path"


def test_the_contract_declares_production_evidence_rather_than_synthetic():
    out = asyncio.run(_v3(FakeDB(shadow=[shadow_doc("2026-01-01T00:00:01+00:00", 1)])))
    assert out["e3_preview"]["data_label"].startswith("REAL PRODUCTION EVIDENCE")
    assert out["e3_preview"]["source"] == "E1_PRODUCTION_EVIDENCE_STORES"
    assert out["mock_data_reachable"] is False


def test_page_counts_never_claim_to_describe_the_whole_endpoint():
    out = asyncio.run(_v3(FakeDB(shadow=[shadow_doc("2026-01-01T00:00:01+00:00", 1)])))
    assert "BOUNDED" in out["e3_preview"]["page_meaning"]
    assert "not proof that nothing happened" in out["activity"]["meaning"]


def test_tenant_fails_closed():
    from edr_trajectory.contracts import TenantRequired
    with pytest.raises(TenantRequired):
        asyncio.run(ps.device_trajectory(FakeDB(), tenant_id="", refs=REFS, endpoint_id="ep_1"))
