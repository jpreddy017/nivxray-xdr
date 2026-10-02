"""§d production adapter — hermetic contract tests.

The live, real-evidence proof is /app/scripts/sd_production_adapter_acceptance.py. These pin the
INVARIANTS so they cannot silently regress: observation-time authority, newest-first total
order, duplicate-free and loss-free paging, tenant fail-closed, deep-link exactness, and the
truthful handling of evidence that has no provable position in time.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from edr_trajectory import production_adapter as pa
from edr_trajectory import production_service as ps
from edr_trajectory.contracts import TenantRequired
from edr_trajectory.paging import BadCursor

T = "ten_test"
DEV = "dev_test01"


def shadow_doc(ts: str | None, pid: int, *, ingest: str = "2030-01-01T00:00:00+00:00",
               tenant: str = T, device: str = DEV, kind: str = "PROCESS") -> dict[str, Any]:
    return {"_id": f"oid_{pid}_{ts}", "tenant_id": tenant, "collector_id": device,
            "ingest_time": ingest, "activity_identity": f"act_{pid}_{ts}",
            "observation_id": f"obs_{pid}_{ts}",
            "event": {"ts": ts, "activity": kind, "op": "create", "device_iid": device,
                      "process": {"pid": pid, "image": f"C:\\p{pid}.exe", "cmdline": f"p{pid} run",
                                  "start_time": ts, "user": "T\\u"},
                      "provenance": {"ingest_job_id": f"raw_{pid}"}}}


class FakeCursor:
    def __init__(self, docs):
        self._docs = docs
        self._sort = None
        self._limit = None

    def sort(self, key, direction):
        self._sort = (key, direction)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def __aiter__(self):
        docs = list(self._docs)
        if self._sort:
            key, direction = self._sort
            docs.sort(key=lambda d: str(pa._dig(d, key) or ""), reverse=direction < 0)
        if self._limit:
            docs = docs[: self._limit]

        async def gen():
            for d in docs:
                yield d
        return gen()


class FakeCollection:
    """Supports exactly the shape the adapter issues: eq, $in, $lte, $ne on a dotted path."""

    def __init__(self, docs):
        self.docs = list(docs)

    def _match(self, doc, flt):
        for k, cond in flt.items():
            v = pa._dig(doc, k)
            if isinstance(cond, dict):
                if "$in" in cond and v not in cond["$in"]:
                    return False
                if "$lte" in cond and not (v is not None and str(v) <= str(cond["$lte"])):
                    return False
                if "$ne" in cond and v == cond["$ne"]:
                    return False
            elif v != cond:
                return False
        return True

    def find(self, flt, projection=None):
        return FakeCursor([d for d in self.docs if self._match(d, flt)])


class FakeDB:
    def __init__(self, shadow=(), canonical=()):
        self._c = {pa.STORE_SHADOW: FakeCollection(shadow),
                   pa.STORE_CANONICAL: FakeCollection(canonical)}

    def __getitem__(self, name):
        return self._c[name]


def page(db, **kw):
    kw.setdefault("tenant_id", T)
    kw.setdefault("refs", [DEV])
    return asyncio.run(pa.page_device_evidence(db, stores=(pa.STORE_SHADOW,), **kw))


# ── A. observation-time authority ─────────────────────────────────────────────

def test_a_ingest_time_is_never_the_ordering_key():
    """An event observed EARLIER but ingested LATER must still sort older.

    This is the backlog-replay invariant: if ingestion time leaked into the ordering, a replayed
    batch would appear at the top of the analyst's timeline.
    """
    db = FakeDB(shadow=[
        shadow_doc("2026-01-01T00:00:00+00:00", 1, ingest="2026-12-31T00:00:00+00:00"),
        shadow_doc("2026-06-01T00:00:00+00:00", 2, ingest="2026-06-01T00:00:01+00:00"),
    ])
    out = page(db, page_size=10)
    assert [e["process"]["pid"] for e in out["items"]] == [2, 1]
    assert out["provenance"]["ingest_time_used_as_observation_time"] is False
    assert out["provenance"]["ordering_authority"] == "STORED_OBSERVATION_TIME"


def test_b_observed_ms_is_derived_never_read_from_the_document():
    """No store holds `observed_ms`; it must be derived from the stored observation time."""
    db = FakeDB(shadow=[shadow_doc("2026-06-01T12:00:00+00:00", 1)])
    ev = page(db)["items"][0]
    assert ev["observed_ms"] == 1780315200000            # 2026-06-01T12:00:00Z
    assert "observed_ms" not in db[pa.STORE_SHADOW].docs[0]
    assert "observed_ms" not in db[pa.STORE_SHADOW].docs[0]["event"]


def test_c_evidence_without_observation_time_is_counted_never_placed():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1), shadow_doc(None, 2)])
    out = page(db)
    assert len(out["items"]) == 1
    assert out["unplaceable_no_observation_time_count"] == 0  # excluded by the index range
    assert all(e["observed_ms"] is not None for e in out["items"])


def test_d_unparseable_observation_time_is_not_given_a_time():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1),
                        shadow_doc("not-a-timestamp", 2)])
    out = page(db)
    assert out["unplaceable_no_observation_time_count"] == 1
    assert [e["process"]["pid"] for e in out["items"]] == [1]


# ── B. ordering and paging (§15) ──────────────────────────────────────────────

def test_e_newest_first():
    db = FakeDB(shadow=[shadow_doc(f"2026-06-{d:02d}T00:00:00+00:00", d) for d in range(1, 11)])
    out = page(db, page_size=10)
    ms = [e["observed_ms"] for e in out["items"]]
    assert ms == sorted(ms, reverse=True)
    assert out["order"] == "NEWEST_FIRST"


def test_f_pages_do_not_overlap_and_lose_nothing():
    db = FakeDB(shadow=[shadow_doc(f"2026-06-01T00:00:{s:02d}+00:00", s) for s in range(30)])
    seen, cursor, pages = [], None, 0
    while True:
        out = page(db, page_size=7, cursor=cursor)
        seen.append([e["event_id"] for e in out["items"]])
        pages += 1
        if not out["has_more"]:
            break
        cursor = out["next_cursor"]
        assert pages < 20
    flat = [x for p in seen for x in p]
    assert not (set(seen[0]) & set(seen[1]))
    assert len(flat) == len(set(flat)) == 30
    assert flat == [e["event_id"] for e in page(db, page_size=100)["items"]]


def test_g_identical_observation_timestamps_keep_a_strict_total_order():
    """Nine rows on one instant must not duplicate or vanish across a page boundary."""
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", p) for p in range(9)])
    seen, cursor = [], None
    while True:
        out = page(db, page_size=4, cursor=cursor)
        seen += [e["event_id"] for e in out["items"]]
        if not out["has_more"]:
            break
        cursor = out["next_cursor"]
    assert len(seen) == len(set(seen)) == 9


def test_h_cursor_is_opaque_and_a_foreign_cursor_is_refused():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1)])
    with pytest.raises(BadCursor):
        page(db, cursor="../../etc/passwd")
    with pytest.raises(BadCursor):
        page(db, cursor="eyJ0IjoxLCJpZCI6IngifQ==")      # valid base64, wrong contract


def test_h2_sub_millisecond_observations_are_never_collapsed_or_skipped():
    """REGRESSION. The stores record MICROSECONDS; `observed_ms` is milliseconds.

    Ordering and paging on the truncated millisecond made distinct observations look like a tie,
    and because the resume boundary used the same truncated value, members of that fake tie
    were dropped. Measured on the real corpus before the fix: 16 observations returned at one
    page size and never returned at another. Every row must survive paging at any page size.
    """
    docs = [shadow_doc(f"2026-06-01T00:00:00.123{n:03d}+00:00", n) for n in range(40)]
    db = FakeDB(shadow=docs)
    # all 40 truncate to the SAME millisecond
    assert len({pa.observation_us(d["event"]["ts"]) for d in docs}) == 40
    one_ms = {p["observed_ms"] for p in page(db, page_size=40)["items"]}
    assert len(one_ms) == 1

    for size in (1, 3, 7, 40):
        seen, cursor, guard = [], None, 0
        while guard < 100:
            out = page(db, page_size=size, cursor=cursor)
            seen += [e["event_id"] for e in out["items"]]
            guard += 1
            if not out["has_more"]:
                break
            cursor = out["next_cursor"]
        assert len(seen) == len(set(seen)) == 40, f"page_size={size} returned {len(seen)} rows"


def test_h3_order_is_identical_at_every_page_size_from_one_anchor():
    docs = [shadow_doc(f"2026-06-01T00:00:00.1{n:05d}+00:00", n) for n in range(60)]
    db = FakeDB(shadow=docs)
    anchor = page(db, page_size=1)["next_cursor"]

    def walk(size):
        seen, cursor, guard = [], anchor, 0
        while guard < 200:
            out = page(db, page_size=size, cursor=cursor)
            seen += [e["event_id"] for e in out["items"]]
            guard += 1
            if not out["has_more"]:
                break
            cursor = out["next_cursor"]
        return seen

    base = walk(1)
    assert len(base) == 59
    for size in (3, 7, 20, 59):
        assert walk(size) == base, f"page_size={size} produced a different order"


def test_i_page_size_is_bounded():
    db = FakeDB(shadow=[shadow_doc(f"2026-06-01T00:00:{s:02d}+00:00", s) for s in range(5)])
    assert page(db, page_size=10**6)["page_size"] == pa.PAGE_MAX
    assert page(db, page_size=0)["page_size"] == pa.PAGE_DEFAULT


# ── C. tenant and endpoint authority ─────────────────────────────────────────

def test_j_no_tenant_fails_closed():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1)])
    with pytest.raises(TenantRequired):
        asyncio.run(pa.page_device_evidence(db, tenant_id="", refs=[DEV]))


def test_k_another_customers_evidence_is_unreachable():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1, tenant="ten_other")])
    assert page(db)["items"] == []


def test_l_unaddressable_endpoint_is_explicit_not_empty_success():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1)])
    out = page(db, refs=[])
    assert out["state"] == "ENDPOINT_NOT_ADDRESSABLE_NO_VALIDATED_REFS"
    assert out["items"] == []


def test_m_only_declared_identity_fields_are_queried():
    from services.edr.endpoint_query import ENDPOINT_KEYED_STORES
    for store in pa.STORES:
        fields = {f for b in pa.branches(store, [DEV], T) for f in b if f != "tenant_id"}
        assert fields <= set(ENDPOINT_KEYED_STORES[store])
    with pytest.raises(KeyError):
        pa.branches("some_undeclared_store", [DEV], T)


def test_n_a_tenant_partitioned_store_is_never_queried_without_its_tenant():
    assert pa.branches(pa.STORE_SHADOW, [DEV], "") == []
    for b in pa.branches(pa.STORE_SHADOW, [DEV], T):
        assert b["tenant_id"] == T


# ── D. deep links (§16) ──────────────────────────────────────────────────────

def test_o_deep_link_resolves_the_exact_observation():
    db = FakeDB(shadow=[shadow_doc(f"2026-06-01T00:00:{s:02d}+00:00", s) for s in range(20)])
    target = page(db, page_size=20)["items"][11]
    r = asyncio.run(pa.resolve_evidence(db, tenant_id=T, refs=[DEV],
                                        event_id=target["event_id"], stores=(pa.STORE_SHADOW,)))
    assert r["state"] == "FOCUS_RESOLVED"
    assert r["event"]["event_id"] == target["event_id"]
    assert r["event"]["observed_at"] == target["observed_at"]


def test_p_a_deep_link_miss_never_selects_a_neighbour():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1)])
    r = asyncio.run(pa.resolve_evidence(db, tenant_id=T, refs=[DEV],
                                        event_id="ce_nope", stores=(pa.STORE_SHADOW,)))
    assert r["state"] == "FOCUS_NOT_RESOLVED"
    assert r["event"] is None
    assert r["reason"] == "EVIDENCE_IDENTITY_NOT_FOUND_FOR_THIS_ENDPOINT"


def test_q_evidence_identity_is_stable_across_reads():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1)])
    assert page(db)["items"][0]["event_id"] == page(db)["items"][0]["event_id"]


# ── E. production assembly (§18 · §19) ───────────────────────────────────────

def traj(db, **kw):
    kw.setdefault("tenant_id", T)
    kw.setdefault("refs", [DEV])
    kw.setdefault("endpoint_id", "ep_test")
    return asyncio.run(ps.device_trajectory(db, stores=(pa.STORE_SHADOW,), **kw))


def test_r_no_evidence_is_a_truthful_empty_state_not_a_fixture():
    out = traj(FakeDB())
    assert out["evidence_state"] == "NO_REAL_EVIDENCE_FOR_THIS_ENDPOINT"
    assert out["mock_data_reachable"] is False
    assert out["lanes"] == []


def test_s_absent_activity_families_are_not_observed_never_clean():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1)])
    fams = traj(db)["families"]
    assert fams["PROCESS"]["state"] == "OBSERVED"
    for fam in ("FILE", "NETWORK", "DNS", "REGISTRY", "DETECTION"):
        assert fams[fam]["state"] == "NOT_OBSERVED_IN_THIS_PAGE"
        assert "did not happen" in fams[fam]["meaning"]
    assert not any(v.get("state") in ("CLEAN", "BENIGN", "SAFE") for v in fams.values())


def test_t_activity_details_never_invent_a_field():
    db = FakeDB(shadow=[shadow_doc("2026-06-01T00:00:00+00:00", 1)])
    d = ps.activity_details(page(db)["items"][0])
    assert d["signer"] == ps.NOT_COLLECTED
    assert d["integrity_level"] == ps.NOT_COLLECTED
    assert d["observation_time_authority"] == "STORED_OBSERVATION_TIME"
    assert d["detection"]["state"] == "NO_DETECTION_ON_THIS_OBSERVATION"
    assert "benign" in d["detection"]["meaning"]
    assert d["process"]["identity_authority"] in ("PID_START_TIME", "SOURCE_PROCESS_GUID",
                                                  "PID_ONLY_NOT_AUTHORITATIVE")


def test_u_focus_outside_the_loaded_page_still_resolves_by_identity():
    db = FakeDB(shadow=[shadow_doc(f"2026-06-01T00:00:{s:02d}+00:00", s) for s in range(40)])
    oldest = page(db, page_size=40)["items"][-1]
    out = traj(db, page_size=5, focus_event_id=oldest["event_id"])
    assert out["focus"]["state"] == "FOCUS_RESOLVED"
    assert out["focus"]["basis"] == "RESOLVED_OUTSIDE_LOADED_PAGE_BY_EVIDENCE_IDENTITY"


def test_v_lineage_is_evidence_based_and_the_page_extent_is_labelled():
    db = FakeDB(shadow=[shadow_doc(f"2026-06-01T00:00:{s:02d}+00:00", s) for s in range(6)])
    out = traj(db)
    assert out["process_graph"]["nodes"]
    assert "NOT OF THE ENDPOINT'S HISTORY" in out["observed_range"]["basis"]
    assert "not 'no activity'" in out["coverage"]["statement"]
