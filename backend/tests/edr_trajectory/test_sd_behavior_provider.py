"""The §d-backed Behavior evidence provider: one read path, truthfully bounded.

No SequenceEngine is constructed, no Behavior rule runs, no shadow state or
checkpoint is written, no Fabric Finding is emitted and no production is
touched. `MongoStoreProvider` is never imported.
"""
from __future__ import annotations

import copy
import inspect
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from edr_plane import behavior_sd_provider as bp
from edr_plane.behavior_evidence_adapter import (REFUSED_KIND,
                                                 REFUSED_NO_RAW_REF,
                                                 REFUSED_TENANT_CONFLICT)
from edr_plane.behavior_sd_provider import SdEvidenceProvider

from test_sd_production_adapter import FakeCollection

T = "ten_e759b7288598bd882e3dcac49d"
T_B = "ten_b000000000000000000000000"
EP = "ep_a67be48d5b4e01d4d9e8"
DEV = "dev_d21e1278f914"


def doc(ts: str, pid: int, *, tenant: str = T, device: str = DEV,
        raw: str | None = None, activity: str = "PROCESS",
        ingest: str = "2030-01-01T00:00:00+00:00") -> dict[str, Any]:
    return {"_id": f"oid_{pid}_{ts}", "tenant_id": tenant, "collector_id": device,
            "ingest_time": ingest, "ingest_job_id": raw or f"raw_{pid}",
            "activity_identity": f"act_{pid}_{ts}",
            "observation_id": f"obs_{pid}_{ts}",
            "event": {"ts": ts, "activity": activity, "op": "start",
                      "device_iid": device, "computer": "KUSHU",
                      "process": {"pid": pid, "image": f"C:\\p{pid}.exe",
                                  "cmdline": f"p{pid} run", "user": "KUSHU\\jp",
                                  "start_time": ts}}}


def db_with(*docs):
    return {"v2_shadow_observations": FakeCollection(list(docs)),
            "xdr_canonical_evidence": FakeCollection([])}


def provider(db, *, tenant=T, endpoint=EP, refs=(DEV, EP), **kw):
    return SdEvidenceProvider(db, tenant_id=tenant, endpoint_id=endpoint,
                              refs=list(refs), **kw)


T0 = datetime(2026, 10, 3, 4, 0, 0, tzinfo=timezone.utc)
T9 = datetime(2026, 10, 3, 5, 0, 0, tzinfo=timezone.utc)


def ts(minute: int, micro: int = 0) -> str:
    return (T0 + timedelta(minutes=minute,
                           microseconds=micro)).isoformat().replace(
        "+00:00", "Z")


async def win(p, *, kinds=("PROCESS",), limit=50, start=T0, end=T9):
    return await p.window(tenant_id=p.tenant_id, endpoint_id=p.endpoint_id,
                          start=start, end=end, kinds=kinds, limit=limit)


# ── the sequence window ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_process_sequence_window_returns_ascending_real_evidence():
    p = provider(db_with(doc(ts(1), 1), doc(ts(3), 3), doc(ts(2), 2)))
    recs = await win(p)
    assert [r.fields["process"]["name"] for r in recs] == ["p1.exe", "p2.exe",
                                                           "p3.exe"]
    assert all(r.kind == "PROCESS" for r in recs)


@pytest.mark.asyncio
async def test_window_filters_by_requested_kinds():
    p = provider(db_with(doc(ts(1), 1), doc(ts(2), 2, activity="DNS")))
    assert len(await win(p, kinds=("PROCESS",))) == 1
    assert len(await win(p, kinds=("DNS",))) == 1


@pytest.mark.asyncio
async def test_window_is_bounded_by_time():
    p = provider(db_with(doc(ts(1), 1), doc(ts(400), 2)))
    recs = await win(p, start=T0, end=T0 + timedelta(minutes=10))
    assert len(recs) == 1


@pytest.mark.asyncio
async def test_window_is_bounded_by_count_so_the_engine_sees_truncation():
    """Returning a full `limit` (= max_window_events + 1) is how the engine
    answers INSUFFICIENT_EVIDENCE rather than NO_MATCH."""
    p = provider(db_with(*[doc(ts(i), i) for i in range(1, 12)]))
    recs = await win(p, limit=5)
    assert len(recs) == 5
    assert p.counters["truncated"] >= 1


@pytest.mark.asyncio
async def test_unbounded_window_is_refused():
    p = provider(db_with(doc(ts(1), 1)))
    with pytest.raises(ValueError):
        await p.window(tenant_id=T, endpoint_id=EP, start=None, end=T9,
                       kinds=("PROCESS",), limit=10)
    with pytest.raises(ValueError):
        await p.window(tenant_id=T, endpoint_id=EP, start=T9, end=T0,
                       kinds=("PROCESS",), limit=10)


# ── tenant and endpoint authority ────────────────────────────────────────

@pytest.mark.asyncio
async def test_exact_tenant_isolation():
    p = provider(db_with(doc(ts(1), 1), doc(ts(2), 2, tenant=T_B)))
    recs = await win(p)
    assert len(recs) == 1
    assert all(r.tenant_id == T and r.ref.tenant_id == T for r in recs)


@pytest.mark.asyncio
async def test_same_endpoint_identifier_in_two_tenants_stays_separate():
    rows = [doc(ts(1), 1), doc(ts(2), 2, tenant=T_B)]
    a = await win(provider(db_with(*rows)))
    b = await win(provider(db_with(*rows), tenant=T_B))
    assert [r.fields["process"]["name"] for r in a] == ["p1.exe"]
    assert [r.fields["process"]["name"] for r in b] == ["p2.exe"]
    assert {r.tenant_id for r in a} == {T}
    assert {r.tenant_id for r in b} == {T_B}


def test_unresolved_tenant_fails_closed():
    for bad in (None, "", "   "):
        with pytest.raises(ValueError):
            SdEvidenceProvider(db_with(), tenant_id=bad, endpoint_id=EP,
                               refs=[DEV])


def test_unresolved_endpoint_fails_closed():
    for bad in (None, "", "  "):
        with pytest.raises(ValueError):
            SdEvidenceProvider(db_with(), tenant_id=T, endpoint_id=bad,
                               refs=[DEV])


def test_endpoint_with_no_validated_refs_fails_closed():
    with pytest.raises(ValueError):
        SdEvidenceProvider(db_with(), tenant_id=T, endpoint_id=EP, refs=[])


@pytest.mark.asyncio
async def test_scope_mismatch_on_a_call_is_refused():
    p = provider(db_with(doc(ts(1), 1)))
    with pytest.raises(ValueError):
        await p.window(tenant_id=T_B, endpoint_id=EP, start=T0, end=T9,
                       kinds=("PROCESS",), limit=10)
    with pytest.raises(ValueError):
        await p.window(tenant_id=T, endpoint_id="ep_other", start=T0, end=T9,
                       kinds=("PROCESS",), limit=10)


@pytest.mark.asyncio
async def test_poisoned_cross_tenant_upstream_row_is_rejected(monkeypatch):
    """Defence in depth: even if §d handed back a foreign row, it never
    reaches the engine."""
    async def poisoned(*_a, **_k):
        from edr_trajectory.providers import from_shadow
        from edr_trajectory.providers import finalize
        row = finalize(from_shadow(doc(ts(1), 1, tenant=T_B)))
        return {"items": [row], "has_more": False, "next_cursor": None}

    monkeypatch.setattr(bp, "page_device_evidence", poisoned)
    p = provider(db_with())
    assert await win(p) == []
    # refused at the adapter (tenant conflict) or at the provider's own
    # post-read guard — either way it never reaches the engine, and it is COUNTED
    assert (p.counters["cross_tenant_rejected"]
            + p.refusals[REFUSED_TENANT_CONFLICT]) == 1


@pytest.mark.asyncio
async def test_endpoint_identity_is_the_resolved_platform_id_not_the_alias():
    p = provider(db_with(doc(ts(1), 1)))
    recs = await win(p)
    assert {r.endpoint_id for r in recs} == {EP}
    assert DEV not in {r.endpoint_id for r in recs}
    assert "KUSHU" not in {r.endpoint_id for r in recs}


# ── identity and ordering authority ──────────────────────────────────────

@pytest.mark.asyncio
async def test_raw_reference_is_preserved_as_the_durable_identity():
    p = provider(db_with(doc(ts(1), 1, raw="raw_abc")))
    rec = (await win(p))[0]
    assert rec.ref.raw_id == "raw_abc"
    assert rec.ref.stable_key().startswith("ev_")


@pytest.mark.asyncio
async def test_stored_observation_time_is_the_ordering_authority():
    p = provider(db_with(doc(ts(3), 3), doc(ts(1), 1), doc(ts(2), 2)))
    recs = await win(p)
    assert [r.event_time for r in recs] == sorted(r.event_time for r in recs)


@pytest.mark.asyncio
async def test_ingest_time_changes_do_not_alter_order_or_identity():
    early = db_with(doc(ts(1), 1, ingest="2030-01-01T00:00:00+00:00"),
                    doc(ts(2), 2, ingest="2031-01-01T00:00:00+00:00"))
    late = db_with(doc(ts(1), 1, ingest="2099-01-01T00:00:00+00:00"),
                   doc(ts(2), 2, ingest="2020-01-01T00:00:00+00:00"))
    a, b = await win(provider(early)), await win(provider(late))
    assert [r.sort_key() for r in a] == [r.sort_key() for r in b]
    assert [r.ref.stable_key() for r in a] == [r.ref.stable_key() for r in b]


# ── deterministic pagination ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pagination_is_deterministic_and_loss_free():
    rows = [doc(ts(i), i) for i in range(1, 10)]
    p = provider(db_with(*rows))
    seen, after = [], None
    for _ in range(5):
        page = await p.page(tenant_id=T, endpoint_id=EP, start=T0, end=T9,
                            after=after, limit=3)
        if not page:
            break
        seen += page
        after = page[-1].sort_key()
    keys = [r.ref.stable_key() for r in seen]
    assert len(keys) == 9
    assert len(set(keys)) == 9                      # no duplicates
    assert [r.sort_key() for r in seen] == sorted(r.sort_key() for r in seen)


@pytest.mark.asyncio
async def test_page_continuation_uses_the_existing_sort_key_identity():
    rows = [doc(ts(i), i) for i in range(1, 6)]
    p = provider(db_with(*rows))
    first = await p.page(tenant_id=T, endpoint_id=EP, start=T0, end=T9,
                         after=None, limit=2)
    second = await p.page(tenant_id=T, endpoint_id=EP, start=T0, end=T9,
                          after=first[-1].sort_key(), limit=2)
    assert all(r.sort_key() > first[-1].sort_key() for r in second)
    assert not {r.ref.stable_key() for r in first} & \
        {r.ref.stable_key() for r in second}


@pytest.mark.asyncio
async def test_page_refuses_an_unbounded_range():
    p = provider(db_with(doc(ts(1), 1)))
    with pytest.raises(ValueError):
        await p.page(tenant_id=T, endpoint_id=EP, start=None, end=None,
                     after=None, limit=5)


@pytest.mark.asyncio
async def test_page_respects_the_caller_bound_even_with_more_upstream():
    p = provider(db_with(*[doc(ts(i), i) for i in range(1, 30)]))
    page = await p.page(tenant_id=T, endpoint_id=EP, start=T0, end=T9,
                        after=None, limit=4)
    assert len(page) == 4


# ── refusal accounting ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_raw_reference_is_counted_never_silently_converted():
    d = doc(ts(1), 1)
    d.pop("ingest_job_id")
    p = provider(db_with(d, doc(ts(2), 2)))
    recs = await win(p)
    assert len(recs) == 1
    assert p.refusals[REFUSED_NO_RAW_REF] == 1
    assert p.counters["rows_refused"] == 1


@pytest.mark.asyncio
async def test_unsupported_kind_is_out_of_scope_not_an_adapter_defect():
    """E14: a valid row of an activity family the Behavior contract does not
    consume is counted as OUT_OF_SCOPE, never as an adapter defect."""
    p = provider(db_with(doc(ts(1), 1, activity="SOMETHING_ELSE"),
                         doc(ts(2), 2)))
    recs = await win(p, kinds=())
    assert len(recs) == 1
    assert p.out_of_scope[REFUSED_KIND] == 1
    assert p.counters["rows_out_of_scope"] == 1
    assert REFUSED_KIND not in p.refusals
    assert p.counters["rows_refused"] == 0
    assert p.snapshot()["out_of_scope"] == {REFUSED_KIND: 1}


@pytest.mark.asyncio
async def test_snapshot_reports_counters_without_writing_anything():
    p = provider(db_with(doc(ts(1), 1)))
    await win(p)
    snap = p.snapshot()
    assert snap["tenant_id"] == T and snap["endpoint_id"] == EP
    assert snap["counters"]["rows_converted"] == 1
    assert snap["counters"]["sd_pages_read"] >= 1


# ── purity and isolation ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_source_documents_are_not_mutated():
    d = doc(ts(1), 1)
    before = copy.deepcopy(d)
    await win(provider(db_with(d)))
    assert d == before


def _code(module) -> str:
    """Executable source only: the module docstring and comments are prose and
    must not be mistaken for behaviour."""
    import ast
    tree = ast.parse(inspect.getsource(module))
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)):
        tree.body = tree.body[1:]
    return "\n".join(line for line in ast.unparse(tree).splitlines()
                     if not line.strip().startswith("#"))


def test_provider_issues_no_query_of_its_own():
    src = _code(bp)
    for forbidden in ("find(", "find_one", "aggregate", "$in", "$gte",
                      "tenant_field", "MongoStoreProvider",
                      "from_shadow", "from_canonical", "sync_collection",
                      "hostname", "device_iid", "ingest_time", "ingested_ms"):
        assert forbidden not in src, forbidden


def test_mongo_store_provider_is_not_imported():
    """Source-based, not session-based: another suite may legitimately import
    edr_behavior.provider, which says nothing about THIS module."""
    assert "MongoStoreProvider" not in _code(bp)
    assert "edr_behavior.provider" not in _code(bp)
    assert "from edr_behavior.provider" not in inspect.getsource(bp)


def test_provider_reads_only_through_the_sd_bounded_page():
    src = inspect.getsource(bp)
    assert "page_device_evidence" in src
    assert src.count("page_device_evidence(") == 1


def test_provider_does_not_execute_or_import_the_behavior_engine():
    import subprocess
    import sys
    from pathlib import Path
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; import edr_plane.behavior_sd_provider;"
         "print(sorted(m for m in sys.modules if m.startswith('edr_behavior')))"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parents[2]))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "['edr_behavior', 'edr_behavior.contracts']"


def test_provider_writes_nothing_anywhere():
    src = _code(bp)
    for forbidden in ("insert_one", "insert_many", "update_one", "replace_one",
                      "upsert", "delete_one", "create_index",
                      "record_endpoint_detection", "e3_behavior_detections",
                      "e3_behavior_replay_checkpoints"):
        assert forbidden not in src, forbidden
