"""Forward-stream frontier: initialize at the current frontier, never at history.

Hermetic. No SequenceEngine, no rule evaluation, no detection document, no run
record, no ledger, no Fabric Finding, no production, no real endpoint.
"""
from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from edr_behavior.replay import InMemoryCheckpointStore
from edr_plane import behavior_shadow_frontier as fr
from edr_plane.behavior_shadow_frontier import (MODE_FRONTIER,
                                                MODE_NO_EVIDENCE,
                                                REFUSED_BACKWARDS,
                                                REFUSED_ENDPOINT,
                                                REFUSED_MALFORMED_KEY,
                                                REFUSED_NOT_INITIALIZED,
                                                REFUSED_RULESET,
                                                REFUSED_UNRESOLVED_ITEM,
                                                ShadowFrontierRefused,
                                                StaleCheckpoint, advance,
                                                initialize, read, stream_id)
from edr_plane.behavior_sd_provider import SdEvidenceProvider

from test_sd_behavior_provider import DEV, EP, T, T_B, db_with, doc, ts

HASH_A = "a1" * 16
HASH_B = "b2" * 16
RULESET = ("rs_core", 3)
BY = "operator@nivxray.com"

W0 = datetime(2026, 10, 3, 4, 0, 0, tzinfo=timezone.utc)
W9 = datetime(2026, 10, 3, 5, 0, 0, tzinfo=timezone.utc)


def provider(db, *, tenant=T, endpoint=EP):
    return SdEvidenceProvider(db, tenant_id=tenant, endpoint_id=endpoint,
                              refs=[DEV, EP])


async def init(db, *, store=None, tenant=T, endpoint=EP, h=HASH_A):
    store = store or InMemoryCheckpointStore()
    cp = await initialize(provider(db, tenant=tenant, endpoint=endpoint), store,
                          tenant_id=tenant, endpoint_id=endpoint,
                          ruleset_id=RULESET[0], ruleset_version=RULESET[1],
                          ruleset_content_hash=h, window_start=W0,
                          window_end=W9, initialized_by=BY)
    return store, cp


def key(minute: int, k: str = "ev_x"):
    return (W0 + timedelta(minutes=minute), k)


# ── initialization ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_initializes_at_the_newest_existing_evidence():
    db = db_with(doc(ts(1), 1), doc(ts(7), 7), doc(ts(4), 4))
    _, cp = await init(db)
    assert cp["mode"] == MODE_FRONTIER
    assert cp["frontier_time"].startswith("2026-10-03T04:07")
    assert cp["frontier_key"].startswith("ev_")
    assert cp["after_time"] == cp["frontier_time"]
    assert cp["after_key"] == cp["frontier_key"]
    assert cp["evaluated_total"] == 0
    assert cp["done"] is False
    assert cp["initialized_by"] == BY
    assert cp["ruleset_content_hash"] == HASH_A
    assert cp["replay_id"] == f"shadow:{HASH_A}"


@pytest.mark.asyncio
async def test_initialization_evaluates_no_rules_and_writes_no_detection():
    """The only collaborator is the §d-backed provider; nothing else is touched."""
    db = db_with(doc(ts(1), 1))
    store, cp = await init(db)
    assert cp["evaluated_total"] == 0
    assert "detections" not in str(store.__dict__)
    src = inspect.getsource(fr)
    for forbidden in ("SequenceEngine", "process(", "e3_behavior_detections",
                      "record_endpoint_detection", "Detection("):
        assert forbidden not in src, forbidden


@pytest.mark.asyncio
async def test_frontier_uses_stored_observation_time_and_stable_key():
    db = db_with(doc(ts(5), 5, raw="raw_zzz"))
    p = provider(db)
    newest = (await p.window(tenant_id=T, endpoint_id=EP, start=W0, end=W9,
                             kinds=(), limit=50))[-1]
    _, cp = await init(db)
    assert cp["frontier_key"] == newest.ref.stable_key()
    assert cp["frontier_time"].startswith(
        newest.event_time.isoformat()[:19])


@pytest.mark.asyncio
async def test_ingest_time_cannot_affect_the_frontier():
    a = db_with(doc(ts(2), 2, ingest="2099-01-01T00:00:00+00:00"),
                doc(ts(3), 3, ingest="2020-01-01T00:00:00+00:00"))
    b = db_with(doc(ts(2), 2, ingest="2020-01-01T00:00:00+00:00"),
                doc(ts(3), 3, ingest="2099-01-01T00:00:00+00:00"))
    _, ca = await init(a)
    _, cb = await init(b)
    assert (ca["frontier_time"], ca["frontier_key"]) == \
        (cb["frontier_time"], cb["frontier_key"])


@pytest.mark.asyncio
async def test_unbounded_initialization_is_refused():
    with pytest.raises(ShadowFrontierRefused):
        await initialize(provider(db_with()), InMemoryCheckpointStore(),
                         tenant_id=T, endpoint_id=EP, ruleset_id="r",
                         ruleset_version=1, ruleset_content_hash=HASH_A,
                         window_start=None, window_end=W9, initialized_by=BY)


# ── no evidence ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_evidence_initialization_is_explicit_and_truthful():
    _, cp = await init(db_with())
    assert cp["mode"] == MODE_NO_EVIDENCE
    assert cp["frontier_time"] is None
    assert cp["frontier_key"] is None
    assert cp["after_time"] is None
    assert cp["after_key"] is None
    # the initialization instant is recorded, but NEVER as an evidence time
    assert cp["initialized_at"] != cp["frontier_time"]
    assert cp["initialized_at"] is not None


@pytest.mark.asyncio
async def test_no_evidence_state_is_not_beginning_of_history():
    store, cp = await init(db_with())
    assert cp["mode"] == MODE_NO_EVIDENCE
    got = await read(store, tenant_id=T, endpoint_id=EP,
                     ruleset_content_hash=HASH_A)
    # no position to resume from, and no pretence of one
    assert got["after_time"] is None
    assert got["mode"] == MODE_NO_EVIDENCE


# ── reading an uninitialized stream ──────────────────────────────────────

@pytest.mark.asyncio
async def test_read_without_initialization_fails_closed():
    with pytest.raises(ShadowFrontierRefused) as e:
        await read(InMemoryCheckpointStore(), tenant_id=T, endpoint_id=EP,
                   ruleset_content_hash=HASH_A)
    assert e.value.reason == REFUSED_NOT_INITIALIZED


@pytest.mark.asyncio
async def test_advance_without_initialization_never_starts_history():
    with pytest.raises(ShadowFrontierRefused) as e:
        await advance(InMemoryCheckpointStore(), tenant_id=T, endpoint_id=EP,
                      ruleset_content_hash=HASH_A,
                      processed_sort_key=key(1, "ev_a"))
    assert e.value.reason == REFUSED_NOT_INITIALIZED


# ── advancement ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_forward_advance_succeeds_and_counts():
    store, cp = await init(db_with(doc(ts(1), 1)))
    out = await advance(store, tenant_id=T, endpoint_id=EP,
                        ruleset_content_hash=HASH_A,
                        processed_sort_key=key(9, "ev_new"),
                        expected_revision=cp["revision"])
    assert out["after_key"] == "ev_new"
    assert out["evaluated_total"] == 1
    assert out["revision"] == cp["revision"] + 1
    assert out["done"] is False


@pytest.mark.asyncio
async def test_same_key_advance_is_idempotent():
    store, cp = await init(db_with(doc(ts(1), 1)))
    first = await advance(store, tenant_id=T, endpoint_id=EP,
                          ruleset_content_hash=HASH_A,
                          processed_sort_key=key(9, "ev_new"))
    again = await advance(store, tenant_id=T, endpoint_id=EP,
                          ruleset_content_hash=HASH_A,
                          processed_sort_key=key(9, "ev_new"))
    assert again["after_key"] == first["after_key"]
    assert again["evaluated_total"] == first["evaluated_total"]
    assert again["revision"] == first["revision"]


@pytest.mark.asyncio
async def test_backward_advance_is_refused():
    store, _ = await init(db_with(doc(ts(5), 5)))
    with pytest.raises(ShadowFrontierRefused) as e:
        await advance(store, tenant_id=T, endpoint_id=EP,
                      ruleset_content_hash=HASH_A,
                      processed_sort_key=key(1, "ev_old"))
    assert e.value.reason == REFUSED_BACKWARDS


@pytest.mark.asyncio
async def test_advance_past_an_unresolved_item_is_refused():
    store, _ = await init(db_with(doc(ts(1), 1)))
    with pytest.raises(ShadowFrontierRefused) as e:
        await advance(store, tenant_id=T, endpoint_id=EP,
                      ruleset_content_hash=HASH_A,
                      processed_sort_key=key(9, "ev_budget"),
                      item_resolved=False)
    assert e.value.reason == REFUSED_UNRESOLVED_ITEM


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [None, (), ("x",), ("not-a-time", "ev_a"),
                                 (datetime(2026, 1, 1), "ev_a"),
                                 (W0, ""), (W0, None), (W0, 7)])
async def test_malformed_sort_key_is_refused(bad):
    store, _ = await init(db_with(doc(ts(1), 1)))
    with pytest.raises(ShadowFrontierRefused) as e:
        await advance(store, tenant_id=T, endpoint_id=EP,
                      ruleset_content_hash=HASH_A, processed_sort_key=bad)
    assert e.value.reason == REFUSED_MALFORMED_KEY


@pytest.mark.asyncio
async def test_stale_revision_is_refused():
    store, cp = await init(db_with(doc(ts(1), 1)))
    await advance(store, tenant_id=T, endpoint_id=EP,
                  ruleset_content_hash=HASH_A,
                  processed_sort_key=key(5, "ev_1"),
                  expected_revision=cp["revision"])
    with pytest.raises(StaleCheckpoint):
        await advance(store, tenant_id=T, endpoint_id=EP,
                      ruleset_content_hash=HASH_A,
                      processed_sort_key=key(6, "ev_2"),
                      expected_revision=cp["revision"])


# ── stream isolation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_mismatch_is_refused():
    store, _ = await init(db_with(doc(ts(1), 1)))
    with pytest.raises(ShadowFrontierRefused) as e:
        await read(store, tenant_id=T_B, endpoint_id=EP,
                   ruleset_content_hash=HASH_A)
    assert e.value.reason == REFUSED_NOT_INITIALIZED   # keyed, so simply absent
    # and a document deliberately placed under the wrong tenant key is rejected
    await store.save(T_B, stream_id(HASH_A), EP,
                     {"mode": MODE_FRONTIER, "tenant_id": T,
                      "endpoint_id": EP, "ruleset_content_hash": HASH_A})
    with pytest.raises(ShadowFrontierRefused) as e2:
        await read(store, tenant_id=T_B, endpoint_id=EP,
                   ruleset_content_hash=HASH_A)
    assert e2.value.reason == fr.REFUSED_TENANT


@pytest.mark.asyncio
async def test_endpoint_mismatch_is_refused():
    store, _ = await init(db_with(doc(ts(1), 1)))
    await store.save(T, stream_id(HASH_A), "ep_other",
                     {"mode": MODE_FRONTIER, "tenant_id": T,
                      "endpoint_id": EP, "ruleset_content_hash": HASH_A})
    with pytest.raises(ShadowFrontierRefused) as e:
        await read(store, tenant_id=T, endpoint_id="ep_other",
                   ruleset_content_hash=HASH_A)
    assert e.value.reason == REFUSED_ENDPOINT


@pytest.mark.asyncio
async def test_ruleset_content_hash_mismatch_is_refused():
    store, _ = await init(db_with(doc(ts(1), 1)))
    await store.save(T, stream_id(HASH_B), EP,
                     {"mode": MODE_FRONTIER, "tenant_id": T,
                      "endpoint_id": EP, "ruleset_content_hash": HASH_A})
    with pytest.raises(ShadowFrontierRefused) as e:
        await read(store, tenant_id=T, endpoint_id=EP,
                   ruleset_content_hash=HASH_B)
    assert e.value.reason == REFUSED_RULESET


@pytest.mark.asyncio
async def test_different_ruleset_hashes_are_independent_streams():
    db = db_with(doc(ts(1), 1), doc(ts(6), 6))
    store, a = await init(db, h=HASH_A)
    _, b = await init(db, store=store, h=HASH_B)
    await advance(store, tenant_id=T, endpoint_id=EP,
                  ruleset_content_hash=HASH_A,
                  processed_sort_key=key(30, "ev_a"))
    assert (await read(store, tenant_id=T, endpoint_id=EP,
                       ruleset_content_hash=HASH_B))["after_key"] == \
        b["after_key"]
    assert a["replay_id"] != b["replay_id"]


@pytest.mark.asyncio
async def test_same_endpoint_id_in_two_tenants_has_isolated_checkpoints():
    rows = [doc(ts(2), 2), doc(ts(3), 3, tenant=T_B)]
    store, a = await init(db_with(*rows))
    _, b = await init(db_with(*rows), store=store, tenant=T_B)
    await advance(store, tenant_id=T, endpoint_id=EP,
                  ruleset_content_hash=HASH_A,
                  processed_sort_key=key(40, "ev_only_a"))
    assert (await read(store, tenant_id=T_B, endpoint_id=EP,
                       ruleset_content_hash=HASH_A))["after_key"] == \
        b["after_key"]
    assert a["tenant_id"] == T and b["tenant_id"] == T_B


@pytest.mark.asyncio
async def test_empty_ruleset_hash_is_refused():
    for bad in (None, "", "   "):
        with pytest.raises(ShadowFrontierRefused):
            stream_id(bad)


# ── forward streams are never "done" ─────────────────────────────────────

@pytest.mark.asyncio
async def test_done_stays_false_for_a_forward_shadow_stream():
    store, cp = await init(db_with(doc(ts(1), 1)))
    assert cp["done"] is False
    out = await advance(store, tenant_id=T, endpoint_id=EP,
                        ruleset_content_hash=HASH_A,
                        processed_sort_key=key(9, "ev_new"))
    assert out["done"] is False
    assert '"done": True' not in inspect.getsource(fr)
    assert "done\": True" not in inspect.getsource(fr)


# ── isolation from everything else ───────────────────────────────────────

def test_module_does_not_import_or_execute_the_behavior_engine():
    import subprocess
    import sys
    from pathlib import Path
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; import edr_plane.behavior_shadow_frontier;"
         "print(sorted(m for m in sys.modules if m.startswith('edr_behavior')))"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parents[2]))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


def test_module_writes_no_detection_ledger_or_finding():
    src = inspect.getsource(fr)
    for forbidden in ("e3_behavior_detections", "record_endpoint_detection",
                      "findings_intake", "EvaluationState", "create_index",
                      "insert_one", "insert_many", "ensure_indexes",
                      "ingest_time", "ingested_ms"):
        assert forbidden not in src, forbidden


def test_module_uses_the_existing_checkpoint_store_protocol_only():
    src = inspect.getsource(fr)
    assert "store.save(" in src and "store.load(" in src
    assert "MongoClient" not in src and "motor" not in src
