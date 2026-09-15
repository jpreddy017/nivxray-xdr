"""Durable acquisition state — restart safety, on disk, per tenant.

The invariant under test:

    A collector restart must neither silently SKIP an uncollected window
    nor produce UNCONTROLLED DUPLICATE evidence.

Every test here uses a real SQLite file in a temp `XDR_STATE_DIR` and
simulates a restart the only honest way — by throwing the objects away and
opening the same file again. Four states stay distinct throughout:

    ACQUIRED  !=  QUEUED  !=  DELIVERED  !=  COMMITTED

and the collection window may only advance on COMMITTED.

The primitive is GENERIC: Microsoft is the first consumer, and one test
drives it with a non-Microsoft stream to keep that honest.
"""
from __future__ import annotations

import httpx
import pytest

from framework.acquisition_state import (ALREADY_COMMITTED, CLAIMED,
                                         CLAIMED_ELSEWHERE, AcquisitionState)
from framework.base import Envelope, Health
from framework.m365_activity import M365ManagementActivityConnector
from framework.outbox import Outbox, OutboxStatus

MS_TENANT = "11111111-2222-3333-4444-555555555555"
BASE = "https://manage.example.test/api/v1.0"
TOKEN_HOST = "https://login.example.test"
CT = "Audit.Exchange"


# ── fixtures ──────────────────────────────────────────────────────
@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    return str(tmp_path)


def _open(state_dir):
    """Open the durable store the way a fresh process would."""
    outbox = Outbox(path=state_dir)
    state = AcquisitionState(connection=outbox._conn, owner="runner-a")
    return outbox, state


def _cfg(**over):
    cfg = {
        "microsoft_tenant_id": MS_TENANT,
        "base_url": BASE,
        "authority": TOKEN_HOST,
        "content_types": [CT],
        "credentials": {"client_id": "app-1", "client_secret": "s3cret"},
        "lookback_minutes": 60,
    }
    cfg.update(over)
    return cfg


def _conn(state, outbox, tenant="acme", identity="m365-1", **over):
    return M365ManagementActivityConnector(
        tenant_id=tenant, config=_cfg(**over), identity=identity,
        state=state, outbox=outbox)


def _record(rid):
    return {"Id": rid, "RecordType": 1, "CreationTime": "2026-06-03T07:45:00",
            "Operation": "New-InboxRule", "OrganizationId": MS_TENANT,
            "UserType": 2, "Workload": "Exchange", "ResultStatus": "True",
            "UserId": "user1@corp.example",
            "Parameters": [{"Name": "ForwardTo",
                            "Value": "attacker@evil.example"}]}


def _mock(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def _client(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _client)


def _feed(pages, blobs, *, blob_status=200, list_status=200, hits=None):
    """A stub Microsoft feed. `pages` is a list of (items, next_page_uri)."""
    def handler(request):
        url = str(request.url)
        if hits is not None:
            hits.append(url)
        if "oauth2" in url:
            return httpx.Response(200, json={"access_token": "tok",
                                             "expires_in": 3600})
        if "subscriptions/content" in url:
            if list_status != 200:
                return httpx.Response(list_status,
                                      headers={"Retry-After": "30"},
                                      text="throttled")
            idx = 1 if "page=2" in url else 0
            items, nxt = pages[min(idx, len(pages) - 1)]
            headers = {"NextPageUri": nxt} if nxt else {}
            return httpx.Response(200, json=items, headers=headers)
        if "/blob/" in url:
            if blob_status != 200:
                return httpx.Response(blob_status, text="gone")
            return httpx.Response(200,
                                  json=blobs.get(url.rsplit("/", 1)[-1], []))
        return httpx.Response(404)
    return handler


def _item(cid, **over):
    d = {"contentType": CT, "contentId": cid,
         "contentUri": f"{BASE}/blob/{cid}",
         "contentCreated": "2026-06-03T09:00:00Z",
         "contentExpiration": "2026-06-10T09:00:00Z"}
    d.update(over)
    return d


def _deliver_all(outbox, tenant="acme", connector="m365-1"):
    rows = [r for r in outbox.list() if r.tenant_id == tenant
            and r.connector_id == connector]
    outbox.mark_delivering([r.id for r in rows])
    outbox.mark_delivered([r.id for r in rows])
    return rows


# ── the declaration must survive the durable hop ──────────────────
def test_the_outbox_preserves_the_declared_source(state_dir):
    outbox, _ = _open(state_dir)
    outbox.record(Envelope(
        tenant_id="acme", source="m365", source_event_id="e1",
        connector_id="m365-1", collector_id="col", collection_method="rest",
        parser_version="v1", source_timestamp=None,
        collection_timestamp="2026-06-03T09:00:00Z", event_type="cloud_audit",
        raw={"Id": "e1"}, declared_source="m365-unified-audit"))
    outbox.close()
    # a restart must still know what this delivery declares
    outbox2, _ = _open(state_dir)
    row = [r for r in outbox2.list() if r.source_event_id == "e1"][0]
    assert row.declared_source == "m365-unified-audit"
    assert row.to_envelope().to_dict()["declared_source"] == \
        "m365-unified-audit"


# ── 1 + 5 · restart during collection / pagination interruption ───
@pytest.mark.asyncio
async def test_restart_mid_pagination_resumes_the_same_page(state_dir,
                                                            monkeypatch):
    next_uri = f"{BASE}/{MS_TENANT}/activity/feed/subscriptions/content?page=2"
    hits = []
    _mock(monkeypatch, _feed(
        [([_item("c1")], next_uri), ([_item("c2")], None)],
        {"c1": [_record("r1")], "c2": [_record("r2")]}, hits=hits))

    outbox, state = _open(state_dir)
    c = _conn(state, outbox, max_pages_per_poll=1)          # stop after p1
    envs = await c.collect()
    assert [e.source_event_id for e in envs] == ["r1"]
    w = state.window("acme", "m365-1", CT)
    assert w["next_page_ref"] == next_uri
    assert w["committed_until"] is None        # nothing accepted yet
    outbox.close()

    # ——— restart ———
    outbox2, state2 = _open(state_dir)
    hits.clear()
    c2 = _conn(state2, outbox2, max_pages_per_poll=1)
    envs2 = await c2.collect()
    assert any("page=2" in u for u in hits), "must resume the stored page"
    assert [e.source_event_id for e in envs2] == ["r2"]


# ── 2 · restart after retrieval, before delivery ──────────────────
@pytest.mark.asyncio
async def test_retrieved_but_unaccepted_content_is_reacquired_not_skipped(
        state_dir, monkeypatch):
    _mock(monkeypatch, _feed([([_item("c1")], None)],
                             {"c1": [_record("r1")]}))
    outbox, state = _open(state_dir)
    c = _conn(state, outbox)
    envs = await c.collect()
    assert len(envs) == 1
    for e in envs:
        outbox.record(e)                       # QUEUED, not delivered
    # not accepted -> the batch is not committed and the window holds
    state.reconcile(outbox)
    assert state.window("acme", "m365-1", CT)["committed_until"] is None
    st = state.status("acme", "m365-1")
    assert {b["state"] for b in st["batches"]} == {"acquired"}
    outbox.close()

    # ——— restart: the blob must be re-acquired (NO SILENT SKIP) ———
    outbox2, state2 = _open(state_dir)
    c2 = _conn(state2, outbox2)
    envs2 = await c2.collect()
    assert [e.source_event_id for e in envs2] == ["r1"]
    # ...and re-delivery must NOT duplicate evidence
    ids = {outbox2.record(e)[0] for e in envs2}
    assert len(ids) == 1
    assert len([r for r in outbox2.list()
                if r.source_event_id == "r1"]) == 1


# ── 3 · restart after successful delivery ─────────────────────────
@pytest.mark.asyncio
async def test_accepted_content_commits_and_is_never_reread(state_dir,
                                                            monkeypatch):
    blob_hits = []

    def handler(request):
        url = str(request.url)
        if "/blob/" in url:
            blob_hits.append(url)
        return _feed([([_item("c1")], None)],
                     {"c1": [_record("r1")]})(request)
    _mock(monkeypatch, handler)

    outbox, state = _open(state_dir)
    c = _conn(state, outbox)
    for e in await c.collect():
        outbox.record(e)
    _deliver_all(outbox)
    state.reconcile(outbox)
    w = state.window("acme", "m365-1", CT)
    assert w["committed_until"] == w["pending_until"] is not None
    outbox.close()

    # ——— restart ———
    outbox2, state2 = _open(state_dir)
    c2 = _conn(state2, outbox2)
    blob_hits.clear()
    envs = await c2.collect()
    assert envs == [] and blob_hits == []
    assert c2.blobs_duplicate == 1


# ── 4 · duplicate contentId ───────────────────────────────────────
def test_a_committed_batch_cannot_be_claimed_again(state_dir):
    outbox, state = _open(state_dir)
    assert state.claim_batch("acme", "m365-1", CT, "c1") == CLAIMED
    state.record_batch_keys("acme", "m365-1", CT, "c1", ["r1"])
    outbox.record(Envelope(
        tenant_id="acme", source="m365", source_event_id="r1",
        connector_id="m365-1", collector_id="col", collection_method="rest",
        parser_version="v1", source_timestamp=None,
        collection_timestamp="x", event_type="cloud_audit", raw={},
        declared_source="m365-unified-audit"))
    _deliver_all(outbox)
    state.reconcile(outbox)
    assert state.claim_batch("acme", "m365-1", CT, "c1") == ALREADY_COMMITTED


# ── 6 · throttling ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_throttling_persists_the_page_and_holds_the_window(
        state_dir, monkeypatch):
    _mock(monkeypatch, _feed([([], None)], {}, list_status=429))
    outbox, state = _open(state_dir)
    c = _conn(state, outbox)
    assert await c.collect() == []
    assert c.health == Health.RATE_LIMITED
    w = state.window("acme", "m365-1", CT)
    assert w["next_page_ref"] and w["committed_until"] is None
    outbox.close()
    # the page survives the restart
    _, state2 = _open(state_dir)
    assert state2.window("acme", "m365-1", CT)["next_page_ref"] == \
        w["next_page_ref"]


# ── 7 · expired blob ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_expired_content_is_reported_and_does_not_hold_the_window(
        state_dir, monkeypatch):
    _mock(monkeypatch, _feed([([_item("c-old")], None)], {},
                             blob_status=410))
    outbox, state = _open(state_dir)
    c = _conn(state, outbox)
    assert await c.collect() == []
    assert c.blobs_expired == 1
    assert "no longer" in c.metrics.last_error
    state.reconcile(outbox)
    # the vendor can never serve it again, so the window may advance, and
    # the loss is in the connector's reported error rather than hidden
    assert state.window("acme", "m365-1", CT)["committed_until"] is not None


# ── 8 · temporary backend failure ─────────────────────────────────
@pytest.mark.asyncio
async def test_a_retrying_delivery_blocks_the_commit_until_accepted(
        state_dir, monkeypatch):
    _mock(monkeypatch, _feed([([_item("c1")], None)],
                             {"c1": [_record("r1")]}))
    outbox, state = _open(state_dir)
    c = _conn(state, outbox)
    for e in await c.collect():
        rid, _ = outbox.record(e)
    outbox.mark_retry(rid, "ingest 503")
    state.reconcile(outbox)
    assert state.window("acme", "m365-1", CT)["committed_until"] is None
    # once the ingest finally accepts it, the window advances
    outbox.mark_delivering([rid])
    outbox.mark_delivered([rid])
    state.reconcile(outbox)
    assert state.window("acme", "m365-1", CT)["committed_until"] is not None


def test_a_dead_lettered_record_blocks_the_window_and_is_reported(state_dir):
    outbox, state = _open(state_dir)
    state.claim_batch("acme", "m365-1", CT, "c1", window_end="2026-06-03T10:00:00+00:00")
    state.set_pending_window("acme", "m365-1", CT,
                             pending_until="2026-06-03T10:00:00+00:00")
    state.record_batch_keys("acme", "m365-1", CT, "c1", ["r1"])
    rid, _ = outbox.record(Envelope(
        tenant_id="acme", source="m365", source_event_id="r1",
        connector_id="m365-1", collector_id="col", collection_method="rest",
        parser_version="v1", source_timestamp=None, collection_timestamp="x",
        event_type="cloud_audit", raw={},
        declared_source="m365-unified-audit"))
    outbox.mark_dead(rid, "ingest rejected permanently")
    result = state.reconcile(outbox)
    assert result["blocked"] and result["blocked"][0]["reason"] == \
        "BLOCKED_BY_DEAD_LETTER_RECORDS"
    assert state.window("acme", "m365-1", CT)["committed_until"] is None
    st = state.status("acme", "m365-1")
    assert st["blocked"][0]["reason"].startswith(
        "BLOCKED_BY_DEAD_LETTER_RECORDS")


# ── 9 · collector crash ───────────────────────────────────────────
def test_a_crashed_owners_claim_expires_and_is_reclaimable(state_dir):
    outbox, _ = _open(state_dir)
    crashed = AcquisitionState(connection=outbox._conn, owner="runner-dead",
                               lease_seconds=0)
    assert crashed.claim_batch("acme", "m365-1", CT, "c1") == CLAIMED
    survivor = AcquisitionState(connection=outbox._conn, owner="runner-b")
    assert survivor.claim_batch("acme", "m365-1", CT, "c1") == CLAIMED


# ── 10 · concurrent collectors ────────────────────────────────────
def test_two_live_collectors_cannot_both_own_a_batch(state_dir):
    outbox, a = _open(state_dir)
    b = AcquisitionState(connection=outbox._conn, owner="runner-b")
    assert a.claim_batch("acme", "m365-1", CT, "c1") == CLAIMED
    assert b.claim_batch("acme", "m365-1", CT, "c1") == CLAIMED_ELSEWHERE
    assert a.claim_batch("acme", "m365-1", CT, "c1") == CLAIMED


@pytest.mark.asyncio
async def test_a_second_collector_skips_a_blob_already_in_flight(
        state_dir, monkeypatch):
    _mock(monkeypatch, _feed([([_item("c1")], None)],
                             {"c1": [_record("r1")]}))
    outbox, a = _open(state_dir)
    b = AcquisitionState(connection=outbox._conn, owner="runner-b")
    assert a.claim_batch("acme", "m365-1", CT, "c1") == CLAIMED
    c = _conn(b, outbox)
    assert await c.collect() == []
    assert c.blobs_in_flight_elsewhere == 1


# ── 11 · tenant + connector isolation ─────────────────────────────
def test_checkpoints_are_tenant_and_connector_scoped(state_dir):
    outbox, state = _open(state_dir)
    state.set_pending_window("tenant-a", "m365-1", CT,
                             pending_until="2026-06-03T10:00:00+00:00")
    state.set_pending_window("tenant-b", "m365-1", CT,
                             pending_until="2026-06-01T10:00:00+00:00")
    state.reconcile(outbox, tenant_id="tenant-a")
    assert state.window("tenant-a", "m365-1", CT)["committed_until"] == \
        "2026-06-03T10:00:00+00:00"
    # tenant B's window was NOT advanced by tenant A's reconciliation
    assert state.window("tenant-b", "m365-1", CT)["committed_until"] is None
    # and a claim in one tenant does not exist in the other
    assert state.claim_batch("tenant-a", "m365-1", CT, "c1") == CLAIMED
    assert state.claim_batch("tenant-b", "m365-1", CT, "c1") == CLAIMED
    assert state.claim_batch("tenant-a", "m365-2", CT, "c1") == CLAIMED
    assert state.status("tenant-b", "m365-1")["windows"][0][
        "committed_until"] is None


def test_one_connectors_batch_is_not_visible_to_another(state_dir):
    _, state = _open(state_dir)
    state.claim_batch("acme", "m365-1", CT, "c1")
    st = state.status("acme", "m365-2")
    assert st["batches"] == [] and st["windows"] == []


# ── record identity ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_record_without_a_microsoft_id_gets_a_nivx_reference(
        state_dir, monkeypatch):
    rec = _record("ignored")
    rec.pop("Id")
    _mock(monkeypatch, _feed([([_item("c9")], None)], {"c9": [rec, dict(rec)]}))
    outbox, state = _open(state_dir)
    c = _conn(state, outbox)
    envs = await c.collect()
    assert [e.source_event_id for e in envs] == ["m365:c9:0", "m365:c9:1"]
    acq = envs[0].raw["_m365_acquisition"]
    assert acq["microsoftEventId"] == "NOT_OBSERVED"
    assert acq["recordReferenceBasis"].startswith("NIVX_ACQUISITION_REFERENCE")
    # deterministic: the same blob re-acquired yields the same keys
    state.release_batch("acme", "m365-1", CT, "c9", reason="test")
    c2 = _conn(state, outbox)
    assert [e.source_event_id for e in await c2.collect()] == \
        ["m365:c9:0", "m365:c9:1"]


# ── the primitive is generic ───────────────────────────────────────
def test_the_primitive_serves_a_non_microsoft_stream(state_dir):
    """A DNS/firewall style connector can reuse it unchanged."""
    outbox, state = _open(state_dir)
    assert state.claim_batch("acme", "dns-export-1", "zone-transfer-logs",
                             "export-2026-06-03-01",
                             declared_source="dns-query-log") == CLAIMED
    state.record_batch_keys("acme", "dns-export-1", "zone-transfer-logs",
                            "export-2026-06-03-01", ["q1", "q2"])
    state.set_pending_window("acme", "dns-export-1", "zone-transfer-logs",
                             pending_until="2026-06-03T10:00:00+00:00")
    for key in ("q1", "q2"):
        rid, _ = outbox.record(Envelope(
            tenant_id="acme", source="dns", source_event_id=key,
            connector_id="dns-export-1", collector_id="col",
            collection_method="rest-poll", parser_version="v1",
            source_timestamp=None, collection_timestamp="x",
            event_type="dns_query", raw={}, declared_source="dns-query-log"))
        outbox.mark_delivering([rid])
        outbox.mark_delivered([rid])
    out = state.reconcile(outbox)
    assert out["committed_batches"] == ["export-2026-06-03-01"]
    assert state.window("acme", "dns-export-1",
                        "zone-transfer-logs")["committed_until"] == \
        "2026-06-03T10:00:00+00:00"


def test_a_batch_with_no_keys_yet_is_reported_as_waiting(state_dir):
    outbox, state = _open(state_dir)
    state.claim_batch("acme", "m365-1", CT, "c1")
    out = state.reconcile(outbox)
    assert out["waiting"][0]["reason"] == "NO_RECORD_KEYS_RECORDED_YET"


def test_missing_outbox_rows_are_never_assumed_accepted(state_dir):
    outbox, state = _open(state_dir)
    state.claim_batch("acme", "m365-1", CT, "c1")
    state.record_batch_keys("acme", "m365-1", CT, "c1", ["never-queued"])
    out = state.reconcile(outbox)
    assert out["committed_batches"] == []
    assert out["waiting"][0]["not_yet_accepted"] == 1


def test_committed_batches_can_be_pruned_without_losing_the_window(state_dir):
    outbox, state = _open(state_dir)
    state.set_pending_window("acme", "m365-1", CT,
                             pending_until="2026-06-03T10:00:00+00:00")
    state.reconcile(outbox)
    assert state.prune_committed(older_than_days=0) >= 0
    assert state.window("acme", "m365-1", CT)["committed_until"] == \
        "2026-06-03T10:00:00+00:00"


def test_the_state_names_the_distinction_it_protects(state_dir):
    _, state = _open(state_dir)
    assert "ACQUIRED != QUEUED != DELIVERED != COMMITTED" in \
        state.status("acme", "m365-1")["states"]


def test_the_outbox_status_lookup_reports_absence_not_success(state_dir):
    outbox, _ = _open(state_dir)
    assert outbox.statuses_for("acme", "m365-1", ["nope"]) == {}
    outbox.record(Envelope(
        tenant_id="acme", source="m365", source_event_id="k1",
        connector_id="m365-1", collector_id="col", collection_method="rest",
        parser_version="v1", source_timestamp=None, collection_timestamp="x",
        event_type="cloud_audit", raw={}, declared_source="m365-unified-audit"))
    assert outbox.statuses_for("acme", "m365-1", ["k1"]) == {
        "k1": OutboxStatus.QUEUED}
    # another tenant cannot see it
    assert outbox.statuses_for("other", "m365-1", ["k1"]) == {}
