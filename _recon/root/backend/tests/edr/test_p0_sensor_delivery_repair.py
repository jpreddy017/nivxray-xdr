"""P0 · Windows sensor delivery repair (F1–F4).

Covers exactly the four defects the investigation proved, and nothing else:
  F1  batch fallback must EXPIRE and be re-probed, not latch for the
      lifetime of the service process;
  F2  an explicitly and repeatedly rejected event must stop blocking the
      queue behind it, while remaining RETAINED and REPORTED;
  F3  a batch that accepted nothing must not end the cycle when progress
      was made, and must never spin on the same head;
  F4  drain mode must be bounded: proven progress only, reachable backend
      only, capped consecutively, and never a hot loop.

EVIDENCE LABELLING — TEST/SYNTHETIC. No live telemetry, no production
query, no endpoint contact.
"""
from __future__ import annotations

import pytest
from tests.edr import fixtures_b5_gap1_source as fx
from tests.edr.test_b5_gap1_pre_canary_acceptance import (  # reuse harness
    FakeBackend, SYSMON,
)

import importlib


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIVXFORGE_SENSOR_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("NIVX_SENSOR_ACQUIRE_BUDGET_SECONDS", "10")
    monkeypatch.setenv("NIVX_SENSOR_DELIVER_BUDGET_SECONDS", "10")
    module = fx.load_sensor(tmp_path / "state")
    source = fx.FakeSource(fx.FakeChannel(SYSMON))
    backend = FakeBackend()
    monkeypatch.setattr(module, "_query_channel", source.query)
    monkeypatch.setattr(module, "_post", backend.post)
    monkeypatch.setattr(module, "_get", lambda *a, **k: {})
    monkeypatch.setattr(module, "_open_session", lambda api, i: "tok")
    monkeypatch.setattr(module, "CHANNELS", tuple(source.channels))
    module.BATCH_SUPPORT.update(available=True, reason=None, retry_at=None)
    fx.write_identity(module)
    journal = module.nvx_journal.open_journal(module.STATE_DIR)
    yield module, source, backend, journal
    journal.close()


def _acquire(module, journal):
    excl = module.nvx_excl.Journal(module.EXCLUSION_JOURNAL)
    module.acquire(journal, {"exclusions": []}, excl, 10.0, fx.IDENTITY)


def _drain(module, journal, budget=5.0):
    return module._drain_journal("http://api", fx.IDENTITY, {"token": "t"},
                                 journal, 30, budget)


# ═════════════ F1 · batch fallback expires and is re-probed ═══════════
def test_batch_fallback_expires_and_is_reprobed(env, monkeypatch):
    module, source, backend, journal = env
    monkeypatch.setenv("NIVX_SENSOR_BATCH_REPROBE_SECONDS", "30")
    source.channel(SYSMON).produce(120, start=1)
    _acquire(module, journal)

    backend.batch_supported = False
    _drain(module, journal)
    assert module.BATCH_SUPPORT["available"] is False
    assert module.BATCH_SUPPORT["retry_at"] is not None, (
        "suppression must carry an expiry, not be permanent")
    assert backend.single_calls > 0, "fallback still delivers"

    # Still inside the cool-down: no pointless re-probe.
    backend.batch_supported = True
    calls = backend.batch_calls
    _drain(module, journal)
    assert backend.batch_calls == calls, "cool-down is honoured"

    # Cool-down elapsed → batching is re-probed WITHOUT a service restart.
    source.channel(SYSMON).produce(60, start=500)
    _acquire(module, journal)
    module.BATCH_SUPPORT["retry_at"] = 0.0
    assert module.batch_available() is True
    _drain(module, journal)
    assert backend.batch_calls > calls, (
        "batch delivery must resume by itself once the backend offers it")
    assert backend.duplicates() == 0


def test_batch_cooldown_is_bounded_below(env, monkeypatch):
    module, *_ = env
    monkeypatch.setenv("NIVX_SENSOR_BATCH_REPROBE_SECONDS", "1")
    assert module.batch_reprobe_seconds() >= 30, (
        "a one-second cool-down would re-probe a 404 route every cycle")


# ═════════════ F2 · quarantine is retained and reported ═══════════════
def test_rejected_head_is_quarantined_not_lost_and_not_blocking(env):
    module, source, backend, journal = env
    source.channel(SYSMON).produce(30, start=1)
    _acquire(module, journal)
    rows = journal.next_undelivered(limit=30)
    stubborn = rows[0]["payload"]              # the HEAD of the queue
    backend.refuse_payloads.add(stubborn)
    limit = module.nvx_journal.limits()["max_delivery_attempts"]

    for _ in range(limit):
        _drain(module, journal)

    assert journal.quarantined() == 1
    assert journal.depth() == 0, "newer evidence is no longer blocked"
    assert len(backend.accepted) == 29, "everything else was delivered"
    health = journal.health()
    assert module.nvx_journal.DELIVERY_QUARANTINE in health["states"]
    assert health["delivery_quarantined"] == 1
    assert health["evidence_by_state"].get(
        module.nvx_journal.REFUSED_UNACCEPTABLE) == 1


def test_quarantine_needs_an_explicit_event_specific_rejection(env):
    """A transport failure must NEVER become a permanent refusal."""
    module, source, backend, journal = env
    source.channel(SYSMON).produce(10, start=1)
    _acquire(module, journal)
    backend.down = True
    for _ in range(12):
        _drain(module, journal)
    assert journal.quarantined() == 0, (
        "an unreachable backend is not a rejection of the evidence")
    assert journal.depth() == 10, "everything stays owned by the endpoint"

    backend.down = False
    _drain(module, journal)
    assert journal.depth() == 0 and len(backend.accepted) == 10


def test_413_and_auth_failures_never_quarantine(env):
    """Size refusals and auth failures are TRANSPORT outcomes, not an
    explicit rejection of the evidence itself."""
    module, source, backend, journal = env
    source.channel(SYSMON).produce(40, start=1)
    _acquire(module, journal)

    backend.max_batch_bytes = 10          # every batch is "too large"
    for _ in range(module.nvx_journal.limits()["max_delivery_attempts"] + 2):
        _drain(module, journal, budget=2.0)
    assert journal.quarantined() == 0, "413 must never quarantine"

    backend.max_batch_bytes = 4 * 1024 * 1024
    calls = {"n": 0}
    real_post = backend.post

    def unauthorised(api, path, body, bearer=None):
        calls["n"] += 1
        if calls["n"] <= 6 and path.startswith("/api/edr/agent/telemetry"):
            raise RuntimeError("401 Unauthorized")
        return real_post(api, path, body, bearer=bearer)

    module._post = unauthorised
    for _ in range(3):
        _drain(module, journal, budget=2.0)
    assert journal.quarantined() == 0, "401 must never quarantine"

    module._post = real_post
    _drain(module, journal, budget=5.0)
    assert journal.depth() == 0 and len(backend.accepted) == 40
    assert backend.duplicates() == 0, "acknowledgement + dedupe unchanged"


def test_quarantined_rows_are_not_redelivered_or_duplicated(env):
    module, source, backend, journal = env
    source.channel(SYSMON).produce(20, start=1)
    _acquire(module, journal)
    head = journal.next_undelivered(limit=20)[0]["payload"]
    backend.refuse_payloads.add(head)
    for _ in range(module.nvx_journal.limits()["max_delivery_attempts"] + 4):
        _drain(module, journal, budget=3.0)
    assert journal.quarantined() == 1
    assert head not in backend.accepted, "a refused event was never accepted"
    assert backend.duplicates() == 0
    # even if the platform later would accept it, the sensor does not
    # silently re-offer it: it is a reported decision, not a retry loop.
    backend.refuse_payloads.clear()
    before = len(backend.accepted)
    _drain(module, journal, budget=3.0)
    assert len(backend.accepted) == before


def test_reclaim_never_deletes_quarantined_evidence(env):
    module, source, backend, journal = env
    source.channel(SYSMON).produce(12, start=1)
    _acquire(module, journal)
    backend.refuse_payloads.add(journal.next_undelivered(limit=12)[0]["payload"])
    for _ in range(module.nvx_journal.limits()["max_delivery_attempts"]):
        _drain(module, journal)
    assert journal.quarantined() == 1
    journal.reclaim()
    assert journal.quarantined() == 1, (
        "reclaim may only free evidence the platform ACCEPTED")


# ═════════════ F3 · no infinite retry, no lost budget ═════════════════
def test_refusing_head_is_offered_once_per_cycle(env):
    module, source, backend, journal = env
    source.channel(SYSMON).produce(5, start=1)
    _acquire(module, journal)
    for row in journal.next_undelivered(limit=5):
        backend.refuse_payloads.add(row["payload"])

    before = backend.batch_calls
    out = _drain(module, journal, budget=3.0)
    assert backend.batch_calls - before == 1, (
        "the same refusing head must not be hammered inside one budget")
    assert out["sent"] == 0 and out["failed"] >= 1
    assert out["backend_unreachable"] is True, (
        "no acceptance and no quarantine means no progress at all")
    assert journal.depth() == 5, "nothing was released"


def test_partial_batch_keeps_spending_the_budget(env):
    module, source, backend, journal = env
    source.channel(SYSMON).produce(150, start=1)
    _acquire(module, journal)
    rows = journal.next_undelivered(limit=150)
    backend.refuse_payloads.add(rows[70]["payload"])   # mid-queue refusal
    out = _drain(module, journal, budget=8.0)
    # Everything up to the refusal plus everything in the batches already
    # in flight is delivered; the refusal itself still owns its place in
    # journal order until it has been rejected `limit` times.
    assert out["sent"] >= 99, "delivery continued past a mid-queue refusal"
    assert backend.batch_calls >= 2, "the budget was not abandoned"
    assert out["backend_unreachable"] is False
    limit = module.nvx_journal.limits()["max_delivery_attempts"]
    for _ in range(limit):
        _drain(module, journal, budget=8.0)
    assert journal.quarantined() == 1
    assert journal.depth() == 0, "the tail behind the refusal drained"
    assert len(backend.accepted) == 149
    assert backend.duplicates() == 0


# ═════════════ F4 · bounded drain mode ════════════════════════════════
@pytest.fixture()
def setup_module_():
    return importlib.import_module("nivxforge_setup")


def test_drain_mode_engages_only_on_proven_progress(setup_module_):
    s = setup_module_
    wait, cycles = s._drain_wait(
        {"delivery_backlog": 50_000, "sent": 900}, 30, 0)
    assert wait == s.DRAIN_WAIT_SECONDS and cycles == 1


def test_drain_mode_refuses_to_spin(setup_module_):
    s = setup_module_
    # nothing delivered → normal cadence, counter reset
    assert s._drain_wait({"delivery_backlog": 50_000, "sent": 0}, 30, 3) == (30.0, 0)
    # backend unreachable → normal cadence even with a huge backlog
    assert s._drain_wait({"delivery_backlog": 50_000, "sent": 10,
                          "backend_unreachable": True}, 30, 3) == (30.0, 0)
    # small backlog → normal cadence
    assert s._drain_wait({"delivery_backlog": 10, "sent": 10}, 30, 0) == (30.0, 0)
    # a malformed report must never shorten the wait
    assert s._drain_wait(None, 30, 5) == (30.0, 0)


def test_drain_mode_takes_a_breather(setup_module_):
    s = setup_module_
    report = {"delivery_backlog": 90_000, "sent": 1_000}
    cycles = 0
    run = longest = breathers = 0
    for _ in range(s.DRAIN_MAX_CONSECUTIVE * 3):
        wait, cycles = s._drain_wait(report, 30, cycles)
        if wait == s.DRAIN_WAIT_SECONDS:
            run += 1
            longest = max(longest, run)
        else:
            run = 0
            breathers += 1
            assert cycles == 0, "the counter resets after a breather"
    assert longest <= s.DRAIN_MAX_CONSECUTIVE - 1, (
        "consecutive short waits are capped")
    assert breathers >= 2, "a full interval is taken periodically"


# ═════════════ sustained load · queue must drain, not grow ════════════
def test_sustained_load_drains_without_duplicates_or_loss(env):
    module, source, backend, journal = env
    produced = []
    for burst in range(6):                       # 6 cycles × 400 events
        produced += source.channel(SYSMON).produce(400, start=1 + burst * 400)
        _acquire(module, journal)
        _drain(module, journal, budget=8.0)
    assert journal.depth() == 0, "delivery kept up with acquisition"
    assert len(backend.accepted) == 2400
    assert backend.duplicates() == 0
    assert journal.quarantined() == 0
    assert sorted(backend.record_ids(SYSMON)) == sorted(
        r["winlog"]["record_id"] if isinstance(r, dict) else r
        for r in [__import__("json").loads(p)["winlog"]["record_id"]
                  for p in backend.accepted])
