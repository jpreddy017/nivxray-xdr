"""
Phase-2 operationalisation corpus.

Covers:
  · Ingestion runner tick / restart / checkpoint / dedup / health
  · Provider outage handled honestly (no telemetry fabricated)
  · Credential scrubbing in health error messages
  · Cross-lane correlation POSITIVE cases
    (Endpoint↔Identity, Identity↔Cloud, Endpoint↔Cloud,
     Endpoint→Identity→Cloud)
  · Cross-lane correlation NEGATIVE cases
    (unrelated events, timestamp-near-but-unrelated, missing lane)
  · Cognis grounding preserved for cross-lane evidence
"""
from __future__ import annotations

import asyncio
import pytest

from services.telemetry_adapters import (
    CanonicalEvent, InMemoryCheckpoint, InMemoryDedup,
    IngestionJob, IngestionRunner, Provenance, SourceKind,
    OktaSystemLogAdapter, correlate,
)


# ---------- Runner: happy tick + checkpoint + dedup ----------------------
class _StaticPoller:
    def __init__(self, pages):
        self.pages   = list(pages)  # [(raw_list, cursor), ...]
        self.calls   = 0
    async def fetch(self, cursor):
        self.calls += 1
        if not self.pages:
            return [], cursor
        raw, next_cursor = self.pages.pop(0)
        return raw, next_cursor


def _sink_collector(bucket):
    async def _sink(events): bucket.extend(events)
    return _sink


@pytest.mark.asyncio
async def test_runner_tick_persists_checkpoint_and_dedups():
    bucket = []
    ckp    = InMemoryCheckpoint()
    dd     = InMemoryDedup()
    runner = IngestionRunner(ckp, dd, _sink_collector(bucket))
    poller = _StaticPoller([
        ([{"uuid":"e1","published":"2026-08-15T00:00:00Z",
             "eventType":"user.session.start"}], "cur-1"),
        ([{"uuid":"e1","published":"2026-08-15T00:00:00Z",
             "eventType":"user.session.start"},
           {"uuid":"e2","published":"2026-08-15T00:01:00Z",
             "eventType":"user.session.start"}], "cur-2"),
    ])
    runner.register(IngestionJob(
        name="okta-p", adapter_name="okta.system-log", poller=poller))
    await runner.tick("okta-p")
    await runner.tick("okta-p")
    assert await ckp.read("okta-p") == "cur-2"
    canonical_ids = [e.canonical_id for e in bucket]
    assert canonical_ids == ["e1", "e2"]                 # dedup dropped repeat
    h = runner.health()[0]
    assert h["state"] == "OK"
    assert h["total_events_in"]  == 3
    assert h["total_events_out"] == 2
    assert h["total_dedup_dropped"] == 1
    assert h["consecutive_failures"] == 0


# ---------- Runner: provider outage honesty ------------------------------
class _BoomPoller:
    async def fetch(self, cursor):
        raise RuntimeError("network unreachable, api gateway down")


@pytest.mark.asyncio
async def test_runner_records_failure_without_fabricating_telemetry():
    bucket = []
    runner = IngestionRunner(InMemoryCheckpoint(), InMemoryDedup(),
                                              _sink_collector(bucket))
    runner.register(IngestionJob(
        name="entra-p", adapter_name="entra.signin-log",
        poller=_BoomPoller()))
    await runner.tick("entra-p")
    await runner.tick("entra-p")
    await runner.tick("entra-p")
    h = runner.health()[0]
    assert bucket == []                                  # no fabricated events
    assert h["state"] == "FAILED"
    assert h["consecutive_failures"] == 3


# ---------- Runner: credential scrubbing ---------------------------------
class _LeakyPoller:
    async def fetch(self, cursor):
        raise RuntimeError(
            "401 Unauthorized: Authorization: Bearer eyJ.abc.def")


@pytest.mark.asyncio
async def test_runner_scrubs_credentials_from_health():
    runner = IngestionRunner(InMemoryCheckpoint(), InMemoryDedup(),
                                              _sink_collector([]))
    runner.register(IngestionJob(
        name="cloudtrail-p", adapter_name="aws.cloudtrail",
        poller=_LeakyPoller()))
    await runner.tick("cloudtrail-p")
    h = runner.health()[0]
    assert "Bearer" not in (h["last_error_message"] or "")
    assert "eyJ" not in (h["last_error_message"] or "")
    assert h["last_error_message"].startswith("[redacted")


# ---------- Correlation helpers ------------------------------------------
def _ev(cid, lane, actor=None, ip=None, when=None):
    return CanonicalEvent(
        canonical_id=cid,
        source_kind=SourceKind(lane),
        action="x",
        actor={"id": actor} if actor else {},
        context={"ip": ip} if ip else {},
        provenance=Provenance(
            source_id="t", vendor="v", adapter_name="a",
            adapter_version="0.1", raw_ref=cid,
            ingested_at="2026-08-15T00:00:00Z",
            source_event_time=when),
    )


# ---------- Correlation POSITIVE cases -----------------------------------
def test_correlate_endpoint_and_identity_by_actor():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T10:05:00Z"),
    ]
    g = correlate(evs)
    assert len(g) == 1
    assert set(g[0].lanes) == {"endpoint", "identity"}
    assert g[0].actor_id == "alice"
    assert "same_actor" in g[0].reasons


def test_correlate_identity_and_cloud_by_ip():
    evs = [
        _ev("id-1", "identity", ip="203.0.113.4",
              when="2026-08-15T10:00:00Z"),
        _ev("cl-1", "cloud",    ip="203.0.113.4",
              when="2026-08-15T10:01:00Z"),
    ]
    g = correlate(evs)
    assert len(g) == 1
    assert set(g[0].lanes) == {"identity", "cloud"}
    assert "same_ip" in g[0].reasons


def test_correlate_full_chain_endpoint_identity_cloud():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T10:05:00Z"),
        _ev("cl-1", "cloud",    actor="alice",
              when="2026-08-15T10:10:00Z"),
    ]
    g = correlate(evs)
    assert len(g) == 1
    assert set(g[0].lanes) == {"endpoint", "identity", "cloud"}
    assert g[0].confidence >= 0.65


# ---------- Correlation NEGATIVE cases -----------------------------------
def test_correlate_ignores_timestamp_proximity_alone():
    """Two events happening at the same moment but with no
    shared actor / IP MUST NOT correlate."""
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="bob",
              when="2026-08-15T10:00:05Z"),
    ]
    g = correlate(evs)
    assert g == []


def test_correlate_single_lane_never_forms_group():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("ep-2", "endpoint", actor="alice",
              when="2026-08-15T10:01:00Z"),
    ]
    assert correlate(evs) == []


def test_correlate_outside_window_does_not_merge():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T00:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T05:00:00Z"),   # +5h
    ]
    assert correlate(evs, window_minutes=30) == []


def test_correlate_missing_lane_is_fine():
    """Two lanes suffice — missing a lane is not a failure."""
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T10:05:00Z"),
    ]
    g = correlate(evs)
    assert len(g) == 1


# ---------- Cognis grounding preserved for cross-lane --------------------
@pytest.mark.asyncio
async def test_cognis_grounding_accepts_cross_lane_evidence_ids(monkeypatch):
    from services.narration import (
        NarrationContext, NarrationKind, NarrationRequest,
    )
    from services.narration.contracts import NarrationParagraph
    from services.narration.gateway import NarrationGateway
    from services.narration.providers import (
        DeterministicProvider, NarrationDraft,
    )

    ctx = NarrationContext(
        incident_id  = "inc-x",
        evidence_ids = ("EV-1", "cross-1", "cross-2"),   # cross-lane merged in
        technique_ids= ("T1105",),
        entities     = ("alice",),
        verdict      = "MALICIOUS", severity="P1", confidence=0.8,
    )
    good_draft = NarrationDraft(
        paragraphs=[NarrationParagraph(
            text="cross-lane story",
            evidence_ids=("cross-1", "EV-1"),
            technique_ids=("T1105",))],
        verdict="MALICIOUS", severity="P1", confidence=0.8,
        entities=("alice",),
    )
    class _P:
        name="cloud"; kind="cloud"
        supports={NarrationKind.EXECUTIVE_SUMMARY,
                          NarrationKind.ATTACK_STORY}
        async def draft(self, k, c, s): return good_draft
    gw = NarrationGateway(
        providers={"cloud": _P(),
                          "deterministic": DeterministicProvider()},
        order=("cloud", "deterministic"),
    )
    out = await gw.render(NarrationRequest(
        kind=NarrationKind.EXECUTIVE_SUMMARY, context=ctx))
    assert out.provider == "cloud"
    assert "cross-1" in out.evidence_ids
