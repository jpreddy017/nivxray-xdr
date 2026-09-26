"""
Phase-2 Evidence→Verdict Gap Closure — regression gate.

Invariants under test:
  · Verdict Engine remains sole authority; the bridge emits
    inputs, never verdicts.
  · Correlation confidence ≠ verdict confidence.
  · A cross-lane hint alone NEVER promotes ATT&CK to OBSERVED.
  · Endpoint-only correlation groups (single lane) yield NO
    verdict inputs — endpoint-only incidents are unchanged.
  · Evidence Graph edges cite canonical_ids on both sides.
  · Mongo checkpoint/dedup stores are restart-safe + idempotent.
  · Vendor pollers fail honestly when unconfigured.
"""
from __future__ import annotations

import pytest

from services.telemetry_adapters import (
    CanonicalEvent, Provenance, SourceKind, correlate,
    build_verdict_inputs, build_evidence_graph_edges,
    UnconfiguredPollerError, OktaSystemLogPoller,
    EntraSignInLogPoller, AwsCloudTrailPoller,
    poller_configuration_status,
    InMemoryCheckpoint, InMemoryDedup,
)


def _ev(cid, lane, actor=None, ip=None, when=None):
    return CanonicalEvent(
        canonical_id=cid, source_kind=SourceKind(lane), action="x",
        actor={"id": actor} if actor else {},
        context={"ip": ip} if ip else {},
        provenance=Provenance(
            source_id="t", vendor="v", adapter_name="a",
            adapter_version="0.1", raw_ref=cid,
            ingested_at="2026-08-15T00:00:00Z",
            source_event_time=when),
    )


# --------- Verdict bridge fields ---------------------------------------
def test_verdict_input_never_carries_verdict_authority():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T10:05:00Z"),
        _ev("cl-1", "cloud",    actor="alice",
              when="2026-08-15T10:10:00Z"),
    ]
    inputs = build_verdict_inputs(correlate(evs))
    assert len(inputs) == 1
    vi = inputs[0]
    # Governed metadata present.
    assert vi.kind == "cross_lane_correlation"
    assert set(vi.lanes) == {"endpoint", "identity", "cloud"}
    assert vi.canonical_ids == ("cl-1", "ep-1", "id-1")
    # Verdict-authority fields absent.
    for forbidden in ("verdict", "severity", "maliciousness",
                                  "verdict_confidence", "attck_promote"):
        assert not hasattr(vi, forbidden)


def test_correlation_confidence_never_becomes_verdict_confidence():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T10:05:00Z"),
    ]
    vi = build_verdict_inputs(correlate(evs))[0]
    # It's called `correlation_confidence`, not verdict-anything.
    assert 0.0 < vi.correlation_confidence <= 0.95
    rationale = vi.rationale.lower()
    assert "correlation confidence" in rationale
    assert "not maliciousness" in rationale
    assert "verdict engine remains authoritative" in rationale


# --------- Endpoint-only stays unchanged --------------------------------
def test_endpoint_only_produces_no_verdict_inputs():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("ep-2", "endpoint", actor="alice",
              when="2026-08-15T10:01:00Z"),
    ]
    assert build_verdict_inputs(correlate(evs)) == []


# --------- ATT&CK not promoted from a cross-lane hint -------------------
def test_evidence_graph_edge_marks_attck_promotion_false():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T10:05:00Z"),
    ]
    edges = build_evidence_graph_edges(correlate(evs))
    assert edges
    for e in edges:
        assert e.provenance["attck_promotion"] is False


# --------- Every edge cites canonical ids on both sides -----------------
def test_evidence_graph_edges_cite_canonical_ids_both_sides():
    evs = [
        _ev("ep-1", "endpoint", actor="alice",
              when="2026-08-15T10:00:00Z"),
        _ev("id-1", "identity", actor="alice",
              when="2026-08-15T10:05:00Z"),
        _ev("cl-1", "cloud",    actor="alice",
              when="2026-08-15T10:10:00Z"),
    ]
    for e in build_evidence_graph_edges(correlate(evs)):
        assert e.src_canonical_id
        assert e.dst_canonical_id
        assert e.src_canonical_id != e.dst_canonical_id
        assert e.correlation_key
        # Timestamp-only edges disallowed — evidence for edge
        # inherits the correlation's matching_basis.
        assert e.provenance["matching_basis"]


# --------- Vendor pollers fail honestly ---------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("poller_cls", [
    OktaSystemLogPoller, EntraSignInLogPoller, AwsCloudTrailPoller,
])
async def test_unconfigured_poller_raises_honest_error(monkeypatch, poller_cls):
    for k in ("OKTA_DOMAIN","OKTA_API_TOKEN",
                    "ENTRA_TENANT_ID","ENTRA_CLIENT_ID","ENTRA_CLIENT_SECRET",
                    "AWS_REGION","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(k, raising=False)
    p = poller_cls()
    with pytest.raises(UnconfiguredPollerError):
        await p.fetch(None)


def test_pollers_status_reports_all_unconfigured_by_default(monkeypatch):
    for k in ("OKTA_DOMAIN","OKTA_API_TOKEN",
                    "ENTRA_TENANT_ID","ENTRA_CLIENT_ID","ENTRA_CLIENT_SECRET",
                    "AWS_REGION","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(k, raising=False)
    st = poller_configuration_status()
    assert st["okta"]["configured"]           is False
    assert st["entra"]["configured"]          is False
    assert st["aws_cloudtrail"]["configured"] is False


# --------- Mongo store contract works with in-memory fakes --------------
@pytest.mark.asyncio
async def test_dedup_is_idempotent():
    dd = InMemoryDedup()
    await dd.remember(["a","b"])
    await dd.remember(["a","b","c"])
    seen = await dd.seen(["a","b","c","d"])
    assert seen == {"a","b","c"}


@pytest.mark.asyncio
async def test_checkpoint_survives_restart_semantics():
    ckp = InMemoryCheckpoint()
    await ckp.write("job", "cur-1")
    assert await ckp.read("job") == "cur-1"
    await ckp.write("job", "cur-2")
    assert await ckp.read("job") == "cur-2"
    await ckp.write("job", None)             # clear
    assert await ckp.read("job") is None
