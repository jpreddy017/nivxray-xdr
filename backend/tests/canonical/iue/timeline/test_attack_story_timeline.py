"""Attack Story Timeline tests — pure projection over Lane A/B/C.

Locks the architectural invariants owner explicitly stated:
  - Timeline is a PROJECTION, NOT a correlator.
  - Consumes canonical LogicalEvents already emitted by Lane A/B/C.
  - Cross-lane fuse = strict union + deterministic sort. No cross-
    lane grouping, no cross-lane semantic reunification.
  - Zero invented events.  Zero cross-lane synthesis.
  - Tenancy firewall — the router refuses to fuse wires that carry
    a different tenant_id than the caller.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.iue.timeline import fuse, project_lane  # noqa: E402


# ── Deterministic fixtures ─────────────────────────────────────────
def _le(ev_id, ts, action, host="dmz01.corp.local", user="jsmith",
         first_seen=None, last_seen=None, count=1,
         extra_canonical=None, tenant="t1", lane_input_id="i1"):
    """Build a minimal LogicalEvent dict — matches the shape emitted
    by the shared aggregator."""
    cf = {
        "canonical.event.timestamp": ts,
        "canonical.event.action":    action,
        "canonical.source.host":     host,
        "canonical.source.user":     user,
    }
    if extra_canonical:
        cf.update(extra_canonical)
    return {
        "event_id":       ev_id,
        "tenant_id":      tenant,
        "input_id":       lane_input_id,
        "source_file_id": "sf_" + ev_id,
        "record_refs":    [ev_id + "_r"],
        "count":          count,
        "first_seen":     first_seen or ts,
        "last_seen":      last_seen or ts,
        "canonical_fields": cf,
        "variability":    {},
        "provenance": {
            "engine":  "iue.aggregator",
            "version": "1.0",
            "at":      "2026-08-26T00:00:00+00:00",
            "upstream_evidence_ids": ["iue.intake:" + ev_id,
                                        "iue.collectors.log:" + ev_id,
                                        "iue.parsers.ndjson:" + ev_id,
                                        "iue.normalizers.field_map:" + ev_id],
        },
    }


def _wire(lane, events, tenant="t1"):
    """Build a T2 wire fragment matching Lane A/B/C output shape."""
    return {
        "intake_decision": {"lane": lane, "tenant_id": tenant,
                              "kind": "test", "input_id": "i-" + lane,
                              "confidence": 0.9, "reasons": [],
                              "ida_class": None, "iue_type": None,
                              "parent_input_id": None,
                              "discovery_depth": 0, "flag_state": "on",
                              "provenance": {}},
        "logical_events":  events,
        "malformed":       [],
        "raw_payload":     {"input_id": "i-" + lane,
                              "tenant_id": tenant},
        "report_extraction_fragment": {},
    }


# ── 1. Single-lane projection ─────────────────────────────────────
class TestProjectLane:
    def test_project_lane_a_events(self):
        events = [
            _le("e1", "2026-08-26T10:00:00+00:00", "detect"),
            _le("e2", "2026-08-26T10:05:00+00:00", "block"),
        ]
        wire = _wire("structured", events)
        proj = project_lane(wire)
        assert len(proj) == 2
        assert proj[0]["timestamp"] == "2026-08-26T10:00:00+00:00"
        assert proj[0]["timestamp_source"] == "canonical"
        assert proj[0]["lane"] == "structured"
        assert proj[0]["action"] == "detect"
        assert proj[0]["host"] == "dmz01.corp.local"
        # Provenance chain preserved verbatim.
        assert "iue.intake:e1" in proj[0]["provenance_chain"]
        assert "iue.parsers.ndjson:e1" in proj[0]["provenance_chain"]

    def test_project_event_without_canonical_timestamp_falls_back(self):
        ev = _le("e1", ts="", action="observe",
                   first_seen="2026-08-26T11:00:00+00:00",
                   last_seen="2026-08-26T11:00:00+00:00")
        # Erase the canonical timestamp field to force fallback.
        del ev["canonical_fields"]["canonical.event.timestamp"]
        wire = _wire("structured", [ev])
        proj = project_lane(wire)
        assert proj[0]["timestamp"] == "2026-08-26T11:00:00+00:00"
        assert proj[0]["timestamp_source"] == "first_seen"

    def test_project_lane_c_artifact_ref_populated(self):
        ev = _le("a1", ts="2026-08-26T12:00:00+00:00", action="upload",
                   extra_canonical={
                       "canonical.artifact.type":         "pdf",
                       "canonical.artifact.display_name": "Adobe PDF",
                       "canonical.file.name":             "advisory.pdf",
                       "canonical.file.hash.sha256":      "a" * 64,
                       "canonical.file.size":             1234,
                   })
        wire = _wire("file", [ev])
        proj = project_lane(wire)
        ref = proj[0]["artifact_ref"]
        assert ref is not None
        assert ref["type"] == "pdf"
        assert ref["display_name"] == "Adobe PDF"
        assert ref["file_name"] == "advisory.pdf"
        assert ref["sha256"] == "a" * 64
        assert ref["size"] == 1234

    def test_project_lane_b_destination_summary(self):
        ev = _le("u1", ts="2026-08-26T13:00:00+00:00", action="visit",
                   extra_canonical={
                       "canonical.destination.url":  "http://evil.example.com/x",
                       "canonical.destination.host": "evil.example.com",
                       "canonical.destination.port": 443,
                   })
        wire = _wire("url", [ev])
        proj = project_lane(wire)
        # URL wins over host+port when both are present.
        assert proj[0]["destination"] == "http://evil.example.com/x"

    def test_empty_wire_returns_empty(self):
        assert project_lane({}) == []
        assert project_lane({"logical_events": []}) == []
        assert project_lane(None) == []


# ── 2. Cross-lane fuse ─────────────────────────────────────────────
class TestFuse:
    def test_chronological_order_across_lanes(self):
        # Interleaved on purpose — fuse must sort them chronologically.
        lane_a = _wire("structured", [
            _le("a1", "2026-08-26T10:03:00+00:00", "detect"),
            _le("a3", "2026-08-26T10:06:00+00:00", "block"),
        ])
        lane_b = _wire("url", [
            _le("b2", "2026-08-26T10:04:00+00:00", "visit",
                 extra_canonical={"canonical.destination.url":
                                    "http://evil.example.com/x"}),
        ])
        lane_c = _wire("file", [
            _le("c1", "2026-08-26T10:05:00+00:00", "upload",
                 extra_canonical={"canonical.artifact.type": "pdf"}),
        ])
        env = fuse([lane_a, lane_b, lane_c])
        assert env["event_count"] == 4
        ts_seq = [e["timestamp"] for e in env["events"]]
        assert ts_seq == sorted(ts_seq), f"not sorted: {ts_seq}"
        assert env["span_start"] == "2026-08-26T10:03:00+00:00"
        assert env["span_end"]   == "2026-08-26T10:06:00+00:00"
        assert set(env["lanes"]) == {"structured", "url", "file"}

    def test_no_cross_lane_correlation(self):
        """Two events with the SAME canonical fields but different
        lanes must remain SEPARATE — fuse is a strict union, not a
        correlator.  Semantic reunification belongs to ICE / SSOT."""
        shared_cf = {
            "canonical.event.timestamp": "2026-08-26T10:00:00+00:00",
            "canonical.event.action":    "download",
            "canonical.source.host":     "dmz01.corp.local",
            "canonical.destination.url": "http://evil.example.com/x",
        }
        ev_a = {"event_id": "a1", "tenant_id": "t1", "input_id": "iA",
                 "source_file_id": "sfA", "record_refs": [],
                 "count": 1, "first_seen": shared_cf["canonical.event.timestamp"],
                 "last_seen": shared_cf["canonical.event.timestamp"],
                 "canonical_fields": dict(shared_cf), "variability": {},
                 "provenance": {"engine": "iue.aggregator", "version": "1.0",
                                  "at": "x", "upstream_evidence_ids": []}}
        ev_c = dict(ev_a); ev_c["event_id"] = "c1"
        env = fuse([_wire("url", [ev_a]), _wire("file", [ev_c])])
        assert env["event_count"] == 2, \
            "cross-lane events must NOT be fused/dedup'd"

    def test_untimed_events_bucket(self):
        ev = _le("u1", ts="", action="observe",
                   first_seen="", last_seen="")
        del ev["canonical_fields"]["canonical.event.timestamp"]
        env = fuse([_wire("structured", [ev])])
        assert env["event_count"] == 0
        assert env["untimed_count"] == 1
        assert env["untimed_events"][0]["event_id"] == "u1"

    def test_deterministic_across_replays(self):
        lane_a = _wire("structured", [
            _le("a1", "2026-08-26T10:00:00+00:00", "detect"),
            _le("a2", "2026-08-26T10:00:00+00:00", "block"),  # same ts
        ])
        env1 = fuse([lane_a])
        env2 = fuse([lane_a])
        assert env1 == env2, "fuse output must be deterministic"

    def test_empty_lanes_returns_empty_envelope(self):
        env = fuse([])
        assert env["event_count"] == 0
        assert env["events"] == []
        assert env["lanes"] == []
        assert env["meta"]["projection"] == "attack_story_timeline"

    def test_hosts_and_users_deduplicated(self):
        ev1 = _le("e1", "2026-08-26T10:00:00+00:00", "x",
                    host="hostA", user="alice")
        ev2 = _le("e2", "2026-08-26T10:01:00+00:00", "y",
                    host="hostA", user="bob")
        ev3 = _le("e3", "2026-08-26T10:02:00+00:00", "z",
                    host="hostB", user="alice")
        env = fuse([_wire("structured", [ev1, ev2, ev3])])
        assert env["hosts"] == ["hostA", "hostB"]
        assert env["users"] == ["alice", "bob"]


# ── 3. Provenance integrity ─────────────────────────────────────────
class TestProvenanceIntegrity:
    def test_provenance_chain_preserved_verbatim(self):
        ev = _le("p1", "2026-08-26T10:00:00+00:00", "test")
        env = fuse([_wire("structured", [ev])])
        chain = env["events"][0]["provenance_chain"]
        # Every upstream id from the aggregator's chain is preserved.
        assert "iue.intake:p1" in chain
        assert "iue.collectors.log:p1" in chain
        assert "iue.parsers.ndjson:p1" in chain
        assert "iue.normalizers.field_map:p1" in chain

    def test_input_id_and_tenant_id_preserved(self):
        ev = _le("t1", "2026-08-26T10:00:00+00:00", "x",
                    tenant="tenantX", lane_input_id="ii-999")
        env = fuse([_wire("structured", [ev], tenant="tenantX")])
        e = env["events"][0]
        assert e["tenant_id"] == "tenantX"
        assert e["input_id"] == "ii-999"


# ── 4. Router-boundary tenancy firewall ─────────────────────────────
class TestTenantFirewall:
    def test_cross_tenant_fuse_rejected(self, monkeypatch):
        """The router must refuse to fuse a wire whose intake_decision
        carries a tenant_id different from the caller's identity."""
        from fastapi.testclient import TestClient
        from server import app
        from deps import get_current_user
        app.dependency_overrides[get_current_user] = \
            lambda: {"email": "alice@x.com", "tenant_id": "tenantA"}
        wire_of_other_tenant = _wire("structured", [
            _le("x1", "2026-08-26T10:00:00+00:00", "detect")
        ], tenant="tenantB")
        try:
            with TestClient(app) as c:
                r = c.post("/api/iue/timeline/fuse",
                              json={"lanes": [wire_of_other_tenant]})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "cross_tenant_fuse_forbidden"

    def test_same_tenant_fuse_accepted(self, monkeypatch):
        from fastapi.testclient import TestClient
        from server import app
        from deps import get_current_user
        app.dependency_overrides[get_current_user] = \
            lambda: {"email": "alice@x.com", "tenant_id": "tenantA"}
        wire = _wire("structured", [
            _le("y1", "2026-08-26T10:00:00+00:00", "detect", tenant="tenantA")
        ], tenant="tenantA")
        try:
            with TestClient(app) as c:
                r = c.post("/api/iue/timeline/fuse",
                              json={"lanes": [wire]})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["event_count"] == 1
        assert body["events"][0]["lane"] == "structured"

    def test_empty_lanes_rejected(self, monkeypatch):
        from fastapi.testclient import TestClient
        from server import app
        from deps import get_current_user
        app.dependency_overrides[get_current_user] = \
            lambda: {"email": "x@x", "tenant_id": "t1"}
        try:
            with TestClient(app) as c:
                r = c.post("/api/iue/timeline/fuse", json={"lanes": []})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "no_lanes"

    def test_unauth_rejected(self):
        from fastapi.testclient import TestClient
        from server import app
        with TestClient(app) as c:
            r = c.post("/api/iue/timeline/fuse", json={"lanes": []})
        assert r.status_code in (401, 403)
