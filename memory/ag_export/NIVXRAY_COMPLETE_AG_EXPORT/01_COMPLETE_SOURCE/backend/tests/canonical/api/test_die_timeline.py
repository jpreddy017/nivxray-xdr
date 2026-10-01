"""Workspace Timeline · MVP contract tests (2026-08-11).

Locks the read-only projection contract of `POST /api/die/timeline`:

    · Every emitted event carries a real timestamp.  No fabricated
      timestamps.
    · Every emitted event carries the P0.2 evidence_ref for the
      MITRE technique it corresponds to.
    · Timeline projection MUST NOT mutate the existing
      `/api/die/investigation-results` payload — the two calls
      remain independent.
    · Empty / prose / narrative-only inputs → zero events (no
      invented events).
    · SEP CSV input → chronologically-sorted event list with host,
      user, process, file_context, event_type, evidence_ref, MITRE
      references.
    · Timeline response stays well under the P0.3 250 KB budget.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "backend"))

os.environ["NIVX_CANONICAL_DIE_ANALYZE"] = "on"

from server import app  # noqa: E402
from services.die.timeline_projection import (  # noqa: E402
    project_timeline,
    _EVENT_KEYS,
)


REQUIRED_EVIDENCE_KEYS = (
    "source", "event_or_rule", "field", "observed_value", "evidence_ref",
)


# ─────────────────────────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    # See test_p02_evidence_chain.py — no `with TestClient(app) as c`
    # so xdist can schedule this module next to others without
    # closing the event loop.
    yield TestClient(app)


def _fixture_sep_csv() -> str:
    return (
        "date,src_host,user,file_name,file_hash,parent_file_name,parent_file_hash,file_path,action,category\n"
        "2026-08-03T13:24:57+00:00,DMZ01.axium.local,jsmith,browserhost.exe,"
        "12f07d1352844bc7f12d3ad598dd73c19d86c5bdbe230e9c0acdebf4e182e2ad,,,"
        "C:\\Program Files\\Edge\\browserhost.exe,detect,Exploit Prevention\n"
        "2026-08-03T13:25:11+00:00,DMZ01.axium.local,jsmith,winlogon.exe,"
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca,"
        "launcher.exe,,C:\\Windows\\System32\\winlogon.exe,block,System Process Protection\n"
        "2026-08-03T13:26:44+00:00,DMZ02.axium.local,rjones,foo.exe,,,,,"
        "detect,Suspicious Endpoint Findings without Tactics\n"
    )


def _fixture_prose() -> str:
    return (
        "During the incident the actor deployed a remote access trojan and "
        "used PowerShell to execute an encoded command."
    )


def _post_timeline(client, text: str) -> dict:
    r = client.post("/api/die/timeline", json={"input": text})
    assert r.status_code == 200, f"http={r.status_code} body={r.text[:400]}"
    return r.json()


def _post_investigation(client, text: str) -> dict:
    r = client.post("/api/die/investigation-results", json={"input": text})
    assert r.status_code == 200
    return r.json()


# ─────────────────────────────────────────────────────────────────
#  Unit tests · services/die/timeline_projection.py
# ─────────────────────────────────────────────────────────────────
class TestUnitTimelineProjection:

    def test_empty_investigation_object_yields_empty_projection(self):
        p = project_timeline("", {})
        assert p["events"] == []
        assert p["event_count"] == 0
        assert p["span_start"] is None
        assert p["span_end"] is None
        assert p["hosts"] == [] and p["users"] == [] and p["sources"] == []

    def test_investigation_without_csv_edr_yields_empty_projection(self):
        # Object with narrative MITRE but no highconf_events → nothing timestamped.
        obj = {"mitre": [{"id": "T1059.001", "name": "PowerShell",
                          "evidence": [{"source": "canonical_narrative",
                                        "event_or_rule": "narrative.foo",
                                        "field": "text_offset",
                                        "observed_value": "-EncodedCommand",
                                        "evidence_ref": "ev-cafebabecafe"}]}]}
        p = project_timeline("", obj)
        assert p["event_count"] == 0, (
            "Narrative-only techniques have no timestamp — they MUST NOT "
            "produce timeline events (no fabrication)."
        )

    def test_event_shape_and_required_keys(self):
        # Minimal but realistic obj with highconf_events + a matching MITRE
        obj = {
            "csv_edr": {
                "highconf_events": [{
                    "date": "2026-08-03T13:00:00+00:00",
                    "host": "H1", "category": "Exploit Prevention",
                    "action": "block", "file": "x.exe",
                    "hash": "a"*64, "technique": "T1203",
                }],
            },
            "mitre": [{"id": "T1203", "name": "Exploitation for Client Execution",
                       "evidence": [{"source": "csv_edr_analyzer",
                                     "event_or_rule": "sep.exploit_prevention.block",
                                     "field": "category+action",
                                     "observed_value": "category=Exploit Prevention; action=block",
                                     "evidence_ref": "ev-1234abcd5678"}]}],
        }
        p = project_timeline("", obj)
        assert p["event_count"] == 1
        ev = p["events"][0]
        for k in _EVENT_KEYS:
            assert k in ev, f"emitted timeline event missing key: {k}"
        assert ev["timestamp"] == "2026-08-03T13:00:00+00:00"
        assert ev["evidence_ref"] == "ev-1234abcd5678"
        assert ev["confidence"] == "high"    # block → high
        assert ev["mitre"] == [{"id": "T1203", "name": "Exploitation for Client Execution"}]

    def test_events_sorted_chronologically(self):
        obj = {"csv_edr": {"highconf_events": [
            {"date": "2026-08-03T13:03:00Z", "host": "H", "category": "A", "action": "detect", "file": "z", "hash": "", "technique": "T1"},
            {"date": "2026-08-03T13:01:00Z", "host": "H", "category": "A", "action": "detect", "file": "z", "hash": "", "technique": "T1"},
            {"date": "2026-08-03T13:02:00Z", "host": "H", "category": "A", "action": "detect", "file": "z", "hash": "", "technique": "T1"},
        ]}, "mitre": []}
        p = project_timeline("", obj)
        ts = [e["timestamp"] for e in p["events"]]
        assert ts == sorted(ts), f"events not chronologically sorted: {ts}"

    def test_events_without_timestamp_are_dropped(self):
        obj = {"csv_edr": {"highconf_events": [
            {"date": "",                        "host": "H", "category": "A", "action": "detect", "file": "", "hash": "", "technique": "T1"},
            {"date": "2026-08-03T13:02:00Z",   "host": "H", "category": "A", "action": "detect", "file": "", "hash": "", "technique": "T1"},
        ]}, "mitre": []}
        p = project_timeline("", obj)
        assert p["event_count"] == 1, (
            "Timeline MUST NOT invent timestamps for events that lack one."
        )


# ─────────────────────────────────────────────────────────────────
#  Wire tests · POST /api/die/timeline
# ─────────────────────────────────────────────────────────────────
class TestWireTimeline:

    def test_empty_input_returns_empty_timeline(self, client):
        p = _post_timeline(client, "")
        assert p["event_count"] == 0
        assert p["events"] == []
        assert p["span_start"] is None and p["span_end"] is None

    def test_prose_input_returns_empty_timeline(self, client):
        """Narrative prose has MITRE hits but no timestamps →
        Timeline MUST be empty (no fabrication)."""
        p = _post_timeline(client, _fixture_prose())
        assert p["event_count"] == 0, (
            f"prose input produced {p['event_count']} events without "
            f"timestamps — that would be fabrication."
        )

    def test_sep_csv_yields_events(self, client):
        p = _post_timeline(client, _fixture_sep_csv())
        assert p["event_count"] > 0
        assert p["span_start"] and p["span_end"]
        assert "DMZ01.axium.local" in p["hosts"]
        assert "jsmith" in p["users"]

    def test_every_wire_event_has_evidence_ref(self, client):
        p = _post_timeline(client, _fixture_sep_csv())
        missing = [e for e in p["events"]
                   if not (isinstance(e.get("evidence_ref"), str)
                           and e["evidence_ref"].startswith("ev-"))]
        assert not missing, (
            f"{len(missing)} timeline events missing evidence_ref: "
            f"{[e.get('event_type') for e in missing[:3]]}"
        )

    def test_every_wire_event_has_required_keys(self, client):
        p = _post_timeline(client, _fixture_sep_csv())
        offenders = []
        for e in p["events"]:
            for k in _EVENT_KEYS:
                if k not in e:
                    offenders.append((e.get("timestamp"), k))
        assert not offenders, f"missing keys in emitted events: {offenders}"

    def test_wire_events_are_chronologically_sorted(self, client):
        p = _post_timeline(client, _fixture_sep_csv())
        ts = [e["timestamp"] for e in p["events"]]
        assert ts == sorted(ts)

    def test_csv_wire_events_enriched_with_user_and_parent(self, client):
        """The CSV row for winlogon.exe declares user=jsmith and
        parent_file_name=launcher.exe.  Timeline must expose both."""
        p = _post_timeline(client, _fixture_sep_csv())
        winlogon = next((e for e in p["events"]
                        if e.get("process") == "winlogon.exe"), None)
        assert winlogon is not None, "winlogon row not projected"
        assert winlogon["user"] == "jsmith"
        assert winlogon["parent_process"] == "launcher.exe"
        assert winlogon["confidence"] == "high"    # action=block
        assert winlogon["file_context"] and \
               winlogon["file_context"].get("path") == r"C:\Windows\System32\winlogon.exe"

    def test_csv_wire_events_carry_mitre_reference(self, client):
        p = _post_timeline(client, _fixture_sep_csv())
        for e in p["events"]:
            m = e.get("mitre") or []
            if not m:
                continue        # events without a promoted technique OK
            for entry in m:
                assert entry.get("id", "").startswith("T"), \
                    f"bad MITRE id in timeline event: {entry}"

    def test_timeline_wire_response_size_under_budget(self, client):
        p = _post_timeline(client, _fixture_sep_csv())
        size = len(json.dumps(p).encode())
        assert size < 250 * 1024, (
            f"timeline wire size {size} B exceeds P0.3 250 KB budget"
        )

    def test_timeline_does_not_pollute_investigation_results(self, client):
        """Regression: adding /api/die/timeline must not cause a
        `timeline` field to appear on the existing investigation
        response. Payload contract preserved."""
        r = _post_investigation(client, _fixture_sep_csv())
        obj = r.get("object") or {}
        assert "timeline" not in obj, (
            "`timeline` field leaked onto /api/die/investigation-results "
            "response. That would break the P0.3 payload-shape contract."
        )

    def test_timeline_evidence_refs_match_investigation_evidence_refs(self, client):
        """Cross-endpoint consistency: for every timeline event that
        cites a MITRE technique, the evidence_ref MUST equal the
        evidence_ref emitted by /api/die/investigation-results for
        that same technique.  Proves Timeline is a projection over
        the SAME P0.2 evidence chain, not a parallel one."""
        text = _fixture_sep_csv()
        tl   = _post_timeline(client, text)
        inv  = _post_investigation(client, text).get("object") or {}
        # Build {tid → set(evidence_refs)} from investigation response.
        inv_refs = {}
        for t in inv.get("mitre") or []:
            tid = t.get("id")
            for ev in (t.get("evidence") or []):
                if isinstance(ev, dict) and ev.get("evidence_ref"):
                    inv_refs.setdefault(tid, set()).add(ev["evidence_ref"])
        # Every timeline event's evidence_ref must appear in the
        # investigation's evidence set for its cited MITRE id.
        mismatches = []
        for e in tl["events"]:
            for m in (e.get("mitre") or []):
                tid = m.get("id")
                refs_for_tid = inv_refs.get(tid, set())
                if e["evidence_ref"] not in refs_for_tid:
                    mismatches.append((tid, e["evidence_ref"], sorted(refs_for_tid)))
        assert not mismatches, (
            f"timeline evidence_ref not found in investigation evidence "
            f"chain: {mismatches[:5]}"
        )
