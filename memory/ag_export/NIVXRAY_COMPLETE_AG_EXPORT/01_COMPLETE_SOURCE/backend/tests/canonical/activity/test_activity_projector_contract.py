"""EDR canonical Activity model — projector contract tests.

Locks owner rule #19: one canonical model drives every panel.

Additional locks:
  - Deterministic entity ids across runs.
  - Process ancestry surfaces parent/child_entity_ids correctly.
  - Every event has entity_id → left rail selection matches.
  - Fields present only when supported by evidence (rule #13).
  - Left inventory contains actual observed entities (rule #8 / #20).
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.activity.projector import build_inventory  # noqa: E402
from services.activity.model import (KIND_PROCESS, KIND_FILE,  # noqa: E402
                                        KIND_NETWORK, KIND_REGISTRY,
                                        KIND_IDENTITY, KIND_SYSTEM,
                                        ENTITY_KINDS)


def _ev(event_id, ts="2026-08-26T10:00:00+00:00", process=None,
         parent=None, cmd=None, file_ref=None, dest=None,
         user=None, host=None, action=None, lane="log",
         canonical_fields=None):
    return {
        "event_id":         event_id,
        "lane":             lane,
        "timestamp":        ts,
        "timestamp_source": "canonical",
        "first_seen":       ts,
        "last_seen":        ts,
        "process":          process,
        "parent_process":   parent,
        "command_line":     cmd,
        "file_ref":         file_ref,
        "destination":      dest,
        "user":             user,
        "host":             host,
        "action":           action,
        "canonical_fields": canonical_fields or {},
        "provenance_chain": [f"iue.intake:{event_id}"],
    }


def _tl(events, untimed=None):
    return {"events": events, "untimed_events": untimed or []}


# ── 1. Empty timeline → empty inventory ──────────────────────────
class TestEmpty:
    def test_no_events_no_entities(self):
        inv = build_inventory(timeline=_tl([])).to_dict()
        for k in ENTITY_KINDS:
            assert inv["entities"][k] == []
        assert inv["events"] == []


# ── 2. Process ancestry (rule #10) ───────────────────────────────
class TestProcessAncestry:
    def test_child_and_parent_entities_created(self):
        events = [_ev("e1", process="powershell.exe",
                        parent="outlook.exe", action="execute")]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        procs = inv["entities"][KIND_PROCESS]
        names = {p["display_name"].lower() for p in procs}
        assert "powershell.exe" in names
        assert "outlook.exe" in names

    def test_child_entity_id_appears_in_parent_children(self):
        events = [_ev("e1", process="powershell.exe",
                        parent="outlook.exe", action="execute")]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        procs_by_name = {p["display_name"].lower(): p
                            for p in inv["entities"][KIND_PROCESS]}
        outlook = procs_by_name["outlook.exe"]
        ps      = procs_by_name["powershell.exe"]
        assert ps["parent_entity_id"] == outlook["entity_id"]
        assert ps["entity_id"] in outlook["child_entity_ids"]


# ── 3. Six-kind inventory populated when evidence supports it ─────
class TestSixKindInventory:
    def test_all_six_kinds_surface_from_mixed_events(self):
        events = [
            _ev("e1", process="powershell.exe", parent="explorer.exe",
                 action="execute", user="skrasowski@WHS_ADMIN",
                 host="dmz01.corp.local"),
            _ev("e2", action="created",
                 file_ref={"path": "C:\\Users\\Public\\payload.dll",
                            "name": "payload.dll"}),
            _ev("e3", action="connect", process="powershell.exe",
                 dest="http://evil.example.com/x"),
            _ev("e4", action="write",
                 canonical_fields={"canonical.registry.key":
                                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}),
        ]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        assert len(inv["entities"][KIND_PROCESS])   >= 2
        assert len(inv["entities"][KIND_FILE])      >= 1
        assert len(inv["entities"][KIND_NETWORK])   >= 1
        assert len(inv["entities"][KIND_REGISTRY])  >= 1
        assert len(inv["entities"][KIND_IDENTITY])  >= 1
        assert len(inv["entities"][KIND_SYSTEM])    >= 1


# ── 4. Determinism ───────────────────────────────────────────────
class TestDeterminism:
    def test_same_input_same_entity_ids(self):
        events = [_ev("e1", process="powershell.exe",
                        parent="outlook.exe", action="execute")]
        a = build_inventory(timeline=_tl(events)).to_dict()
        b = build_inventory(timeline=_tl(events)).to_dict()
        a_ids = sorted(e["entity_id"] for e in a["entities"][KIND_PROCESS])
        b_ids = sorted(e["entity_id"] for e in b["entities"][KIND_PROCESS])
        assert a_ids == b_ids

    def test_events_sorted_chronologically(self):
        events = [
            _ev("e1", ts="2026-08-26T10:03:00+00:00", process="A.exe"),
            _ev("e2", ts="2026-08-26T10:01:00+00:00", process="B.exe"),
            _ev("e3", ts="2026-08-26T10:02:00+00:00", process="C.exe"),
        ]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        ts_order = [e["timestamp"] for e in inv["events"]]
        assert ts_order == sorted(ts_order)


# ── 5. Rule #12 — right-panel is pre-populated (no selection needed) ─
class TestRightPanelPopulation:
    def test_inventory_contains_full_attribute_set(self):
        events = [_ev("e1", process="privacybrowse.exe",
                        parent="sihost.exe",
                        cmd="C:\\Users\\PrivacyBrowse.exe --no-sandbox",
                        canonical_fields={
                            "canonical.process.pid":         4384,
                            "canonical.process.integrity":   "Medium",
                            "canonical.file.hash.sha256":    "abc" * 20,
                            "canonical.file.hash.md5":       "def" * 10,
                            "canonical.file.hash.sha1":      "aaa" * 13,
                            "canonical.file.path":           "C:\\Users\\PrivacyBrowse.exe",
                            "canonical.file.signer":         "Unknown Publisher",
                            "canonical.file.signature_status": "unsigned",
                        },
                        user="skrasowski@WHS_ADMIN")]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        procs = {p["display_name"].lower(): p
                    for p in inv["entities"][KIND_PROCESS]}
        pb = procs["privacybrowse.exe"]
        attrs = pb["attributes"]
        # Owner rule #13: only display fields actually supported by evidence.
        for k in ("pid", "user", "integrity", "command_line",
                  "sha256", "md5", "sha1", "path",
                  "signer", "signature_status"):
            assert attrs.get(k) is not None, f"missing attribute {k}"


# ── 6. Event → entity linkage (rules #12 · #19) ────────────────────
class TestEventEntityLinkage:
    def test_each_event_maps_to_an_existing_entity(self):
        events = [_ev("e1", process="powershell.exe",
                        parent="outlook.exe", action="execute")]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        proc_ids = {p["entity_id"] for p in inv["entities"][KIND_PROCESS]}
        for e in inv["events"]:
            if e["kind"] == KIND_PROCESS:
                assert e["entity_id"] in proc_ids, \
                    f"event {e['event_id']} → orphan entity {e['entity_id']}"

    def test_selecting_entity_returns_its_events(self):
        events = [
            _ev("e1", ts="2026-08-26T10:00:00+00:00",
                 process="powershell.exe", parent="outlook.exe",
                 action="execute"),
            _ev("e2", ts="2026-08-26T10:01:00+00:00",
                 process="powershell.exe", parent="outlook.exe",
                 action="query"),
        ]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        procs = {p["display_name"].lower(): p
                    for p in inv["entities"][KIND_PROCESS]}
        ps = procs["powershell.exe"]
        # Both e1 and e2 must be linked to the same powershell entity.
        assert set(ps["event_ids"]) == {"e1", "e2"}


# ── 7. Compromise-window overlay, NOT filter (rule #9) ──────────
class TestOverlayNotFilter:
    def test_normal_activity_events_are_kept(self):
        """Even benign events must appear in the trajectory.  The
        compromise window is an overlay, not a filter."""
        events = [
            _ev("e_norm", process="chrome.exe", parent="explorer.exe",
                 action="execute"),
            _ev("e_bad",  process="powershell.exe", parent="winword.exe",
                 action="execute", cmd="-enc XYZ"),
        ]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        ev_ids = {e["event_id"] for e in inv["events"]}
        assert ev_ids == {"e_norm", "e_bad"}


# ── 8. PrivacyBrowse realistic evidence (rule #17) ──────────────
class TestPrivacyBrowseScenario:
    def test_privacybrowse_evidence_surfaces_correctly(self):
        """Owner-provided realistic scenario — no invented facts."""
        events = [
            _ev("evt-001",
                 ts="2026-06-15T14:32:11+00:00",
                 process="privacybrowse.exe",
                 parent="sihost.exe",
                 cmd="C:\\Users\\PrivacyBrowse.exe --no-sandbox",
                 file_ref={"path": "C:\\Users\\PrivacyBrowse.exe",
                            "name": "PrivacyBrowse.exe",
                            "sha1": "f1b89473dc4be914f44193c3259ca7c93a6fe2ba",
                            "md5":  "50e207c52a0305495f9dcfb947ee116d"},
                 user="skrasowski@WHS_ADMIN",
                 host="win10-user01.local",
                 action="execute",
                 canonical_fields={"canonical.process.pid": 4384}),
            _ev("evt-002",
                 ts="2026-06-15T14:32:12+00:00",
                 action="quarantine_failed",
                 process="privacybrowse.exe",
                 file_ref={"path": "C:\\Users\\PrivacyBrowse.exe",
                            "name": "PrivacyBrowse.exe"}),
        ]
        inv = build_inventory(timeline=_tl(events)).to_dict()
        procs = {p["display_name"].lower(): p
                    for p in inv["entities"][KIND_PROCESS]}
        assert "privacybrowse.exe" in procs
        assert "sihost.exe" in procs
        pb = procs["privacybrowse.exe"]
        assert pb["parent_entity_id"] == procs["sihost.exe"]["entity_id"]
        assert pb["attributes"]["sha1"] == \
               "f1b89473dc4be914f44193c3259ca7c93a6fe2ba"
        assert pb["attributes"]["user"] == "skrasowski@WHS_ADMIN"
