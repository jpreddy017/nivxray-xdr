"""Workspace Query/Hunt · MVP contract tests (2026-08-11).

Locks the read-only scoped-sub-view contract of `POST /api/die/query`:

    · Empty filter returns exactly the same events the Timeline
      would render (Query is a filter over Timeline, not a
      re-analysis).
    · Every filter constraint narrows results correctly and never
      manufactures rows.
    · Every returned row carries the P0.2 evidence_ref.
    · Result rows share the same shape as Timeline events so the
      Timeline / Table / (future) Process-Tree / Graph views can
      consume them.
    · Query calls MUST NOT perturb `/api/die/investigation-results`
      or `/api/die/timeline` outside their known telemetry drift
      (per-call `telemetry_id` + timing metrics, which is
      pre-existing and unrelated to Query).  The SEMANTIC content
      of both endpoints stays identical across arbitrary Query
      invocations.
"""
from __future__ import annotations
import hashlib
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
from services.die.query_hunt import (  # noqa: E402
    run_query,
    _clean_filters,
    _matches,
)


REQUIRED_EVIDENCE_KEYS = (
    "source", "event_or_rule", "field", "observed_value", "evidence_ref",
)


# ─────────────────────────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
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


def _post_query(client, text: str, filters: dict) -> dict:
    r = client.post("/api/die/query",
                    json={"input": text, "filters": filters})
    assert r.status_code == 200, f"http={r.status_code} body={r.text[:400]}"
    return r.json()


def _post_investigation(client, text: str) -> dict:
    r = client.post("/api/die/investigation-results", json={"input": text})
    assert r.status_code == 200
    return r.json()


def _post_timeline(client, text: str) -> dict:
    r = client.post("/api/die/timeline", json={"input": text})
    assert r.status_code == 200
    return r.json()


# ─────────────────────────────────────────────────────────────────
#  Signature helpers — strip known per-call telemetry so we can
#  assert semantic invariance.
# ─────────────────────────────────────────────────────────────────
def _semantic_signature(inv_resp: dict) -> str:
    """SHA256 of the investigation response minus known per-call
    non-determinism (telemetry_id + timing metrics).  These fields
    are pre-existing runtime measurements — they change every call
    regardless of Query."""
    obj = dict(inv_resp.get("object") or {})
    meta = dict(obj.get("metadata") or {})
    meta.pop("performance", None)
    meta.pop("pipeline_timings", None)
    obj["metadata"] = meta
    canon = {**inv_resp, "object": obj}
    blob = json.dumps(canon, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


# ─────────────────────────────────────────────────────────────────
#  Unit tests · services/die/query_hunt.py
# ─────────────────────────────────────────────────────────────────
class TestUnitQueryHunt:

    def test_clean_filters_drops_empty_and_none(self):
        c = _clean_filters({"host": "H1", "user": "", "action": None,
                            "mitre": "T1055", "trailing_ws": "  x  ",
                            "junk_int": 42})
        assert c == {"host": "H1", "mitre": "T1055",
                     "trailing_ws": "x", "junk_int": "42"}

    def test_empty_filters_returns_every_event(self):
        obj = _investigation_obj_with_events()
        p = run_query("", obj, {})
        assert p["event_count"] == p["total_available"]

    def test_host_filter_narrows(self):
        obj = _investigation_obj_with_events()
        p = run_query("", obj, {"host": "H1"})
        assert p["event_count"] == 2
        assert p["matched_hosts"] == ["H1"]

    def test_mitre_filter_exact(self):
        obj = _investigation_obj_with_events()
        p = run_query("", obj, {"mitre": "T1055"})
        assert p["event_count"] == 1
        assert p["results"][0]["mitre"] == [{"id": "T1055", "name": "PI"}]

    def test_action_filter_matches_event_type_suffix(self):
        obj = _investigation_obj_with_events()
        p = run_query("", obj, {"action": "block"})
        assert p["event_count"] == 1
        assert p["results"][0]["confidence"] == "high"

    def test_date_range_inclusive(self):
        obj = _investigation_obj_with_events()
        p = run_query("", obj, {"date_from": "2026-08-03T13:01:00Z",
                                 "date_to":   "2026-08-03T13:02:59Z"})
        assert p["event_count"] == 2

    def test_impossible_filter_returns_zero_but_preserves_totals(self):
        obj = _investigation_obj_with_events()
        p = run_query("", obj, {"host": "NONEXISTENT"})
        assert p["event_count"] == 0
        assert p["total_available"] > 0
        assert p["matched_hosts"] == []

    def test_result_rows_carry_evidence_ref(self):
        obj = _investigation_obj_with_events()
        p = run_query("", obj, {})
        # Every row that cites a MITRE technique must expose the
        # P0.2 evidence_ref for that technique.  Rows without any
        # MITRE mapping legitimately have no evidence_ref.
        for e in p["results"]:
            if e.get("mitre"):
                assert isinstance(e.get("evidence_ref"), str)
                assert e["evidence_ref"].startswith("ev-")


def _investigation_obj_with_events() -> dict:
    return {
        "csv_edr": {"highconf_events": [
            {"date":"2026-08-03T13:01:00Z", "host":"H1", "category":"A",
             "action":"detect", "file":"x", "hash":"", "technique":"T1203"},
            {"date":"2026-08-03T13:02:00Z", "host":"H1", "category":"A",
             "action":"block",  "file":"y", "hash":"", "technique":"T1055"},
            {"date":"2026-08-03T13:03:00Z", "host":"H2", "category":"B",
             "action":"detect", "file":"z", "hash":"", "technique":""},
        ]},
        "mitre": [
            {"id":"T1203","name":"EC","evidence":[{"source":"csv_edr_analyzer",
             "event_or_rule":"sep.a.detect","field":"category+action",
             "observed_value":"category=A; action=detect",
             "evidence_ref":"ev-aaaa11112222"}]},
            {"id":"T1055","name":"PI","evidence":[{"source":"csv_edr_analyzer",
             "event_or_rule":"sep.a.block","field":"category+action",
             "observed_value":"category=A; action=block",
             "evidence_ref":"ev-bbbb33334444"}]},
        ],
    }


# ─────────────────────────────────────────────────────────────────
#  Wire tests · POST /api/die/query
# ─────────────────────────────────────────────────────────────────
class TestWireQueryHunt:

    def test_empty_filter_matches_timeline_event_count(self, client):
        text = _fixture_sep_csv()
        q = _post_query(client, text, {})
        t = _post_timeline(client, text)
        assert q["total_available"] == q["event_count"] == t["event_count"], (
            f"Query with empty filter should return every event Timeline "
            f"would render. q_total={q['total_available']} "
            f"q_count={q['event_count']} timeline_count={t['event_count']}"
        )

    def test_query_row_shape_matches_timeline_event_shape(self, client):
        text = _fixture_sep_csv()
        q = _post_query(client, text, {})
        t = _post_timeline(client, text)
        assert q["event_count"] > 0 and t["event_count"] > 0
        q_keys = set(q["results"][0].keys())
        t_keys = set(t["events"][0].keys())
        assert q_keys == t_keys, (
            f"Query row and Timeline event must share the same shape. "
            f"diff: q-t={q_keys-t_keys} t-q={t_keys-q_keys}"
        )

    def test_every_result_row_has_evidence_ref(self, client):
        q = _post_query(client, _fixture_sep_csv(), {})
        missing = [e for e in q["results"]
                   if not (isinstance(e.get("evidence_ref"), str)
                           and e["evidence_ref"].startswith("ev-"))]
        assert not missing, f"{len(missing)} query rows without evidence_ref"

    def test_impossible_host_returns_zero(self, client):
        q = _post_query(client, _fixture_sep_csv(), {"host": "NONEXISTENT"})
        assert q["event_count"] == 0
        assert q["total_available"] > 0    # underlying evidence untouched

    def test_action_block_filter(self, client):
        q = _post_query(client, _fixture_sep_csv(), {"action": "block"})
        assert q["event_count"] >= 1
        for r in q["results"]:
            assert "block" in (r["event_type"] or "").lower()
            assert r["confidence"] == "high"

    def test_user_and_action_intersection(self, client):
        q = _post_query(client, _fixture_sep_csv(),
                        {"user": "rjones", "action": "detect"})
        assert q["event_count"] == 1
        r = q["results"][0]
        assert r["user"] == "rjones"

    def test_mitre_filter_narrows_to_exact_technique(self, client):
        q = _post_query(client, _fixture_sep_csv(), {"mitre": "T1055"})
        assert q["event_count"] >= 1
        for r in q["results"]:
            tids = [m["id"] for m in (r.get("mitre") or [])]
            assert "T1055" in tids

    def test_file_hash_exact_filter(self, client):
        h = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca"
        q = _post_query(client, _fixture_sep_csv(), {"file_hash": h})
        assert q["event_count"] >= 1
        for r in q["results"]:
            assert (r.get("file_context") or {}).get("sha256") == h

    def test_empty_input_returns_zero_no_fabrication(self, client):
        q = _post_query(client, "", {})
        assert q["event_count"] == 0
        assert q["results"] == []

    def test_prose_input_returns_zero(self, client):
        q = _post_query(client, "During the incident the actor deployed a remote access trojan.", {})
        assert q["event_count"] == 0

    def test_filters_applied_echoes_cleaned(self, client):
        q = _post_query(client, _fixture_sep_csv(),
                        {"host": "  DMZ01  ", "user": "",
                         "junk_ignored": None, "action": "block"})
        assert q["filters_applied"] == {"host": "DMZ01", "action": "block"}

    def test_response_size_under_budget(self, client):
        q = _post_query(client, _fixture_sep_csv(), {})
        size = len(json.dumps(q).encode())
        assert size < 250 * 1024, f"query size {size} B > 250 KB"

    # ─── Analyst-friendly input · natural language & partial hash ────
    @pytest.mark.parametrize("action_input,expected", [
        ("block",     2),
        ("Blocked",   2),
        ("BLOCKING",  2),
        ("blocked",   2),
        ("detect",    3),
        ("Detected",  3),
        ("Detecting", 3),
        # Actions genuinely absent in this fixture — must still be 0
        # (no fabrication), not the analyst's fault:
        ("quarantined", 0),
        ("Allowed",     0),
    ])
    def test_action_filter_accepts_natural_tense(self, client, action_input, expected):
        q = _post_query(client, _fixture_sep_csv(), {"action": action_input})
        assert q["event_count"] == expected, (
            f"analyst tense '{action_input}' expected {expected} events, got "
            f"{q['event_count']}. The action filter must accept the "
            f"analyst's natural tense (Blocked / Detected / Quarantined / "
            f"Allowed) and map it to the canonical stem (block / detect / …)."
        )

    @pytest.mark.parametrize("hash_input,expected_ge", [
        ("12f07d1352844bc7f12d3ad598dd73c19d86c5bdbe230e9c0acdebf4e182e2ad", 1),
        ("12f07d135284",   1),   # partial 12-char prefix
        ("12F07D13",       1),   # upper-case 8-char prefix
        ("noSuchPrefix",   0),
    ])
    def test_file_hash_accepts_partial_and_case_insensitive(self, client, hash_input, expected_ge):
        q = _post_query(client, _fixture_sep_csv(), {"file_hash": hash_input})
        if expected_ge == 0:
            assert q["event_count"] == 0
        else:
            assert q["event_count"] >= expected_ge, (
                f"partial hash '{hash_input}' returned {q['event_count']} "
                f"events; analysts often paste truncated hashes so a "
                f"substring match must succeed."
            )

    def test_single_field_query_returns_results(self, client):
        """Regression for the 'query returns nothing when only one field
        is set' UX bug: a single well-formed filter must match events."""
        singles = [
            {"host": "DMZ01"},         # partial host name
            {"user": "jsmith"},        # user only
            {"action": "Blocked"},     # analyst tense
            {"process": "winlogon"},   # process substring
            {"mitre": "T1055"},        # exact technique
            {"file_hash": "12f07d13"}, # 8-char hash prefix
        ]
        for f in singles:
            q = _post_query(client, _fixture_sep_csv(), f)
            assert q["event_count"] > 0, (
                f"single-field query {f} returned 0 events — this is the "
                f"UX bug the analyst reported.  Every one of these filters "
                f"names data that exists in the fixture."
            )


# ─────────────────────────────────────────────────────────────────
#  Auto-Visualization capability contract (2026-08-11).
# ─────────────────────────────────────────────────────────────────
class TestAutoVisualization:
    """Query response MUST expose `capabilities` and `default_view`
    that let the Workspace UI pick the right visualization without
    inventing evidence."""

    def test_zero_results_disables_every_visualization(self, client):
        """The dangerous case the owner flagged: 0 results MUST NOT
        fall back to the unfiltered investigation.  Every capability
        is False, default_view is None, and the frontend renders an
        explicit no-visualization state."""
        q = _post_query(client, _fixture_sep_csv(), {"host": "NONEXISTENT"})
        assert q["event_count"] == 0
        assert q["default_view"] is None, (
            "default_view MUST be None for 0-result queries so the UI "
            "cannot silently substitute the full investigation."
        )
        caps = q["capabilities"]
        assert caps == {"timeline": False, "process_tree": False,
                        "graph": False, "table": False}, (
            f"0-result query must disable every visualization; got {caps}"
        )

    def test_capabilities_present_for_all_wire_responses(self, client):
        q = _post_query(client, _fixture_sep_csv(), {})
        assert "capabilities" in q
        assert "default_view" in q
        assert set(q["capabilities"]) == {"timeline", "process_tree", "graph", "table"}
        for k, v in q["capabilities"].items():
            assert isinstance(v, bool), f"capabilities.{k} must be bool, got {type(v)}"

    def test_sep_csv_supports_all_four_visualizations(self, client):
        """The SEP fixture has 2 hosts + 2 users + a parent→child edge
        (launcher.exe → winlogon.exe).  Every visualization is
        evidence-supported."""
        q = _post_query(client, _fixture_sep_csv(), {})
        assert q["capabilities"] == {"timeline": True, "process_tree": True,
                                     "graph": True, "table": True}
        assert q["parent_child_edges"] >= 1
        assert len(q["matched_hosts"]) >= 2
        assert len(q["matched_users"]) >= 2

    def test_default_view_is_process_tree_when_parent_child_evidence_exists(self, client):
        """process_tree is a stronger signal than timeline when
        parent→child evidence exists — the UI defaults to it."""
        q = _post_query(client, _fixture_sep_csv(), {})
        assert q["default_view"] == "process_tree"

    def test_default_view_is_timeline_when_no_parent_child_evidence(self, client):
        """Filter down to events without parent_process → default_view
        should degrade to timeline (still evidence-backed)."""
        # rjones' foo.exe event has no parent_process in the fixture.
        q = _post_query(client, _fixture_sep_csv(), {"user": "rjones"})
        assert q["event_count"] > 0
        assert q["parent_child_edges"] == 0
        assert q["capabilities"]["process_tree"] is False
        assert q["default_view"] == "timeline"

    def test_graph_only_when_two_or_more_hosts_or_edges(self, client):
        # Restrict to a single host → graph capability may still be
        # true if a parent→child edge is present, but hosts alone are
        # insufficient.  Verify the derivation is truthful.
        q = _post_query(client, _fixture_sep_csv(), {"host": "DMZ02"})
        # DMZ02 = rjones' single event, no parent_process
        assert len(q["matched_hosts"]) == 1
        assert len(q["matched_users"]) == 1
        assert q["parent_child_edges"] == 0
        assert q["capabilities"]["graph"] is False

    def test_matched_processes_present_when_events_exist(self, client):
        q = _post_query(client, _fixture_sep_csv(), {})
        assert isinstance(q.get("matched_processes"), list)
        assert "winlogon.exe" in q["matched_processes"]

    def test_zero_result_does_not_report_underlying_events_as_matched(self, client):
        """Guardrail: 0 results must NOT accidentally expose the
        underlying investigation's hosts/users/processes."""
        q = _post_query(client, _fixture_sep_csv(), {"host": "NONEXISTENT"})
        assert q["event_count"] == 0
        assert q["matched_hosts"] == []
        assert q["matched_users"] == []
        assert q["matched_processes"] == []
        assert q["parent_child_edges"] == 0
        # But `total_available` still shows what the analyst filtered from —
        # so they know the investigation itself has 5 events and their
        # filter was the reason for the empty result.
        assert q["total_available"] >= 1


# ─────────────────────────────────────────────────────────────────
#  Cross-endpoint invariance — the "Sample1 equivalent" for Query.
# ─────────────────────────────────────────────────────────────────
class TestQueryDoesNotPerturb:
    """Executing arbitrary Query calls MUST NOT alter the semantic
    output of `/api/die/investigation-results` or `/api/die/timeline`.
    The only allowed drift is telemetry (per-call telemetry_id +
    pipeline timings), which is pre-existing and unrelated to Query.
    """

    def test_investigation_semantic_signature_unchanged(self, client):
        text = _fixture_sep_csv()
        before = _post_investigation(client, text)
        sig_before = _semantic_signature(before)

        # Fire multiple arbitrary Query calls that touch every filter.
        for f in [
            {},
            {"host": "DMZ01"},
            {"user": "jsmith", "action": "block"},
            {"mitre": "T1055"},
            {"date_from": "2026-08-03T00:00:00Z",
             "date_to":   "2026-08-04T00:00:00Z"},
            {"file_hash": "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca"},
            {"host": "NONEXISTENT"},
        ]:
            _post_query(client, text, f)

        after = _post_investigation(client, text)
        sig_after = _semantic_signature(after)
        assert sig_before == sig_after, (
            "Executing Query/Hunt calls perturbed the semantic content "
            "of /api/die/investigation-results (excluding known telemetry "
            "drift).  Query MUST be a strict read-only projection."
        )

    def test_timeline_byte_identical_across_queries(self, client):
        text = _fixture_sep_csv()
        before = _post_timeline(client, text)
        for f in [{}, {"host": "DMZ01"}, {"action": "block"}]:
            _post_query(client, text, f)
        after = _post_timeline(client, text)
        # Timeline doesn't include per-call telemetry, so byte-identical
        # equality is the correct invariant.
        assert json.dumps(before, sort_keys=True) == json.dumps(after, sort_keys=True), (
            "Query calls perturbed the Timeline output. Timeline MUST "
            "remain byte-identical."
        )

    def test_query_evidence_refs_match_investigation(self, client):
        """Every evidence_ref emitted by Query must appear in the
        investigation's evidence chain for the same MITRE technique.
        Proves Query is a projection of the same P0.2 chain, not a
        parallel one."""
        text = _fixture_sep_csv()
        q = _post_query(client, text, {})
        inv = _post_investigation(client, text).get("object") or {}
        inv_refs = {}
        for t in inv.get("mitre") or []:
            tid = t.get("id")
            for ev in (t.get("evidence") or []):
                if isinstance(ev, dict) and ev.get("evidence_ref"):
                    inv_refs.setdefault(tid, set()).add(ev["evidence_ref"])
        mismatches = []
        for e in q["results"]:
            for m in (e.get("mitre") or []):
                tid = m.get("id")
                if e["evidence_ref"] not in inv_refs.get(tid, set()):
                    mismatches.append((tid, e["evidence_ref"]))
        assert not mismatches, (
            f"query evidence_ref not found in the investigation's P0.2 "
            f"evidence chain for its cited MITRE: {mismatches[:5]}"
        )
