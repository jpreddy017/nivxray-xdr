"""DT2-1 · server-side semantics the navigation engine depends on.

Hermetic: pure Python over the DT2-0 contract layer, no Mongo, no network,
no environment. Runs inside the authoritative CI scope (`tests/edr`).

These cases are the PYTEST rows of the DT2-1 50-case matrix. Interaction
mechanics are NOT claimed here — they belong to the unit (vitest) and
browser (Playwright) harnesses.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from edr_plane import trajectory as dt2
from edr_plane.trajectory import contract as c
from edr_plane.trajectory import models as m

WEB = pathlib.Path("/app/apps/nivxray-xdr/src/nivxforge/trajectory")
DT2_DIR = WEB / "dt2"

START = "2026-06-01T00:00:00+00:00"
END = "2026-06-02T00:00:00+00:00"


def _row(iid: str, ts: str, **kw):
    row = {"event_iid": iid, "timestamp": ts, "kind": "process_create",
           "process": "powershell.exe", "process_iid": "guid-1",
           "lane_index": 0, "disposition": "UNKNOWN_NOT_ASSESSED",
           "provenance": {"raw_event_id": f"raw-{iid}",
                          "canonical_event_id": f"can-{iid}",
                          "parser_state": "CANONICALIZED"}}
    row.update(kw)
    return row


ROWS = [
    _row("a", "2026-06-01T01:00:00+00:00"),
    _row("b", "2026-06-01T01:00:00+00:00"),          # equal timestamp
    _row("c", "2026-06-01T02:00:00+00:00", is_detection=True,
         detection={"finding_id": "f1", "rule_ids": ["r1"]}),
    _row("d", "2026-06-01T03:00:00+00:00", kind="file_create",
         file="C:/tmp/x.exe"),
]


# ── density: navigation quantity, never severity ──────────────────────

def test_p01_density_buckets_are_emitted_for_the_requested_span():
    buckets = c.density(ROWS, START, END)
    assert buckets, "the overview needs density to navigate by"
    assert all(isinstance(b, m.DensityBucket) for b in buckets)


def test_p02_density_carries_no_severity_field_of_any_kind():
    forbidden = {"severity", "threat", "malicious", "verdict",
                 "disposition", "risk", "score", "confidence"}
    for bucket in c.density(ROWS, START, END):
        assert not (set(bucket.__dict__) & forbidden)


def test_p03_density_declares_navigation_only_semantics():
    for bucket in c.density(ROWS, START, END):
        assert bucket.semantics == "NAVIGATION_ONLY_NOT_SEVERITY"


def test_p04_density_counts_are_never_negative():
    with pytest.raises(ValueError):
        m.DensityBucket(start=START, end=END, stream="events", count=-1)


def test_p05_a_detection_stream_is_separate_from_the_events_stream():
    streams = {b.stream for b in c.density(ROWS, START, END)}
    assert "events" in streams and "detection" in streams


def test_p06_density_of_an_empty_window_is_empty_not_fabricated():
    assert c.density([], START, END) == []


# ── retention and coverage truth ──────────────────────────────────────

def test_p07_available_range_is_derived_from_observations_only():
    w = c.build({"events": ROWS}, endpoint_id="ep1",
                requested_start=START, requested_end=END)
    assert w.available_range["from"] == "2026-06-01T01:00:00+00:00"
    assert w.available_range["to"] == "2026-06-01T03:00:00+00:00"
    assert w.available_range["state"] == m.AVAIL_AVAILABLE


def test_p08_requested_range_is_echoed_and_never_overwritten():
    w = c.build({"events": ROWS}, endpoint_id="ep1",
                requested_start=START, requested_end=END)
    assert w.requested_range == {"from": START, "to": END}


def test_p09_retention_boundary_stays_unknown_without_proof():
    w = c.build({"events": ROWS}, endpoint_id="ep1")
    assert w.retention_boundary["state"] == m.AVAIL_UNKNOWN
    assert "NOT_PROVABLE" in w.retention_boundary["basis"]


def test_p10_an_empty_window_is_unknown_coverage_not_absence():
    cov = c.coverage({}, [], START, END)
    assert cov and all(i.state == m.COV_UNKNOWN for i in cov)
    assert all(i.absence_inferable is False for i in cov)
    assert "not proof of" in (cov[0].reason or "")


def test_p11_a_span_before_the_first_observation_is_unknown():
    cov = c.coverage({}, ROWS, START, END)
    unknown = [i for i in cov if i.state == m.COV_UNKNOWN]
    assert unknown, "the unobserved head of the window must stay UNKNOWN"
    assert all(i.boundary_certainty == "UNKNOWN" for i in unknown)


def test_p12_not_collected_is_never_invented_by_the_window_builder():
    cov = c.coverage({}, ROWS, START, END)
    assert all(i.state != m.COV_NOT_COLLECTED for i in cov)


# ── cursor determinism the navigation engine relies on ────────────────

def test_p13_cursor_is_timestamp_plus_event_iid_not_timestamp_alone():
    cur = m.TrajectoryCursor.parse({"timestamp": START, "event_iid": "a"})
    assert cur.timestamp == START and cur.event_iid == "a"


def test_p14_equal_timestamps_remain_distinguishable_observations():
    w = c.build({"events": ROWS}, endpoint_id="ep1")
    ids = [o.observation_id for o in w.observations]
    assert ids.count("a") == 1 and ids.count("b") == 1


# ── focus / selection semantics ───────────────────────────────────────

def test_p15_focus_by_raw_event_id_resolves_exactly():
    res = c.resolve_focus(
        m.FocusTarget(kind="raw_event_id", value="raw-c"), ROWS)
    assert res.state == m.FOCUS_RESOLVED
    assert res.observation_id == "c"
    assert res.basis == "EXACT_EVIDENCE_ID"


def test_p16_focus_outside_the_window_fails_explicitly():
    res = c.resolve_focus(
        m.FocusTarget(kind="raw_event_id", value="raw-zzz"), ROWS)
    assert res.state == m.FOCUS_EVIDENCE_MISSING
    assert res.observation_id is None


def test_p17_ambiguous_focus_never_silently_picks_one():
    dupes = [_row("x", "2026-06-01T01:00:00+00:00"),
             _row("y", "2026-06-01T01:00:00+00:00")]
    for row in dupes:
        row["provenance"]["raw_event_id"] = "raw-dupe"
    res = c.resolve_focus(
        m.FocusTarget(kind="raw_event_id", value="raw-dupe"), dupes)
    assert res.state == m.FOCUS_AMBIGUOUS


def test_p18_process_identity_authority_is_declared_not_assumed():
    w = c.build({"events": ROWS}, endpoint_id="ep1")
    assert w.process_instances
    for p in w.process_instances:
        assert p.identity_authority in (m.AUTHORITY_AUTHORITATIVE,
                                        m.AUTHORITY_DERIVED,
                                        m.AUTHORITY_UNSTABLE)


def test_p19_pid_reuse_yields_two_instances_and_is_never_merged():
    rows = [_row("p1", "2026-06-01T01:00:00+00:00", process_iid="guid-A",
                 pid=4242),
            _row("p2", "2026-06-01T05:00:00+00:00", process_iid="guid-B",
                 pid=4242)]
    ids = {p.process_iid for p in c.process_instances(rows, "ep1")}
    assert len(ids) == 2


# ── V1 additive compatibility (DT2-1 must not break it) ───────────────

def test_p20_augment_preserves_every_v1_key_byte_for_byte():
    v1 = {"events": ROWS, "lane_axis": {"total_lanes": 3, "lanes": []},
          "activity": {"days": []}, "time_range": {"start": START,
                                                   "end": END},
          "projection": {"state": "COMPLETE"}, "cursor": None,
          "epistemic_state": {"state": "OK"}}
    before = json.dumps(v1, sort_keys=True, default=str)
    out = dt2.augment(dict(v1), endpoint_id="ep1")
    for key, value in v1.items():
        assert out[key] == value
    assert "dt2" in out
    assert json.dumps(v1, sort_keys=True, default=str) == before


def test_p21_the_dt2_key_is_json_serializable_for_the_browser():
    out = dt2.augment({"events": ROWS}, endpoint_id="ep1")
    json.dumps(out["dt2"])


def test_p22_a_v1_only_client_can_ignore_dt2_entirely():
    out = dt2.augment({"events": ROWS, "lane_axis": {"lanes": []}},
                      endpoint_id="ep1")
    del out["dt2"]
    assert set(out) == {"events", "lane_axis"}


def test_p23_the_projection_still_creates_no_store():
    w = c.build({"events": ROWS}, endpoint_id="ep1")
    assert w.provenance["creates_no_store"] is True


# ── the DT2-1 frontend engine: structural guarantees ──────────────────

def test_p24_the_dt2_1_engine_modules_exist():
    for name in ("pointer.js", "viewport.js", "navigation.js",
                 "requests.js", "urlState.js", "loadState.js",
                 "density.js", "bounded.js", "index.js"):
        assert (DT2_DIR / name).is_file(), name


def test_p25_the_old_unbounded_wheel_arithmetic_is_gone():
    src = (WEB / "AmpCanvas.jsx").read_text()
    assert "deltaY > 0 ? 1.25 : 0.8" not in src, \
        "compounding per-event zoom factor must not return"
    assert "normalizeWheel" in src and "governZoom" in src
    assert "governPan" in src and "governLane" in src


def test_p26_the_canvas_zoom_is_anchored_on_the_pointer():
    src = (WEB / "AmpCanvas.jsx").read_text()
    assert "timeAtX" in src and "pointerXRef" in src
    assert "zoomBySteps" in src


def test_p27_the_zoom_ladder_spans_thirty_days_down_to_one_second():
    src = (DT2_DIR / "viewport.js").read_text()
    assert "30 * MS.d" in src and "MS.s," in src
    assert "MAX_SPAN_MS" in src and "MIN_SPAN_MS" in src


def test_p28_every_delta_mode_is_converted_explicitly():
    src = (DT2_DIR / "pointer.js").read_text()
    for token in ("PIXEL", "LINE", "PAGE", "LINE_TO_PX", "PAGE_TO_PX"):
        assert token in src


def test_p29_sensitivity_is_clamped_per_event_and_per_window():
    src = (DT2_DIR / "pointer.js").read_text()
    assert "PAN_MAX_FRACTION_PER_EVENT" in src
    assert "PAN_MAX_FRACTION_PER_WINDOW" in src
    assert "LANE_MAX_ROWS_PER_EVENT" in src
    assert "ZOOM_MAX_STEPS_PER_EVENT" in src


def test_p30_requests_carry_a_generation_and_an_abort_signal():
    src = (DT2_DIR / "requests.js").read_text()
    assert "AbortController" in src
    assert "DISCARDED_STALE" in src and "generation" in src


def test_p31_the_request_key_includes_tenant_and_endpoint():
    src = (DT2_DIR / "requests.js").read_text()
    assert "tenantId" in src and "endpointId" in src
    assert "NO_TENANT" in src


def test_p32_no_credential_may_be_serialized_into_the_url():
    src = (DT2_DIR / "urlState.js").read_text()
    assert "SENSITIVE_PATTERN" in src and "assertNoSensitive" in src
    for token in ("token", "secret", "bearer", "jwt"):
        assert token in src


def test_p33_viewport_geometry_replaces_and_selection_pushes():
    src = (DT2_DIR / "urlState.js").read_text()
    assert '"event"' in src.replace("'", '"')
    assert "PUSH_KEYS" in src and "REPLACE_KEYS" in src
    assert "transient" in src


def test_p34_failure_and_cancellation_are_not_absence_of_activity():
    src = (DT2_DIR / "loadState.js").read_text()
    assert "isObservationAbsence" in src
    assert "FAILED" in src and "CANCELED" in src
    assert "STALE_RESPONSE_DISCARDED" in src


def test_p35_the_page_does_not_fetch_the_whole_history():
    src = (WEB / "EdrDeviceTrajectoryPage.jsx").read_text()
    assert "time_start" in src and "time_end" in src
    assert "prefetchTargets" in src
    assert "MAX_PREFETCH_IN_FLIGHT" in (DT2_DIR / "requests.js").read_text()


def test_p36_the_trajectory_exposes_no_response_action():
    for name in ("pointer.js", "viewport.js", "navigation.js",
                 "requests.js", "urlState.js", "loadState.js",
                 "density.js", "bounded.js"):
        src = (DT2_DIR / name).read_text().lower()
        for banned in ("isolate", "quarantine", "kill_process",
                       "/response/execute", "block_hash"):
            assert banned not in src, f"{name}:{banned}"


def test_p37_the_engine_never_writes_evidence():
    for name in ("pointer.js", "viewport.js", "navigation.js",
                 "requests.js", "urlState.js", "loadState.js",
                 "density.js", "bounded.js"):
        src = (DT2_DIR / name).read_text()
        for banned in ("api.post", "api.put", "api.delete", "api.patch"):
            assert banned not in src, f"{name}:{banned}"


def test_p38_selection_identity_is_process_iid_never_pid():
    src = (DT2_DIR / "navigation.js").read_text()
    assert "processInstanceIdOf" in src
    assert "process_iid" in src
    assert "o?.pid" not in src and "obs.pid" not in src
