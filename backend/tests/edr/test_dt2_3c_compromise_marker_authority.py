"""The navigator's compromise marker and the compromise CONTRACT are one
authority.

Owner rule: `NO AUTHORITATIVE COMPROMISE = NO COMPROMISE PRESENTATION`.

Before this gate the marker was counted from the per-observation
`compromise_authority` classification, so:

  * the clean 3,299-record Windows corpus reported 70 navigator
    "compromise events" while its contract state was
    `NO_AUTHORITATIVE_COMPROMISE_OBSERVED`;
  * the fixture endpoint that DOES carry an authoritative compromise
    reported zero.

The marker now derives from the contract-validated compromise store and
nowhere else.
"""
from __future__ import annotations

from edr_plane.trajectory_window import _activity, _mark_compromises

DAY = "2026-09-22"


def _rows(n, **over):
    out = []
    for i in range(n):
        out.append({"timestamp": f"{DAY}T16:20:0{i % 10}.000000+00:00",
                    "event_iid": f"evt_{i}",
                    "disposition": "UNKNOWN_NOT_ASSESSED",
                    "is_detection": False,
                    **over})
    return out


def _cev(at, cid="cmp_1"):
    return {"compromise_event_id": cid, "observed_at": at}


# A · a MITRE-attributed observation is NOT a compromise
def test_mitre_attributed_observation_earns_no_marker():
    rows = _rows(70, compromise_authority="MITRE_ATTRIBUTED_EVIDENCE")
    out = _mark_compromises(_activity(rows, DAY), [], DAY)
    assert out["days"][0]["total"] == 70
    assert out["days"][0]["compromises"] == 0
    assert all(b["compromises"] == 0 for b in out["day_bins"])


# B · a detection-fabric attribution is NOT a compromise either
def test_detection_attribution_earns_no_marker():
    rows = _rows(5, compromise_authority="DETECTION_FABRIC_ATTRIBUTION",
                 is_detection=True)
    out = _mark_compromises(_activity(rows, DAY), None, DAY)
    assert out["days"][0]["detections"] == 5
    assert out["days"][0]["compromises"] == 0


# C · an authoritative compromise DOES earn exactly one marker
def test_authoritative_compromise_earns_one_marker():
    rows = _rows(6)
    out = _mark_compromises(
        _activity(rows, DAY), [_cev(f"{DAY}T16:20:03.600000+00:00")], DAY)
    assert out["days"][0]["compromises"] == 1
    marked = [b for b in out["day_bins"] if b["compromises"]]
    assert len(marked) == 1
    assert marked[0]["first_compromise_at"] == f"{DAY}T16:20:03.600000+00:00"
    assert marked[0]["first_compromise_iid"] == "cmp_1"


# D · the marker is stamped even on a day with no projected rows,
#     because the compromise is itself the evidence
def test_compromise_on_a_day_with_no_rows_still_marks_the_day():
    out = _mark_compromises(_activity([], DAY),
                            [_cev("2026-09-23T01:00:00+00:00", "cmp_x")], DAY)
    days = {d["day"]: d for d in out["days"]}
    assert days["2026-09-23"]["compromises"] == 1
    assert days["2026-09-23"]["total"] == 0


# E · two compromises in one bin are two, not one
def test_two_compromises_in_one_bin_are_counted_separately():
    out = _mark_compromises(
        _activity(_rows(2), DAY),
        [_cev(f"{DAY}T16:20:01.000000+00:00", "cmp_a"),
         _cev(f"{DAY}T16:20:02.000000+00:00", "cmp_b")], DAY)
    assert out["days"][0]["compromises"] == 2
    marked = [b for b in out["day_bins"] if b["compromises"]]
    assert sum(b["compromises"] for b in marked) == 2
    assert marked[0]["first_compromise_iid"] == "cmp_a"


# F · a compromise with no observed_at is never placed by guesswork
def test_a_compromise_without_a_time_is_not_placed():
    out = _mark_compromises(_activity(_rows(2), DAY),
                            [{"compromise_event_id": "cmp_n"}], DAY)
    assert out["days"][0]["compromises"] == 0


# G · the basis is declared, so a consumer cannot mistake the source
def test_compromise_basis_is_declared():
    assert _activity(_rows(1), DAY)["compromise_basis"] == \
        "AUTHORITATIVE_COMPROMISE_EVENTS_ONLY"


# H · the row-flag path is GONE from the activity builder
def test_activity_never_reads_the_observation_compromise_flag():
    import inspect

    import edr_plane.trajectory_window as tw
    src = inspect.getsource(tw._activity)
    assert "compromise_authority" not in src
