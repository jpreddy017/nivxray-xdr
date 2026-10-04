"""TS_LEXICOGRAPHIC_WINDOW_EXCLUSION regression.

Window inclusion, sorting and cursor paging must compare INSTANTS. Sysmon's
`2026-09-22 15:43:31.770` and the Event Log's `2026-09-22T15:43:31.770Z` are
the same class of UTC instant and must behave identically.
"""
from edr_plane.instant import instant_ms, parse_instant, rfc3339
from edr_plane import trajectory_window as tw


def test_sysmon_space_form_parses_to_same_instant_as_iso():
    assert instant_ms("2026-09-22 15:43:31.770") \
        == instant_ms("2026-09-22T15:43:31.770Z")


def test_windows_100ns_precision_parses_without_rounding_up():
    dt = parse_instant("2026-09-22T16:46:06.3636853Z")
    assert dt is not None and dt.microsecond == 363685


def test_offset_form_is_converted_to_utc():
    assert instant_ms("2026-09-22T17:43:31.770+02:00") \
        == instant_ms("2026-09-22 15:43:31.770")


def test_unparseable_timestamp_is_none_never_a_fabricated_time():
    for bad in ("", None, "not-a-time", "2026-13-45 99:99:99"):
        assert instant_ms(bad) is None


def test_rfc3339_preserves_the_instant_and_invents_no_precision():
    assert rfc3339("2026-09-22 15:43:31.770") == "2026-09-22T15:43:31.770Z"
    assert rfc3339("2026-09-22 15:43:31") == "2026-09-22T15:43:31Z"
    assert instant_ms(rfc3339("2026-09-22 15:43:31.770")) \
        == instant_ms("2026-09-22 15:43:31.770")


def test_lexicographic_comparison_would_have_excluded_the_space_form():
    # the defect, pinned so it cannot return unnoticed
    assert not ("2026-09-22 15:43:31.770" >= "2026-09-22T15:40:00.000Z")
    assert instant_ms("2026-09-22 15:43:31.770") \
        >= instant_ms("2026-09-22T15:40:00.000Z")


def _row(ts, iid):
    return {"timestamp": ts, "timestamp_instant_ms": instant_ms(ts),
            "event_iid": iid}


def test_mixed_representations_sort_chronologically():
    rows = [_row("2026-09-22T16:46:06.3636853Z", "c"),
            _row("2026-09-22 15:43:31.770", "a"),
            _row("2026-09-22 16:20:01.349", "b")]
    assert [r["event_iid"] for r in sorted(rows, key=tw._row_chrono)] \
        == ["a", "b", "c"]


def test_unparseable_rows_sort_last_and_are_not_given_a_time():
    rows = [_row("not-a-time", "x"), _row("2026-09-22 15:43:31.770", "a")]
    ordered = sorted(rows, key=tw._row_chrono)
    assert [r["event_iid"] for r in ordered] == ["a", "x"]
    assert ordered[-1]["timestamp_instant_ms"] is None


def test_cursor_round_trip_orders_by_instant_across_representations():
    cur = tw._cursor_encode("2026-09-22 15:43:31.770", "a",
                            instant_ms("2026-09-22 15:43:31.770"))
    after = tw._cursor_decode(cur)
    at = tw._chrono(after["ms"], after["iid"])
    assert tw._row_chrono(_row("2026-09-22T16:20:01.349Z", "b")) > at
    assert not tw._row_chrono(_row("2026-09-22 15:00:00.000", "z")) > at


def test_legacy_cursor_without_ms_is_still_ordered_by_instant():
    import base64
    import json
    legacy = base64.urlsafe_b64encode(json.dumps(
        {"ts": "2026-09-22 15:43:31.770", "iid": "a"}).encode()).decode()
    after = tw._cursor_decode(legacy)
    assert after["ms"] == instant_ms("2026-09-22 15:43:31.770")
