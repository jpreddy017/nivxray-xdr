"""Identity must not discard another host's event or a distinct POSIX file."""
import pytest

from edr_trajectory.contracts import event
from edr_trajectory.identity import dedupe
from edr_trajectory.lineage import isolate, lane_of, lanes, lanes_of
from edr_trajectory.providers import finalize


def file_event(path, index=0, **overrides):
    return finalize(event(tenant_id="t", device_id="d", event_id=f"e{index}",
                          kind="FILE_WRITE", observed_ms=1000 + index,
                          file={"path": path}, **overrides))


def test_same_source_identifier_on_different_hosts_or_tenants_survives():
    a = event(tenant_id="t", device_id="a", event_id="source-1")
    b = event(tenant_id="t", device_id="b", event_id="source-1")
    c = event(tenant_id="other", device_id="a", event_id="source-1")
    rows, suppressed = dedupe([a, b, c])
    assert len(rows) == 3 and suppressed == 0
    assert {(r["tenant_id"], r["device_id"]) for r in rows} == {
        ("t", "a"), ("t", "b"), ("other", "a")}


def test_same_host_cross_store_copy_still_merges_sources_and_lateness():
    a = event(tenant_id="t", device_id="d", event_id="same", sources=["canonical"], ingested_ms=2000)
    b = event(tenant_id="t", device_id="d", event_id="same", sources=["shadow"], ingested_ms=1500)
    [row], suppressed = dedupe([a, b])
    assert suppressed == 1 and row["sources"] == ["canonical", "shadow"]
    assert row["ingested_ms"] == 1500


def test_posix_case_distinct_files_are_not_collapsed_into_one_lane():
    events = [file_event("/tmp/Drop", 0), file_event("/tmp/drop", 1)]
    rows = lanes(events, 0, 2000)["lanes"]
    assert {r["lane_id"] for r in rows} == {"file:/tmp/Drop", "file:/tmp/drop"}
    assert all(r["event_count"] == 1 for r in rows)
    for ev in events:
        assert lanes_of(ev) == [lane_of(ev)]
        assert lane_of(ev) in {r["lane_id"] for r in rows}


def test_windows_case_variants_retain_existing_lane_identity():
    events = [file_event(r"C:\Temp\Drop.exe", 0), file_event(r"c:\temp\drop.exe", 1)]
    [row] = lanes(events, 0, 2000)["lanes"]
    assert row["lane_id"] == r"file:c:\temp\drop.exe"
    assert row["event_count"] == 2
    assert all(lane_of(ev) == row["lane_id"] for ev in events)


@pytest.mark.parametrize("subject", ["file", "process"])
def test_uppercase_recorded_hash_resolves_lineage_pivot(subject):
    ev = file_event("/tmp/Drop", process={"pid": 1, "guid": "g"})
    ev[subject]["sha256"] = "AB" * 32
    assert isolate([ev], sha256="ab" * 32)["seeds"] == [ev["process_key"]]
