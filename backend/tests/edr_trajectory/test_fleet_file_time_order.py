"""Fleet file chronology shares the existing canonical instant parser."""
from services.edr import file_trajectory as ft


def run(monkeypatch, times):
    class Store:
        def find(self, query, projection):
            assert query == {"tenant_id": "t"}
            return [{"event": {"iid": f"e{i}", "device_iid": f"d{i}", "ts": ts,
                               "kind": "file_create", "process": {"name": "dropper.exe"}}}
                    for i, ts in enumerate(times)]
    monkeypatch.setattr(ft, "_obs", Store())
    return ft.fleet_trajectory("name", "dropper.exe", tenant_id="t")


def test_mixed_windows_and_iso_shapes_use_real_chronology(monkeypatch):
    out = run(monkeypatch, ["2026-10-02 07:10:00.000", "2026-10-02T06:00:00Z"])
    assert [e["event_iid"] for e in out["events"]] == ["e1", "e0"]
    assert out["first_observed"] == "2026-10-02T06:00:00Z"
    assert out["last_observed"] == "2026-10-02 07:10:00.000"
    assert [r["device_iid"] for r in out["entry_points"]] == ["d1"]


def test_equivalent_instants_keep_all_earliest_hosts(monkeypatch):
    out = run(monkeypatch, ["2026-10-02T07:00:00+01:00", "2026-10-02 06:00:00"])
    assert {r["device_iid"] for r in out["entry_points"]} == {"d0", "d1"}


def test_invalid_time_preserved_without_inventing_earliest_host(monkeypatch):
    out = run(monkeypatch, ["bad-time", None, "2026-10-02T06:00:00Z"])
    assert len(out["events"]) == 3
    assert out["timestamp_unresolved_events"] == 2
    assert out["first_observed"] == out["last_observed"] == "2026-10-02T06:00:00Z"
    assert [r["device_iid"] for r in out["entry_points"]] == ["d2"]
    out = run(monkeypatch, [None, "bad-time"])
    assert out["first_observed"] is out["last_observed"] is None
    assert out["entry_points"] == []


def test_endpoint_rollup_uses_instants(monkeypatch):
    class Store:
        def find(self, query, projection):
            return [{"event": {"iid": f"e{i}", "device_iid": "d", "ts": ts,
                               "process": {"name": "dropper.exe"}}}
                    for i, ts in enumerate(["2026-10-02 07:10:00", "2026-10-02T06:00:00Z"])]
    monkeypatch.setattr(ft, "_obs", Store())
    row = ft.fleet_trajectory("name", "dropper.exe", tenant_id="t")["endpoint_rows"][0]
    assert row["first_seen"] == "2026-10-02T06:00:00Z"
    assert row["last_seen"] == "2026-10-02 07:10:00"
