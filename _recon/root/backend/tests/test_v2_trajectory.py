"""Phase 3d · Trajectory engine unit tests."""
from __future__ import annotations
import hashlib
import json
import pytest
from v2.trajectory import (
    build_device_trajectory, TrajectoryFrame, LANE_ORDER, LANES,
)
from v2.trajectory.schema import lane_for


def _mk_event(kind, ts, iid, **extra):
    e = {"iid": iid, "case_id": "c1", "adapter": "sysmon",
         "adapter_version": "1.0", "ts": ts, "sequence": 0, "kind": kind,
         "device_iid": "dev_test", "process": {}, "artefacts_iids": [], "raw": {}}
    e.update(extra)
    return e


class TestLaneAssignment:
    @pytest.mark.parametrize("kind,expected", [
        ("process_create",     "process"),
        ("file_write",         "file"),
        ("registry_value_set", "registry"),
        ("network_connect",    "network"),
        ("dns_query",          "network"),
        ("logon_success",      "system"),
        ("service_install",    "system"),
        ("unknown_kind",       "system"),
    ])
    def test_lane_mapping(self, kind, expected):
        assert lane_for(kind) == expected

    def test_lane_order_locked(self):
        assert LANE_ORDER == ("system", "process", "file", "network", "registry")

    def test_lanes_exposed_for_ui(self):
        assert len(LANES) == 5
        assert LANES[0].order == 0
        assert LANES[-1].order == 4


class TestBuildDeviceTrajectory:
    def test_frames_produced_and_ordered_by_ts(self):
        events = [
            _mk_event("process_create",    "2026-06-29T10:00:02Z", "evt_2"),
            _mk_event("registry_value_set","2026-06-29T10:00:01Z", "evt_1"),
            _mk_event("network_connect",   "2026-06-29T10:00:03Z", "evt_3"),
        ]
        frames = build_device_trajectory(events, device_iid="dev_test")
        assert [f.action for f in frames] == ["registry_value_set", "process_create", "network_connect"]
        assert [f.lane for f in frames] == ["registry", "process", "network"]

    def test_deterministic_across_runs(self):
        events = [_mk_event("process_create", "2026-06-29T10:00:00Z", f"evt_{i}") for i in range(5)]
        a = [f.frame_iid for f in build_device_trajectory(events, device_iid="dev_test")]
        b = [f.frame_iid for f in build_device_trajectory(events, device_iid="dev_test")]
        assert a == b
        assert all(iid.startswith("tf_") for iid in a)

    def test_off_device_events_filtered(self):
        events = [
            _mk_event("process_create", "2026-06-29T10:00:00Z", "evt_1",
                      device_iid="dev_other"),
            _mk_event("process_create", "2026-06-29T10:00:01Z", "evt_2",
                      device_iid="dev_test"),
        ]
        frames = build_device_trajectory(events, device_iid="dev_test")
        assert len(frames) == 1

    def test_entity_refs_populated(self):
        e = _mk_event("registry_value_set", "2026-06-29T10:00:00Z", "evt_1",
                      process_iid="proc_x", actor_iid="usr_a",
                      artefacts_iids=["reg_hkcu_run"])
        e["process"] = {"name": "explorer.exe", "parent_iid": "proc_parent"}
        frames = build_device_trajectory([e], device_iid="dev_test")
        f = frames[0]
        assert f.process and f.process.iid == "proc_x"
        assert f.parent and f.parent.iid == "proc_parent"
        assert f.registry and f.registry.iid == "reg_hkcu_run"
        assert f.user and f.user.iid == "usr_a"
        assert f.device.iid == "dev_test"

    def test_to_dict_is_json_serialisable(self):
        e = _mk_event("process_create", "2026-06-29T10:00:00Z", "evt_1",
                      process_iid="proc_x")
        f = build_device_trajectory([e], device_iid="dev_test")[0]
        s = json.dumps(f.to_dict())
        # sha16 fingerprint sanity
        assert hashlib.sha256(s.encode()).hexdigest()


class TestTrajectoryEndpointRegistered:
    def test_endpoint_in_openapi(self):
        from server import app
        paths = {r.path for r in app.routes if hasattr(r, "path")}
        assert "/api/v2/cases/{case_id}/trajectory/device" in paths
