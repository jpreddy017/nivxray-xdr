"""Honest state · a non-process entity must never occupy the `process` field.

Reported from the UI: the Device Trajectory rendered a PROCESSES lifeline
labelled `203.0.113.77` with the badge `[77]` — a remote IP address shown
as a running process, with its last octet read as a file extension.

Root cause (two independent fallbacks, both fixed):
  * `services/edr/device_identity.observations()` used
    `proc.get("name") or raw.get("entity")`. For a network-only
    observation `raw["entity"]` is the remote endpoint.
  * `routers/edr.py` activity projection used
    `ent.get("process") or ent.get("name")` for EVERY entity kind.

Both surfaced only once P1.10 started delivering real firewall telemetry
that legitimately carries NO process evidence at all.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import services.edr.device_identity as di  # noqa: E402

NETWORK_OBS = {
    "case_id": None,
    "origin": "collector-live",
    "process_iid": "",
    "event": {
        "iid": "ev-net-1",
        "kind": "network_connect",
        "device_iid": "dev_test_fw",
        "computer": "TEST-FW01",
        "host": {"hostname": "TEST-FW01"},
        # No process entity at all — a firewall session has none.
        "process": {},
        "raw": {"entity": "203.0.113.77",
                 "target": "203.0.113.77",
                 "provider": "Fortinet FortiGate",
                 "user": "n.iyer"},
        "artefacts": {"network": [{"dst_ip": "203.0.113.77"}]},
        "ts": "2026-06-11T09:22:10+00:00",
    },
}

PROCESS_OBS = {
    "case_id": None,
    "origin": "collector-live",
    "process_iid": "proc-1",
    "event": {
        "iid": "ev-proc-1",
        "kind": "process_create",
        "device_iid": "dev_test_srv",
        "computer": "TEST-SRV01",
        "host": {"hostname": "TEST-SRV01"},
        "process": {"name": "certutil.exe", "image": r"C:\Windows\certutil.exe"},
        "raw": {"entity": "certutil.exe", "target": r"C:\temp\a.dll"},
        "ts": "2026-06-11T09:24:00+00:00",
    },
}


def _observations(monkeypatch, docs, hostname):
    class _Col:
        def find(self, *a, **kw):
            return iter(docs)

    monkeypatch.setattr(di, "_obs", _Col())
    return di.observations(
        hostname, True, None,
        identity={"device_iid": docs[0]["event"]["device_iid"],
                   "hostname": hostname})


def test_network_only_observation_has_no_process_and_says_unknown(monkeypatch):
    rows = _observations(monkeypatch, [NETWORK_OBS], "TEST-FW01")
    assert len(rows) == 1
    row = rows[0]
    assert row["process"] is None, \
        "a remote endpoint must never occupy the process field"
    assert row["process_state"] == "UNKNOWN"
    # The endpoint is still fully present — as a target, not an actor.
    assert row["file"] == "203.0.113.77"
    assert row["lane"] == "network"


def test_real_process_evidence_is_still_reported(monkeypatch):
    rows = _observations(monkeypatch, [PROCESS_OBS], "TEST-SRV01")
    row = rows[0]
    assert row["process"] == "certutil.exe"
    assert row["process_state"] == "OBSERVED"
    assert row["path"] == r"C:\Windows\certutil.exe"


def test_activity_projection_gates_process_on_entity_kind():
    """The second fallback, in the ActivityInventory projection.

    Checked structurally: this projection needs live case documents plus
    a built ActivityInventory to exercise behaviourally, so the invariant
    asserted here is that the `process` field is gated on the entity kind
    and that an epistemic state is emitted alongside it.
    """
    import inspect

    import routers.edr as edr
    src = inspect.getsource(edr.get_device_trajectory)
    assert "is_process = " in src, \
        "the activity projection must gate `process` on the entity kind"
    assert '"process_state":' in src, \
        "the activity projection must declare process_state"
    assert "if is_process else None" in src, \
        "a non-process entity must yield process=None"
