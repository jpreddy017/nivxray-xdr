"""Trajectory schema · TrajectoryFrame + entity references.

Every frame is entity-aware: it carries stable iids for every
significant entity involved (device / process / parent / file /
registry / network / user). This gives downstream consumers (UI,
pivots, cross-device joins) direct paths without re-parsing raw
events.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Final

# Lane order is the visual order in the Device Trajectory UI (top
# to bottom). Locked here so the backend produces frames tagged
# with a lane that the frontend can consume without any lookup.
LANE_ORDER: Final[tuple[str, ...]] = (
    "system", "process", "file", "network", "registry",
)

# Every CEM event kind maps to exactly one lane. Missing kinds
# fall back to "system".
_KIND_TO_LANE: Final[dict[str, str]] = {
    "process_create":       "process",
    "process_exit":         "process",
    "process_access":       "process",
    "image_load":           "process",
    "thread_create":        "process",
    "remote_thread_create": "process",
    "memory_alloc":         "process",
    "memory_protect":       "process",
    "handle_open":          "process",
    "file_create":          "file",
    "file_write":           "file",
    "file_delete":          "file",
    "file_rename":          "file",
    "directory_create":     "file",
    "registry_create":      "registry",
    "registry_value_set":   "registry",
    "registry_delete":      "registry",
    "network_connect":      "network",
    "network_listen":       "network",
    "dns_query":            "network",
    "http_request":         "network",
    "smb_share_access":     "network",
    "ssh_session_open":     "network",
    "rdp_session_open":     "network",
    "logon_success":        "system",
    "logon_failure":        "system",
    "service_install":      "system",
    "service_start":        "system",
    "driver_load":          "system",
    "scheduled_task_create":"system",
    "wmi_subscribe":        "system",
    "kernel_event":         "system",
}


def lane_for(event_kind: str) -> str:
    return _KIND_TO_LANE.get(event_kind, "system")


@dataclass(frozen=True)
class EntityRef:
    """Stable, minimal reference to an entity involved in a frame."""
    kind: str           # "device" | "process" | "file" | "network_conn" | ...
    iid: str            # globally unique investigation id
    label: str | None = None


@dataclass(frozen=True)
class Lane:
    """Static UI lane descriptor — pushed to the frontend so the
    backend controls lane order + labels, not the client."""
    key: str            # matches LANE_ORDER
    label: str
    order: int


LANES: Final[tuple[Lane, ...]] = tuple(
    Lane(key=k, label=k.capitalize(), order=i) for i, k in enumerate(LANE_ORDER)
)


@dataclass(frozen=True)
class TrajectoryFrame:
    """One row of the Device Trajectory.

    Deterministic construction: identical events → identical frames.
    """
    frame_iid: str              # stable "tf_<sha16>"
    ts: str                     # ISO-8601 UTC — event timestamp
    lane: str                   # one of LANE_ORDER
    action: str                 # canonical short verb, e.g. "process_create"
    label: str                  # human-readable — e.g. "cmd.exe spawned powershell.exe"
    device:   EntityRef
    process:  EntityRef | None = None
    parent:   EntityRef | None = None
    file:     EntityRef | None = None
    registry: EntityRef | None = None
    network:  EntityRef | None = None
    user:     EntityRef | None = None
    mitre:    tuple[str, ...] = ()
    labels:   tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k, v in list(d.items()):
            if isinstance(v, tuple):
                d[k] = list(v)
        return d
