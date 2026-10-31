"""NivXRay v2 · Trajectory Engine (Phase 3d).

Entity-aware Device Trajectory Engine — turns a stream of CEM v1
events into ordered `TrajectoryFrame` objects with stable entity
references (device / process / parent / file / registry / network /
user). This is the substrate for the Device Trajectory UI, process
ancestry, entity pivoting, and future multi-host reconstruction.

Feature-flagged on `TRAJECTORY_ENGINE`.
"""
from v2.trajectory.schema import (  # noqa: F401
    TrajectoryFrame,
    EntityRef,
    Lane,
    LANE_ORDER,
    LANES,
)
from v2.trajectory.device import (  # noqa: F401
    build_device_trajectory,
    build_from_observations,
)
