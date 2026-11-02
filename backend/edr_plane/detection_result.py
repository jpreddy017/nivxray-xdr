"""Validate detection completion before projecting an evaluated outcome."""


def require_detection_result(result):
    """A returned pipeline dictionary alone is not proof rules executed."""
    detection = result.get("detection")
    executed = any(
        isinstance(stage, dict)
        and stage.get("stage") == "detection"
        and stage.get("status") == "EXECUTED"
        for stage in (result.get("stages") or [])
    )
    if (not executed or not isinstance(detection, dict) or not detection
            or detection.get("status") == "EXECUTION_FAILED"):
        raise RuntimeError(
            "detection evaluation did not complete; pipeline blocker: "
            + str(result.get("blocker") or "missing completion evidence")
        )
    return detection
