"""Local stage measurements; never substitute processing time for event time."""
from contextlib import contextmanager
from datetime import datetime, timezone
from time import perf_counter_ns


@contextmanager
def measure(timings, stage):
    """Measure one stage, including failed stages, without payload contents.

    Wall times support correlation; duration uses a monotonic clock. A failed
    stage has ended_at, not a fabricated successful completion timestamp.
    """
    if timings is None:
        yield
        return
    item = {"started_at": datetime.now(timezone.utc).isoformat()}
    timings[stage] = item
    start = perf_counter_ns()
    try:
        yield
    except BaseException:
        item["state"] = "FAILED"
        raise
    else:
        item["state"] = "COMPLETED"
    finally:
        item["ended_at"] = datetime.now(timezone.utc).isoformat()
        item["duration_ms"] = (perf_counter_ns() - start) / 1_000_000
