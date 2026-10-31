"""G-31 recheck — does canonical `event_time` preserve the SENSOR observation
timestamp? Hermetic: parser/normalizer only, no DB, no pipeline write.

Scope is strictly the question asked. If the earlier scratch observation was a
malformed-fixture artifact, say so; if a real timestamp defect appears, report
it and stop rather than fixing it here.
"""
import sys

sys.path.insert(0, "/app/backend")
from detection_content.telemetry.nivxforge_sensor_dsm import \
    NivXForgeSensorDSM  # noqa: E402

OBSERVED = "2026-06-06T14:00:00.123456+00:00"
EP = "ep_a67be48d5b4e01d4d9e8"


def shapes():
    """Representative payload shapes, including the one the 34F scratch run
    used (which carried `ts`/`timestamp` instead of `observed_at`)."""
    core = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
            "pid": 4242, "ppid": 1, "image": "bash",
            "image_path": "/usr/bin/bash", "command_line": "bash -c id",
            "user": "root", "collection_method": "PROC_POLL",
            "parent_lookup_state": "OBSERVED", "parent_image": "sshd",
            "hostname": "lab-linux-01"}
    return {
        "observed_at (documented sensor field)": {**core,
                                                  "observed_at": OBSERVED},
        "ts only (the 34F scratch shape)": {**core, "ts": OBSERVED},
        "timestamp only": {**core, "timestamp": OBSERVED},
        "observed_at + ts": {**core, "observed_at": OBSERVED, "ts": OBSERVED},
    }


def main():
    dsm = NivXForgeSensorDSM()
    for label, ev in shapes().items():
        parsed = dsm.select_parser().parse(ev)
        canonical = dsm.select_normalizer().normalize(
            parsed, collector_id=EP, integration_id="g31",
            trace_id="raw_g31", tenant_id="ten_x")
        basis = (canonical.get("additional_fields") or {}).get(
            "event_time_basis") or (canonical.get("provenance") or {}).get(
            "event_time_basis")
        print(f"\n--- {label}")
        print("  payload observed field :",
              {k: ev[k] for k in ("observed_at", "ts", "timestamp")
               if k in ev})
        print("  canonical.event_time   :", canonical.get("event_time"))
        print("  preserves observation  :",
              str(canonical.get("event_time") or "").startswith(
                  "2026-06-06T14:00:00"))
        print("  event_time_basis       :", basis)


main()
