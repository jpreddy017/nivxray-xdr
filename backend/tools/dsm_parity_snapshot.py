"""DSM selection parity harness · P0-2.

Captures, for a fixed fixture set, which DSM id each registry selects.
Run BEFORE and AFTER the registry unification and diff the JSON:
    python3 -m tools.dsm_parity_snapshot > /tmp/dsm_parity_<tag>.json
"""
from __future__ import annotations

import json
import sys

FIXTURES: dict[str, dict] = {
    "suricata_eve_alert": {
        "event_type": "alert", "src_ip": "10.1.2.3", "dest_ip": "10.4.5.6",
        "timestamp": "2026-09-05T00:00:00Z",
        "alert": {"signature_id": 2027865, "signature": "ET TROJAN test"},
    },
    "suricata_eve_flow": {
        "event_type": "flow", "src_ip": "10.1.2.3", "dest_ip": "10.4.5.6",
        "timestamp": "2026-09-05T00:00:00Z",
    },
    # Windows-Security DSM supported ONLY 4688/4768/4769 before P0-3.
    # 4624/4625 logon coverage added 2026-09-05 (owner-authorised).
    "windows_security_4688": {
        "EventID": 4688, "Channel": "Security",
        "Computer": "WORKSTATION-01.corp.local",
        "TimeCreated": "2026-09-05T00:00:00Z",
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd /c whoami",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "SubjectUserName": "admin_jp", "SubjectDomainName": "CORP",
        },
    },
    "windows_security_4624_logon": {
        "EventID": 4624, "Channel": "Security", "Computer": "WIN-1",
        "TimeCreated": "2026-09-05T00:00:00Z",
        "EventData": {"TargetUserName": "alice", "LogonType": "3"},
    },
    # Sysmon DSM requires provider containing "Sysmon" (sysmon_dsm.py:204-206).
    "sysmon_1_process_create": {
        "provider": "Microsoft-Windows-Sysmon", "event_id": 1,
        "Computer": "WIN-1", "TimeCreated": "2026-09-05T00:00:00Z",
        "EventData": {"Image": "C:/Windows/System32/cmd.exe",
                      "CommandLine": "cmd /c whoami", "User": "WIN-1/alice",
                      "ProcessId": "4242", "ParentImage": "C:/explorer.exe"},
    },
    "sysmon_3_network": {
        "provider": "Microsoft-Windows-Sysmon", "event_id": 3,
        "Computer": "WIN-1", "TimeCreated": "2026-09-05T00:00:00Z",
        "EventData": {"SourceIp": "10.1.2.3", "DestinationIp": "8.8.8.8",
                      "DestinationPort": "53", "Image": "C:/curl.exe"},
    },
    "sysmon_unsupported_eid": {
        "provider": "Microsoft-Windows-Sysmon", "event_id": 255,
        "Computer": "WIN-1", "TimeCreated": "2026-09-05T00:00:00Z",
        "EventData": {},
    },
    # Overlap probe: a Sysmon-provider event whose EventID is also a
    # Windows-Security ID.  Proves which DSM wins on collision.
    "overlap_sysmon_provider_eid_4688": {
        "provider": "Microsoft-Windows-Sysmon", "event_id": 4688,
        "Computer": "WIN-1", "TimeCreated": "2026-09-05T00:00:00Z",
        "EventData": {"NewProcessName": "C:/cmd.exe"},
    },
    # Raising probe: supports() must fail closed, never propagate.
    "raising_probe": None,  # replaced at runtime by _ExplodingEvent()
    "linux_auditd_execve": {
        "type": "SYSCALL", "audit_type": "SYSCALL", "node": "lx-1",
        "syscall": "59", "comm": "bash", "exe": "/bin/bash",
        "auid": "1000", "uid": "1000",
        "msg": "audit(1757000000.123:456)",
    },
    "aws_cloudtrail_event": {
        "eventVersion": "1.08", "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser", "awsRegion": "us-east-1",
        "eventTime": "2026-09-05T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "userName": "root"},
        "recipientAccountId": "111122223333",
    },
    "unsupported_garbage": {"foo": "bar"},
    "not_a_dict": None,
}


class _ExplodingEvent(dict):
    """A dict whose .get() raises — probes fail-closed behaviour of supports()."""

    def get(self, *args, **kwargs):  # noqa: D102
        raise RuntimeError("exploding event fixture")


FIXTURES["raising_probe"] = _ExplodingEvent({"event_type": "x"})


def _identify(dsm) -> str | None:
    if dsm is None:
        return None
    return getattr(dsm, "id", dsm.__class__.__name__)


def snapshot() -> dict:
    out: dict = {"pipeline_registry": {}, "telemetry_registry": {}}

    from detection_content.xdr_pipeline import DSM_REGISTRY
    out["pipeline_registry"]["inventory"] = [d.get("id") for d in DSM_REGISTRY.list()]
    for name, ev in FIXTURES.items():
        try:
            out["pipeline_registry"][name] = _identify(DSM_REGISTRY.resolve(ev))
        except Exception as exc:  # captured, not swallowed
            out["pipeline_registry"][name] = f"RAISED:{type(exc).__name__}"

    from detection_content.telemetry import TELEMETRY_DSM_REGISTRY as T
    out["telemetry_registry"]["inventory"] = [d.get("id") for d in T.list()]
    for name, ev in FIXTURES.items():
        try:
            out["telemetry_registry"][name] = _identify(T.resolve(ev))
        except Exception as exc:
            out["telemetry_registry"][name] = f"RAISED:{type(exc).__name__}"

    out["same_object"] = (
        DSM_REGISTRY is T
    )
    return out


if __name__ == "__main__":
    json.dump(snapshot(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
