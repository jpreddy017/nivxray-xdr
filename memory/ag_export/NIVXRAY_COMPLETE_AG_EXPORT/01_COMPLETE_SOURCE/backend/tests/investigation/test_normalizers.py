"""Stage 4 · Vendor Normalizers → CEMv1 tests."""
import json

from nivxforge.investigation.cem import (
    CanonicalEventModel, EventKind, SeverityLevel,
)
from nivxforge.investigation.pipeline.input_classification import classify_input
from nivxforge.investigation.pipeline.normalizers import normalize
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.vendor_detection import Vendor, detect_vendor


def _cem(raw: str) -> CanonicalEventModel:
    parsed = parse_input(raw, classify_input(raw))
    return normalize(parsed, detect_vendor(parsed))


def test_cisco_secure_endpoint_emits_cem():
    payload = json.dumps({
        "id": "e-42", "date": "2026-01-15T10:22:00Z",
        "detection": "W32.Trojan.Emotet",
        "event_type": "Threat Detected",
        "event_type_id": 1090519054,
        "connector_guid": "cg-1", "severity": "High",
        "computer": {"connector_guid": "cg-1", "hostname": "WKS-42",
                     "operating_system": "Windows 10"},
        "file": {"disposition": "Malicious",
                 "file_name": "invoice.exe",
                 "file_path": "C:/Users/John/Downloads/invoice.exe",
                 "identity": {"sha256": "a" * 64, "md5": "b" * 32}},
        "network_info": {"remote_ip": "198.51.100.7",
                          "remote_port": 443,
                          "dirty_url": "http://bad.com/p1"},
    })
    cem = _cem(payload)
    assert cem.vendor_route == "cisco_secure_endpoint"
    assert len(cem.events) == 1
    evt = cem.events[0]
    assert evt.host and evt.host.name == "WKS-42"
    assert evt.file and evt.file.hash_sha256 == "a" * 64
    assert evt.network and evt.network.url == "http://bad.com/p1"
    assert evt.detection and evt.detection.name == "W32.Trojan.Emotet"
    assert evt.detection.severity == SeverityLevel.high
    assert len(cem.incidents) == 1


def test_sysmon_process_create_from_json():
    payload = json.dumps({
        "EventID": 1, "Computer": "host-a",
        "User": "CORP\\alice",
        "Image": "C:/Windows/System32/cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImage": "C:/explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "ProcessId": 1234, "ParentProcessId": 100,
        "Hashes": "SHA256=" + "d" * 64,
    })
    cem = _cem(payload)
    assert cem.vendor_route == "sysmon"
    evt = cem.events[0]
    assert evt.kind == EventKind.process_create
    assert evt.process.command_line == "cmd.exe /c whoami"
    assert evt.process.hash_sha256 == "d" * 64
    assert evt.parent_process.image == "C:/explorer.exe"
    assert evt.user.name == "alice"
    assert evt.user.domain == "CORP"


def test_sysmon_dns_query():
    payload = json.dumps({
        "EventID": 22, "Computer": "h1",
        "QueryName": "malicious.example",
        "QueryType": "A",
    })
    cem = _cem(payload)
    evt = cem.events[0]
    assert evt.kind == EventKind.dns_query
    assert evt.dns and evt.dns.query == "malicious.example"


def test_sysmon_network_connect():
    payload = json.dumps({
        "EventID": 3, "Computer": "h1",
        "SourceIp": "10.0.0.1", "SourcePort": 5555,
        "DestinationIp": "1.2.3.4", "DestinationPort": 443,
        "Protocol": "tcp", "Initiated": "true",
    })
    cem = _cem(payload)
    evt = cem.events[0]
    assert evt.kind == EventKind.network_connect
    assert evt.network.dst_ip == "1.2.3.4"
    assert evt.network.direction == "outbound"


def test_generic_fallback_emits_event_from_command_field():
    payload = json.dumps({"foo": 1, "cmdLine": "certutil -urlcache -f x y"})
    cem = _cem(payload)
    assert cem.vendor_route == "generic"
    assert cem.events
    # generic normalizer surfaces command_line via _first_cmd_like
    evt = cem.events[0]
    assert evt.process and "certutil" in (evt.process.command_line or "")


def test_encoded_command_input_produces_generic_event_with_command():
    """Encoded PS should still create a Process node with the raw
    input as `command_line` — so Artifact Discovery finds it later."""
    cem = _cem("powershell -EncodedCommand SGVsbG8=")
    assert cem.events
    evt = cem.events[0]
    assert evt.process and "powershell" in evt.process.command_line.lower()
