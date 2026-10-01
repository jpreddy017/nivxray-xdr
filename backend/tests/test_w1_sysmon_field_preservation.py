"""W1 (host-independent half) · Sysmon field preservation.

REPLAY/SYNTHETIC PROVEN — these tests drive the real parser and normalizer
with records in Sysmon's documented shape. They prove canonicalization,
provenance, binding and the negative controls. They do **not** and cannot
prove real-source availability: W1's genuine-host acceptance stays
REAL_SOURCE_BLOCKED.

The invariant this suite exists for: `OriginalFileName` is PE metadata and
`process.name` is the on-disk basename. Collapsing them let a renamed-binary
rule judge the very value an attacker controls.
"""
from __future__ import annotations

import pytest

from detection_content.rule_store_binding import (_FIELD_MAP, _Binding,
                                                  flatten_with_paths)
from detection_content.telemetry.sysmon_dsm import SysmonDSM, _sysmon_hashes

SHA256 = "c" * 64
MD5 = "b" * 32
DSM = SysmonDSM()


def canonical(ev, tenant="default"):
    parsed = DSM.select_parser().parse(ev)
    return DSM.select_normalizer().normalize(
        parsed, "microsoft-sysmon", "col-w1", "int-w1", "tr-w1",
        tenant_id=tenant)


def eid1(**over):
    ev = {"event_id": 1, "provider": "Microsoft-Windows-Sysmon",
          "Computer": "WS-W1", "User": "CORP\\alice",
          "Image": "C:\\Users\\Public\\svchost.exe",
          "OriginalFileName": "PowerShell.EXE",
          "ProcessId": "4711", "ProcessGuid": "{w1-child}",
          "CommandLine": "svchost.exe -enc SQBFAFgA",
          "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
          "ParentCommandLine": "WINWORD.EXE /n invoice.docm",
          "ParentProcessId": "500", "ParentProcessGuid": "{w1-parent}",
          "Hashes": f"MD5={MD5},SHA256={SHA256}",
          "UtcTime": "2026-06-01T10:00:00Z"}
    ev.update(over)
    return ev


# ── the fields the DSM used to discard ──────────────────────────────

def test_sysmon_hashes_reach_canonical_process_hash_evidence():
    c = canonical(eid1())
    assert c["process"]["hashes"]["sha256"] == SHA256
    assert c["process"]["hashes"]["md5"] == MD5
    prov = c["process"]["field_provenance"]
    assert prov["hashes.sha256"].startswith("sysmon:EventData.Hashes(SHA256)")
    assert "image that was executed" in prov["hashes.sha256"]


def test_parent_image_and_parent_command_line_are_preserved():
    c = canonical(eid1())
    p = c["process"]
    assert p["parent_executable_path"].endswith("WINWORD.EXE")
    assert p["parent_command_line"] == "WINWORD.EXE /n invoice.docm"
    assert p["parent_name"] == "WINWORD.EXE"          # unchanged basename
    assert p["field_provenance"]["parent_executable_path"] \
        == "sysmon:EventData.ParentImage"
    assert p["field_provenance"]["parent_command_line"] \
        == "sysmon:EventData.ParentCommandLine"


def test_file_create_produces_canonical_file_evidence():
    c = canonical({"event_id": 11, "provider": "Microsoft-Windows-Sysmon",
                   "Computer": "WS-W1",
                   "TargetFilename": "C:\\Users\\Public\\payload.exe",
                   "Image": "C:\\Windows\\System32\\certutil.exe",
                   "ProcessGuid": "{w1-child}",
                   "UtcTime": "2026-06-01T10:00:01Z"})
    assert c["event_type"] == "file_create"
    assert c["file"]["path"] == "C:\\Users\\Public\\payload.exe"
    assert c["file"]["name"] == "payload.exe"
    assert c["file"]["field_provenance"]["path"] \
        == "sysmon:EventData.TargetFilename"
    # no hash was observed on this record, so none is invented
    assert c["file"]["hashes"] == {}


def test_a_process_event_never_becomes_file_evidence():
    assert canonical(eid1())["file"]["path"] == ""


# ── the OriginalFileName invariant ──────────────────────────────────

def test_original_file_name_is_its_own_field_and_not_the_on_disk_name():
    c = canonical(eid1())
    assert c["process"]["original_file_name"] == "PowerShell.EXE"
    assert c["process"]["name"] == "svchost.exe"      # the renamed binary
    assert c["process"]["original_file_name"] != c["process"]["name"]
    assert c["process"]["field_provenance"]["original_file_name"] \
        == "sysmon:EventData.OriginalFileName"


def test_the_sigma_namespace_no_longer_conflates_the_two():
    assert _FIELD_MAP["OriginalFileName"] == (("process",
                                               "original_file_name"),)
    flat, paths = flatten_with_paths(canonical(eid1()))
    assert flat["OriginalFileName"] == "PowerShell.EXE"
    assert paths["OriginalFileName"] == "process.original_file_name"
    # …and an unobserved OriginalFileName is ABSENT, not the image basename.
    flat2 = flatten_with_paths(canonical(eid1(OriginalFileName="")))[0]
    assert "OriginalFileName" not in flat2
    assert flat2["Image"].endswith("svchost.exe")


def test_a_renamed_binary_rule_reads_metadata_not_the_attacker_name():
    rule = _Binding({
        "id": "det_w1_rename", "upstream_id": "w1_renamed_powershell",
        "title": "Renamed PowerShell", "license_policy_state": "PERMITTED",
        "state": "VALIDATED", "enabled": "True", "level": "high",
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {"selection": {"OriginalFileName": "PowerShell.EXE"},
                      "condition": "selection"}})
    assert rule.state == "BOUND"
    from detection_content.nivxray_native_sigma import evaluate as nx
    assert nx(rule.parsed, flatten_with_paths(canonical(eid1()))[0])
    # Under the old conflation this would have compared against
    # basename(Image) = "svchost.exe" and silently missed.
    absent = flatten_with_paths(canonical(eid1(OriginalFileName="")))[0]
    assert not nx(rule.parsed, absent)


# ── hash honesty ────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expect_ok,expect_rejected", [
    (f"SHA256={SHA256}", {"sha256"}, set()),
    (f"SHA1=aaaa,SHA256={SHA256}", {"sha256"}, {"sha1"}),
    (f"SHA256={'z' * 64}", set(), {"sha256"}),
    ("SHA256=", set(), {"sha256"}),
    ("", set(), set()),
    (None, set(), set()),
    (SHA256, {"sha256"}, set()),
])
def test_a_malformed_digest_is_refused_never_stored(raw, expect_ok,
                                                    expect_rejected):
    split = _sysmon_hashes(raw)
    assert set(split["hashes"]) == expect_ok
    assert set(split["rejected"]) == expect_rejected


def test_a_refused_hash_is_reported_and_absent_from_evidence():
    c = canonical(eid1(Hashes="SHA256=nothex"))
    assert c["process"]["hashes"] == {}
    assert "REFUSED" in c["process"]["field_provenance"]["hashes_rejected"]
    assert "sha256" not in flatten_with_paths(c)[0]


def test_a_sysmon_hash_can_be_consumed_by_the_ioc_hash_predicate():
    from detection_content import ioc_watchlist as iw
    preds, reason = iw.bind_predicates(
        {"selection": {"hash.sha256|watchlist": "ioc.file.sha256"},
         "condition": "selection"})
    assert preds and "ANY_OF" in reason
    from deps import sync_collection
    col = sync_collection(iw.WATCHLIST_COLLECTION)
    src = "w1-test-source"
    col.insert_one({"kind": "sha256", "value": SHA256, "source": src,
                    "severity": "high"})
    try:
        c = canonical(eid1())
        cit = iw.evaluate(preds, c,
                          f"xdr_canonical_evidence/{c['event_id']}")
        assert cit and cit["matched_conditions"]
        m = cit["matched_conditions"][0]
        assert m["canonical_field"] == "process.hashes.sha256"
        assert m["observed_value"] == SHA256
        # missing hash → no match; wrong hash → no match
        assert iw.evaluate(preds, canonical(eid1(Hashes="")), None) is None
        assert iw.evaluate(preds, canonical(eid1(Hashes=f"SHA256={'a' * 64}")),
                           None) is None
    finally:
        col.delete_many({"kind": "sha256", "value": SHA256, "source": src})


# ── nothing about the identity model moved ──────────────────────────

def test_process_identity_semantics_are_unchanged():
    c = canonical(eid1())
    assert c["process"]["process_guid"] == "{w1-child}"
    assert c["process"]["parent_process_guid"] == "{w1-parent}"
    assert c["process"]["attribution_state"] == "SOURCE_PROCESS_IDENTITY"
    pid_only = canonical(eid1(ProcessGuid="", ParentProcessGuid=""))
    assert pid_only["process"]["attribution_state"] \
        == "PID_ONLY_NOT_AUTHORITATIVE"
    assert "PID is reused" in pid_only["process"]["attribution_reason"]


def test_windows_execution_content_is_still_product_gated():
    # W1's host-independent half must NOT make Windows content live.
    from detection_content import rule_store_binding as rsb
    assert rsb._COLLECTED_PRODUCTS == {"linux"}
    b = _Binding({"id": "det_w1_exec", "upstream_id": "w1_exec",
                  "title": "Encoded PowerShell",
                  "license_policy_state": "PERMITTED", "state": "VALIDATED",
                  "enabled": "True", "level": "high",
                  "logsource": {"category": "process_creation",
                                "product": "windows"},
                  "detection": {"selection": {"CommandLine|contains": "-enc",
                                              "Image|endswith": ".exe"},
                                "condition": "selection"}})
    assert b.state == "NO_TELEMETRY"
    assert "no windows endpoint telemetry is collected" in b.reason
