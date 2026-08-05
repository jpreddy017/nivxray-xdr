"""
DKP · Seed patterns
───────────────────
Curated, high-signal seed set.  Every entry is hand-reviewed against
real intrusion reports; grow via a JSON overlay or by direct edit.
"""
from .models import Pattern, Signature as S

SEED_PATTERNS = [

    # ── T1490 · Inhibit System Recovery ──────────────────────────
    Pattern(
        id="dkp.shadow_copy_removal",
        name="Shadow Copy Removal",
        intent="Destroy recovery snapshots — precursor to ransomware",
        signatures=[
            S(kind="regex", pattern=r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows", weight=2),
            S(kind="regex", pattern=r"(?i)wbadmin\s+delete\s+catalog", weight=1.5),
            S(kind="regex", pattern=r"(?i)bcdedit\s+/set\s+.*recoveryenabled\s+no", weight=1.5),
            S(kind="regex", pattern=r"(?i)win32_shadowcopy.*\.delete\(\)", weight=2),
            S(kind="mitre",  id="T1490", weight=1),
        ],
        mitre=["T1490"],
        enterprise_uses=[],
        malware_uses=["Ryuk","LockBit","Conti","Akira","BlackCat","REvil","BlackBasta"],
        families=["Ryuk","LockBit","Conti","Akira","BlackCat","REvil"],
        typical_parent="powershell.exe",
        typical_child=None,
        common_followon="Ransomware encryption",
        confidence=98,
        narrative_template=(
            "The command deletes Volume Shadow Copies "
            "({evidence}), preventing restoration from local "
            "snapshots. This behavior commonly occurs immediately "
            "before ransomware encryption and maps to MITRE ATT&CK "
            "technique T1490 (Inhibit System Recovery)."
        ),
        investigation=[
            "Check for concurrent file-encryption or ransom-note drops in the same session.",
            "Correlate parent process — legitimate backup tools rarely delete all shadows.",
            "Hunt across the environment for identical vssadmin invocations in the last 24h.",
        ],
        detection_logic="process.name in ('vssadmin.exe','wbadmin.exe','bcdedit.exe') AND process.args : 'delete'",
    ),

    # ── T1105 · Ingress Tool Transfer (PS download-cradle) ───────
    Pattern(
        id="dkp.ps_download_cradle",
        name="PowerShell Download & Execute",
        intent="Payload retrieval and staged execution",
        signatures=[
            S(kind="flag", flag="download_cradle", weight=1.5),
            S(kind="regex", pattern=r"(?i)new-object\s+net\.webclient", weight=1),
            S(kind="regex", pattern=r"(?i)(invoke-webrequest|iwr|invoke-restmethod|irm)\b", weight=1),
            S(kind="regex", pattern=r"(?i)start-bitstransfer", weight=1),
            S(kind="flag", flag="iex_invocation", weight=1),
            S(kind="mitre", id="T1105", weight=0.5),
        ],
        mitre=["T1105","T1059.001"],
        enterprise_uses=["Intune","SCCM","Chocolatey","winget","MDT"],
        malware_uses=["Emotet","Qakbot","IcedID","Bumblebee","Cobalt Strike","AsyncRAT"],
        families=["Emotet","Qakbot","IcedID","Cobalt Strike"],
        typical_parent="powershell.exe",
        typical_child="rundll32.exe",
        common_followon="Reflective code loading / persistence install",
        confidence=88,
        narrative_template=(
            "The PowerShell payload downloads a remote resource "
            "({evidence}) and invokes it in-memory using IEX, a "
            "classic download-cradle pattern used by first-stage "
            "loaders. This maps to T1105 (Ingress Tool Transfer) "
            "and T1059.001 (PowerShell) and is functionally "
            "indistinguishable from the initial-access technique "
            "used by Emotet, IcedID, and Qakbot."
        ),
        investigation=[
            "Fetch the remote URL in an isolated sandbox for stage-2 analysis.",
            "Check TLS certificate, ASN, and passive DNS for the C2 domain.",
            "Correlate with recent Office child-process spawns.",
        ],
    ),

    # ── T1027 · Obfuscated Files or Information (encoded PS) ────
    Pattern(
        id="dkp.ps_encoded_command",
        name="PowerShell EncodedCommand",
        intent="Defense Evasion via encoded/obfuscated content",
        signatures=[
            S(kind="flag", flag="encoded_command", weight=2),
            S(kind="regex", pattern=r"(?i)-e(?:nc(?:od(?:ed(?:command)?)?)?)?\s+[A-Za-z0-9+/=]{20,}", weight=1),
            S(kind="regex", pattern=r"(?i)\[convert\]::frombase64string", weight=1.5),
        ],
        mitre=["T1027","T1059.001"],
        enterprise_uses=["automation scripts","packaged tooling"],
        malware_uses=["nearly universal in PS-borne malware"],
        families=["Emotet","Qakbot","IcedID","APT29","APT41"],
        typical_parent="cmd.exe",
        typical_child="powershell.exe",
        common_followon="Download cradle / reflective loader",
        confidence=90,
        narrative_template=(
            "The command uses PowerShell's -EncodedCommand or "
            "[Convert]::FromBase64String to conceal its payload "
            "({evidence}). Encoding is a strong defense-evasion "
            "signal (T1027) — the decoded content should be "
            "inspected for follow-on techniques."
        ),
        investigation=[
            "Decode the base64 blob (utf-16-le default) and re-analyze recursively.",
            "Look for staged download cradles or reflective loaders in the decoded content.",
        ],
    ),

    # ── T1562.001 · AMSI Bypass ──────────────────────────────────
    Pattern(
        id="dkp.amsi_bypass",
        name="AMSI Bypass",
        intent="Disable or evade the AMSI scanner",
        signatures=[
            S(kind="flag", flag="amsi_bypass", weight=2),
            S(kind="regex", pattern=r"(?i)amsi(?:_)?scanbuffer|amsi(?:_)?initfailed|amsiutils", weight=1.5),
        ],
        mitre=["T1562.001","T1059.001"],
        enterprise_uses=[],
        malware_uses=["Cobalt Strike","Metasploit","Empire","Sliver","Nighthawk"],
        families=["Cobalt Strike","Empire","Sliver"],
        typical_parent="powershell.exe",
        typical_child=None,
        common_followon="Reflective code loading",
        confidence=95,
        narrative_template=(
            "The payload references AMSI internals ({evidence}), "
            "consistent with a bypass attempt against the Antimalware "
            "Scan Interface — a defense-evasion move seen in nearly "
            "every offensive-security framework."
        ),
        investigation=[
            "Check the loaded modules — reflective assembly loads typically follow.",
            "Hunt for `amsiInitFailed` or `AmsiScanBuffer` string references in child processes.",
        ],
    ),

    # ── T1620 · Reflective Code Loading ──────────────────────────
    Pattern(
        id="dkp.reflective_loader",
        name="Reflective Code Loading",
        intent="Execute code in-memory without touching disk",
        signatures=[
            S(kind="flag", flag="reflection_load", weight=2),
            S(kind="regex", pattern=r"(?i)system\.reflection\.assembly", weight=1),
            S(kind="regex", pattern=r"(?i)virtualalloc|virtualprotect", weight=1),
            S(kind="regex", pattern=r"(?i)kernel32\.dll|user32\.dll", weight=0.5),
        ],
        mitre=["T1620","T1059.001"],
        enterprise_uses=[],
        malware_uses=["Cobalt Strike","Metasploit","Empire","Nighthawk","Sliver"],
        families=["Cobalt Strike","Empire","Nighthawk"],
        typical_parent="powershell.exe",
        common_followon="C2 beacon",
        confidence=92,
        narrative_template=(
            "The payload prepares reflective code loading "
            "({evidence}). Analysts should expect a fileless "
            "beacon or loader running under the current PowerShell "
            "process — no artifacts will land on disk."
        ),
    ),

    # ── T1053.005 · Scheduled Task Persistence ───────────────────
    Pattern(
        id="dkp.schtasks_persistence",
        name="Scheduled Task Persistence",
        intent="Establish persistence via a scheduled task",
        signatures=[
            S(kind="regex", pattern=r"(?i)schtasks(?:\.exe)?\s+/create\b", weight=2),
            S(kind="regex", pattern=r"(?i)register-scheduledtask", weight=1.5),
        ],
        mitre=["T1053.005"],
        enterprise_uses=["Windows Update maintenance","backup schedulers","GPO tasks"],
        malware_uses=["Qakbot","BumbleBee","AsyncRAT","IcedID"],
        families=["Qakbot","IcedID","AsyncRAT"],
        typical_parent="cmd.exe / powershell.exe",
        common_followon="Delayed second-stage execution",
        confidence=80,
        narrative_template=(
            "The command registers a scheduled task ({evidence}) — "
            "a common persistence primitive (T1053.005). Trigger "
            "frequency and the referenced binary should be inspected "
            "for suspicious behavior."
        ),
        investigation=[
            "Enumerate tasks created in the last 24h.",
            "Follow the referenced binary through Artifact Router.",
        ],
    ),

    # ── T1218.010 · Regsvr32 Squiblydoo ──────────────────────────
    Pattern(
        id="dkp.regsvr32_squiblydoo",
        name="Regsvr32 Squiblydoo",
        intent="Signed-binary proxy execution",
        signatures=[
            S(kind="regex", pattern=r"(?i)regsvr32(?:\.exe)?\s+.*(?:/s\s+)?/i:https?://", weight=2),
            S(kind="regex", pattern=r"(?i)regsvr32(?:\.exe)?\s+.*scrobj\.dll", weight=1.5),
        ],
        mitre=["T1218.010"],
        enterprise_uses=[],
        malware_uses=["Cobalt Strike","APT34","IcedID"],
        families=["Cobalt Strike","IcedID"],
        typical_parent="cmd.exe",
        common_followon="Remote scriptlet execution",
        confidence=93,
        narrative_template=(
            "Regsvr32 is invoked with a remote scriptlet URL "
            "({evidence}) — the Squiblydoo application-control "
            "bypass (T1218.010). Analysts should treat this as "
            "confirmed malicious in almost every enterprise context."
        ),
    ),

    # ── T1218.005 · Mshta remote HTA ─────────────────────────────
    Pattern(
        id="dkp.mshta_remote",
        name="Mshta Remote HTA Execution",
        intent="Signed-binary proxy execution via mshta",
        signatures=[
            S(kind="regex", pattern=r"(?i)mshta(?:\.exe)?\s+https?://", weight=2),
            S(kind="regex", pattern=r"(?i)mshta(?:\.exe)?\s+.*javascript:", weight=1.5),
        ],
        mitre=["T1218.005"],
        malware_uses=["Lazarus","APT32","Kimsuky","Ursnif"],
        families=["Ursnif","Lazarus"],
        confidence=93,
        narrative_template=(
            "Mshta is invoked against a remote HTA or inline "
            "JavaScript payload ({evidence}) — a signed-binary "
            "proxy technique (T1218.005) frequently seen in "
            "spear-phishing loaders."
        ),
    ),

    # ── T1059.007 · JS ActiveX RCE ───────────────────────────────
    Pattern(
        id="dkp.js_activex_rce",
        name="JavaScript ActiveX Shell Execution",
        intent="Windows Script Host abuse via ActiveX",
        signatures=[
            S(kind="flag", flag="activex_abuse", weight=2),
            S(kind="flag", flag="shell_exec", weight=1),
            S(kind="regex", pattern=r"(?i)new\s+activexobject\(\s*['\"]wscript\.shell", weight=1.5),
        ],
        mitre=["T1059.007","T1218.005"],
        malware_uses=["Ursnif","IcedID","QakBot"],
        families=["Ursnif","IcedID"],
        typical_parent="wscript.exe / mshta.exe",
        typical_child="powershell.exe / cmd.exe",
        confidence=88,
        narrative_template=(
            "The JavaScript instantiates WScript.Shell and calls "
            "Run/Exec ({evidence}) — the classic ActiveX-based RCE "
            "used by phishing loaders (T1059.007)."
        ),
    ),

    # ── T1059.005 · VBScript CreateObject Shell.Run ──────────────
    Pattern(
        id="dkp.vbs_shell_run",
        name="VBScript Shell Execution",
        intent="Command execution via WScript.Shell.Run",
        signatures=[
            S(kind="flag", flag="shell_execute", weight=2),
            S(kind="regex", pattern=r"(?i)createobject\s*\(\s*['\"]wscript\.shell", weight=1.5),
        ],
        mitre=["T1059.005"],
        malware_uses=["Emotet phishing lures","Ursnif","QakBot"],
        families=["Emotet","Ursnif"],
        typical_parent="wscript.exe",
        typical_child="powershell.exe",
        confidence=85,
        narrative_template=(
            "The VBScript instantiates WScript.Shell and invokes "
            "Run ({evidence}) — a phishing-borne execution pattern "
            "mapped to T1059.005."
        ),
    ),

    # ── T1059.004 · Bash reverse shell ───────────────────────────
    Pattern(
        id="dkp.bash_reverse_shell",
        name="Bash Reverse Shell",
        intent="Interactive command-and-control over TCP",
        signatures=[
            S(kind="flag", flag="reverse_shell", weight=2),
            S(kind="regex", pattern=r"(?i)/dev/tcp/[0-9.]+/\d+", weight=1.5),
        ],
        mitre=["T1059.004","T1071.001"],
        malware_uses=["Kinsing","XORDDoS","LockBit-Linux"],
        families=["Kinsing","LockBit-Linux"],
        confidence=93,
        narrative_template=(
            "The bash payload opens a raw TCP reverse shell "
            "({evidence}) — a classic Linux post-exploitation "
            "primitive (T1059.004)."
        ),
    ),

    # ── T1053.003 · Cron persistence ─────────────────────────────
    Pattern(
        id="dkp.cron_persistence",
        name="Cron Persistence",
        intent="Establish scheduled persistence on Linux",
        signatures=[
            S(kind="regex", pattern=r"(?i)\bcrontab\b|/etc/cron\.(?:d|hourly|daily)/", weight=1.5),
            S(kind="flag", flag="persistence", weight=1),
        ],
        mitre=["T1053.003"],
        malware_uses=["Kinsing","TeamTNT","XMRig-loader"],
        families=["Kinsing","TeamTNT"],
        confidence=80,
        narrative_template=(
            "The payload writes a cron entry ({evidence}) — Linux "
            "persistence via T1053.003."
        ),
    ),

    # ── T1105 · curl-pipe-shell (Bash) ───────────────────────────
    Pattern(
        id="dkp.curl_pipe_shell",
        name="Curl-to-Shell Dropper",
        intent="Fetch and execute payload in a single line",
        signatures=[
            S(kind="flag", flag="pipe_to_shell", weight=2),
            S(kind="regex", pattern=r"(?i)(?:curl|wget)[^|;\n]+\|\s*(?:bash|sh)\b", weight=1.5),
        ],
        mitre=["T1105","T1059.004"],
        enterprise_uses=["package installers (Homebrew, rustup, oh-my-zsh)"],
        malware_uses=["Kinsing","TeamTNT","XMRig-loader"],
        families=["Kinsing","TeamTNT"],
        confidence=82,
        narrative_template=(
            "The command pipes a remote script directly into a shell "
            "interpreter ({evidence}) — instantly retrieves and "
            "executes payload (T1105 + T1059.004). "
            "Enterprise installers use the same pattern; correlate "
            "with the fetched host to disambiguate."
        ),
    ),

    # ── T1059.006 · Python subprocess dropper ────────────────────
    Pattern(
        id="dkp.python_exec_encoded",
        name="Python Encoded exec()",
        intent="In-memory execution of decoded payload",
        signatures=[
            S(kind="flag", flag="dynamic_exec", weight=2),
            S(kind="flag", flag="encoded_payload", weight=1.5),
            S(kind="regex", pattern=r"(?i)exec\s*\(\s*base64\.b64decode", weight=2),
        ],
        mitre=["T1027","T1059.006"],
        malware_uses=["Empire-Python","Chisel-py loader","cross-platform droppers"],
        families=["Empire-Python"],
        confidence=87,
        narrative_template=(
            "The Python payload decodes and executes a base64 blob "
            "in-memory ({evidence}) — obfuscation (T1027) plus "
            "Python interpreter abuse (T1059.006)."
        ),
    ),
]
