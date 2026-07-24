"""v2/ikb/entries.py · IKB seed entries.

Three seed entries directly from the operator's Phase 5 reference links:
  · svchost.exe          — service-host binary
  · WerFault.exe         — Windows Error Reporting (in-the-wild abuse 2024-2026)
  · Windows Event 4624   — successful logon (Ultimate Windows Security reference)

These are the template — every future KB entry follows the same schema.
"""
from __future__ import annotations
from .schema import KBEntry


ENTRIES: list[KBEntry] = [

    # ─── Telemetry source · Microsoft Sysmon ─────────────────────────
    KBEntry(
        id="telemetry_source:sysmon",
        kind="telemetry_source",
        label="Microsoft Sysmon",
        category="endpoint_telemetry",
        description=("Sysinternals system-monitoring driver. The canonical "
                     "high-fidelity endpoint telemetry source for Windows. "
                     "Every Sysmon Event ID maps deterministically into the "
                     "IKG's canonical schema."),
        normal_behavior={
            "event_id_map": {
                "1":  "Process creation             → IKG event/process",
                "2":  "File create-time changed     → IKG file (timestomp signal)",
                "3":  "Network connection           → IKG network",
                "5":  "Process terminated           → IKG event",
                "6":  "Driver loaded                → IKG module",
                "7":  "Image loaded (DLL)           → IKG module",
                "8":  "CreateRemoteThread           → IKG event (injection signal)",
                "9":  "RawAccessRead                → IKG event",
                "10": "ProcessAccess                → IKG event (LSASS-access signal)",
                "11": "FileCreate                   → IKG file",
                "12": "RegistryEvent (Object)       → IKG registry",
                "13": "RegistryEvent (Value Set)    → IKG registry",
                "14": "RegistryEvent (Key/Value Rename)",
                "15": "FileCreateStreamHash         → IKG file (ADS signal)",
                "17": "PipeCreated                  → IKG event",
                "18": "PipeConnected                → IKG event",
                "19": "WmiEventFilter               → IKG event",
                "20": "WmiEventConsumer             → IKG event (persistence signal)",
                "21": "WmiEventConsumerToFilter     → IKG event (persistence signal)",
                "22": "DNSEvent                     → IKG network",
                "23": "FileDelete                   → IKG file",
                "24": "ClipboardChange              → IKG event",
                "25": "ProcessTampering             → IKG event (evasion signal)",
                "26": "FileDeleteDetected           → IKG file",
                "27": "FileBlockExecutable          → IKG event",
                "28": "FileBlockShredding           → IKG event",
                "29": "FileExecutableDetected       → IKG file",
            },
        },
        detection_guidance=[
            "Every Sysmon EventID must map into exactly ONE canonical IKG node.",
            "Preserve original Sysmon EventID in the event attrs for round-trip.",
        ],
        mitre=[],
        references=[
            "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        ],
    ),

    # ─── Windows Event · 4688 · Process Creation ─────────────────────
    KBEntry(
        id="windows_event:4688",
        kind="windows_event",
        label="Windows Security Event 4688",
        category="process_creation",
        description=("A new process has been created. When enabled with "
                     "Command Line Auditing (ProcessCreationIncludeCmdLine_Enabled "
                     "GPO) this is the canonical Windows-native equivalent to "
                     "Sysmon Event 1."),
        normal_behavior={
            "important_fields": [
                "NewProcessId", "NewProcessName", "TokenElevationType",
                "ProcessId (parent)", "ParentProcessName", "CommandLine",
                "SubjectUserSid", "TargetUserSid", "MandatoryLabel",
            ],
            "requires_gpo": ("Computer Configuration → Administrative Templates → "
                             "System → Audit Process Creation → Include command "
                             "line in process creation events = Enabled."),
        },
        detection_guidance=[
            "Correlate NewProcessId → future 4688/4634 events on the same PID.",
            "Correlate ProcessId (parent) → the spawning 4688.",
            "CommandLine is the primary attacker-visible field — inspect always.",
            "TokenElevationType 2 = elevated with UAC prompt (analyst attention).",
        ],
        common_abuse=[
            {"pattern": "TokenElevationType = TokenElevationTypeFull (2) from a low-integrity parent",
             "reason":  "UAC bypass",
             "mitre":   ["T1548.002"], "severity": "high"},
        ],
        mitre=["T1059"],
        references=[
            "https://lantern.splunk.com/Security_Use_Cases/Threat_Hunting/"
            "Enabling_Windows_event_log_process_command_line_logging_via_group_policy_object",
        ],
    ),

    # ─── LOLBAS project — Living Off The Land Binary corpus ─────────
    KBEntry(
        id="lolbas:corpus",
        kind="mitre_technique",
        label="LOLBAS Project · Living Off The Land Binaries",
        category="signed_binary_abuse",
        description=("The LOLBAS project catalogues signed Microsoft binaries "
                     "that attackers abuse for execution, download, exfil, "
                     "credential access, and defense evasion. NivXRay uses it "
                     "as an *enrichment* source — a signed binary is not "
                     "inherently malicious, only when execution CONTEXT is off."),
        normal_behavior={
            "principle": ("Judge context, not the binary. Same rundll32 that "
                          "loads windows shell extensions can also load a "
                          "malicious DLL from C:\\Users\\Public — context is "
                          "everything."),
            "high_risk_binaries": [
                "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
                "mshta.exe", "msiexec.exe", "wmic.exe", "installutil.exe",
                "regasm.exe", "msbuild.exe", "csc.exe", "hh.exe",
                "cmstp.exe", "atbroker.exe", "presentationhost.exe",
                "mavinject.exe", "werfault.exe",
            ],
            "abuse_functions": [
                "Execute", "Download", "AWL Bypass", "Credentials",
                "Defense Evasion", "Persistence", "Recon", "Compress",
            ],
        },
        common_abuse=[
            {"pattern": "LOLBin spawned by an Office / browser / explorer parent",
             "reason":  "not a legitimate spawn context for these binaries",
             "mitre":   ["T1218"], "severity": "high"},
            {"pattern": "LOLBin loading a DLL from user-writable path",
             "reason":  "DLL side-loading pattern",
             "mitre":   ["T1574.002"], "severity": "critical"},
            {"pattern": "LOLBin invoking a remote URL / scriptlet",
             "reason":  "download-and-execute cradle",
             "mitre":   ["T1105"], "severity": "critical"},
        ],
        detection_guidance=[
            "Never block on binary name alone.",
            "Always inspect parent process, command-line arguments, and loaded "
            "DLLs — the LOLBAS entries document each binary's abuse function.",
        ],
        mitre=["T1218", "T1574", "T1105"],
        references=["https://lolbas-project.github.io/"],
    ),

    # ─── Decoder · XOR cipher ────────────────────────────────────────
    KBEntry(
        id="decoder:xor",
        kind="decoder",
        label="XOR Cipher",
        category="obfuscation_decoder",
        description=("Symmetric bitwise XOR with a repeating key. The most "
                     "common obfuscation applied to shellcode, config blobs, "
                     "and command-line payloads. NivXRay's decoder attempts "
                     "single-byte and short-key XOR when a payload has high "
                     "entropy and lacks readable ASCII."),
        normal_behavior={
            "properties": [
                "self-inverse: (A ^ K) ^ K = A",
                "key length inferred by index-of-coincidence on repeated patterns",
                "single-byte XOR has 255 candidate keys — brute force always feasible",
            ],
            "signals_worth_decoding": [
                "PowerShell -EncodedCommand blobs after base64",
                "Registry blobs with Value type Binary + high entropy",
                "Command-line arguments containing hex-string payloads",
            ],
        },
        detection_guidance=[
            "High entropy + no printable ASCII + suspicious parent = decode candidate.",
            "After decoding, re-run detection signals on the decoded content.",
        ],
        mitre=["T1027", "T1140"],
        references=["https://en.wikipedia.org/wiki/XOR_cipher"],
    ),

    # ─── Enterprise baseline · Windows Update / OneDrive / Chrome Updater
    KBEntry(
        id="enterprise_baseline:windows_update",
        kind="enterprise_baseline",
        label="Windows Update",
        category="microsoft_update_agent",
        description="Legitimate OS update pipeline. Runs constantly on any Windows endpoint.",
        normal_behavior={
            "expected_processes": ["wuauclt.exe", "usoclient.exe", "TrustedInstaller.exe",
                                   "svchost.exe -k wusvcs", "TiWorker.exe"],
            "expected_network":   ["*.windowsupdate.com", "*.update.microsoft.com",
                                   "*.delivery.mp.microsoft.com"],
            "expected_files":     ["C:\\Windows\\SoftwareDistribution\\..."],
        },
        false_positives=[
            {"context": "Monthly patch Tuesday",
             "reason":  "sudden burst of downloads, service restarts, and reboots."},
        ],
        mitre=[],
    ),

    KBEntry(
        id="enterprise_baseline:onedrive",
        kind="enterprise_baseline",
        label="Microsoft OneDrive",
        category="cloud_sync",
        description="Cloud file sync client. Constant file & network activity is normal.",
        normal_behavior={
            "expected_processes": ["OneDrive.exe", "FileCoAuth.exe"],
            "expected_paths":     ["%LocalAppData%\\Microsoft\\OneDrive\\..."],
            "expected_network":   ["*.live.com", "*.onedrive.com", "*.sharepoint.com"],
        },
        false_positives=[
            {"context": "Bulk file operations",
             "reason":  "user pasting many files triggers many file-write events."},
        ],
        mitre=[],
    ),

    KBEntry(
        id="enterprise_baseline:chrome_updater",
        kind="enterprise_baseline",
        label="Google Chrome Updater",
        category="browser_updater",
        description="Chrome's background updater. Runs as a scheduled task.",
        normal_behavior={
            "expected_processes": ["GoogleUpdate.exe", "GoogleCrashHandler.exe",
                                   "chrome.exe --type=<worker>"],
            "expected_paths":     ["C:\\Program Files (x86)\\Google\\Update\\..."],
            "expected_network":   ["*.gvt1.com", "*.google.com"],
        },
        mitre=[],
    ),
]  # ← existing 3 entries appended below by extend()


# ── Preserve the three seed entries added in the initial commit ────────
_svchost = KBEntry(
    id="windows_binary:svchost.exe",
    kind="windows_binary",
    label="svchost.exe",
    category="service_host",
    description=("Generic Windows service host process. Legitimately "
                 "hosts one or more services in a service group specified "
                 "by the -k flag. Anomalies almost always indicate abuse."),
    normal_behavior={
        "expected_parents":       ["services.exe"],
        "expected_children":      [],
        "expected_paths":         ["C:\\Windows\\System32\\svchost.exe",
                                   "C:\\Windows\\SysWOW64\\svchost.exe"],
        "expected_command_line":  [
            "svchost.exe -k <serviceGroup>",
            "svchost.exe -k <serviceGroup> -p",
            "svchost.exe -k <serviceGroup> -s <service>",
        ],
        "flag_semantics": {
            "-k": "service group name (netsvcs, LocalService, LocalServiceNetworkRestricted, …)",
            "-p": "protect the process (Windows 10+, service must be protected too)",
            "-s": "the specific service within the group",
        },
    },
    common_abuse=[
        {"pattern": "svchost.exe with parent != services.exe",
         "reason":  "attacker-launched impersonator or process hollowing target",
         "mitre":   ["T1055", "T1036.005"], "severity": "high"},
        {"pattern": "svchost.exe with no -k flag",
         "reason":  "legitimate svchost NEVER runs without -k",
         "mitre":   ["T1036.005"], "severity": "critical"},
        {"pattern": "svchost.exe not in System32 / SysWOW64",
         "reason":  "path masquerade (T1036.005 · masquerading)",
         "mitre":   ["T1036.005"], "severity": "critical"},
        {"pattern": "svchost.exe spawning cmd.exe / powershell.exe",
         "reason":  "service hosts should not spawn interactive shells",
         "mitre":   ["T1055"], "severity": "high"},
    ],
    detection_guidance=[
        "Validate parent = services.exe.",
        "Validate command line contains -k <known-group>.",
        "Validate binary path is exactly System32\\svchost.exe.",
        "Flag any svchost with unexpected child processes.",
    ],
    false_positives=[
        {"context": "Windows Update servicing",
         "reason":  "wuauserv briefly spawns short-lived child procs during update."},
    ],
    mitre=["T1055", "T1036.005"],
    correlation_rules=[
        {"if": "parent != services.exe", "boost_family": "evasion"},
        {"if": "cmdline lacks -k",       "boost_family": "evasion"},
        {"if": "spawns SHELL_LIKE",      "boost_family": "execution"},
    ],
    references=[
        "https://superuser.com/questions/391864/what-command-line-options-are-available-to-svchost-exe",
        "https://nasbench.medium.com/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747",
        "https://pusha.be/index.php/2020/05/07/exploration-of-svchost-exe-p-flag/",
    ],
)

_werfault = KBEntry(
    id="windows_binary:werfault.exe",
    kind="windows_binary",
    label="WerFault.exe",
    category="error_reporting",
    description=("Windows Error Reporting host. Legitimately spawned by "
                 "svchost's WerSvc when a program crashes. In-the-wild "
                 "campaigns (2024-2026) abuse it via DLL side-loading of "
                 "faultrep.dll delivered from an ISO or LNK loader."),
    normal_behavior={
        "expected_parents":       ["svchost.exe (WerSvc)"],
        "expected_paths":         ["C:\\Windows\\System32\\WerFault.exe",
                                   "C:\\Windows\\SysWOW64\\WerFault.exe"],
        "expected_command_line":  [
            "WerFault.exe -pss -s <session>",
            "WerFault.exe -u -p <pid>",
        ],
    },
    common_abuse=[
        {"pattern": "WerFault.exe spawned from Office / browser / explorer",
         "reason":  "legitimate WerFault is spawned by WerSvc svchost only",
         "mitre":   ["T1218"], "severity": "high"},
        {"pattern": "WerFault.exe launched from an ISO/IMG/LNK mount",
         "reason":  "DLL side-loading pattern used to load a rogue faultrep.dll",
         "mitre":   ["T1574.002"], "severity": "critical"},
        {"pattern": "WerFault.exe loading faultrep.dll from a non-system path",
         "reason":  "side-loaded malicious DLL",
         "mitre":   ["T1574.002"], "severity": "critical"},
    ],
    detection_guidance=[
        "Validate parent = svchost.exe (WerSvc).",
        "Validate path is System32 / SysWOW64.",
        "Flag WerFault spawned from user-writable / removable-media paths.",
        "Correlate with recent ISO/IMG/LNK mount events.",
    ],
    mitre=["T1218", "T1574.002"],
    correlation_rules=[
        {"if": "parent NOT svchost.exe", "boost_family": "evasion"},
        {"if": "path not in system32",   "boost_family": "evasion"},
    ],
    references=[
        "https://www.bleepingcomputer.com/news/security/hackers-abuse-windows-error-reporting-tool-to-deploy-malware/",
    ],
)

_evt4624 = KBEntry(
    id="windows_event:4624",
    kind="windows_event",
    label="Windows Security Event 4624",
    category="authentication",
    description=("An account was successfully logged on. Rich structured "
                 "event carrying Logon Type, source IP, elevated-token "
                 "status, authentication package and Logon ID for "
                 "downstream correlation."),
    normal_behavior={
        "logon_types": {
            "2":  "Interactive (at console)",
            "3":  "Network (SMB, Kerberos, NTLM over network)",
            "4":  "Batch (scheduled task)",
            "5":  "Service (service startup)",
            "7":  "Unlock",
            "8":  "NetworkCleartext (BAD — cleartext creds)",
            "9":  "NewCredentials (RunAs /netonly)",
            "10": "RemoteInteractive (RDP)",
            "11": "CachedInteractive (cached logon)",
        },
        "important_fields": [
            "SubjectUserSid", "TargetUserName", "LogonType",
            "AuthenticationPackageName", "IpAddress", "ElevatedToken",
            "LogonId", "ProcessId",
        ],
    },
    common_abuse=[
        {"pattern": "LogonType 3 (network) from external IP",
         "reason":  "possible lateral movement or brute force",
         "mitre":   ["T1021"], "severity": "high"},
        {"pattern": "LogonType 10 (RDP) from external IP",
         "reason":  "external RDP is a classic exploitation vector",
         "mitre":   ["T1021.001"], "severity": "high"},
        {"pattern": "LogonType 9 (NewCredentials) — runas /netonly",
         "reason":  "credential theft / passing-the-hash",
         "mitre":   ["T1078"], "severity": "high"},
        {"pattern": "AuthenticationPackage = NTLM on internal service accounts",
         "reason":  "should be Kerberos; downgrade signals possible attack",
         "mitre":   ["T1187"], "severity": "medium"},
        {"pattern": "ElevatedToken=Yes for unusual user",
         "reason":  "privilege escalation",
         "mitre":   ["T1078"], "severity": "high"},
    ],
    detection_guidance=[
        "Correlate LogonId with Process Creation (4688) — links logon to child processes.",
        "For LogonType 3/10, always check IpAddress against internal/known ranges.",
        "Flag NetworkCleartext (LogonType 8) as always suspicious.",
    ],
    mitre=["T1021", "T1078", "T1187"],
    references=[
        "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624",
    ],
)

ENTRIES.extend([_svchost, _werfault, _evt4624])


_INDEX = {e.id: e for e in ENTRIES}


def lookup(entry_id: str) -> KBEntry | None:
    return _INDEX.get(entry_id)


def all_entries() -> list[KBEntry]:
    return list(ENTRIES)
