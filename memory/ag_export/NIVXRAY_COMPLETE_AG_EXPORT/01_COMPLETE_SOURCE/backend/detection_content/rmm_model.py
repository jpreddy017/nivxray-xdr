"""
NivXRay XDR — Remote Monitoring & Management (RMM) Trusted Capability Abuse Model.
Provides multi-dimensional contextual discrimination for 14 commercial and open-source RMM tools.

Rejects binary signatures (e.g. AnyDesk != Automatic Attack).
Evaluates 12 contextual dimensions:
    capability + identity + authorization + source + destination +
    time + business context + behavior + sequence + privilege +
    reachability + resulting state

Directly integrates with NivXRay Security State and CapabilityAbuseState.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

try:
    from security_state.detection_bridge import CapabilityAbuseState, ContextualAssessment
except (ImportError, ValueError):
    from ..security_state.detection_bridge import CapabilityAbuseState, ContextualAssessment


@dataclass
class RMMProductProfile:
    name: str
    vendor: str
    primary_executables: List[str]
    default_services: List[str]
    default_install_paths: List[str]
    network_endpoints: List[str]
    suspicious_cli_flags: List[str]
    category: str = "RMM"


# Canonical 14-Tool Enterprise RMM Catalogue
RMM_CATALOGUE: Dict[str, RMMProductProfile] = {
    "anydesk": RMMProductProfile(
        name="AnyDesk",
        vendor="AnyDesk Software GmbH",
        primary_executables=["anydesk.exe"],
        default_services=["AnyDesk Service", "anydesk"],
        default_install_paths=[r"C:\Program Files (x86)\AnyDesk", r"C:\Program Files\AnyDesk"],
        network_endpoints=["*.net.anydesk.com", "7070", "6568"],
        suspicious_cli_flags=["--install", "--start-with-win", "--silent", "--set-password"],
    ),
    "screenconnect": RMMProductProfile(
        name="ConnectWise ScreenConnect",
        vendor="ConnectWise",
        primary_executables=["screenconnect.clientservice.exe", "screenconnect.windowsclient.exe"],
        default_services=["ScreenConnect Client"],
        default_install_paths=[r"C:\Program Files (x86)\ScreenConnect Client"],
        network_endpoints=["*.screenconnect.com", "8041", "8040"],
        suspicious_cli_flags=["?e=Access", "?y=Guest", "/install"],
    ),
    "atera": RMMProductProfile(
        name="Atera",
        vendor="Atera Networks",
        primary_executables=["ateraagent.exe", "agentpackagemonitoring.exe"],
        default_services=["AteraAgent"],
        default_install_paths=[r"C:\Program Files\Atera Networks\AteraAgent"],
        network_endpoints=["*.atera.com", "app.atera.com"],
        suspicious_cli_flags=["/quiet", "/qn", "IntegratorKey"],
    ),
    "splashtop": RMMProductProfile(
        name="Splashtop",
        vendor="Splashtop Inc.",
        primary_executables=["srserver.exe", "srservice.exe", "splashtopstreamer.exe"],
        default_services=["SplashtopRemoteService"],
        default_install_paths=[r"C:\Program Files (x86)\Splashtop\Splashtop Remote"],
        network_endpoints=["*.api.splashtop.com", "6783"],
        suspicious_cli_flags=["preconfigured", "inject_streamer", "deploy_code"],
    ),
    "teamviewer": RMMProductProfile(
        name="TeamViewer",
        vendor="TeamViewer AG",
        primary_executables=["teamviewer.exe", "teamviewer_service.exe"],
        default_services=["TeamViewer"],
        default_install_paths=[r"C:\Program Files\TeamViewer", r"C:\Program Files (x86)\TeamViewer"],
        network_endpoints=["*.teamviewer.com", "5938"],
        suspicious_cli_flags=["--ImportSettings", "/S", "--Password"],
    ),
    "ninjaone": RMMProductProfile(
        name="NinjaOne",
        vendor="NinjaOne",
        primary_executables=["ninjarmmagent.exe", "njagent.exe"],
        default_services=["NinjaRMMAgent"],
        default_install_paths=[r"C:\Program Files (x86)\NinjaRMM"],
        network_endpoints=["*.ninjarmm.com"],
        suspicious_cli_flags=["--unattended", "--silent"],
    ),
    "meshcentral": RMMProductProfile(
        name="MeshCentral / MeshAgent",
        vendor="Open Source",
        primary_executables=["meshagent.exe", "meshagent64.exe"],
        default_services=["Mesh Agent"],
        default_install_paths=[r"C:\Program Files\Mesh Agent"],
        network_endpoints=["443", "80"],
        suspicious_cli_flags=["-connect", "-install", "-run"],
    ),
    "rustdesk": RMMProductProfile(
        name="RustDesk",
        vendor="Open Source",
        primary_executables=["rustdesk.exe"],
        default_services=["RustDesk"],
        default_install_paths=[r"%APPDATA%\RustDesk", r"C:\Program Files\RustDesk"],
        network_endpoints=["*.rustdesk.com", "21115", "21116"],
        suspicious_cli_flags=["--install-service", "--password", "--silent-install"],
    ),
    "logmein": RMMProductProfile(
        name="GoTo / LogMeIn",
        vendor="GoTo Inc.",
        primary_executables=["logmein.exe", "lmiguardian.exe", "g2mcomm.exe"],
        default_services=["LogMeIn"],
        default_install_paths=[r"C:\Program Files (x86)\LogMeIn"],
        network_endpoints=["*.logmein.com", "*.goto.com"],
        suspicious_cli_flags=["/quiet", "/passive", "/norestart"],
    ),
    "netsupport": RMMProductProfile(
        name="NetSupport Manager",
        vendor="NetSupport Ltd",
        primary_executables=["client32.exe", "run32.exe"],
        default_services=["NetSupport Client Driver"],
        default_install_paths=[r"C:\Program Files (x86)\NetSupport\NetSupport Manager"],
        network_endpoints=["5405"],
        suspicious_cli_flags=["/quiet", "client32.ini", "-h"],
    ),
    "simplehelp": RMMProductProfile(
        name="SimpleHelp",
        vendor="SimpleHelp",
        primary_executables=["simpleservice.exe", "simpleagent.exe"],
        default_services=["SimpleHelp"],
        default_install_paths=[r"C:\Program Files\SimpleHelp"],
        network_endpoints=["443", "80"],
        suspicious_cli_flags=["--unattended", "--service"],
    ),
    "pdq": RMMProductProfile(
        name="PDQ Deploy",
        vendor="PDQ.com",
        primary_executables=["pdqdeployrunner.exe", "pdqdeployconsole.exe"],
        default_services=["PDQDeployService"],
        default_install_paths=[r"C:\Program Files (x86)\Admin Arsenal\PDQ Deploy"],
        network_endpoints=["445", "139"],
        suspicious_cli_flags=["-execute", "-package"],
    ),
    "nable": RMMProductProfile(
        name="N-able",
        vendor="N-able",
        primary_executables=["n-centralagent.exe", "basupsrvc.exe"],
        default_services=["Windows Agent Service"],
        default_install_paths=[r"C:\Program Files (x86)\N-able Technologies"],
        network_endpoints=["*.n-able.com", "*.system-monitor.com"],
        suspicious_cli_flags=["/qn", "/s"],
    ),
    "levelio": RMMProductProfile(
        name="Level.io",
        vendor="Level Software Inc.",
        primary_executables=["level.exe", "level-agent.exe"],
        default_services=["LevelAgent"],
        default_install_paths=[r"C:\Program Files\Level"],
        network_endpoints=["*.level.io"],
        suspicious_cli_flags=["install", "api-key"],
    ),
}


class RMMCapabilityEvaluator:
    """Evaluates RMM activity across the 12 contextual dimensions."""

    @classmethod
    def identify_rmm(cls, process_name: str, command_line: str = "") -> Optional[RMMProductProfile]:
        p_lower = (process_name or "").lower().split("\\")[-1]
        cmd_lower = (command_line or "").lower()
        for profile in RMM_CATALOGUE.values():
            if any(exe in p_lower for exe in profile.primary_executables):
                return profile
            if any(exe in cmd_lower for exe in profile.primary_executables):
                return profile
        return None

    @classmethod
    def evaluate_rmm_context(
        cls,
        *,
        process_name: str,
        command_line: str = "",
        identity: str = "guest",
        is_authorized_identity: bool = False,
        install_path: str = "",
        execution_hour: int = 14,  # standard business hour
        parent_process: str = "explorer.exe",
        has_suspicious_flags: bool = False,
        preceded_by_phishing_or_dumping: bool = False,
        is_privileged_identity: bool = False,
        reachability_to_crown_jewels: bool = False,
        target_crown_jewels: Optional[List[str]] = None,
    ) -> ContextualAssessment:
        profile = cls.identify_rmm(process_name, command_line)
        tool_name = profile.name if profile else "Unknown RMM"

        # Check for suspicious CLI flags
        cmd_lower = command_line.lower()
        if profile and not has_suspicious_flags:
            has_suspicious_flags = any(flag.lower() in cmd_lower for flag in profile.suspicious_cli_flags)

        # Check for non-standard install paths (e.g. Temp, AppData, Downloads)
        path_lower = (install_path or process_name).lower()
        is_staged_in_temp = any(p in path_lower for p in ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\perflogs\\"))

        context_factors: List[str] = [f"RMM Tool: {tool_name}"]
        if is_authorized_identity: context_factors.append("Identity authorized in IT inventory")
        else: context_factors.append(f"Unenrolled identity: '{identity}'")

        if is_staged_in_temp: context_factors.append("Staged in abnormal execution directory (Temp/AppData)")
        if has_suspicious_flags: context_factors.append("Unattended background execution flags detected")
        if execution_hour < 6 or execution_hour > 20: context_factors.append(f"Off-hours execution (Hour: {execution_hour})")
        if preceded_by_phishing_or_dumping: context_factors.append("Preceded by credential dumping or initial access beacon")
        if reachability_to_crown_jewels: context_factors.append("Host has verified lateral reachability to Domain Controller/Crown Jewels")

        # 12-Dimension Decision Hierarchy
        if is_authorized_identity and not is_staged_in_temp and not has_suspicious_flags and not preceded_by_phishing_or_dumping:
            abuse_state = CapabilityAbuseState.AUTHORIZED_ACTIVITY
            severity = "INFORMATIONAL"
            confidence = "0.95"
            explanation = f"Legitimate administrative operation of {tool_name} by authorized IT identity '{identity}'."

        elif is_authorized_identity and (is_staged_in_temp or has_suspicious_flags):
            abuse_state = CapabilityAbuseState.SUSPICIOUS_ANOMALY
            severity = "MEDIUM"
            confidence = "0.75"
            explanation = f"Authorized user running {tool_name} via non-standard parameters or temporary path."

        elif not is_authorized_identity and not preceded_by_phishing_or_dumping and not reachability_to_crown_jewels:
            abuse_state = CapabilityAbuseState.ABUSED_CAPABILITY
            severity = "HIGH"
            confidence = "0.85"
            explanation = f"Unenrolled identity '{identity}' executing {tool_name} without documented IT change ticket."

        elif not is_authorized_identity and reachability_to_crown_jewels and not preceded_by_phishing_or_dumping:
            abuse_state = CapabilityAbuseState.ATTACK_CAPABLE
            severity = "HIGH"
            confidence = "0.90"
            explanation = f"Unenrolled {tool_name} execution on host with direct reachability to Crown Jewels {target_crown_jewels or ['Domain Controller']}."

        elif preceded_by_phishing_or_dumping or (reachability_to_crown_jewels and is_privileged_identity):
            abuse_state = CapabilityAbuseState.CONFIRMED_ATTACK
            severity = "CRITICAL"
            confidence = "0.98"
            explanation = f"CONFIRMED ATTACK: Hostile deployment of {tool_name} following credential compromise with lateral reachability to critical infrastructure."

        else:
            abuse_state = CapabilityAbuseState.BENIGN_DUAL_USE
            severity = "LOW"
            confidence = "0.80"
            explanation = f"Standard portable execution of dual-use RMM utility {tool_name}."

        return ContextualAssessment(
            detection_id=f"RMM-ASSESS-{profile.name.upper() if profile else 'GENERIC'}",
            rule_name=f"Dual-Use RMM Capability Abuse: {tool_name}",
            abuse_state=abuse_state,
            escalated_severity=severity,
            escalated_confidence=confidence,
            contextual_factors=context_factors,
            supporting_evidence_ids=[],
            reachability_to_crown_jewels=reachability_to_crown_jewels,
            target_crown_jewels=target_crown_jewels or [],
            is_privileged_identity=is_privileged_identity,
            explanation=explanation,
        )


RMM_EVALUATOR = RMMCapabilityEvaluator()
