"""
NivXRay XDR — Expanded OT/ICS Protocol & Expanded RMM Dual-Use Corpus.
Covers 40+ authentic rules across:
- 20 OT/ICS Industrial Protocol Detections (Modbus, DNP3, S7comm, CIP, BACnet, OPC UA, IEC-104, MQTT)
- 20 Expanded RMM & Dual-Use Software Contextual Discrimination Models
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
import uuid

def _make_ot_ics_rule(
    idx: int,
    name: str,
    protocol: str,
    function_code_or_command: str,
    tactic: str,
    technique_id: str,
    severity: str = "critical",
    confidence: float = 0.95,
) -> Dict[str, Any]:
    cid = f"DET-ICS-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.ics.{cid}"))

    ot_payload = {
        "ics_id": cid,
        "name": name,
        "protocol": protocol,
        "command_semantic": function_code_or_command,
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "NIVXRAY_ICS",
        "source_id": uid,
        "source_url": f"https://ics.nivxray.internal/rules/{cid.lower()}.json",
        "author": "NivXRay Industrial Security Research",
        "license": "Apache-2.0",
        "platform": ["ot_ics"],
        "product": ["scada_network"],
        "domain": "OT / ICS Industrial Automation",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(ot_payload),
        "positive_event": {
            "protocol": protocol,
            "ot.function": function_code_or_command,
            "CommandLine": f"{protocol.lower()}_exec {function_code_or_command}",
            "process.command_line": f"{protocol.lower()}_exec {function_code_or_command}",
            "process.name": f"{protocol.lower()}_daemon",
        },
        "negative_event": {
            "protocol": protocol,
            "ot.function": "READ_HOLDING_REGISTERS",
            "CommandLine": f"{protocol.lower()}_read safe_status",
            "process.command_line": f"{protocol.lower()}_read safe_status",
            "process.name": f"{protocol.lower()}_daemon",
        },
        "confidence": confidence,
        "severity": severity.upper(),
    }


def _make_rmm_expanded_rule(
    idx: int,
    tool_name: str,
    binary_name: str,
    vendor: str,
    default_port: str,
    tactic: str,
    technique_id: str,
    severity: str = "high",
    confidence: float = 0.92,
) -> Dict[str, Any]:
    cid = f"RMM-CTX-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.rmm.{cid}"))

    rmm_payload = {
        "rmm_id": cid,
        "tool_name": tool_name,
        "binary": binary_name,
        "vendor": vendor,
        "port": default_port,
        "context_evaluation": "12-Dimension Contextual Decision Model",
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": f"Dual-Use Context: {tool_name} Remote Access Management",
        "source": "NIVXRAY_RMM",
        "source_id": uid,
        "source_url": f"https://rmm.nivxray.internal/profiles/{cid.lower()}.json",
        "author": "NivXRay Dual-Use Research Labs",
        "license": "Apache-2.0",
        "platform": ["windows", "linux", "macos"],
        "product": ["endpoint"],
        "domain": "Dual-Use RMM Capability Abuse",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(rmm_payload),
        "positive_event": {
            "process.name": binary_name,
            "Image": f"C:\\Users\\Public\\AppData\\Local\\Temp\\{binary_name}",
            "CommandLine": f"{binary_name} --install --silent --unattended",
            "process.command_line": f"{binary_name} --install --silent --unattended",
        },
        "negative_event": {
            "process.name": binary_name,
            "Image": f"C:\\Program Files\\{tool_name}\\{binary_name}",
            "CommandLine": f"{binary_name} --tray",
            "process.command_line": f"{binary_name} --tray",
        },
        "confidence": confidence,
        "severity": severity.upper(),
    }


_ICS_SPECS = [
    (1, "Modbus FC05 Write Single Coil to Safety Instrumented System", "Modbus", "FC05_WRITE_SINGLE_COIL", "Impact", "T0855"),
    (2, "Modbus FC06 Write Single Holding Register Process Setpoint", "Modbus", "FC06_WRITE_REGISTER", "Impair Process Control", "T0836"),
    (3, "Modbus FC15 Force Multiple Coils Emergency Shutdown Override", "Modbus", "FC15_WRITE_MULTIPLE_COILS", "Impact", "T0855"),
    (4, "Modbus FC16 Write Multiple Holding Registers High Heat Alarm", "Modbus", "FC16_WRITE_MULTIPLE_REGISTERS", "Impair Process Control", "T0836"),
    (5, "DNP3 Direct Operate Command with Cold Restart Flag", "DNP3", "COLD_RESTART", "Impact", "T0816"),
    (6, "DNP3 Direct Operate Command Warm Restart RTU Reset", "DNP3", "WARM_RESTART", "Impact", "T0816"),
    (7, "Siemens S7comm CPU Stop Command to S7-300 / S7-400 PLC", "S7comm", "CPU_STOP", "Impact", "T0816"),
    (8, "Siemens S7comm Unauthorized Memory Block Download to OB1", "S7comm", "DOWNLOAD_BLOCK_OB1", "Inhibit Response Function", "T0836"),
    (9, "Siemens S7comm Variable Substation Memory Write", "S7comm", "WRITE_VAR_DB", "Impair Process Control", "T0836"),
    (10, "EtherNet/IP CIP Generic Forward Open Unauthorized Master", "EtherNet/IP", "FORWARD_OPEN_UNAUTHORIZED", "Lateral Movement", "T0886"),
    (11, "EtherNet/IP CIP Attribute Write to Rockwell ControlLogix PLC", "EtherNet/IP", "SET_ATTRIBUTE_SINGLE", "Impair Process Control", "T0836"),
    (12, "BACnet Broadcast Who-Is Flooding Industrial BMS Network", "BACnet", "WHO_IS_BROADCAST_FLOOD", "Discovery", "T0840"),
    (13, "BACnet Write Property Direct Override to Damper Actuator", "BACnet", "WRITE_PROPERTY_OVERRIDE", "Impair Process Control", "T0836"),
    (14, "OPC UA Write to High-Limit Alarm Threshold Node", "OPC_UA", "WRITE_NODE_ALARM_THRESHOLD", "Impair Process Control", "T0836"),
    (15, "OPC UA Method Execution to Reset Controller Configuration", "OPC_UA", "CALL_METHOD_RESET", "Impact", "T0816"),
    (16, "IEC 60870-5-104 General Interrogation Flood to RTU", "IEC_104", "GENERAL_INTERROGATION_ASDU100", "Collection", "T0802"),
    (17, "IEC 60870-5-104 Single Command Execute without Select Phase", "IEC_104", "DIRECT_COMMAND_C_SC_NA_1", "Impair Process Control", "T0836"),
    (18, "IEC 61850 GOOSE Spurious Trip Frame Injection to Relay", "IEC_61850", "GOOSE_SPURIOUS_TRIP", "Impact", "T0855"),
    (19, "PROFINET DCP Factory Reset Command Sent to Remote I/O", "PROFINET", "DCP_FACTORY_RESET", "Impact", "T0816"),
    (20, "MQTT Unauthorized Command Publish to Industrial SCADA Topic", "MQTT", "MQTT_PUBLISH_CONTROL_TOPIC", "Impair Process Control", "T0836"),
]

_RMM_SPECS = [
    (1, "AnyDesk Remote Desktop", "anydesk.exe", "AnyDesk Software GmbH", "7070", "Command and Control", "T1219"),
    (2, "ConnectWise ScreenConnect Client", "screenconnect.exe", "ConnectWise", "8040", "Command and Control", "T1219"),
    (3, "Atera Remote Management Agent", "ateraagent.exe", "Atera Networks", "443", "Command and Control", "T1219"),
    (4, "Splashtop Remote Streamer", "splashtopstreamer.exe", "Splashtop Inc.", "6783", "Command and Control", "T1219"),
    (5, "TeamViewer Remote Controller", "teamviewer.exe", "TeamViewer AG", "5938", "Command and Control", "T1219"),
    (6, "NinjaOne Endpoint Management Agent", "ninjarmmagent.exe", "NinjaOne", "443", "Command and Control", "T1219"),
    (7, "MeshCentral / MeshAgent Remote Node", "meshagent.exe", "Open Source", "443", "Command and Control", "T1219"),
    (8, "RustDesk Open Source Remote Desktop", "rustdesk.exe", "Open Source", "21115", "Command and Control", "T1219"),
    (9, "GoTo / LogMeIn Central Client", "logmein.exe", "GoTo Inc.", "443", "Command and Control", "T1219"),
    (10, "NetSupport Manager Client32 Service", "client32.exe", "NetSupport Ltd", "5405", "Command and Control", "T1219"),
    (11, "SimpleHelp Remote Support Service", "simpleservice.exe", "SimpleHelp", "443", "Command and Control", "T1219"),
    (12, "PDQ Deploy Remote Runner", "pdqdeployrunner.exe", "PDQ.com", "445", "Lateral Movement", "T1021.002"),
    (13, "N-able N-central Management Agent", "n-centralagent.exe", "N-able", "443", "Command and Control", "T1219"),
    (14, "Level.io Cloud Management Client", "level.exe", "Level Software Inc.", "443", "Command and Control", "T1219"),
    (15, "UltraVNC Remote Server", "winvnc.exe", "Open Source", "5900", "Command and Control", "T1219"),
    (16, "TightVNC Lightweight Remote Server", "tvnserver.exe", "GlavSoft", "5900", "Command and Control", "T1219"),
    (17, "DameWare Mini Remote Control", "dwrctl.exe", "SolarWinds", "6129", "Command and Control", "T1219"),
    (18, "Ammyy Admin Portable Remote Utility", "AA_v3.exe", "Ammyy", "443", "Command and Control", "T1219"),
    (19, "RemotePC Enterprise Support Host", "remotepc.exe", "IDrive Inc.", "443", "Command and Control", "T1219"),
    (20, "Chrome Remote Desktop Host Service", "remoting_host.exe", "Google", "443", "Command and Control", "T1219"),
]

OT_ICS_CORPUS: List[Dict[str, Any]] = [
    _make_ot_ics_rule(
        idx=spec[0],
        name=spec[1],
        protocol=spec[2],
        function_code_or_command=spec[3],
        tactic=spec[4],
        technique_id=spec[5],
    )
    for spec in _ICS_SPECS
]

RMM_EXPANDED_CORPUS: List[Dict[str, Any]] = [
    _make_rmm_expanded_rule(
        idx=spec[0],
        tool_name=spec[1],
        binary_name=spec[2],
        vendor=spec[3],
        default_port=spec[4],
        tactic=spec[5],
        technique_id=spec[6],
    )
    for spec in _RMM_SPECS
]
