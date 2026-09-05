"""RC5 · Phase 5 · MITRE ATT&CK v2 Mapper.

Deterministic, behavior-driven mapping of Phase-4 `Behavior[]` outputs onto
MITRE ATT&CK v14 techniques (Enterprise matrix, incl. sub-techniques).

Design contract (§ 8 of RC5_SEMANTIC_ENGINE_SPEC.md):

  * Consumes `Behavior[]` (already produced from an ExecGraph).
  * Emits `MitreMapping[]`, each carrying:
      - technique_id (+ optional sub_technique_id)
      - tactic + tactic_id (TA00xx)
      - confidence  = min(rule.base_confidence, behavior.confidence)
      - evidence_behavior_ids  (≥1)
      - evidence_node_ids      (≥1, resolved via Behavior.evidence_nodes)
      - data_sources           (Sysmon / EventLog / EDR / Network / …)
      - detections             ({sigma, kql, spl, aql} placeholders)
  * A single behavior CAN emit multiple mappings (1:N; e.g. an encoded
    PowerShell process spawn maps to both T1059.001 and T1027.010).
  * NO keyword regex on raw text. Rules match on:
      Behavior.tactic
      Behavior.sub_kind
      Behavior.parameters[key] (exact or set membership)
  * Deterministic: same behaviors in ⇒ identical (byte-equal) mappings out.

Kill-list § 13 gate: legacy `_KEYWORD_MITRE_MAP` in `operations.py` remains
callable, but `mitre_mapper.map_behaviors(...)` is the ONLY code path used
when `SEMANTIC_ENGINE_V2=true`. Any new import of `_KEYWORD_MITRE_MAP`
outside a legacy shim fails the CI gate (test_no_keyword_mitre_imports.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple
import hashlib

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..exec_graph import Behavior, ExecGraph, SCHEMA_VERSION, TacticKind
from ..plugin_api import Detector, register_detector


# ---------------------------------------------------------------------------
# MITRE ATT&CK Enterprise Tactics (v14) — Behavior.tactic ↔ Mitre tactic
# ---------------------------------------------------------------------------
MITRE_TACTIC_IDS: Dict[str, Tuple[str, str]] = {
    # Behavior tactic value          → (Mitre tactic id, canonical name)
    "reconnaissance":       ("TA0043", "Reconnaissance"),
    "resource_development": ("TA0042", "Resource Development"),
    "initial_access":       ("TA0001", "Initial Access"),
    "execution":            ("TA0002", "Execution"),
    "persistence":          ("TA0003", "Persistence"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "defense_evasion":      ("TA0005", "Defense Evasion"),
    "credential_access":    ("TA0006", "Credential Access"),
    "discovery":            ("TA0007", "Discovery"),
    "lateral_movement":     ("TA0008", "Lateral Movement"),
    "collection":           ("TA0009", "Collection"),
    "command_and_control":  ("TA0011", "Command and Control"),
    "exfiltration":         ("TA0010", "Exfiltration"),
    "impact":               ("TA0040", "Impact"),
    # Supporting tactics — map to the closest Mitre tactic; some are ancillary
    "dns_query":            ("TA0011", "Command and Control"),
    "firewall_rule":        ("TA0005", "Defense Evasion"),
    "named_pipe":           ("TA0011", "Command and Control"),
    "clipboard":            ("TA0009", "Collection"),
    "certificate":          ("TA0005", "Defense Evasion"),
    "token_manipulation":   ("TA0004", "Privilege Escalation"),
    "wmi_subscription":     ("TA0003", "Persistence"),
}


# ---------------------------------------------------------------------------
# MitreMapping — frozen output record
# ---------------------------------------------------------------------------
class MitreMapping(BaseModel):
    """One (Behavior → ATT&CK technique) mapping.

    Immutable. Every field is analyst-auditable.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    technique_id: str                          # e.g. "T1059"
    sub_technique_id: Optional[str] = None     # e.g. "T1059.001"
    technique_name: str
    tactic: str                                # Behavior tactic value
    tactic_id: str                             # TA0002
    tactic_name: str                           # "Execution"
    confidence: int                            # 0–100
    evidence_behavior_ids: Tuple[str, ...]
    evidence_node_ids: Tuple[str, ...]
    reconstructed: Tuple[str, ...] = ()        # deduped reconstructed strings
    data_sources: Tuple[str, ...] = ()
    detections: Dict[str, str] = Field(default_factory=dict)
    rule_id: str = ""                          # matches `MitreRule.rule_id`
    schema_version: int = SCHEMA_VERSION
    notes: Tuple[str, ...] = ()

    @field_validator("evidence_behavior_ids", "evidence_node_ids")
    @classmethod
    def _nonempty(cls, v: Tuple[str, ...]) -> Tuple[str, ...]:
        if not v:
            raise ValueError("evidence lists must contain ≥1 id")
        return v

    @field_validator("confidence")
    @classmethod
    def _clamp(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"confidence must be in [0, 100], got {v}")
        return v

    @field_validator("technique_id")
    @classmethod
    def _valid_tid(cls, v: str) -> str:
        if not (v.startswith("T") and v[1:].isdigit() and 3 <= len(v) <= 6):
            raise ValueError(f"malformed technique_id: {v!r}")
        return v


# ---------------------------------------------------------------------------
# Rule definition — pure data. Matching is via structured predicates only.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MitreRule:
    rule_id: str
    technique_id: str
    sub_technique_id: Optional[str]
    technique_name: str
    behavior_tactic: TacticKind
    sub_kind: Optional[str] = None             # exact match against Behavior.sub_kind
    param_predicates: Tuple[Tuple[str, Callable[[Any], bool]], ...] = ()
    base_confidence: int = 90
    data_sources: Tuple[str, ...] = ()
    detections: Dict[str, str] = field(default_factory=dict)
    notes: Tuple[str, ...] = ()

    def matches(self, b: Behavior) -> bool:
        if b.tactic != self.behavior_tactic:
            return False
        if self.sub_kind is not None and b.sub_kind != self.sub_kind:
            return False
        for key, pred in self.param_predicates:
            if key not in b.parameters:
                return False
            if not pred(b.parameters[key]):
                return False
        return True


# ── param-predicate helpers (all deterministic, no regex on free-text) ────
def _in(*values: str) -> Callable[[Any], bool]:
    lset = frozenset(v.lower() for v in values)
    return lambda x: str(x or "").strip().lower() in lset


def _bare_in(*values: str) -> Callable[[Any], bool]:
    lset = frozenset(v.lower() for v in values)
    def _p(x: Any) -> bool:
        s = str(x or "").strip().lower()
        return s in lset or s.rsplit(".", 1)[0] in lset
    return _p


def _startswith_any(*prefixes: str) -> Callable[[Any], bool]:
    lows = tuple(p.lower() for p in prefixes)
    return lambda x: str(x or "").strip().lower().startswith(lows)


def _eq(value: Any) -> Callable[[Any], bool]:
    return lambda x: x == value


# ---------------------------------------------------------------------------
# MITRE_RULES — canonical rule table (Phase 5 baseline; append-only).
# Every entry MUST be exercised by ≥1 positive and ≥1 negative unit test.
# ---------------------------------------------------------------------------
_PS_IMAGES = ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
_CMD_IMAGES = ("cmd", "cmd.exe")
_WSCRIPT_IMAGES = ("wscript", "wscript.exe", "cscript", "cscript.exe")
_MSHTA_IMAGES = ("mshta", "mshta.exe")
_RUNDLL32_IMAGES = ("rundll32", "rundll32.exe")
_REGSVR32_IMAGES = ("regsvr32", "regsvr32.exe")
_WMIC_IMAGES = ("wmic", "wmic.exe")
_BITSADMIN_IMAGES = ("bitsadmin", "bitsadmin.exe", "start-bitstransfer")
_CERTUTIL_IMAGES = ("certutil", "certutil.exe")
_SCHTASKS_IMAGES = ("schtasks", "schtasks.exe", "at", "at.exe",
                    "new-scheduledtask", "register-scheduledtask")
_SC_IMAGES = ("sc", "sc.exe", "new-service", "install-service")
_MIMIKATZ_IMAGES = ("mimikatz", "mimikatz.exe")
_PROCDUMP_IMAGES = ("procdump", "procdump.exe")
_NTDSUTIL_IMAGES = ("ntdsutil", "ntdsutil.exe")


MITRE_RULES: Tuple[MitreRule, ...] = (
    # ── Execution ───────────────────────────────────────────────────────
    MitreRule(
        rule_id="R-EXE-PS",
        technique_id="T1059", sub_technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        behavior_tactic=TacticKind.execution, sub_kind="process_spawn",
        param_predicates=(("image", _bare_in(*_PS_IMAGES)),),
        base_confidence=95,
        data_sources=("Sysmon EventID 1", "Windows Event 4688",
                      "PowerShell Operational (4104)", "EDR ProcessCreate"),
        detections={
            "sigma": "process_creation:\n  Image|endswith: '\\powershell.exe'",
            "kql":   "DeviceProcessEvents | where FileName in ('powershell.exe','pwsh.exe')",
            "spl":   "index=win Image=\"*\\\\powershell.exe\"",
            "aql":   "SELECT * FROM processes WHERE lower(image_name) IN ('powershell.exe','pwsh.exe')",
        },
    ),
    MitreRule(
        rule_id="R-EXE-CMD",
        technique_id="T1059", sub_technique_id="T1059.003",
        technique_name="Command and Scripting Interpreter: Windows Command Shell",
        behavior_tactic=TacticKind.execution, sub_kind="process_spawn",
        param_predicates=(("image", _bare_in(*_CMD_IMAGES)),),
        base_confidence=90,
        data_sources=("Sysmon EventID 1", "Windows Event 4688"),
        detections={
            "sigma": "process_creation:\n  Image|endswith: '\\cmd.exe'",
            "kql":   "DeviceProcessEvents | where FileName == 'cmd.exe'",
        },
    ),
    MitreRule(
        rule_id="R-EXE-VBS-JS",
        technique_id="T1059", sub_technique_id="T1059.005",
        technique_name="Command and Scripting Interpreter: Visual Basic / JScript (WScript host)",
        behavior_tactic=TacticKind.execution, sub_kind="process_spawn",
        param_predicates=(("image", _bare_in(*_WSCRIPT_IMAGES)),),
        base_confidence=85,
        data_sources=("Sysmon EventID 1", "Windows Event 4688"),
        detections={"sigma": "process_creation:\n  Image|endswith:\n    - '\\wscript.exe'\n    - '\\cscript.exe'"},
    ),
    MitreRule(
        rule_id="R-EXE-WMIC",
        technique_id="T1047", sub_technique_id=None,
        technique_name="Windows Management Instrumentation",
        behavior_tactic=TacticKind.execution, sub_kind="process_spawn",
        param_predicates=(("image", _bare_in(*_WMIC_IMAGES)),),
        base_confidence=88,
        data_sources=("Sysmon EventID 1", "WMI-Activity/Operational"),
        detections={"kql": "DeviceProcessEvents | where FileName == 'wmic.exe'"},
    ),
    MitreRule(
        rule_id="R-EXE-SHELLCODE",
        technique_id="T1055", sub_technique_id="T1055.002",
        technique_name="Process Injection: Portable Executable / Shellcode",
        behavior_tactic=TacticKind.execution, sub_kind="shellcode_exec",
        base_confidence=95,
        data_sources=("Sysmon EventID 10 (ProcessAccess)", "EDR memory events"),
        detections={"sigma": "image_load:\n  ImageLoaded|endswith:\n    - '\\amsi.dll'"},
    ),
    MitreRule(
        rule_id="R-EXE-DLLLOAD",
        technique_id="T1129", sub_technique_id=None,
        technique_name="Shared Modules",
        behavior_tactic=TacticKind.execution, sub_kind="dll_load",
        base_confidence=70,
        data_sources=("Sysmon EventID 7 (ImageLoaded)",),
        detections={},
    ),

    # ── System Binary Proxy Execution (defense evasion via LOLBIN)  ────
    MitreRule(
        rule_id="R-DE-MSHTA",
        technique_id="T1218", sub_technique_id="T1218.005",
        technique_name="System Binary Proxy Execution: Mshta",
        behavior_tactic=TacticKind.execution, sub_kind="process_spawn",
        param_predicates=(("image", _bare_in(*_MSHTA_IMAGES)),),
        base_confidence=92,
        data_sources=("Sysmon EventID 1", "Windows Event 4688"),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\mshta.exe'"},
    ),
    MitreRule(
        rule_id="R-DE-RUNDLL32",
        technique_id="T1218", sub_technique_id="T1218.011",
        technique_name="System Binary Proxy Execution: Rundll32",
        behavior_tactic=TacticKind.execution, sub_kind="process_spawn",
        param_predicates=(("image", _bare_in(*_RUNDLL32_IMAGES)),),
        base_confidence=88,
        data_sources=("Sysmon EventID 1",),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\rundll32.exe'"},
    ),
    MitreRule(
        rule_id="R-DE-REGSVR32",
        technique_id="T1218", sub_technique_id="T1218.010",
        technique_name="System Binary Proxy Execution: Regsvr32",
        behavior_tactic=TacticKind.execution, sub_kind="process_spawn",
        param_predicates=(("image", _bare_in(*_REGSVR32_IMAGES)),),
        base_confidence=88,
        data_sources=("Sysmon EventID 1",),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\regsvr32.exe'"},
    ),

    # ── Command and Control ─────────────────────────────────────────────
    MitreRule(
        rule_id="R-C2-DOWNLOAD",
        technique_id="T1105", sub_technique_id=None,
        technique_name="Ingress Tool Transfer",
        behavior_tactic=TacticKind.command_and_control, sub_kind="download",
        base_confidence=92,
        data_sources=("Zeek/Suricata HTTP", "Sysmon EventID 3 (Network)",
                      "EDR Network telemetry"),
        detections={
            "sigma": "network_connection:\n  Initiated: true\n  DestinationPort:\n    - 80\n    - 443",
            "kql":   "DeviceNetworkEvents | where InitiatingProcessFileName in ('powershell.exe','curl.exe','wget.exe')",
        },
    ),
    MitreRule(
        rule_id="R-C2-BITS",
        technique_id="T1197", sub_technique_id=None,
        technique_name="BITS Jobs",
        behavior_tactic=TacticKind.command_and_control, sub_kind="download",
        param_predicates=(("image", _bare_in(*_BITSADMIN_IMAGES)),),
        base_confidence=90,
        data_sources=("Sysmon EventID 1", "BITS-Client/Operational"),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\bitsadmin.exe'"},
    ),
    MitreRule(
        rule_id="R-DE-CERTUTIL",
        technique_id="T1140", sub_technique_id=None,
        technique_name="Deobfuscate/Decode Files or Information (Certutil)",
        behavior_tactic=TacticKind.command_and_control, sub_kind="download",
        param_predicates=(("image", _bare_in(*_CERTUTIL_IMAGES)),),
        base_confidence=90,
        data_sources=("Sysmon EventID 1",),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\certutil.exe'"},
    ),
    MitreRule(
        rule_id="R-C2-HTTP",
        technique_id="T1071", sub_technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        behavior_tactic=TacticKind.command_and_control, sub_kind="http",
        base_confidence=80,
        data_sources=("Zeek HTTP", "Firewall/Proxy logs", "EDR Network telemetry"),
        detections={"kql": "DeviceNetworkEvents | where RemotePort in (80, 443, 8080, 8443)"},
    ),
    MitreRule(
        rule_id="R-C2-DNS",
        technique_id="T1071", sub_technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        behavior_tactic=TacticKind.dns_query,
        base_confidence=70,
        data_sources=("Zeek DNS", "Windows DNS-Client/Operational"),
        detections={"kql": "DeviceDnsEvents | project QueryName, QueryType"},
    ),
    MitreRule(
        rule_id="R-C2-NAMED-PIPE",
        technique_id="T1573", sub_technique_id=None,
        technique_name="Encrypted Channel (named pipes as covert transport)",
        behavior_tactic=TacticKind.named_pipe,
        base_confidence=60,
        data_sources=("Sysmon EventID 17/18 (PipeEvent)",),
        detections={"sigma": "pipe_created:\n  PipeName|contains: '\\'"},
    ),

    # ── Persistence ─────────────────────────────────────────────────────
    MitreRule(
        rule_id="R-PERS-AUTORUN",
        technique_id="T1547", sub_technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
        behavior_tactic=TacticKind.persistence, sub_kind="autorun_registration",
        base_confidence=95,
        data_sources=("Sysmon EventID 13 (RegistryValueSet)",),
        detections={
            "sigma": "registry_set:\n  TargetObject|contains: '\\CurrentVersion\\Run'",
            "kql":   "DeviceRegistryEvents | where RegistryKey contains 'CurrentVersion\\\\Run'",
        },
    ),
    MitreRule(
        rule_id="R-PERS-SCHTASKS",
        technique_id="T1053", sub_technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        behavior_tactic=TacticKind.persistence, sub_kind="create_task",
        base_confidence=92,
        data_sources=("Sysmon EventID 1", "Windows TaskScheduler/Operational (106/140)"),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\schtasks.exe'"},
    ),
    MitreRule(
        rule_id="R-PERS-SERVICE",
        technique_id="T1543", sub_technique_id="T1543.003",
        technique_name="Create or Modify System Process: Windows Service",
        behavior_tactic=TacticKind.persistence, sub_kind="install_service",
        base_confidence=92,
        data_sources=("Sysmon EventID 1", "Windows Event 7045"),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\sc.exe'\n  CommandLine|contains: ' create '"},
    ),
    MitreRule(
        rule_id="R-PERS-REGISTRY",
        technique_id="T1112", sub_technique_id=None,
        technique_name="Modify Registry",
        behavior_tactic=TacticKind.persistence, sub_kind="write_registry",
        base_confidence=70,
        data_sources=("Sysmon EventID 12/13 (RegistrySet)",),
        detections={"sigma": "registry_set:\n  EventType: SetValue"},
    ),
    MitreRule(
        rule_id="R-PERS-WMI-SUB",
        technique_id="T1546", sub_technique_id="T1546.003",
        technique_name="Event Triggered Execution: WMI Event Subscription",
        behavior_tactic=TacticKind.wmi_subscription,
        base_confidence=95,
        data_sources=("Sysmon EventID 19/20/21 (WmiEvent)",),
        detections={"sigma": "wmi_event:\n  EventType: WmiEventConsumerToFilter"},
    ),

    # ── Credential Access ───────────────────────────────────────────────
    MitreRule(
        rule_id="R-CRED-MIMIKATZ",
        technique_id="T1003", sub_technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory",
        behavior_tactic=TacticKind.credential_access, sub_kind="dump_credentials",
        param_predicates=(("image", _bare_in(*_MIMIKATZ_IMAGES)),),
        base_confidence=98,
        data_sources=("Sysmon EventID 10 (ProcessAccess of lsass.exe)", "EDR memory events"),
        detections={"sigma": "process_access:\n  TargetImage|endswith: '\\lsass.exe'"},
    ),
    MitreRule(
        rule_id="R-CRED-PROCDUMP-LSASS",
        technique_id="T1003", sub_technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory (procdump)",
        behavior_tactic=TacticKind.credential_access, sub_kind="dump_credentials",
        param_predicates=(("image", _bare_in(*_PROCDUMP_IMAGES)),),
        base_confidence=93,
        data_sources=("Sysmon EventID 1 + 10 (ProcessAccess)",),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\procdump.exe'"},
    ),
    MitreRule(
        rule_id="R-CRED-NTDSUTIL",
        technique_id="T1003", sub_technique_id="T1003.003",
        technique_name="OS Credential Dumping: NTDS",
        behavior_tactic=TacticKind.credential_access, sub_kind="dump_credentials",
        param_predicates=(("image", _bare_in(*_NTDSUTIL_IMAGES)),),
        base_confidence=90,
        data_sources=("Sysmon EventID 1", "Windows Directory-Service events"),
        detections={"sigma": "process_creation:\n  Image|endswith: '\\ntdsutil.exe'"},
    ),

    # ── Defense Evasion ─────────────────────────────────────────────────
    MitreRule(
        rule_id="R-DE-OBF-ENCODED",
        technique_id="T1027", sub_technique_id="T1027.010",
        technique_name="Obfuscated Files or Information: Command Obfuscation (encoded)",
        behavior_tactic=TacticKind.defense_evasion, sub_kind="obfuscation",
        param_predicates=(("kind", _eq("encoded_command")),),
        base_confidence=92,
        data_sources=("PowerShell Operational (4104)", "Sysmon EventID 1"),
        detections={
            "sigma": "process_creation:\n  CommandLine|contains: ' -enc '",
            "kql":   "DeviceProcessEvents | where ProcessCommandLine has ' -enc '",
        },
    ),
    MitreRule(
        rule_id="R-DE-AMSI",
        technique_id="T1562", sub_technique_id="T1562.001",
        technique_name="Impair Defenses: Disable or Modify Tools (AMSI bypass)",
        behavior_tactic=TacticKind.defense_evasion, sub_kind="bypass_amsi",
        base_confidence=97,
        data_sources=("Sysmon EventID 7 (AMSI-relevant module)", "AntiMalware-Scan-Interface/Operational"),
        detections={"sigma": "powershell_script:\n  ScriptBlockText|contains: 'AmsiUtils'"},
    ),
    MitreRule(
        rule_id="R-DE-ETW",
        technique_id="T1562", sub_technique_id="T1562.006",
        technique_name="Impair Defenses: Indicator Blocking (ETW bypass)",
        behavior_tactic=TacticKind.defense_evasion, sub_kind="bypass_etw",
        base_confidence=97,
        data_sources=("Sysmon EventID 12/13", "EDR ETW telemetry"),
        detections={"sigma": "powershell_script:\n  ScriptBlockText|contains: 'EtwEventWrite'"},
    ),
    MitreRule(
        rule_id="R-DE-REFLECTION",
        technique_id="T1620", sub_technique_id=None,
        technique_name="Reflective Code Loading",
        behavior_tactic=TacticKind.defense_evasion, sub_kind="reflection",
        base_confidence=90,
        data_sources=("Sysmon EventID 7 (ImageLoaded)", "AMSI 4104"),
        detections={"sigma": "powershell_script:\n  ScriptBlockText|contains: 'Reflection.Assembly'"},
    ),
    MitreRule(
        rule_id="R-DE-MEMORY-ALLOC",
        technique_id="T1055", sub_technique_id=None,
        technique_name="Process Injection (VirtualAlloc / NtAllocateVirtualMemory)",
        behavior_tactic=TacticKind.defense_evasion, sub_kind="memory_alloc",
        base_confidence=80,
        data_sources=("Sysmon EventID 10 (ProcessAccess)", "EDR memory events"),
        detections={},
    ),

    # ── Discovery (from process_spawn on discovery LOLBINs — covered later
    # ── in Phase 6 LOLBIN v2. Kept here as a base surface for now.)
    # ── Exfiltration ───────────────────────────────────────────────────
    MitreRule(
        rule_id="R-EXFIL-UPLOAD",
        technique_id="T1041", sub_technique_id=None,
        technique_name="Exfiltration Over C2 Channel",
        behavior_tactic=TacticKind.exfiltration, sub_kind="upload",
        base_confidence=88,
        data_sources=("Zeek HTTP/FTP", "Sysmon EventID 3 (Network)"),
        detections={"sigma": "process_creation:\n  Image|endswith:\n    - '\\ftp.exe'\n    - '\\scp.exe'"},
    ),

    # ── Impact ──────────────────────────────────────────────────────────
    MitreRule(
        rule_id="R-IMP-FILE-DELETE",
        technique_id="T1485", sub_technique_id=None,
        technique_name="Data Destruction (file delete)",
        behavior_tactic=TacticKind.impact, sub_kind="file_delete",
        base_confidence=60,
        data_sources=("Sysmon EventID 23 (FileDelete)",),
        detections={"sigma": "file_delete:\n  Image|endswith:\n    - '\\cmd.exe'"},
    ),

    # ── Collection ──────────────────────────────────────────────────────
    MitreRule(
        rule_id="R-COL-FILE-CREATE",
        technique_id="T1005", sub_technique_id=None,
        technique_name="Data from Local System (staged file created)",
        behavior_tactic=TacticKind.collection, sub_kind="file_create",
        base_confidence=45,
        data_sources=("Sysmon EventID 11 (FileCreate)",),
        detections={},
    ),
    MitreRule(
        rule_id="R-COL-CLIPBOARD",
        technique_id="T1115", sub_technique_id=None,
        technique_name="Clipboard Data",
        behavior_tactic=TacticKind.clipboard,
        base_confidence=70,
        data_sources=("EDR clipboard telemetry",),
        detections={},
    ),
)


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------
class MitreMapper(Detector):
    """Deterministic ATT&CK v14 mapper (Behavior[] → MitreMapping[])."""
    name = "mitre_mapper"

    def detect(self, graph: ExecGraph) -> Dict[str, Any]:
        from .behavior_extractor import extract_behaviors
        return {"mitre": self.map_behaviors(extract_behaviors(graph))}

    # ─── main API ──────────────────────────────────────────────────────
    def map_behaviors(self, behaviors: List[Behavior]) -> List[MitreMapping]:
        if not behaviors:
            return []
        # Grouping key: (technique_id, sub_technique_id, rule_id).
        # Multiple behaviors with the same key merge into ONE mapping with
        # unioned evidence — deterministic ordering by first-behavior index.
        groups: Dict[Tuple[str, Optional[str], str],
                     Dict[str, Any]] = {}
        order: List[Tuple[str, Optional[str], str]] = []

        for b in behaviors:
            for rule in MITRE_RULES:
                if not rule.matches(b):
                    continue
                key = (rule.technique_id, rule.sub_technique_id, rule.rule_id)
                if key not in groups:
                    tactic_id, tactic_name = MITRE_TACTIC_IDS.get(
                        b.tactic.value, ("TA0000", "Unknown"))
                    groups[key] = {
                        "rule": rule,
                        "tactic_value": b.tactic.value,
                        "tactic_id": tactic_id,
                        "tactic_name": tactic_name,
                        "behavior_ids": [],
                        "node_ids": [],
                        "confidences": [],
                        "reconstructed": [],
                        "seen_recon": set(),
                    }
                    order.append(key)
                g = groups[key]
                g["behavior_ids"].append(b.id)
                for nid in b.evidence_nodes:
                    if nid not in g["node_ids"]:
                        g["node_ids"].append(nid)
                g["confidences"].append(min(rule.base_confidence, b.confidence))
                if b.reconstructed and b.reconstructed not in g["seen_recon"]:
                    g["reconstructed"].append(b.reconstructed)
                    g["seen_recon"].add(b.reconstructed)

        out: List[MitreMapping] = []
        for key in order:
            g = groups[key]
            rule: MitreRule = g["rule"]
            behavior_ids = tuple(g["behavior_ids"])
            node_ids = tuple(g["node_ids"])
            # Deterministic ID — sha1 of the rule + evidence lists.
            digest = hashlib.sha1(
                "|".join((rule.rule_id, rule.technique_id,
                          rule.sub_technique_id or "",
                          ",".join(behavior_ids),
                          ",".join(node_ids))).encode("utf-8")
            ).hexdigest()[:12]
            out.append(MitreMapping(
                id="m_" + digest,
                technique_id=rule.technique_id,
                sub_technique_id=rule.sub_technique_id,
                technique_name=rule.technique_name,
                tactic=g["tactic_value"],
                tactic_id=g["tactic_id"],
                tactic_name=g["tactic_name"],
                confidence=max(g["confidences"]) if g["confidences"] else rule.base_confidence,
                evidence_behavior_ids=behavior_ids,
                evidence_node_ids=node_ids,
                reconstructed=tuple(g["reconstructed"]),
                data_sources=rule.data_sources,
                detections=dict(rule.detections),
                rule_id=rule.rule_id,
                notes=rule.notes,
            ))
        return out


# ---------------------------------------------------------------------------
# Register + module-level accessors
# ---------------------------------------------------------------------------
_INSTANCE = MitreMapper()
register_detector(_INSTANCE)


def map_behaviors_to_mitre(behaviors: List[Behavior]) -> List[MitreMapping]:
    return _INSTANCE.map_behaviors(behaviors)


def get_mitre_mapper() -> MitreMapper:
    return _INSTANCE


def get_rules() -> Tuple[MitreRule, ...]:
    return MITRE_RULES


__all__ = [
    "MitreMapping",
    "MitreRule",
    "MITRE_RULES",
    "MITRE_TACTIC_IDS",
    "MitreMapper",
    "map_behaviors_to_mitre",
    "get_mitre_mapper",
    "get_rules",
]
