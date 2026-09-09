"""v2/ikb/schema.py · Investigation Knowledge Base entry schema."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any


KIND_CHOICES = (
    "windows_binary",       # e.g. svchost.exe, WerFault.exe, cmd.exe
    "windows_event",        # e.g. Event ID 4624 (logon)
    "telemetry_source",     # Sysmon, EDR, XDR, Splunk, …
    "registry_key",         # e.g. HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    "mitre_technique",      # e.g. T1218 (Signed Binary Proxy Execution)
    "enterprise_baseline",  # e.g. OneDrive, Chrome Updater
    "decoder",              # e.g. XOR, Base64, gzip
)


@dataclass
class KBEntry:
    """A single Investigation Knowledge Base entry."""
    id:              str            # "windows_binary:svchost.exe"
    kind:            str            # one of KIND_CHOICES
    label:           str            # "svchost.exe"
    category:        str            # e.g. "service_host"
    description:     str            # one-line summary

    normal_behavior: dict[str, Any] = field(default_factory=dict)
    # keys: expected_parents[], expected_children[], expected_paths[],
    #       expected_command_line[], expected_registry[], expected_network[]

    common_abuse:    list[dict[str, Any]] = field(default_factory=list)
    # each: {pattern, reason, mitre[], severity: low|medium|high|critical}

    detection_guidance: list[str] = field(default_factory=list)
    false_positives:    list[dict[str, str]] = field(default_factory=list)
    mitre:              list[str] = field(default_factory=list)
    correlation_rules:  list[dict[str, Any]] = field(default_factory=list)
    references:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
