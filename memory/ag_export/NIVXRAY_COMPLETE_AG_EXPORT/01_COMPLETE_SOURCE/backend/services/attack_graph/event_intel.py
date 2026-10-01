"""Round 35 · NivXRay XDR · Windows Security Event ID Intelligence.

First-class Event ID knowledge layer.  Each entry answers:
  * What does the event mean?
  * Which fields matter?
  * Which capabilities should investigate it?
  * Which ATT&CK techniques does it commonly support?
  * Which related event IDs form its natural correlation chain?

This is a curated reference (Windows Security Log Encyclopedia +
Sysmon operational intelligence).  Nothing here is fabricated.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


# Provider-scoped registry so future sources (Sysmon, PowerShell,
# Defender, EDRs) can register their own event vocabularies.

WINDOWS_SECURITY_EVENTS: Dict[str, Dict[str, Any]] = {
    "4624": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Successful logon",
        "category":       "Logon/Logoff",
        "significance":   4,
        "fields":         ["SubjectUserName", "TargetUserName", "LogonType",
                              "IpAddress", "LogonId"],
        "capabilities":   ["identity_pivot", "historical_correlation"],
        "attack_hints":   ["T1078"],
        "related_events": ["4625", "4648", "4672", "4634"],
    },
    "4625": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Failed logon",
        "category":       "Logon/Logoff",
        "significance":   3,
        "fields":         ["TargetUserName", "IpAddress", "FailureReason", "LogonType"],
        "capabilities":   ["identity_pivot", "historical_correlation"],
        "attack_hints":   ["T1110"],
        "related_events": ["4624", "4740"],
    },
    "4648": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Explicit credential use",
        "category":       "Logon/Logoff",
        "significance":   4,
        "fields":         ["SubjectUserName", "TargetUserName",
                              "ProcessName", "TargetServerName"],
        "capabilities":   ["identity_pivot", "process_ancestry",
                              "historical_correlation"],
        "attack_hints":   ["T1078", "T1550"],
        "related_events": ["4624", "4672", "4688"],
    },
    "4672": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Special privileges assigned",
        "category":       "Logon/Logoff",
        "significance":   4,
        "fields":         ["SubjectUserName", "PrivilegeList"],
        "capabilities":   ["identity_pivot"],
        "attack_hints":   ["T1078"],
        "related_events": ["4624", "4648"],
    },
    "4688": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Process created",
        "category":       "Process Tracking",
        "significance":   5,
        "fields":         ["NewProcessName", "ParentProcessName",
                              "CommandLine", "SubjectUserName", "TokenElevationType"],
        "capabilities":   ["process_ancestry", "commandline_decode",
                              "lolbas_lookup", "file_reputation"],
        "attack_hints":   ["T1059", "T1218", "T1059.001", "T1059.003"],
        "related_events": ["4689", "4624", "4672"],
    },
    "4689": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Process exited",
        "category":       "Process Tracking",
        "significance":   2,
        "fields":         ["ProcessName", "ProcessId", "Status"],
        "capabilities":   ["process_ancestry"],
        "attack_hints":   [],
        "related_events": ["4688"],
    },
    "4697": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Service installed",
        "category":       "System",
        "significance":   5,
        "fields":         ["ServiceName", "ServiceFileName", "ServiceType"],
        "capabilities":   ["process_ancestry", "file_reputation"],
        "attack_hints":   ["T1543.003"],
        "related_events": ["4688"],
    },
    "4698": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Scheduled task created",
        "category":       "Object Access",
        "significance":   5,
        "fields":         ["TaskName", "TaskContent", "SubjectUserName"],
        "capabilities":   ["process_ancestry", "commandline_decode"],
        "attack_hints":   ["T1053"],
        "related_events": ["4688"],
    },
    "4657": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Registry value modified",
        "category":       "Object Access",
        "significance":   4,
        "fields":         ["ObjectName", "ObjectValueName", "NewValue"],
        "capabilities":   ["process_ancestry"],
        "attack_hints":   ["T1547.001", "T1112"],
        "related_events": ["4688"],
    },
    "4740": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Account locked out",
        "category":       "Account Management",
        "significance":   3,
        "fields":         ["TargetUserName", "TargetDomainName"],
        "capabilities":   ["identity_pivot"],
        "attack_hints":   ["T1110"],
        "related_events": ["4625"],
    },
    "4776": {
        "provider":       "Microsoft-Windows-Security-Auditing",
        "name":           "Credential validation",
        "category":       "Account Logon",
        "significance":   3,
        "fields":         ["TargetUserName", "Workstation", "Status"],
        "capabilities":   ["identity_pivot"],
        "attack_hints":   ["T1078"],
        "related_events": ["4624", "4625"],
    },
    "1102": {
        "provider":       "Microsoft-Windows-Eventlog",
        "name":           "Security audit log cleared",
        "category":       "Log Clearing",
        "significance":   5,
        "fields":         ["SubjectUserName"],
        "capabilities":   ["identity_pivot"],
        "attack_hints":   ["T1070.001"],
        "related_events": [],
    },
    # Sysmon
    "sysmon:1": {
        "provider":       "Microsoft-Windows-Sysmon",
        "name":           "Process create (Sysmon)",
        "category":       "Process Tracking",
        "significance":   5,
        "fields":         ["Image", "ParentImage", "CommandLine",
                              "Hashes", "User", "IntegrityLevel"],
        "capabilities":   ["process_ancestry", "commandline_decode",
                              "lolbas_lookup", "file_reputation"],
        "attack_hints":   ["T1059", "T1218"],
        "related_events": ["4688"],
    },
    "sysmon:3": {
        "provider":       "Microsoft-Windows-Sysmon",
        "name":           "Network connection (Sysmon)",
        "category":       "Network",
        "significance":   4,
        "fields":         ["Image", "DestinationIp", "DestinationPort",
                              "DestinationHostname"],
        "capabilities":   ["network_pivot", "dns_pivot", "ioc_pivot"],
        "attack_hints":   ["T1071"],
        "related_events": ["sysmon:1"],
    },
    "sysmon:11": {
        "provider":       "Microsoft-Windows-Sysmon",
        "name":           "File created (Sysmon)",
        "category":       "File",
        "significance":   3,
        "fields":         ["TargetFilename", "Image", "Hashes"],
        "capabilities":   ["file_reputation", "process_ancestry"],
        "attack_hints":   ["T1105"],
        "related_events": ["sysmon:1"],
    },
}


def get_event_intel(event_id: str,
                       provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return the intelligence descriptor for an event id."""
    key = str(event_id).strip().lower()
    if provider and provider.lower().find("sysmon") >= 0:
        key = f"sysmon:{key}"
    return WINDOWS_SECURITY_EVENTS.get(key) \
              or WINDOWS_SECURITY_EVENTS.get(str(event_id).strip())


def infer_event_id(canonical: Optional[Dict[str, Any]]) -> Optional[str]:
    """Deterministic best-effort event-id extraction from canonical
    evidence.  Returns ``None`` if no id can be honestly inferred
    (never fabricates)."""
    if not canonical:
        return None
    # Canonical `event.id`, `dsm.event_id`, or provider-specific
    # signature id mapped to a Windows Security equivalent.
    e = (canonical.get("event") or {}).get("id") \
              or (canonical.get("dsm") or {}).get("event_id")
    if e is not None:
        return str(e)
    proc = canonical.get("process") or {}
    if proc.get("name"):
        # Process telemetry present but no explicit event id — map to
        # Sysmon 1 as an honest surrogate.
        dsm = (canonical.get("dsm") or {}).get("id") or ""
        return "sysmon:1" if "sysmon" in dsm.lower() else "4688"
    return None
