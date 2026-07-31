"""Input Understanding Engine (IUE).

Before any decoder, IOC extractor, or verdict engine runs, the IUE asks
ONE question: "What did I just receive?" — and answers with a
deterministic fingerprint that classifies the input into one of a
fixed set of analyst-recognisable types. This fingerprint is stamped
into ``cio.input_understanding`` and drives:

  - The TOPBAR input-type badge on Lab v2.
  - The choice of downstream pipeline (auto-investigate vs decode).
  - The opening paragraph of the analyst narrative ("I received a
    Cisco XDR incident with N events, ...").

The IUE is intentionally simple and structural: regex + JSON-key
fingerprints, no LLM, no network, deterministic. It NEVER modifies
the input — it only classifies it.

Categories (17 total):
    cisco_xdr | crowdstrike | defender | qradar | sentinelone |
    splunk | sysmon_xml | windows_event | powershell | cmd | bash |
    base64 | stix | yara | email_headers | ioc_list | json_generic |
    unknown

Return shape (JSON-serialisable dict):
    {
      "type": "cisco_xdr",             # canonical short id
      "label": "Cisco XDR Incident",   # analyst-facing label
      "confidence": 0.92,               # 0..1 — higher when multiple
                                        # fingerprints hit
      "fingerprints": [                # ordered fingerprints that fired
        "json_root_object", "vendor:Cisco XDR",
        "keys:[incident, references, entities]"
      ],
      "route": "auto-investigate",     # v2/auto-investigate | decode/smart
      "size_bytes": 4321,
      "line_count": 1,
    }
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

# ── Canonical types + analyst-facing labels ──────────────────────────
INPUT_TYPES: Dict[str, str] = {
    "cisco_xdr":         "Cisco XDR Incident",
    "crowdstrike":       "CrowdStrike Falcon Detection",
    "defender":          "Microsoft Defender Alert",
    "sentinelone":       "SentinelOne Threat",
    "qradar":            "IBM QRadar Offense",
    "splunk":            "Splunk Notable Event",
    "sysmon_xml":        "Sysmon XML Event",
    "windows_event":     "Windows Event Log",
    "powershell":        "PowerShell Command",
    "cmd":               "Windows CMD Command",
    "bash":              "Unix Shell Command",
    "base64":            "Base64-Encoded Blob",
    "stix":              "STIX 2.x Bundle",
    "yara":              "YARA Rule",
    "email_headers":     "Email Headers",
    "ioc_list":          "IOC List",
    "json_generic":      "Generic JSON Payload",
    "unknown":           "Unclassified Input",
}

# Routing decisions — every classified type maps to the right pipeline.
_ROUTE_BY_TYPE: Dict[str, str] = {
    "cisco_xdr":     "auto-investigate",
    "crowdstrike":   "auto-investigate",
    "defender":      "auto-investigate",
    "sentinelone":   "auto-investigate",
    "qradar":        "auto-investigate",
    "splunk":        "auto-investigate",
    "sysmon_xml":    "auto-investigate",
    "windows_event": "auto-investigate",
    "stix":          "auto-investigate",
    "email_headers": "auto-investigate",
    "ioc_list":      "auto-investigate",
    "json_generic":  "auto-investigate",
    # Payload-flavoured inputs go through the deep decoder pipeline.
    "powershell":    "decode",
    "cmd":           "decode",
    "bash":          "decode",
    "base64":        "decode",
    "yara":          "decode",
    "unknown":       "decode",
}

# JSON-key fingerprints per vendor.
_VENDOR_JSON_FINGERPRINTS: List[Tuple[str, set]] = [
    ("cisco_xdr", {"incident_id", "references", "entities", "detections"}),
    ("cisco_xdr", {"connector_guid", "computer", "detection"}),   # Secure Endpoint
    ("crowdstrike", {"falcon_host_link", "event_simpleName"}),
    ("crowdstrike", {"DeviceName", "TacticName", "TechniqueName"}),
    ("defender", {"AlertId", "detectionSource"}),
    ("defender", {"alertId", "computerDnsName", "severity"}),
    ("sentinelone", {"agentDetectionInfo", "threatInfo"}),
    ("qradar", {"offense_source", "magnitude", "credibility"}),
    ("qradar", {"qid", "offenseId", "categoryName"}),
    ("splunk", {"index", "sourcetype", "raw"}),
    ("splunk", {"search_name", "risk_score"}),
]

# Structural regex fingerprints for non-JSON inputs.
_PS_HINTS = re.compile(
    r"(?i)\b(powershell(\.exe)?|-EncodedCommand|IEX|Invoke-Expression|"
    r"New-Object|DownloadString|Get-Process|Set-ExecutionPolicy|"
    r"Import-Module|Start-BitsTransfer|Invoke-Item|Invoke-WebRequest|"
    r"Start-Sleep|Get-Content|Add-Type|Out-File|Reflection\.Assembly|"
    r"\$env:|\.ps1|\-NoProfile|\-WindowStyle|\-nop\b|\-ExecutionPolicy)\b"
)
_CMD_HINTS = re.compile(
    r"(?i)(^|\s)(cmd(\.exe)?|reg\.exe|certutil\.exe|bitsadmin\.exe|"
    r"mshta\.exe|regsvr32\.exe|schtasks\.exe|net\.exe|whoami|"
    r"cscript\.exe|wmic\.exe|copy\s+\/y|del\s+\/f)"
)
_BASH_HINTS = re.compile(
    r"(?im)(^\s*#!\/(bin|usr)\/(bash|sh|zsh)|"
    r"\b(wget|curl|chmod\s+\+x|bash\s+-c|sh\s+-c)\b)"
)
_BASE64_ONLY = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_SYSMON_XML = re.compile(r"(?i)<Event\b[^>]*xmlns=[\"']http:\/\/schemas\.microsoft\.com\/win\/2004\/08\/events\/event")
_WINDOWS_EVENT_XML = re.compile(r"(?i)<EventID>\d+</EventID>|<Provider Name=\"Microsoft-Windows")
_STIX_HINTS = re.compile(r"\"type\":\s*\"bundle\"|\"spec_version\":\s*\"2\.")
_YARA_RULE = re.compile(r"(?im)^\s*rule\s+\w+\s*(:\s*\w+\s*)?\{\s*(meta|strings|condition)\s*:")
_EMAIL_HDR = re.compile(r"(?im)^(Received|From|To|Subject|Message-ID|Return-Path|DKIM-Signature|X-Originating-IP):\s")
_IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?:\/\/[^\s\"'<>]+", re.I)
_HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I
)


def _looks_like_base64(text: str) -> bool:
    stripped = re.sub(r"\s+", "", text)
    return (
        len(stripped) >= 32
        and _BASE64_ONLY.match(stripped) is not None
        and len(stripped) % 4 == 0
    )


def _is_ioc_list(text: str) -> Tuple[bool, int]:
    """Detect IOC-list heuristic: 3+ lines each of which is dominated
    by an IP / URL / hash / domain and nothing else."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 3:
        return False, 0
    ioc_lines = 0
    for ln in lines:
        # Strip common bullets and commas.
        core = re.sub(r"[,\-\*\|]+", " ", ln).strip()
        if not core:
            continue
        if _URL_RE.fullmatch(core) or _IP_RE.fullmatch(core) or _HASH_RE.fullmatch(core):
            ioc_lines += 1
        elif _DOMAIN_RE.fullmatch(core) and " " not in core:
            ioc_lines += 1
    # 70%+ of non-empty lines are IOCs.
    return (ioc_lines / max(1, len(lines))) >= 0.7, ioc_lines


def _classify_json(text: str) -> Tuple[str, float, List[str]]:
    """Return (type, confidence, fingerprints) for a JSON input.
    Never raises — a JSONDecodeError bubbles up to caller."""
    doc = json.loads(text)
    fingerprints: List[str] = ["json_root_" + type(doc).__name__.lower()]
    if isinstance(doc, list):
        if doc and isinstance(doc[0], dict):
            doc = doc[0]                                        # flatten to first item
            fingerprints.append("json_root_array_of_objects")
    if not isinstance(doc, dict):
        return "json_generic", 0.4, fingerprints
    keys = set(doc.keys())
    # STIX?
    if _STIX_HINTS.search(text):
        return "stix", 0.9, fingerprints + ["stix_spec_version"]
    # Vendor JSON fingerprints.
    for vendor_type, sig in _VENDOR_JSON_FINGERPRINTS:
        overlap = sig & keys
        if len(overlap) >= max(2, len(sig) // 2):
            fingerprints.append(f"vendor:{INPUT_TYPES[vendor_type]}")
            fingerprints.append(f"keys:{sorted(overlap)}")
            return vendor_type, min(1.0, 0.6 + 0.1 * len(overlap)), fingerprints
    # Fallback loose matches.
    if "AlertId" in keys or "detectionSource" in keys:
        return "defender", 0.55, fingerprints + ["loose:defender"]
    if "falcon_host_link" in keys or "event_simpleName" in keys:
        return "crowdstrike", 0.55, fingerprints + ["loose:crowdstrike"]
    if "EventID" in keys and "EventData" in keys:
        return "sysmon_xml", 0.55, fingerprints + ["loose:sysmon"]
    # Incident-shaped fallback for anything with host/user/process/hash keys.
    incident_hint_keys = {"incident", "alert", "host", "user", "process", "hash", "sha256"}
    if len(incident_hint_keys & keys) >= 2:
        return "json_generic", 0.5, fingerprints + [f"incident_keys:{sorted(incident_hint_keys & keys)}"]
    return "json_generic", 0.35, fingerprints


def understand(input_text: str) -> Dict[str, Any]:
    """Classify an arbitrary input string. Pure function of the input —
    deterministic, no I/O, no LLM."""
    if not isinstance(input_text, str):
        return {
            "type": "unknown",
            "label": INPUT_TYPES["unknown"],
            "confidence": 0.0,
            "fingerprints": ["non_string_input"],
            "route": _ROUTE_BY_TYPE["unknown"],
            "size_bytes": 0,
            "line_count": 0,
        }

    text = input_text
    size = len(text)
    lines = text.splitlines()

    # 1. Structural JSON attempt.
    trimmed = text.strip()
    if trimmed.startswith("{") or trimmed.startswith("["):
        try:
            t, conf, fps = _classify_json(trimmed)
            return {
                "type": t,
                "label": INPUT_TYPES[t],
                "confidence": conf,
                "fingerprints": fps,
                "route": _ROUTE_BY_TYPE[t],
                "size_bytes": size,
                "line_count": len(lines),
            }
        except (json.JSONDecodeError, ValueError):
            pass                                                 # fall through

    # 2. XML — Sysmon / Windows Event.
    if trimmed.startswith("<"):
        if _SYSMON_XML.search(text):
            return _emit("sysmon_xml", 0.9, ["xml_sysmon_ns"], size, len(lines))
        if _WINDOWS_EVENT_XML.search(text):
            return _emit("windows_event", 0.85, ["xml_eventid"], size, len(lines))

    # 3. Structured line-oriented sources.
    if _EMAIL_HDR.search(text):
        return _emit("email_headers", 0.9, ["header_signature"], size, len(lines))
    if _YARA_RULE.search(text):
        return _emit("yara", 0.95, ["yara_rule_signature"], size, len(lines))
    is_ioc, ioc_count = _is_ioc_list(text)
    if is_ioc:
        return _emit("ioc_list", 0.85, [f"ioc_lines:{ioc_count}"], size, len(lines))

    # 4. Command-line flavoured single-line-heavy inputs.
    if _PS_HINTS.search(text):
        # PowerShell classifier bumps confidence when the tell-tale
        # -EncodedCommand switch is present.
        fp = ["ps_hints"]
        conf = 0.85
        if re.search(r"(?i)-EncodedCommand\b", text):
            fp.append("encoded_command")
            conf = 0.95
        return _emit("powershell", conf, fp, size, len(lines))
    if _CMD_HINTS.search(text):
        return _emit("cmd", 0.75, ["cmd_hints"], size, len(lines))
    if _BASH_HINTS.search(text):
        return _emit("bash", 0.75, ["bash_hints"], size, len(lines))

    # 5. Pure Base64.
    if _looks_like_base64(text):
        return _emit("base64", 0.9, ["base64_only_chars"], size, len(lines))

    # 6. Splunk raw log heuristic — key=value pairs on one line.
    if re.search(r"\b\w+=[^\s,]+", text) and text.count("=") >= 5 and len(lines) <= 5:
        return _emit("splunk", 0.6, ["kv_pairs"], size, len(lines))

    # 7. Unknown.
    return _emit("unknown", 0.2, ["no_signal"], size, len(lines))


def _emit(t: str, conf: float, fps: List[str], size: int, line_count: int) -> Dict[str, Any]:
    return {
        "type": t,
        "label": INPUT_TYPES[t],
        "confidence": round(conf, 2),
        "fingerprints": fps,
        "route": _ROUTE_BY_TYPE[t],
        "size_bytes": size,
        "line_count": line_count,
    }


__all__ = ["understand", "INPUT_TYPES"]
