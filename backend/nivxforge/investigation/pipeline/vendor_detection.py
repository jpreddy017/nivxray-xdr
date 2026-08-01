"""Stage 3 · Vendor Detection.

Given a `ParsedInput` from Stage 2, identify the originating vendor so
Stage 4 (Normalization) knows which adapter to run. Detection is
STRUCTURAL (looks at record shape / key inventory) — NOT filename or
Content-Type based.

Vendor codes are stable identifiers used across the pipeline
(`vendor_route` in CEM). Adding a new vendor here is additive and
never modifies existing codes.

Detection returns confidence 0..1. If nothing matches, returns
`generic_json` (or `plain_text` for non-record inputs) so downstream
stages ALWAYS have a normalizer to run.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .input_classification import InputClass
from .parser import ParsedInput


class Vendor:
    CISCO_SECURE_ENDPOINT = "cisco_secure_endpoint"
    CISCO_XDR = "cisco_xdr"
    SYSMON = "sysmon"
    WINDOWS_EVENT = "windows_event"
    DEFENDER = "microsoft_defender"
    CROWDSTRIKE = "crowdstrike"
    SURICATA = "suricata"
    ZEEK = "zeek"
    GENERIC_JSON = "generic_json"
    ENCODED_COMMAND = "encoded_command"
    PLAIN_COMMAND = "plain_command"
    PLAIN_TEXT = "plain_text"


@dataclass(frozen=True)
class VendorDetection:
    vendor: str
    confidence: float
    reason: str
    matched_keys: List[str]


# Signature = (vendor, [required_keys_any_of], [any_of_key_substrings], confidence)
_JSON_SIGNATURES: List[Dict[str, Any]] = [
    {
        # Cisco Secure Endpoint via the CMS MDR / z_product feed — flat
        # JSON with `conn_guid` / `src_host` / `console.amp.cisco.com` /
        # `z_product: "Secure Endpoint"`.
        "vendor": Vendor.CISCO_SECURE_ENDPOINT,
        "must_any": ["conn_guid", "z_product", "console_link",
                      "src_host", "src_ip", "detection"],
        "must_all": [],
        "value_hints": ["console.amp.cisco.com", "cisco:amp:event",
                         "Secure Endpoint", "cisco secure endpoint",
                         "amp for endpoints", "cisco amp",
                         "mdr_fileless", "z_product"],
        "confidence": 0.95,
    },
    {
        "vendor": Vendor.CISCO_SECURE_ENDPOINT,
        "must_any": ["computer", "detection", "event_type_id",
                      "cloud_ioc", "connector_guid"],
        "must_all": [],
        "value_hints": ["cisco secure endpoint", "amp for endpoints",
                         "cisco amp", "secure endpoint"],
        "confidence": 0.95,
    },
    {
        "vendor": Vendor.CISCO_XDR,
        "must_any": ["incident_id", "detection_source", "asset",
                      "playbook", "observables"],
        "must_all": [],
        "value_hints": ["cisco xdr", "xdr incident"],
        "confidence": 0.9,
    },
    {
        "vendor": Vendor.SYSMON,
        "must_any": ["EventID", "System", "EventData", "Image",
                      "ParentImage", "CommandLine", "ProcessGuid"],
        "must_all": [],
        "value_hints": ["Sysmon", "Microsoft-Windows-Sysmon"],
        "confidence": 0.9,
    },
    {
        "vendor": Vendor.WINDOWS_EVENT,
        "must_any": ["EventRecordID", "Provider", "Channel",
                      "TimeCreated"],
        "must_all": [],
        "value_hints": ["Microsoft-Windows-Security-Auditing",
                         "Microsoft-Windows-PowerShell"],
        "confidence": 0.75,
    },
    {
        "vendor": Vendor.DEFENDER,
        "must_any": ["AlertId", "AlertTitle", "DeviceName",
                      "ThreatFamilyName", "InitiatingProcessCommandLine"],
        "must_all": [],
        "value_hints": ["Microsoft Defender", "MDE"],
        "confidence": 0.9,
    },
    {
        "vendor": Vendor.CROWDSTRIKE,
        "must_any": ["falcon_host_link", "aid", "cid",
                      "ExternalApiType", "DetectDescription"],
        "must_all": [],
        "value_hints": ["CrowdStrike", "Falcon"],
        "confidence": 0.9,
    },
    {
        "vendor": Vendor.SURICATA,
        "must_any": ["event_type", "alert", "src_ip", "dest_ip",
                      "flow_id", "signature"],
        "must_all": [],
        "value_hints": ["Suricata"],
        "confidence": 0.7,
    },
    {
        "vendor": Vendor.ZEEK,
        "must_any": ["uid", "id.orig_h", "id.resp_h", "proto"],
        "must_all": [],
        "value_hints": ["Zeek", "Bro"],
        "confidence": 0.75,
    },
]


def _collect_record_keys(recs: List[Dict[str, Any]]) -> List[str]:
    keys = set()
    def _walk(o, depth=0):
        if depth > 4:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                keys.add(k)
                _walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o[:5]:
                _walk(v, depth + 1)
    for r in recs[:20]:
        _walk(r)
    return sorted(keys)


def _text_hints(recs: List[Dict[str, Any]], hints: List[str]) -> bool:
    if not hints:
        return False
    hay = ""
    def _flatten(o, depth=0):
        nonlocal hay
        if depth > 4 or len(hay) > 20000:
            return
        if isinstance(o, dict):
            for v in o.values():
                _flatten(v, depth + 1)
        elif isinstance(o, list):
            for v in o[:5]:
                _flatten(v, depth + 1)
        elif isinstance(o, str):
            hay += " " + o
    for r in recs[:5]:
        _flatten(r)
    hay_l = hay.lower()
    return any(h.lower() in hay_l for h in hints)


def detect_vendor(parsed: ParsedInput) -> VendorDetection:
    """Detect vendor from a `ParsedInput`. Never raises."""
    if parsed.kind == InputClass.EMPTY:
        return VendorDetection(Vendor.PLAIN_TEXT, 1.0,
                                "empty input", [])
    if parsed.kind == InputClass.ENCODED_CMD:
        return VendorDetection(Vendor.ENCODED_COMMAND, 0.98,
                                "encoded powershell command detected", [])
    if parsed.kind == InputClass.PLAIN_COMMAND:
        return VendorDetection(Vendor.PLAIN_COMMAND, 0.9,
                                "plain command line detected", [])
    if parsed.kind == InputClass.PLAIN_TEXT:
        return VendorDetection(Vendor.PLAIN_TEXT, 0.5,
                                "unstructured text", [])
    if parsed.kind == InputClass.XML:
        # XML with EventID + ProcessGuid = Sysmon.
        keys = _collect_record_keys(parsed.records)
        if "EventID" in keys and any(
            k in keys for k in ("ProcessGuid", "Image", "CommandLine")
        ):
            return VendorDetection(Vendor.SYSMON, 0.9,
                                    "xml carries sysmon shape",
                                    ["EventID", "ProcessGuid"])
        return VendorDetection(Vendor.WINDOWS_EVENT, 0.7,
                                "xml event data", keys[:10])

    if parsed.kind == InputClass.KEY_VALUE:
        keys = _collect_record_keys(parsed.records)
        if any(k in keys for k in ("id.orig_h", "id.resp_h", "uid")):
            return VendorDetection(Vendor.ZEEK, 0.8, "zeek kv fields",
                                    keys[:10])
        if any(k in keys for k in ("src_ip", "dest_ip", "signature")):
            return VendorDetection(Vendor.SURICATA, 0.7, "suricata kv",
                                    keys[:10])
        return VendorDetection(Vendor.GENERIC_JSON, 0.4,
                                "kv without vendor markers", keys[:10])

    # JSON / NDJSON / CSV → score signatures.
    if parsed.kind not in (InputClass.JSON, InputClass.NDJSON,
                            InputClass.CSV):
        return VendorDetection(Vendor.GENERIC_JSON, 0.4,
                                "unclassified structured input", [])

    keys = _collect_record_keys(parsed.records)
    best: Optional[VendorDetection] = None
    for sig in _JSON_SIGNATURES:
        matched: List[str] = []
        for k in sig["must_any"]:
            # Case-sensitive first (Cisco `computer` ≠ Sysmon `Computer`).
            if k in keys:
                matched.append(k)
        must_all_ok = True
        for k in sig.get("must_all", []):
            if k not in keys:
                must_all_ok = False
                break
        if not must_all_ok:
            continue
        if not matched and not _text_hints(parsed.records,
                                           sig.get("value_hints", [])):
            continue
        base = sig["confidence"]
        boost = 0.02 * (len(matched) - 1) if matched else 0.0
        conf = min(0.99, base + boost)
        if _text_hints(parsed.records, sig.get("value_hints", [])):
            conf = min(0.99, conf + 0.05)
        cand = VendorDetection(
            sig["vendor"], conf,
            f"matched {len(matched)} keys" if matched else "text hint",
            matched,
        )
        if best is None or cand.confidence > best.confidence:
            best = cand

    if best:
        return best

    return VendorDetection(Vendor.GENERIC_JSON, 0.4,
                            "no vendor signature matched",
                            keys[:10])


__all__ = ["Vendor", "VendorDetection", "detect_vendor"]
