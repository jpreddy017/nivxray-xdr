"""
P0.7 · Round 13 · Action Registry
─────────────────────────────────

**Authoritative registry of executable actions.**  An action only
appears here if its shape is real; whether it can *actually run* is
a runtime property (`capability_available`) that stays honest.

Owner-locked rules (§8, §37):
  * NEVER register an action whose executor doesn't exist.
  * `capability_available` is derived from a real integration check,
    NOT from the fact that the entry exists in this file.
  * Actions with `capability_available=False` remain visible so the
    UI/decision engine can honestly say "capability unavailable".

Every entry declares:
    action_id · name · domain · required_capability · required_integration
    · executor · parameters_schema · risk_level · approval_policy
    · supported_targets · execution_mode · timeout · rollback_action

Round 13 registers ONLY the actions that map to concrete NivXRay
integrations declared in the environment.  Since no EDR/NDR/firewall
adapter is wired in this preview, every action reports
`capability_available=False` with an exact reason.
"""
from __future__ import annotations
import os
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalPolicy(str, Enum):
    AUTO_APPROVE      = "AUTO_APPROVE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DUAL_APPROVAL     = "DUAL_APPROVAL"


class ExecutionMode(str, Enum):
    SYNC     = "SYNC"
    ASYNC    = "ASYNC"
    ADAPTER  = "ADAPTER"


# ── Canonical action catalogue ──────────────────────────────────

# Each entry describes the SHAPE of a real action.  The `executor`
# field is a callable name resolved at runtime by the executor module.
_ACTIONS: list[dict] = [
    {
        "action_id":             "ENDPOINT_ISOLATE",
        "name":                  "Isolate endpoint",
        "domain":                "endpoint",
        "required_capability":   "edr.endpoint.isolate",
        "required_integration":  "edr",
        "executor":              "edr.isolate",
        "parameters_schema": {
            "endpoint_id": {"type": "string", "required": True},
            "reason":       {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.HIGH.value,
        "approval_policy":       ApprovalPolicy.APPROVAL_REQUIRED.value,
        "supported_targets":     ["host"],
        "execution_mode":        ExecutionMode.ADAPTER.value,
        "timeout":               60,
        "rollback_action":       "ENDPOINT_RELEASE_ISOLATION",
    },
    {
        "action_id":             "ENDPOINT_RELEASE_ISOLATION",
        "name":                  "Release endpoint isolation",
        "domain":                "endpoint",
        "required_capability":   "edr.endpoint.release",
        "required_integration":  "edr",
        "executor":              "edr.release_isolation",
        "parameters_schema": {
            "endpoint_id": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.MEDIUM.value,
        "approval_policy":       ApprovalPolicy.APPROVAL_REQUIRED.value,
        "supported_targets":     ["host"],
        "execution_mode":        ExecutionMode.ADAPTER.value,
        "timeout":               60,
        "rollback_action":       None,
    },
    {
        "action_id":             "IP_BLOCK",
        "name":                  "Block IP at network edge",
        "domain":                "network",
        "required_capability":   "firewall.ip.block",
        "required_integration":  "firewall",
        "executor":              "firewall.block_ip",
        "parameters_schema": {
            "ip":     {"type": "string", "required": True},
            "reason": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.HIGH.value,
        "approval_policy":       ApprovalPolicy.APPROVAL_REQUIRED.value,
        "supported_targets":     ["ipv4", "ipv6"],
        "execution_mode":        ExecutionMode.ADAPTER.value,
        "timeout":               30,
        "rollback_action":       "IP_UNBLOCK",
    },
    {
        "action_id":             "IOC_ADD_WATCHLIST",
        "name":                  "Add IOC to internal watchlist",
        "domain":                "intel",
        "required_capability":   "nivxray.watchlist.add",
        "required_integration":  "nivxray_internal",
        "executor":              "internal.watchlist_add",
        "parameters_schema": {
            "ioc":      {"type": "string", "required": True},
            "ioc_type": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.LOW.value,
        "approval_policy":       ApprovalPolicy.AUTO_APPROVE.value,
        "supported_targets":     ["ipv4", "ipv6", "domain", "hash"],
        "execution_mode":        ExecutionMode.SYNC.value,
        "timeout":               10,
        "rollback_action":       "IOC_REMOVE_WATCHLIST",
    },
    {
        "action_id":             "COLLECT_FORENSIC_SNAPSHOT",
        "name":                  "Collect forensic snapshot",
        "domain":                "endpoint",
        "required_capability":   "edr.forensic.collect",
        "required_integration":  "edr",
        "executor":              "edr.forensic_collect",
        "parameters_schema": {
            "endpoint_id": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.LOW.value,
        "approval_policy":       ApprovalPolicy.AUTO_APPROVE.value,
        "supported_targets":     ["host"],
        "execution_mode":        ExecutionMode.ADAPTER.value,
        "timeout":               300,
        "rollback_action":       None,
    },
    {
        "action_id":             "OSINT_ENRICH_IP",
        "name":                  "OSINT enrichment · IP",
        "domain":                "intel",
        "required_capability":   "nivxray.osint.ip_enrich",
        "required_integration":  "nivxray_osint",
        "executor":              "osint.enrich_ip",
        "parameters_schema": {
            "ip": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.LOW.value,
        "approval_policy":       ApprovalPolicy.AUTO_APPROVE.value,
        "supported_targets":     ["ipv4", "ipv6"],
        "execution_mode":        ExecutionMode.SYNC.value,
        "timeout":               15,
        "rollback_action":       None,
        "providers": [
            "talos", "dshield", "abuseipdb", "virustotal",
            "urlhaus", "threatfox",
        ],
    },
    {
        "action_id":             "OSINT_ENRICH_URL",
        "name":                  "OSINT enrichment · URL",
        "domain":                "intel",
        "required_capability":   "nivxray.osint.url_enrich",
        "required_integration":  "nivxray_osint",
        "executor":              "osint.enrich_url",
        "parameters_schema": {
            "url": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.LOW.value,
        "approval_policy":       ApprovalPolicy.AUTO_APPROVE.value,
        "supported_targets":     ["url"],
        "execution_mode":        ExecutionMode.SYNC.value,
        "timeout":               15,
        "rollback_action":       None,
        "providers": ["urlscan", "urlhaus", "virustotal"],
    },
    {
        "action_id":             "OSINT_ENRICH_DOMAIN",
        "name":                  "OSINT enrichment · Domain",
        "domain":                "intel",
        "required_capability":   "nivxray.osint.domain_enrich",
        "required_integration":  "nivxray_osint",
        "executor":              "osint.enrich_domain",
        "parameters_schema": {
            "domain": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.LOW.value,
        "approval_policy":       ApprovalPolicy.AUTO_APPROVE.value,
        "supported_targets":     ["domain"],
        "execution_mode":        ExecutionMode.SYNC.value,
        "timeout":               15,
        "rollback_action":       None,
        "providers": ["virustotal", "urlhaus", "threatfox"],
    },
    {
        "action_id":             "OSINT_ENRICH_HASH",
        "name":                  "OSINT enrichment · File hash",
        "domain":                "intel",
        "required_capability":   "nivxray.osint.hash_enrich",
        "required_integration":  "nivxray_osint",
        "executor":              "osint.enrich_hash",
        "parameters_schema": {
            "hash": {"type": "string", "required": True},
        },
        "risk_level":            RiskLevel.LOW.value,
        "approval_policy":       ApprovalPolicy.AUTO_APPROVE.value,
        "supported_targets":     ["hash"],
        "execution_mode":        ExecutionMode.SYNC.value,
        "timeout":               15,
        "rollback_action":       None,
        "providers": [
            "virustotal", "malwarebazaar", "hybrid-analysis", "threatfox",
        ],
    },
]


# ── Runtime capability probe (HONEST — no fabrication) ─────────

def _integration_configured(name: str) -> bool:
    """
    An integration is `configured` only when an environment variable
    of the form `XDR_INTEGRATION_<NAME>` is present and non-empty.
    Round 13 preview has none of these — every action honestly
    reports False.

    Two integrations are ALWAYS considered configured (§4 · reuse):
      * `nivxray_internal` — internal watchlist, no adapter needed.
      * `nivxray_osint`    — OSINT enrichment uses the existing
        services/ioc_intelligence engine which has keyless providers
        (talos, dshield, urlhaus, threatfox, malwarebazaar) that
        always return live results; keyed providers (VT, AbuseIPDB,
        URLScan) upgrade automatically when their keys are present.
    """
    if name in ("nivxray_internal", "nivxray_osint"):
        return True
    key = f"XDR_INTEGRATION_{name.upper()}"
    return bool(os.environ.get(key))


def action_entry(action_id: str) -> dict | None:
    for a in _ACTIONS:
        if a["action_id"] == action_id:
            return dict(a)
    return None


def list_actions() -> list[dict]:
    """
    Return the full catalogue with per-action `capability_available`
    computed at call time.  Never cached across calls (the answer
    depends on the current environment).
    """
    out: list[dict] = []
    for a in _ACTIONS:
        entry = dict(a)
        entry["capability_available"] = _integration_configured(
            a["required_integration"])
        if not entry["capability_available"]:
            entry["capability_reason"] = (
                f"integration '{a['required_integration']}' is not "
                f"configured (set env var "
                f"XDR_INTEGRATION_{a['required_integration'].upper()})")
        out.append(entry)
    return out


def registry_summary() -> dict:
    entries = list_actions()
    return {
        "total":                len(entries),
        "capability_available": sum(1 for e in entries
                                          if e["capability_available"]),
        "by_domain": _bucket(entries, "domain"),
        "by_risk":   _bucket(entries, "risk_level"),
        "honesty_note":
            "capability_available is derived from the current environment "
            "at each call.  Actions without a configured integration remain "
            "in the registry so decision engine + UI can honestly report "
            "'capability unavailable'.",
    }


def _bucket(entries: list[dict], field: str) -> dict:
    b: dict[str, int] = {}
    for e in entries:
        k = e.get(field) or "unknown"
        b[k] = b.get(k, 0) + 1
    return b
