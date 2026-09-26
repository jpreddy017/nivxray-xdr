"""
Rule Studio Lane Schemas — deterministic field vocabulary per lane.

Every lane exposes a curated field vocabulary sourced from real
telemetry contracts (ECS · Sigma · Sysmon · Zeek).  The schema is
consumed by the Rule Studio New Rule wizard so authors get the right
condition surface for their lane without switching to advanced DSL.

Anti-fabrication rule:  fields listed here MUST correspond to fields
NivXRay's collectors + normalization emit.  No aspirational fields.
"""
from __future__ import annotations

LANE_SCHEMAS: dict = {
    # ── Event / Log Source ──────────────────────────────────────
    "event": {
        "display_name": "Event / Log Source",
        "canonical_schema": "ecs",
        "operators": ["equals", "contains", "startswith", "endswith",
                                "regex", "in", "not_equals", "gte", "lte"],
        "fields": [
            {"key": "event.id",             "type": "int",    "example": "4688",
              "description": "Native event ID (e.g. Windows Security 4688)"},
            {"key": "event.provider",       "type": "string", "example": "Microsoft-Windows-Sysmon",
              "description": "Log provider / source"},
            {"key": "event.channel",        "type": "string", "example": "Security",
              "description": "Log channel (Security, Application, Sysmon)"},
            {"key": "event.severity",       "type": "enum",   "values": ["low", "medium", "high", "critical"]},
            {"key": "event.action",         "type": "string", "example": "logon"},
            {"key": "event.outcome",        "type": "enum",   "values": ["success", "failure", "unknown"]},
            {"key": "event.category",       "type": "string", "example": "authentication"},
            {"key": "source.ip",            "type": "ip"},
            {"key": "destination.ip",       "type": "ip"},
            {"key": "user.name",            "type": "string"},
            {"key": "host.name",            "type": "string"},
            {"key": "@timestamp",           "type": "datetime"},
        ],
        "templates": [
            {"title": "Windows failed logon 4625",
              "detection": {"selection": {"event.id": 4625,
                                                              "event.provider": "Microsoft-Windows-Security-Auditing"},
                                    "condition": "selection"}},
            {"title": "Successful admin authentication",
              "detection": {"selection": {"event.category": "authentication",
                                                              "event.outcome": "success",
                                                              "user.name|endswith": "-admin"},
                                    "condition": "selection"}},
        ],
    },
    # ── Endpoint / EDR ──────────────────────────────────────────
    "endpoint": {
        "display_name": "Endpoint / EDR",
        "canonical_schema": "ecs-endpoint",
        "operators": ["equals", "contains", "endswith", "regex", "in",
                                "not_endswith"],
        "fields": [
            {"key": "process.name",           "type": "string", "example": "powershell.exe"},
            {"key": "process.executable",     "type": "path",   "example": "C:\\Windows\\System32\\powershell.exe"},
            {"key": "process.command_line",   "type": "string"},
            {"key": "process.pid",            "type": "int"},
            {"key": "process.parent.name",    "type": "string"},
            {"key": "process.parent.command_line", "type": "string"},
            {"key": "process.hash.sha256",    "type": "hash"},
            {"key": "process.code_signature.signer", "type": "string"},
            {"key": "process.code_signature.trusted","type": "bool"},
            {"key": "file.path",              "type": "path"},
            {"key": "file.hash.sha256",       "type": "hash"},
            {"key": "registry.path",          "type": "path"},
            {"key": "registry.value.name",    "type": "string"},
            {"key": "user.name",              "type": "string"},
            {"key": "user.integrity_level",   "type": "enum",
              "values": ["low", "medium", "high", "system"]},
            {"key": "network.direction",      "type": "enum",
              "values": ["inbound", "outbound"]},
            {"key": "lolbas.capability",      "type": "string",
              "description": "NivXRay-native · LOLBIN capability observation"},
        ],
        "templates": [
            {"title": "WINWORD spawns PowerShell",
              "detection": {"selection": {"process.name|endswith": "powershell.exe",
                                                              "process.parent.name|endswith": "winword.exe"},
                                    "condition": "selection"}},
            {"title": "rundll32 launches remote payload",
              "detection": {"selection": {"process.name|endswith": "rundll32.exe",
                                                              "process.command_line|contains": "http"},
                                    "condition": "selection"}},
        ],
    },
    # ── IOC / Threat Intelligence ───────────────────────────────
    "ioc": {
        "display_name": "IOC / Threat Intelligence",
        "canonical_schema": "stix",
        "operators": ["equals", "in", "contains", "regex"],
        "fields": [
            {"key": "ioc.type",       "type": "enum",
              "values": ["ipv4", "ipv6", "domain", "url", "sha256",
                                "sha1", "md5", "email", "certificate"]},
            {"key": "ioc.value",      "type": "string"},
            {"key": "ioc.list",       "type": "string",
              "description": "Threat-intel feed name (e.g. urlhaus, misp)"},
            {"key": "ioc.confidence", "type": "int",
              "description": "0-100"},
            {"key": "ioc.first_seen", "type": "datetime"},
            {"key": "ioc.last_seen",  "type": "datetime"},
            {"key": "ioc.provider",   "type": "string"},
        ],
        "templates": [
            {"title": "IP present in URLhaus + observed egress",
              "detection": {"ioc":     {"ioc.type": "ipv4",
                                                        "ioc.list": "urlhaus"},
                                    "observed": {"destination.ip|match": "$ioc.value"},
                                    "condition": "ioc and observed"}},
        ],
    },
    # ── Network / IDS / IPS ────────────────────────────────────
    "network": {
        "display_name": "Network / IDS / IPS",
        "canonical_schema": "ecs-network-flow",
        "operators": ["equals", "contains", "in", "gte", "lte", "regex"],
        "fields": [
            {"key": "network.protocol",    "type": "enum",
              "values": ["tcp", "udp", "icmp", "http", "tls", "dns", "smb"]},
            {"key": "network.transport",   "type": "string"},
            {"key": "network.direction",   "type": "enum",
              "values": ["inbound", "outbound", "internal"]},
            {"key": "destination.port",    "type": "int"},
            {"key": "source.port",         "type": "int"},
            {"key": "destination.ip",      "type": "ip"},
            {"key": "source.ip",           "type": "ip"},
            {"key": "tls.server.subject.common_name", "type": "string"},
            {"key": "tls.ja3",             "type": "string"},
            {"key": "tls.ja4",             "type": "string"},
            {"key": "http.request.method", "type": "string"},
            {"key": "http.user_agent",     "type": "string"},
            {"key": "http.url.path",       "type": "string"},
            {"key": "ids.signature.id",    "type": "int"},
            {"key": "ids.signature.severity","type": "enum",
              "values": ["low", "medium", "high", "critical"]},
        ],
        "templates": [
            {"title": "Outbound HTTP with curl UA to external",
              "detection": {"selection": {"network.direction": "outbound",
                                                              "http.user_agent|startswith": "curl/"},
                                    "condition": "selection"}},
            {"title": "TLS to self-signed cert outbound",
              "detection": {"selection": {"network.protocol": "tls",
                                                              "network.direction": "outbound",
                                                              "tls.server.subject.common_name|contains": "self-signed"},
                                    "condition": "selection"}},
        ],
    },
}


def get_lane_schema(lane: str) -> dict | None:
    return LANE_SCHEMAS.get(lane)


def all_lane_schemas() -> dict:
    return LANE_SCHEMAS
