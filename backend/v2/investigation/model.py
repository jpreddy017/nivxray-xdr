"""NivXRay Investigation Model — the Phase-1 foundation of AUTO
INVESTIGATE v3.

The core architectural shift: NO stage of the pipeline may write
prose, produce a recommendation, or classify a verdict from raw text.
Every downstream stage consumes THIS model. That separation is what
lets one engine deliver consistent analyst-quality reports across
Cisco XDR, CrowdStrike, Defender, SentinelOne, QRadar, Splunk,
Sysmon, and cloud alerts.

Phase-1 buckets (per spec):
  IncidentMetadata · AssetContext · ProcessActivity · FileActivity
  NetworkActivity · RegistryActivity · AuthenticationActivity
  ThreatIntelContext · HistoricalContext

Everything is intentionally source-agnostic — the *builder* is what
knows how to translate a specific vendor format. The model itself
never assumes a schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class IncidentMetadata:
    incident_id: str = ""
    detection_sources: list[str] = field(default_factory=list)
    alert_names: list[str] = field(default_factory=list)
    severity: str = ""
    detection_times: list[str] = field(default_factory=list)
    case_status: str = ""


@dataclass
class AssetContext:
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    cloud_assets: list[str] = field(default_factory=list)


@dataclass
class ProcessChain:
    grandparent: str = ""
    parent: str = ""
    process: str = ""
    child: str = ""
    command_line: str = ""
    working_directory: str = ""
    ts: str = ""
    hostname: str = ""
    user: str = ""


@dataclass
class FileEvent:
    action: str = ""              # created | executed | modified | deleted | quarantined | downloaded | renamed | restored
    path: str = ""
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    ts: str = ""
    hostname: str = ""


@dataclass
class NetworkEvent:
    protocol: str = ""            # http | https | dns | smb | ldap | kerberos …
    direction: str = ""           # inbound | outbound
    src: str = ""
    dst: str = ""
    port: int | None = None
    url: str = ""
    domain: str = ""
    dns_query: str = ""
    ts: str = ""
    classification: str = ""      # attacker | reference | benign | suspect | unknown


@dataclass
class RegistryEvent:
    action: str = ""              # created | modified | deleted
    path: str = ""
    value_name: str = ""
    value_data: str = ""
    is_persistence: bool = False   # Run keys, Services, Scheduled Tasks, CLSID
    ts: str = ""
    hostname: str = ""


@dataclass
class AuthEvent:
    kind: str = ""                # interactive | rdp | winrm | smb | kerberos | ntlm
    user: str = ""
    src_host: str = ""
    dst_host: str = ""
    result: str = ""              # success | failure
    ts: str = ""


@dataclass
class TIItem:
    kind: str = ""                # sha256 | url | domain | ip
    value: str = ""
    verdict: str = ""             # malicious | suspicious | benign | unknown
    family: str = ""              # malware family (e.g. "Banker Trojan")
    detection_name: str = ""
    source: str = ""              # "VirusTotal", "Cisco Secure Endpoint", …


@dataclass
class HistoricalItem:
    kind: str = ""                # prior_detection | same_hash | same_host | same_user | same_process
    description: str = ""
    ts: str = ""


@dataclass
class InvestigationModel:
    """The single source of truth for every downstream stage."""
    incident:  IncidentMetadata     = field(default_factory=IncidentMetadata)
    assets:    AssetContext         = field(default_factory=AssetContext)
    processes: list[ProcessChain]   = field(default_factory=list)
    files:     list[FileEvent]      = field(default_factory=list)
    network:   list[NetworkEvent]   = field(default_factory=list)
    registry:  list[RegistryEvent]  = field(default_factory=list)
    auth:      list[AuthEvent]      = field(default_factory=list)
    ti:        list[TIItem]         = field(default_factory=list)
    history:   list[HistoricalItem] = field(default_factory=list)
    # Free-form structured events surfaced by the incident parser but
    # not yet classified into one of the above buckets.
    raw_events: list[dict]          = field(default_factory=list)
    # Diagnostic — which spec-mandated evidence buckets have data?
    coverage:  dict                 = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["coverage"] = self._coverage()
        return d

    def _coverage(self) -> dict:
        return {
            "incident_metadata": bool(self.incident.incident_id or self.incident.alert_names),
            "asset_context":     bool(self.assets.hosts or self.assets.users),
            "process_activity":  bool(self.processes),
            "file_activity":     bool(self.files),
            "network_activity":  bool(self.network),
            "registry_activity": bool(self.registry),
            "authentication":    bool(self.auth),
            "threat_intel":      bool(self.ti),
            "historical":        bool(self.history),
        }


# ─── Builder — populates the model from any telemetry ────────────
# Deterministic, source-agnostic. When a source knows more (e.g. Cisco
# XDR JSON with named fields), a source-specific adapter can populate
# the model more richly — but the base builder always yields SOMETHING.

def build_model(raw: str,
                mdr_events: list[Any],
                fis: dict,
                osint: dict,
                url_buckets: dict) -> InvestigationModel:
    """Fuse every artefact we already have into the Investigation Model."""
    m = InvestigationModel()

    # ── Incident metadata ────────────────────────────────────────
    m.incident.detection_sources = sorted({e.source for e in mdr_events if getattr(e, "source", "")})
    m.incident.alert_names       = sorted({e.detection_name for e in mdr_events if getattr(e, "detection_name", "")})
    m.incident.detection_times   = sorted({e.ts_raw for e in mdr_events if getattr(e, "ts_raw", "")})
    m.incident.severity          = fis.get("severity", "")

    # ── Asset context ────────────────────────────────────────────
    m.assets.hosts   = sorted({e.hostname for e in mdr_events if getattr(e, "hostname", "")})
    m.assets.users   = sorted({e.user for e in mdr_events if getattr(e, "user", "")})
    m.assets.domains = sorted({d for d in fis.get("iocs", {}).get("domains", []) or [] if _looks_internal(d)})

    # ── Process activity ─────────────────────────────────────────
    for e in mdr_events:
        if getattr(e, "process", "") or getattr(e, "command_line", ""):
            m.processes.append(ProcessChain(
                parent=e.parent_process, process=e.process,
                child=e.child_process, command_line=e.command_line,
                ts=e.ts_raw, hostname=e.hostname, user=e.user,
            ))

    # ── File activity ────────────────────────────────────────────
    for e in mdr_events:
        if e.sha256 or e.path:
            m.files.append(FileEvent(
                action=e.action or "observed",
                path=e.path, sha256=e.sha256, sha1=e.sha1, md5=e.md5,
                ts=e.ts_raw, hostname=e.hostname,
            ))

    # ── Network activity (from URL classification) ───────────────
    for cls, entries in (url_buckets or {}).items():
        for u in entries:
            m.network.append(NetworkEvent(
                protocol=("https" if u["url"].startswith("https") else "http"),
                direction="outbound",
                url=u["url"], domain=u.get("host", ""),
                port=u.get("port"),
                classification=cls,
            ))
    for ip in fis.get("iocs", {}).get("ips") or []:
        m.network.append(NetworkEvent(
            protocol="", direction="outbound", dst=ip,
            classification=("benign" if _looks_private(ip) else "unknown"),
        ))

    # ── Threat intelligence ──────────────────────────────────────
    hits = (osint or {}).get("hits") or {}
    for k, entries in hits.items():
        for it in entries or []:
            if isinstance(it, dict):
                m.ti.append(TIItem(
                    kind=k.rstrip("s"), value=it.get("value", ""),
                    verdict=it.get("verdict", ""),
                    family=it.get("family", ""),
                    detection_name=it.get("detection_name", ""),
                    source=it.get("source", "local_ti"),
                ))
            elif isinstance(it, str):
                m.ti.append(TIItem(kind=k.rstrip("s"), value=it,
                                   source="local_ti"))
    # Named threats from mdr events
    for e in mdr_events:
        if getattr(e, "threat_name", ""):
            m.ti.append(TIItem(kind="detection", value=e.threat_name,
                               detection_name=e.detection_name,
                               source=e.source or "endpoint"))

    # ── Historical context — dedup on host / hash ────────────────
    seen_hosts = {e.hostname for e in mdr_events if e.hostname}
    if len(mdr_events) > 1:
        m.history.append(HistoricalItem(
            kind="same_host",
            description=(f"{len(mdr_events)} events observed on the same "
                         f"host{'(s)' if len(seen_hosts) > 1 else ''} "
                         f"{sorted(seen_hosts) or '(unknown)'}."),
        ))
    hashes = {e.sha256 for e in mdr_events if e.sha256}
    if len(hashes) > 1:
        m.history.append(HistoricalItem(
            kind="multiple_hashes",
            description=f"{len(hashes)} distinct file hashes observed in the incident."))

    # ── Raw events (preserve everything) ─────────────────────────
    m.raw_events = [e.to_dict() for e in mdr_events]
    m.coverage = m._coverage()
    return m


def _looks_private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _looks_internal(host: str) -> bool:
    h = (host or "").lower()
    return h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan")
