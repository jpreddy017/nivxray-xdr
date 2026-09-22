"""Windows Event Log acquisition — the PERMANENT multi-channel adapter.

W2-1 · Program B. This replaces nothing about W1: the W1 PowerShell/Sysmon
forwarder stays frozen as historical evidence and is **not** grown into the
permanent architecture. This adapter is the architecture:

    Windows Event Log
      → native subscription (EvtSubscribe, per channel, XPath-filtered)
      → channel bookmark (durable, per tenant/collector/channel)
      → durable outbox (existing SQLite engine)
      → authenticated NivX ingestion
      → raw persistence → DSM → normalization → canonical evidence

The acquisition invariant is preserved literally:

    Read → Make Durable → Advance Acquisition → Deliver → Account → Verify

`collect()` performs **Read** and returns envelopes; the runtime performs
Make Durable (outbox) and Deliver; `advance()` performs Advance Acquisition
only after the outbox has the records. Delivery accounting stays with the
outbox and is reflected back through `WindowsBookmarkStore.commit_delivered`.

PLATFORM HONESTY
This collector runs on Linux in this deployment. The native reader binds
`win32evtlog` only on Windows; everywhere else the adapter reports
`UNSUPPORTED_PLATFORM` and collects NOTHING. It never simulates a Windows
event, and a channel it could not read is reported as unread — never as
empty and never as healthy.

DELIBERATE NON-BEHAVIOURS
  * No SID→name rendering at the endpoint. A SID is preserved verbatim;
    principal resolution is an enrichment decision for the core, which has
    the directory context and the audit trail for it.
  * No EventRecordID-only checkpoint (see `windows_bookmarks`).
  * No message-string rendering as the authority: raw XML is preserved.
  * No collapsing of the three clocks — activity, sensor observation and
    ingestion stay separate all the way through.
"""
from __future__ import annotations

import os
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol

from framework.base import Capability, Connector, Envelope, Health
from framework.windows_bookmarks import (
    RESUME_FRESH, RESUME_LOG_CLEARED, RESUME_STALE, WindowsBookmarkStore,
)

PARSER_VERSION = "windows-eventlog/1.0.0"
COLLECTION_METHOD = "windows-eventlog"

#: Channels this adapter is architected for. Adding one is a PROFILE change,
#: never another collector. `supported` means the adapter knows the channel's
#: identity and declared source; it does not claim telemetry exists.
#: COLLECTION SUPPORT — can this adapter acquire the channel reliably?
#: This is a DIFFERENT fact from analysis support below, and the two are never
#: merged: XML reaching the server does not mean the platform understands it.
#: `declared_source` is what the delivery declares at the authenticated ingest
#: boundary; an unmapped channel would be refused with DECLARATION_REQUIRED.
CHANNELS: Dict[str, Dict[str, str]] = {
    # ── Critical security value ───────────────────────────────────
    "Microsoft-Windows-Sysmon/Operational": {
        "declared_source": "sysmon", "label": "Sysmon", "value": "CRITICAL"},
    "Security": {
        "declared_source": "windows_security", "label": "Security",
        "value": "CRITICAL"},
    "Microsoft-Windows-PowerShell/Operational": {
        "declared_source": "windows_powershell",
        "label": "PowerShell Operational", "value": "CRITICAL"},
    "Windows PowerShell": {
        "declared_source": "windows_powershell",
        "label": "Windows PowerShell (classic)", "value": "HIGH"},
    "Microsoft-Windows-Windows Defender/Operational": {
        "declared_source": "microsoft_defender",
        "label": "Microsoft Defender", "value": "CRITICAL"},
    # ── High security value ───────────────────────────────────────
    "Microsoft-Windows-TaskScheduler/Operational": {
        "declared_source": "windows_task_scheduler",
        "label": "Task Scheduler", "value": "HIGH"},
    "Microsoft-Windows-WMI-Activity/Operational": {
        "declared_source": "windows_wmi", "label": "WMI Activity",
        "value": "HIGH"},
    "Microsoft-Windows-AppLocker/EXE and DLL": {
        "declared_source": "windows_applocker", "label": "AppLocker",
        "value": "HIGH"},
    "Microsoft-Windows-CodeIntegrity/Operational": {
        "declared_source": "windows_code_integrity", "label": "Code Integrity",
        "value": "HIGH"},
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": {
        "declared_source": "windows_rdp", "label": "RDP · local session",
        "value": "HIGH"},
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": {
        "declared_source": "windows_rdp", "label": "RDP · remote connection",
        "value": "HIGH"},
    "Microsoft-Windows-WinRM/Operational": {
        "declared_source": "windows_winrm", "label": "WinRM", "value": "HIGH"},
    "Microsoft-Windows-DNS-Client/Operational": {
        "declared_source": "windows_dns_client", "label": "DNS Client",
        "value": "HIGH"},
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": {
        "declared_source": "windows_firewall", "label": "Windows Firewall",
        "value": "HIGH"},
    "Microsoft-Windows-SmbClient/Security": {
        "declared_source": "windows_smb", "label": "SMB client security",
        "value": "HIGH"},
    "Directory Service": {
        "declared_source": "windows_directory_service",
        "label": "Directory Service (DC)", "value": "CRITICAL"},
    "Microsoft-Windows-DNSServer/Audit": {
        "declared_source": "windows_dns_server", "label": "DNS Server audit",
        "value": "HIGH"},
    # ── Operational / posture ─────────────────────────────────────
    "System": {"declared_source": "windows_system", "label": "System",
               "value": "HIGH"},
    "Application": {"declared_source": "windows_application",
                    "label": "Application", "value": "MEDIUM"},
    "Microsoft-Windows-BitLocker/BitLocker Management": {
        "declared_source": "windows_bitlocker", "label": "BitLocker",
        "value": "MEDIUM"},
    "Microsoft-Windows-WindowsUpdateClient/Operational": {
        "declared_source": "windows_update", "label": "Windows Update",
        "value": "MEDIUM"},
}

#: ANALYSIS SUPPORT — can the platform PARSE, NORMALIZE and reason over it?
#: Acquisition is not comprehension. A channel absent from this map is
#: acquired and preserved verbatim, and reported as
#: `NORMALIZATION: NOT YET SUPPORTED · DETECTION COVERAGE: NOT AVAILABLE`.
#: It must never be rolled up as HEALTHY because XML arrived.
ANALYSIS_SUPPORTED = {
    "Microsoft-Windows-Sysmon/Operational": {
        "dsm": "sysmon_dsm", "normalization": "SUPPORTED",
        "detection_coverage": "SUPPORTED"},
    # W2-1 · Security and both PowerShell channels are normalized by the
    # core DSMs `windows-security-evd` and `windows-powershell-evd`.
    # `detection_coverage` is stated separately and deliberately: canonical
    # evidence exists and can be reasoned over, but published detection
    # content for these channels is still being built, and claiming
    # coverage we cannot demonstrate would be the exact lie this two-state
    # model exists to prevent.
    "Security": {
        "dsm": "windows-security-evd", "normalization": "SUPPORTED",
        "detection_coverage": "PARTIAL"},
    "Microsoft-Windows-PowerShell/Operational": {
        "dsm": "windows-powershell-evd", "normalization": "SUPPORTED",
        "detection_coverage": "NOT AVAILABLE"},
    "Windows PowerShell": {
        "dsm": "windows-powershell-evd", "normalization": "SUPPORTED",
        "detection_coverage": "NOT AVAILABLE"},
    "Microsoft-Windows-Windows Defender/Operational": {
        "dsm": "windows-defender-evd", "normalization": "SUPPORTED",
        "detection_coverage": "NOT AVAILABLE"},
}

#: The DSM roadmap order the owner set. Declared here so the admin surface
#: can state WHEN, not just that something is missing.
ANALYSIS_ROADMAP = [
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "System", "Application",
]


def analysis_support(channel: str) -> Dict[str, Any]:
    """The SECOND state. Collection support lives in `CHANNELS`."""
    hit = ANALYSIS_SUPPORTED.get(channel)
    if hit:
        return {"normalization": hit["normalization"],
                "detection_coverage": hit["detection_coverage"],
                "dsm": hit["dsm"], "roadmap_position": None}
    pos = (ANALYSIS_ROADMAP.index(channel) + 1
           if channel in ANALYSIS_ROADMAP else None)
    return {
        "normalization": "NOT YET SUPPORTED",
        "detection_coverage": "NOT AVAILABLE",
        "dsm": None,
        "roadmap_position": pos,
        "reason": ("this channel is acquired and its raw XML is preserved "
                   "verbatim, but no DSM parses it into canonical evidence "
                   "yet — so it cannot be reasoned over or detected on"),
    }


#: WEF/WEC is a LATER milestone and is declared, not silently missing.
UNSUPPORTED_CHANNELS = {
    "ForwardedEvents": (
        "WEF/WEC collection is a later milestone: a forwarded record's origin "
        "computer and its collector host are different facts, and this adapter "
        "does not yet prove that distinction end to end"),
}


@dataclass
class CollectionProfile:
    """A DECLARATIVE acquisition contract — what to read, never how.

    A profile is versioned so a channel's state can say which contract
    produced it. Changing a filter is therefore an auditable event rather
    than an invisible behaviour change.
    """
    profile_id: str
    version: str
    channels: List[str]
    #: Optional per-channel XPath filter applied by WINDOWS, at the
    #: subscription — not by us after reading everything.
    filters: Dict[str, str] = field(default_factory=dict)
    max_events_per_read: int = 500

    def validate(self) -> List[Dict[str, str]]:
        problems: List[Dict[str, str]] = []
        for ch in self.channels:
            if ch in UNSUPPORTED_CHANNELS:
                problems.append({"channel": ch, "code": "UNSUPPORTED_CHANNEL",
                                 "reason": UNSUPPORTED_CHANNELS[ch]})
            elif ch not in CHANNELS:
                problems.append({
                    "channel": ch, "code": "UNKNOWN_CHANNEL",
                    "reason": ("this channel has no declared source mapping, so "
                               "the core would refuse its deliveries with "
                               "DECLARATION_REQUIRED")})
        return problems

    def to_dict(self) -> Dict[str, Any]:
        return {"profile_id": self.profile_id, "version": self.version,
                "channels": list(self.channels), "filters": dict(self.filters),
                "max_events_per_read": self.max_events_per_read}


#: FIRST REAL-WINDOWS VALIDATION PROFILE. Deliberately NOT every channel the
#: reader supports: process/network/registry/file from Sysmon, authentication
#: and security auditing from Security, script execution from PowerShell.
VALIDATION_PROFILE = CollectionProfile(
    profile_id="windows-validation",
    version="1.0.0",
    channels=["Microsoft-Windows-Sysmon/Operational",
              "Security",
              "Microsoft-Windows-PowerShell/Operational"],
)

#: RECOMMENDED SECURITY — the standing production profile.
RECOMMENDED_SECURITY_PROFILE = CollectionProfile(
    profile_id="windows-recommended-security",
    version="1.0.0",
    channels=["Microsoft-Windows-Sysmon/Operational",
              "Security",
              "Microsoft-Windows-PowerShell/Operational",
              "Microsoft-Windows-Windows Defender/Operational",
              "Microsoft-Windows-TaskScheduler/Operational",
              "Microsoft-Windows-WMI-Activity/Operational"],
)

#: FORENSIC / HIGH VISIBILITY — higher volume, opt-in.
FORENSIC_PROFILE = CollectionProfile(
    profile_id="windows-forensic",
    version="1.0.0",
    channels=RECOMMENDED_SECURITY_PROFILE.channels + [
        "System", "Application",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-WinRM/Operational",
        "Microsoft-Windows-DNS-Client/Operational",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "Microsoft-Windows-SmbClient/Security"],
)

#: DOMAIN CONTROLLER — adds directory/authentication authority telemetry.
DOMAIN_CONTROLLER_PROFILE = CollectionProfile(
    profile_id="windows-domain-controller",
    version="1.0.0",
    channels=RECOMMENDED_SECURITY_PROFILE.channels + [
        "Directory Service", "Microsoft-Windows-DNSServer/Audit"],
)

PROFILES = {p.profile_id: p for p in (
    VALIDATION_PROFILE, RECOMMENDED_SECURITY_PROFILE, FORENSIC_PROFILE,
    DOMAIN_CONTROLLER_PROFILE)}

#: Back-compat alias — the first profile a fresh connector uses.
BASELINE_PROFILE = VALIDATION_PROFILE


class EvtReader(Protocol):
    """The native boundary, isolated so acquisition logic is testable.

    An implementation returns records EXACTLY as Windows produced them plus
    the bookmark describing the position AFTER those records.
    """

    def read(self, channel: str, *, bookmark_xml: Optional[str],
             xpath: Optional[str], limit: int) -> Dict[str, Any]: ...


class UnsupportedPlatformReader:
    """The reader used when this process is not Windows.

    It reads nothing and says why. It is not a stub that returns an empty
    success: an unread channel and an empty channel are different facts.
    """

    reason = ("this collector process is not running on Windows, so no "
              "native Event Log subscription can be opened here")

    def read(self, channel: str, *, bookmark_xml: Optional[str],
             xpath: Optional[str], limit: int) -> Dict[str, Any]:
        return {"records": [], "bookmark_xml": bookmark_xml,
                "state": "UNSUPPORTED_PLATFORM", "reason": self.reason}


class NativeEvtReader:
    """`win32evtlog` EvtSubscribe + bookmark, bound lazily.

    Imported inside `read` so the module remains importable — and unit
    testable — on a non-Windows collector host.
    """

    def read(self, channel: str, *, bookmark_xml: Optional[str],
             xpath: Optional[str], limit: int) -> Dict[str, Any]:
        try:
            import win32evtlog  # type: ignore
        except Exception as exc:  # pragma: no cover - Windows only
            return {"records": [], "bookmark_xml": bookmark_xml,
                    "state": "READER_UNAVAILABLE",
                    "reason": f"win32evtlog could not be bound: {exc}"}
        # pragma: no cover - requires a Windows host with the channel present
        bookmark = (win32evtlog.EvtCreateBookmark(bookmark_xml)
                    if bookmark_xml else win32evtlog.EvtCreateBookmark(None))
        flags = (win32evtlog.EvtSubscribeStartAfterBookmark if bookmark_xml
                 else win32evtlog.EvtSubscribeStartAtOldestRecord)
        handle = win32evtlog.EvtSubscribe(
            channel, flags, None, None, bookmark if bookmark_xml else None,
            xpath)
        records: List[str] = []
        while len(records) < limit:
            events = win32evtlog.EvtNext(handle, limit - len(records),
                                         -1, 0)
            if not events:
                break
            for ev in events:
                records.append(win32evtlog.EvtRender(
                    ev, win32evtlog.EvtRenderEventXml))
                win32evtlog.EvtUpdateBookmark(bookmark, ev)
        return {"records": records,
                "bookmark_xml": win32evtlog.EvtRender(
                    bookmark, win32evtlog.EvtRenderBookmark),
                "state": "READ_OK", "reason": None}


# ── raw XML → identity/provenance facts (NO interpretation) ────────
_RX = {
    "record_id": re.compile(r"<EventRecordID>(\d+)</EventRecordID>"),
    "event_id": re.compile(r"<EventID[^>]*>(\d+)</EventID>"),
    "computer": re.compile(r"<Computer>([^<]+)</Computer>"),
    "time_created": re.compile(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]"),
    "provider": re.compile(r"<Provider Name=['\"]([^'\"]+)['\"]"),
    "channel": re.compile(r"<Channel>([^<]+)</Channel>"),
    "level": re.compile(r"<Level>(\d+)</Level>"),
    "utc_time": re.compile(r"<Data Name=['\"]UtcTime['\"]>([^<]+)</Data>"),
    "user_sid": re.compile(r"<Security UserID=['\"]([^'\"]+)['\"]"),
}


def extract_facts(xml: str) -> Dict[str, Any]:
    """Pull only what identity, routing and time REQUIRE.

    Everything else stays in the raw XML for the core's DSM. Nothing here
    interprets the event, and a field that is absent stays absent — it is
    never defaulted into existence.
    """
    out: Dict[str, Any] = {}
    for key, rx in _RX.items():
        m = rx.search(xml or "")
        if m:
            out[key] = m.group(1)
    if "record_id" in out:
        out["record_id"] = int(out["record_id"])
    return out


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class WindowsEventLogConnector(Connector):
    """Native, multi-channel, bookmark-resumed Windows acquisition."""

    source_type = "windows-eventlog"
    label = "Windows Event Log"
    capabilities = [Capability.PROCESSES, Capability.FILE_EVENTS,
                    Capability.NETWORK_EVENTS, Capability.USERS]
    configuration_schema = {
        "type": "object",
        "properties": {
            "profile_id": {"type": "string"},
            "channels": {"type": "array", "items": {"type": "string"}},
            "filters": {"type": "object"},
            "max_events_per_read": {"type": "integer"},
        },
    }
    credential_requirements: List[str] = []  # local privilege, not a secret

    def __init__(self, tenant_id: str, config: Dict[str, Any],
                 identity: Optional[str] = None,
                 *, reader: Optional[EvtReader] = None,
                 bookmarks: Optional[WindowsBookmarkStore] = None,
                 collector_id: Optional[str] = None):
        super().__init__(tenant_id, config)
        # G1/B1 · the collector service rehydrates and creates every
        # connector as `cls(tenant_id=…, config=…, identity=rec.id)`, the
        # same contract the REST/webhook/syslog adapters honour. Without it
        # this adapter raised TypeError, which boot swallowed, so the
        # Windows connector silently never started.
        if identity:
            self.identity = identity
            self.checkpoint.connector_id = identity
        named = PROFILES.get(config.get("profile_id") or "")
        if named and not config.get("channels"):
            config = {**config, "channels": list(named.channels),
                      "profile_version": config.get("profile_version")
                      or named.version}
        self.profile = CollectionProfile(
            profile_id=config.get("profile_id") or BASELINE_PROFILE.profile_id,
            version=config.get("profile_version") or BASELINE_PROFILE.version,
            channels=list(config.get("channels")
                          or BASELINE_PROFILE.channels),
            filters=dict(config.get("filters") or {}),
            max_events_per_read=int(config.get("max_events_per_read") or 500),
        )
        self.reader: EvtReader = reader or (
            NativeEvtReader() if platform.system() == "Windows"
            else UnsupportedPlatformReader())
        self.bookmarks = bookmarks or WindowsBookmarkStore()
        # G1/B2 · THE collector identity. It anchors both the envelope the
        # authoritative boundary matches against its enrolled collector AND
        # the bookmark scope `(tenant, collector_id, channel)`. A generated
        # value would change on every process start, so acquisition could
        # never resume and ingest could never recognise the collector: an
        # undeclared identity therefore fails closed instead.
        declared_collector = (collector_id
                              or config.get("collector_id")
                              or os.environ.get("NIVX_COLLECTOR_ID"))
        declared_collector = str(declared_collector).strip() \
            if declared_collector else ""
        if not declared_collector:
            raise ValueError(
                "windows-eventlog connector requires an authoritative "
                "collector_id: set it in the connector configuration "
                "(`config.collector_id`) or in NIVX_COLLECTOR_ID. It must be "
                "the id of the collector enrolled in NivXRay XDR — it anchors "
                "envelope identity and bookmark scope, so it is never "
                "generated.")
        self.collector_id = declared_collector
        #: Bookmarks READ in the last collect, awaiting Advance Acquisition.
        self._pending: Dict[str, str] = {}
        #: Per-channel acquisition accounting for this process.
        self.channel_reports: Dict[str, Dict[str, Any]] = {}

    # ── identity ──────────────────────────────────────────────────
    def event_identity(self, facts: Dict[str, Any], channel: str) -> Optional[str]:
        """Channel-qualified identity.

        `tenant + origin_computer + channel + event_record_id`. A record id
        alone collides across channels and across hosts, so it is never the
        identity by itself. Without a record id there is no identity — the
        delivery is honest about being unidentifiable rather than inventing
        a surrogate that would defeat dedupe.
        """
        rid = facts.get("record_id")
        if rid is None:
            return None
        origin = facts.get("computer") or "UNKNOWN_ORIGIN"
        return f"{self.tenant_id}|{origin}|{channel}|{rid}"

    async def test_connection(self) -> Dict[str, Any]:
        problems = self.profile.validate()
        probe = self.reader.read(self.profile.channels[0] if
                                 self.profile.channels else "System",
                                 bookmark_xml=None, xpath=None, limit=1)
        ok = probe.get("state") == "READ_OK"
        self.health = Health.CONNECTED if ok else Health.ERROR
        return {"ok": ok, "state": probe.get("state"),
                "reason": probe.get("reason"),
                "profile": self.profile.to_dict(),
                "profile_problems": problems}

    # ── Read ──────────────────────────────────────────────────────
    async def collect(self) -> List[Envelope]:
        envelopes: List[Envelope] = []
        self._pending = {}
        self.channel_reports = {}
        for channel in self.profile.channels:
            if channel in UNSUPPORTED_CHANNELS or channel not in CHANNELS:
                self.channel_reports[channel] = {
                    "state": "NOT_COLLECTED",
                    "reason": UNSUPPORTED_CHANNELS.get(
                        channel,
                        "this channel has no declared source mapping"),
                }
                continue

            resume = self.bookmarks.resume_for(
                self.tenant_id, self.collector_id, channel)
            read = self.reader.read(
                channel, bookmark_xml=resume.get("bookmark_xml"),
                xpath=self.profile.filters.get(channel),
                limit=self.profile.max_events_per_read)

            if read.get("state") != "READ_OK":
                self.channel_reports[channel] = {
                    "state": read.get("state"),
                    "reason": read.get("reason"),
                    "resume": resume.get("classification"),
                    "events_read": 0,
                }
                self.bookmarks.record_read(
                    tenant_id=self.tenant_id, collector_id=self.collector_id,
                    channel=channel, bookmark_xml=None, record_ids=[],
                    profile_id=self.profile.profile_id,
                    profile_version=self.profile.version,
                    error=read.get("reason"))
                continue

            sensor_observed_at = _utcnow_iso()
            record_ids: List[int] = []
            newest_activity: Optional[str] = None
            declared = CHANNELS[channel]["declared_source"]

            for xml in read.get("records") or []:
                facts = extract_facts(xml)
                if facts.get("record_id") is not None:
                    record_ids.append(facts["record_id"])
                # Activity instant: the event's OWN clock. Sysmon's UtcTime
                # is the activity instant; TimeCreated is when the provider
                # wrote the record. They are never substituted for one
                # another, and neither becomes the ingest time.
                activity = facts.get("utc_time") or facts.get("time_created")
                if activity and (newest_activity is None
                                 or activity > newest_activity):
                    newest_activity = activity
                envelopes.append(Envelope(
                    tenant_id=self.tenant_id,
                    source=declared,
                    source_event_id=self.event_identity(facts, channel),
                    connector_id=self.identity,
                    collector_id=self.collector_id,
                    collection_method=COLLECTION_METHOD,
                    parser_version=PARSER_VERSION,
                    source_timestamp=activity,
                    collection_timestamp=sensor_observed_at,
                    event_type=f"{channel}/{facts.get('event_id') or 'unknown'}",
                    raw={"xml": xml, "channel": channel},
                    canonical={
                        # Identity + routing facts only. The core's DSM owns
                        # interpretation; this is provenance, not authority.
                        "channel": channel,
                        "provider": facts.get("provider"),
                        "event_id": facts.get("event_id"),
                        "event_record_id": facts.get("record_id"),
                        "origin_computer": facts.get("computer"),
                        "collector_host": platform.node(),
                        "level": facts.get("level"),
                        # A SID is carried verbatim: no endpoint-side
                        # principal rendering.
                        "user_sid": facts.get("user_sid"),
                        "activity_occurred_at": activity,
                        "activity_time_source": (
                            "EventData.UtcTime" if facts.get("utc_time")
                            else "System.TimeCreated" if facts.get("time_created")
                            else None),
                        "sensor_observed_at": sensor_observed_at,
                        "profile_id": self.profile.profile_id,
                        "profile_version": self.profile.version,
                    },
                    declared_source=declared,
                ))

            outcome = self.bookmarks.record_read(
                tenant_id=self.tenant_id, collector_id=self.collector_id,
                channel=channel, bookmark_xml=None, record_ids=record_ids,
                newest_activity_at=newest_activity,
                origin_computer=(extract_facts(
                    (read.get("records") or [""])[0]).get("computer")
                    if read.get("records") else None),
                profile_id=self.profile.profile_id,
                profile_version=self.profile.version)

            # Make Durable happens in the runtime (outbox). The new bookmark
            # is held PENDING until then — advancing it here would allow a
            # crash between read and persist to skip evidence silently.
            if read.get("bookmark_xml"):
                self._pending[channel] = read["bookmark_xml"]

            self.channel_reports[channel] = {
                "state": "READ_OK",
                # Two INDEPENDENT states. Collection success never implies
                # the platform can analyse what it collected.
                "collection_support": "SUPPORTED",
                "analysis_support": analysis_support(channel),
                "security_value": CHANNELS[channel].get("value"),
                "resume": resume.get("classification"),
                "resume_reason": resume.get("reason"),
                "events_read": len(read.get("records") or []),
                "identified": sum(1 for e in envelopes
                                  if e.raw.get("channel") == channel
                                  and e.source_event_id),
                "unidentified": sum(1 for e in envelopes
                                    if e.raw.get("channel") == channel
                                    and not e.source_event_id),
                "log_cleared": outcome.get("log_cleared"),
                "log_cleared_reason": outcome.get("log_cleared_reason"),
                "bookmark_pending": channel in self._pending,
                "newest_activity_at": newest_activity,
                "sensor_observed_at": sensor_observed_at,
            }

        self.metrics.events_collected += len(envelopes)
        self.metrics.last_attempt = _utcnow_iso()
        if envelopes:
            self.metrics.last_success = self.metrics.last_attempt
        return envelopes

    # ── Advance Acquisition (only after Make Durable) ─────────────
    def advance(self, *, durable_channels: Optional[Iterable[str]] = None
                ) -> Dict[str, Any]:
        """Persist the pending bookmarks whose records are durable.

        Called by the runtime AFTER the outbox has accepted the envelopes.
        A channel not listed stays where it was and is re-read — duplicate
        delivery is absorbed by the outbox's unique key, whereas a skipped
        window is unrecoverable.
        """
        allow = set(durable_channels) if durable_channels is not None \
            else set(self._pending)
        advanced: Dict[str, Any] = {}
        for channel, bookmark in list(self._pending.items()):
            if channel not in allow:
                advanced[channel] = {
                    "advanced": False,
                    "reason": ("the records from this read are not durable "
                               "yet — the acquisition position stays put and "
                               "the window is re-read")}
                continue
            self.bookmarks.record_read(
                tenant_id=self.tenant_id, collector_id=self.collector_id,
                channel=channel, bookmark_xml=bookmark, record_ids=[],
                profile_id=self.profile.profile_id,
                profile_version=self.profile.version)
            advanced[channel] = {"advanced": True}
            self._pending.pop(channel, None)
        return advanced

    # ── Account ───────────────────────────────────────────────────
    def acquisition_report(self) -> Dict[str, Any]:
        """Per-channel acquisition truth for the admin surface.

        Every field is measured or explicitly absent. A channel that could
        not be read reports the reason; it never reports zero events as if
        the channel were quiet.
        """
        return {
            "tenant_id": self.tenant_id,
            "collector_id": self.collector_id,
            "collector_host": platform.node(),
            "platform": platform.system(),
            "reader": type(self.reader).__name__,
            "profile": self.profile.to_dict(),
            "profile_problems": self.profile.validate(),
            "channels": self.channel_reports,
            "persisted_state": self.bookmarks.channels(
                self.tenant_id, self.collector_id),
            "invariant": ("Read → Make Durable → Advance Acquisition → "
                          "Deliver → Account → Verify"),
            "analysis_support_by_channel": {
                ch: analysis_support(ch) for ch in self.profile.channels},
            "state_model_note": (
                "COLLECTION SUPPORT and ANALYSIS SUPPORT are separate facts. "
                "A channel may be RECEIVING while its normalization is NOT "
                "YET SUPPORTED and its detection coverage NOT AVAILABLE — "
                "that combination is valid and is never rolled up as HEALTHY"),
        }
