"""P2 Slice-1 · Sysmon Event 1 (Process Create) → canonical behavioral
evidence. See `/app/memory/adr/0010q-p2-slice-1-blueprint.md`.

Contract (locked):
  · Accepts a single Sysmon Event 1 or an `<Events>` wrapper containing
    Event 1 elements. Every Event MUST have `System.EventID == 1`.
  · Emits a list of `BehavioralEvidence` dict records. Each record's
    shape mirrors the P0.2 evidence-chain records so downstream
    consumers do not need a special branch.
  · Parent-child relationship is EVIDENCE, not truth. Corroboration
    counted separately; `parent_child_uncorroborated=True` when
    fewer than 2 corroborating fields are present.
  · The adapter does NOT invoke a MITRE mapper. The router hands the
    normalized `command_line` to `services.die.api.analyze()` — the
    UI-DEF-02 authoritative surface — separately.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from typing import Any, Dict, List, Optional, Tuple

# Prefer defusedxml (XXE-safe) but degrade gracefully. The bare stdlib
# parser is still safe against XXE in Python 3.7+ because entity
# resolution defaults to disabled, but defusedxml adds belt-and-braces.
try:
    import defusedxml.ElementTree as _ET   # type: ignore
    _XML_PARSER = "defusedxml"
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as _ET    # type: ignore
    _XML_PARSER = "stdlib"

_WEV_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

ADAPTER_ID = "sysmon.slice2@1.0"

# Event IDs Slice-2 accepts. Any other EID → 422 unsupported_event_id.
_SUPPORTED_EIDS = frozenset({"1", "3"})


class SysmonAdapterError(ValueError):
    """Adapter refused the input. Carries a short machine code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# XML plumbing
# ---------------------------------------------------------------------------
def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_child(elem: Any, name: str) -> Optional[Any]:
    for c in elem:
        if _localname(c.tag) == name:
            return c
    return None


def _read_event_data(evt: Any) -> Dict[str, str]:
    ed = _find_child(evt, "EventData")
    if ed is None:
        return {}
    out: Dict[str, str] = {}
    for d in ed:
        if _localname(d.tag) != "Data":
            continue
        name = d.attrib.get("Name") or ""
        out[name] = (d.text or "").strip()
    return out


def _read_system(evt: Any) -> Dict[str, str]:
    sys_ = _find_child(evt, "System")
    if sys_ is None:
        return {}
    out: Dict[str, str] = {}
    for c in sys_:
        name = _localname(c.tag)
        if name == "EventID":
            out["EventID"] = (c.text or "").strip()
        elif name == "TimeCreated":
            out["TimeCreated"] = c.attrib.get("SystemTime", "") or ""
        elif name == "Computer":
            out["Computer"] = (c.text or "").strip()
    return out


def _iter_events(root: Any):
    """Yield every `<Event>` element inside a well-formed root."""
    tag = _localname(root.tag)
    if tag == "Event":
        yield root
        return
    if tag == "Events":
        for c in root:
            if _localname(c.tag) == "Event":
                yield c
        return
    # Unknown wrapper — search one level deep for Event children.
    for c in root:
        if _localname(c.tag) == "Event":
            yield c


# ---------------------------------------------------------------------------
# Evidence record construction
# ---------------------------------------------------------------------------
def _short_ref(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]


def _canonicalize_ip(raw: str) -> str:
    """Return the RFC 5952 / IPv4-mapped canonical form of `raw`.

    Rules per ADR-0010r §6-10:
      · IPv4 → dotted-quad, no leading zeros, lower-cased.
      · IPv6 → RFC 5952 compressed representation, lower-cased.
      · IPv4-mapped IPv6 (`::ffff:192.168.1.5`) collapses to the
        IPv4 dotted-quad.
      · Unparseable input is returned verbatim (never fabricated).
    The canonical form is deterministic; identical logical addresses
    always produce identical bytes, so evidence_ref is stable across
    replays regardless of source formatting.
    """
    v = (raw or "").strip()
    if not v:
        return ""
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return v
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip).lower()


# Fields whose value depends on host configuration or a Sysmon reverse
# lookup — never authoritative. Analyst-visible chip only. Per
# ADR-0010r §11-14.
_ADVISORY_FIELDS = {
    "network.destination_hostname",
    "network.source_hostname",
    "network.destination_port_name",
    "network.source_port_name",
}


def _corroboration_flags(evt_data: Dict[str, str]) -> Dict[str, Any]:
    """Determine which corroborating fields accompany the parent-child claim.

    Per ADR-0010q §4 the parent-child link is EVIDENCE, not truth. We
    surface the corroboration count so the analyst sees the strength
    of the claim without any implicit verdict inference.
    """
    flags: Dict[str, bool] = {
        "parent_image_path": bool(evt_data.get("ParentImage", "").strip()
                                   and "\\" in (evt_data.get("ParentImage") or "")),
        "hashes":            bool(evt_data.get("Hashes", "").strip()),
        "user_session":      bool(evt_data.get("LogonId", "").strip()
                                   or evt_data.get("User", "").strip()),
        "integrity_level":   bool(evt_data.get("IntegrityLevel", "").strip()),
        "temporal_delta":    bool(evt_data.get("UtcTime", "").strip()
                                   and evt_data.get("ParentProcessGuid", "").strip()),
    }
    count = sum(1 for v in flags.values() if v)
    return {
        "flags":                    flags,
        "count":                    count,
        "sufficient_for_provenance": count >= 2,
    }


# The Sysmon Event-1 fields we lift into evidence records. Anything
# absent from the payload is simply not emitted (no fabricated values).
_EVIDENCE_FIELD_MAP_EID1 = (
    ("CommandLine",    "process.command_line",     "high"),
    ("Image",          "process.image",            "high"),
    ("ParentImage",    "parent.image",             "medium"),
    ("ParentCommandLine", "parent.command_line",   "medium"),
    ("Hashes",         "process.hashes",           "high"),
    ("IntegrityLevel", "process.integrity_level",  "medium"),
    ("User",           "process.user",             "medium"),
    ("LogonId",        "process.logon_id",         "low"),
    ("ProcessId",      "process.pid",              "high"),
    ("ProcessGuid",    "process.guid",             "high"),
    ("ParentProcessId", "parent.pid",              "medium"),
    ("ParentProcessGuid", "parent.guid",           "medium"),
    ("CurrentDirectory", "process.cwd",            "low"),
)

# Sysmon Event 3 (Network Connect) canonical field map. Every field
# below appears in the response ONLY if Sysmon emitted it — no
# fabrication. Confidence tiers reflect how load-bearing each field is
# for behavioral chain reconstruction.
_EVIDENCE_FIELD_MAP_EID3 = (
    ("Image",              "process.image",              "high"),
    ("ProcessId",          "process.pid",                "high"),
    ("ProcessGuid",        "process.guid",               "high"),
    ("User",               "process.user",               "medium"),
    ("Protocol",           "network.protocol",           "high"),
    ("Initiated",          "network.initiated",          "medium"),
    ("SourceIsIpv6",       "network.source_is_ipv6",     "low"),
    ("SourceIp",           "network.source_ip",          "high"),
    ("SourcePort",         "network.source_port",        "medium"),
    ("SourceHostname",     "network.source_hostname",    "medium"),
    ("SourcePortName",     "network.source_port_name",   "low"),
    ("DestinationIsIpv6",  "network.destination_is_ipv6","low"),
    ("DestinationIp",      "network.destination_ip",     "high"),
    ("DestinationPort",    "network.destination_port",   "high"),
    ("DestinationHostname","network.destination_hostname","high"),
    ("DestinationPortName","network.destination_port_name","low"),
    ("RuleName",           "network.rule_name",          "medium"),
)


def _behavioral_records(evt_data: Dict[str, str],
                         system:   Dict[str, str],
                         evidence_ref: str,
                         *,
                         source_tag: str,
                         event_or_rule: str,
                         field_map,
                         extras: Optional[Dict[str, Any]] = None,
                         canonicalized_overrides: Optional[Dict[str, str]] = None,
                         ) -> List[Dict[str, Any]]:
    """Build one evidence record per non-empty Sysmon Data field.

    `canonicalized_overrides` — mapping of wire_field → canonicalized
    value. Used so the emitted `observed_value` for IP fields is the
    RFC-5952/IPv4-dotted canonical form even when Sysmon delivered a
    verbose IPv6 encoding.
    """
    records: List[Dict[str, Any]] = []
    for wire_name, canonical_field, confidence in field_map:
        raw = (evt_data.get(wire_name) or "").strip()
        if not raw:
            continue
        v = (canonicalized_overrides or {}).get(wire_name, raw)
        rec = {
            "source":         source_tag,
            "event_or_rule":  event_or_rule,
            "field":          canonical_field,
            "observed_value": v[:800],
            "evidence_ref":   evidence_ref,
            "confidence":     confidence,
            "provenance":     {
                "adapter": ADAPTER_ID,
                "wire_field": wire_name,
                "host":       system.get("Computer") or None,
                "time":       system.get("TimeCreated") or None,
            },
        }
        # Hostname / *PortName fields are advisory only.
        if canonical_field in _ADVISORY_FIELDS:
            rec["derivation"] = "sysmon_reverse_lookup"
            rec["advisory"]   = True
            rec["confidence"] = "advisory"
        if extras:
            rec.update(extras)
        records.append(rec)
    return records


def _classify_destination_ip(ip: str) -> str:
    """Return a coarse classification for a CANONICALIZED destination
    IP address without inventing threat intel. Values: "loopback" ·
    "rfc1918" · "linklocal" · "rfc4193" · "external" · "unknown". Used
    only as an EVIDENCE FLAG that the analyst / investigation engine
    can read — never a verdict driver.

    Uses explicit RFC-1918 / IANA reserved-range membership rather
    than Python's `is_private`, which conflates the RFC-1918 space
    with documentation / TEST-NET / benchmarking ranges. Analysts
    treat 198.51.100.0/24 (TEST-NET-2) as external for chain
    reconstruction purposes."""
    v = (ip or "").strip()
    if not v:
        return "unknown"
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "linklocal"
    if isinstance(addr, ipaddress.IPv4Address):
        # RFC 1918 explicit membership only.
        for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            if addr in ipaddress.ip_network(cidr):
                return "rfc1918"
        return "external"
    if isinstance(addr, ipaddress.IPv6Address):
        # ULA fc00::/7 = RFC 4193
        if addr in ipaddress.ip_network("fc00::/7"):
            return "rfc4193"
    return "external"


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def normalize_sysmon_xml(xml_text: str,
                          max_bytes: int = 512 * 1024
                          ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Parse a Sysmon Event-1 XML payload and return
    `(evidence_records, meta)`.

    `meta` includes: `adapter`, `xml_parser`, `event_count`,
    `parent_child_evidence.uncorroborated_count`, and — most
    importantly — the flat `command_line` fields (indexed per event)
    so the caller can hand them to the authoritative MITRE surface.
    """
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise SysmonAdapterError("empty_input", "empty or non-string XML payload")
    if len(xml_text.encode("utf-8")) > max_bytes:
        raise SysmonAdapterError("payload_too_large",
                                  f"XML payload exceeds {max_bytes} bytes")

    try:
        root = _ET.fromstring(xml_text)
    except _ET.ParseError as exc:
        raise SysmonAdapterError("malformed_xml", f"XML parse error: {exc}") from exc

    events = list(_iter_events(root))
    if not events:
        raise SysmonAdapterError("no_event_element", "no <Event> element found")

    all_records: List[Dict[str, Any]] = []
    command_lines: List[str] = []
    uncorroborated = 0
    parent_child_pairs: List[Dict[str, Any]] = []
    network_connections: List[Dict[str, Any]] = []
    dedup_index: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}
    counts = {"eid1": 0, "eid3": 0}
    # ProcessGuid → list of evidence_refs from Event 1 (populated first)
    # so Event 3 correlations can point at the process-create record.
    guid_to_eid1_ref: Dict[str, str] = {}
    guid_to_image:    Dict[str, str] = {}

    # ── Fail-loud per-ingest cap (ADR-0010r §34-36) ─────────────────
    eid3_seen = 0
    eid3_cap  = int(os.environ.get("NIVX_SYSMON_EID3_MAX_EVENTS", "5000"))

    for evt in events:
        system = _read_system(evt)
        eid_raw = system.get("EventID", "").strip()
        if eid_raw not in _SUPPORTED_EIDS:
            raise SysmonAdapterError(
                "unsupported_event_id",
                f"Slice-2 supports Sysmon Event IDs {sorted(_SUPPORTED_EIDS)} "
                f"only; got EventID={eid_raw!r}",
            )
        evt_data = _read_event_data(evt)

        if eid_raw == "1":
            counts["eid1"] += 1
            command_line = (evt_data.get("CommandLine") or "").strip()
            image        = (evt_data.get("Image") or "").strip()
            parent_image = (evt_data.get("ParentImage") or "").strip()
            proc_guid    = (evt_data.get("ProcessGuid") or "").strip()
            # Deterministic evidence_ref — same input → same ref.
            evidence_ref = _short_ref("sysmon.eid1",
                                        system.get("TimeCreated", ""),
                                        image, command_line,
                                        evt_data.get("ProcessId", ""),
                                        proc_guid)
            records = _behavioral_records(evt_data, system, evidence_ref,
                                            source_tag="sysmon.eid1",
                                            event_or_rule="sysmon.process_create",
                                            field_map=_EVIDENCE_FIELD_MAP_EID1)
            all_records.extend(records)
            if command_line:
                command_lines.append(command_line)
            if proc_guid:
                # First Event 1 for a given ProcessGuid wins the
                # correlation slot; subsequent duplicates keep the same
                # ref (determinism).
                guid_to_eid1_ref.setdefault(proc_guid, evidence_ref)
                guid_to_image.setdefault(proc_guid, image)

            corr = _corroboration_flags(evt_data)
            if not corr["sufficient_for_provenance"]:
                uncorroborated += 1
            parent_child_pairs.append({
                "child_image":    image,
                "child_pid":      evt_data.get("ProcessId") or "",
                "child_process_guid": proc_guid,
                "parent_image":   parent_image,
                "parent_pid":     evt_data.get("ParentProcessId") or "",
                "parent_process_guid": evt_data.get("ParentProcessGuid") or "",
                "corroboration":  corr,
                "parent_child_uncorroborated": not corr["sufficient_for_provenance"],
                "evidence_ref":   evidence_ref,
            })

        else:  # eid_raw == "3"
            counts["eid3"] += 1
            eid3_seen += 1
            if eid3_seen > eid3_cap:
                raise SysmonAdapterError(
                    "eid3_cap_exceeded",
                    f"Event 3 per-ingest cap exceeded (limit={eid3_cap}, "
                    f"seen={eid3_seen}). Refusing to silently truncate "
                    f"evidence. Raise NIVX_SYSMON_EID3_MAX_EVENTS to accept "
                    f"a larger batch, or split the payload.",
                )
            image      = (evt_data.get("Image") or "").strip()
            proc_guid  = (evt_data.get("ProcessGuid") or "").strip()
            proc_pid   = (evt_data.get("ProcessId") or "").strip()
            raw_dst_ip = (evt_data.get("DestinationIp") or "").strip()
            raw_src_ip = (evt_data.get("SourceIp") or "").strip()
            dst_ip     = _canonicalize_ip(raw_dst_ip)
            src_ip     = _canonicalize_ip(raw_src_ip)
            dst_port   = (evt_data.get("DestinationPort") or "").strip()
            initiated  = (evt_data.get("Initiated") or "").strip().lower() == "true"
            protocol   = (evt_data.get("Protocol") or "").strip().lower()
            dst_class  = _classify_destination_ip(dst_ip)

            # ── Correlation state (ADR-0010r §17-19) ──────────────
            if proc_guid and proc_guid in guid_to_eid1_ref:
                correlation_state    = "RESOLVED"
                correlated_ref       = guid_to_eid1_ref[proc_guid]
                correlated_image     = guid_to_image.get(proc_guid) or image
            elif proc_guid:
                correlation_state    = "UNRESOLVED_DANGLING"
                correlated_ref       = None
                correlated_image     = ""
            elif proc_pid:
                correlation_state    = "AMBIGUOUS_PID_ONLY"
                correlated_ref       = None
                correlated_image     = ""
            else:
                correlation_state    = "UNRESOLVED_DANGLING"
                correlated_ref       = None
                correlated_image     = ""

            # ── Deterministic evidence_ref based on CANONICAL IP ──
            evidence_ref = _short_ref("sysmon.eid3",
                                        system.get("TimeCreated", ""),
                                        image, proc_guid,
                                        dst_ip, dst_port,
                                        protocol,
                                        "in" if not initiated else "out")
            extras = {
                "network_destination_class": dst_class,
                "correlation_state":         correlation_state,
            }
            if correlated_ref:
                extras["correlated_with"] = {
                    "process_guid":                proc_guid,
                    "process_image":               correlated_image,
                    "process_create_evidence_ref": correlated_ref,
                }
            # Feed emitted evidence records the CANONICAL IP text so
            # `observed_value` reflects the normalized form.
            canonicalized = {"DestinationIp": dst_ip, "SourceIp": src_ip}
            records = _behavioral_records(evt_data, system, evidence_ref,
                                            source_tag="sysmon.eid3",
                                            event_or_rule="sysmon.network_connect",
                                            field_map=_EVIDENCE_FIELD_MAP_EID3,
                                            extras=extras,
                                            canonicalized_overrides=canonicalized)
            all_records.extend(records)

            # ── Deduplication key (ADR-0010r §30) ─────────────────
            dedup_key = (proc_guid, protocol, dst_ip, dst_port,
                          "in" if not initiated else "out")
            time_str = system.get("TimeCreated") or ""
            existing = dedup_index.get(dedup_key)
            if existing is None:
                conn = {
                    "evidence_ref":        evidence_ref,
                    "process_image":       image,
                    "process_pid":         proc_pid,
                    "process_guid":        proc_guid,
                    "protocol":            protocol,
                    "initiated":           initiated,
                    "source_ip":           src_ip,
                    "source_ip_raw":       raw_src_ip,
                    "source_port":         (evt_data.get("SourcePort") or "").strip(),
                    "destination_ip":      dst_ip,
                    "destination_ip_raw":  raw_dst_ip,
                    "destination_port":    dst_port,
                    "destination_hostname": evt_data.get("DestinationHostname") or "",
                    "destination_class":   dst_class,
                    "correlation_state":   correlation_state,
                    "correlated_with_process_create": correlated_ref,
                    "count":               1,
                    "first_seen":          time_str,
                    "last_seen":           time_str,
                    "raw_refs":            [evidence_ref],
                }
                network_connections.append(conn)
                dedup_index[dedup_key] = conn
            else:
                existing["count"] += 1
                if time_str:
                    if not existing["first_seen"] or time_str < existing["first_seen"]:
                        existing["first_seen"] = time_str
                    if not existing["last_seen"] or time_str > existing["last_seen"]:
                        existing["last_seen"] = time_str
                if evidence_ref not in existing["raw_refs"]:
                    existing["raw_refs"].append(evidence_ref)

    meta: Dict[str, Any] = {
        "adapter":        ADAPTER_ID,
        "xml_parser":     _XML_PARSER,
        "event_count":    len(events),
        "event_counts_by_id": counts,
        "command_lines":  command_lines,
        "parent_child_pairs": parent_child_pairs,
        "parent_child_uncorroborated_count": uncorroborated,
        "network_connections": network_connections,
        "correlations_by_process_guid": {
            g: {"process_create_evidence_ref": r,
                "process_image":               guid_to_image.get(g) or ""}
            for g, r in guid_to_eid1_ref.items()
        },
        "limitations": {
            "ppid_spoofing":
                "Parent-child linkage in Sysmon Event 1 is not verifiable "
                "against PPID spoofing (T1134.004). Corroborate with image "
                "path, hash, user session, integrity level, and temporal "
                "sequence — see corroboration flags per event.",
            "destination_reputation":
                "A network connection to a destination is EVIDENCE only. "
                "The adapter never labels a destination malicious on the "
                "strength of an Event 3 record alone. Correlate with the "
                "process-create evidence, command-line IOC extraction, and "
                "downstream investigation engine outputs.",
        },
    }
    return all_records, meta
