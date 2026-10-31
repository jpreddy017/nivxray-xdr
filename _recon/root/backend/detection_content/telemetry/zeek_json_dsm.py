"""Zeek / Corelight JSON DSM — Gate N1, the first authoritative NETWORK source.

Two Zeek log types, ONE declared source (`zeek-json`) and ONE DSM that
dispatches on Zeek's own `_path`:

    conn   the flow: 5-tuple, volume by direction, duration, connection state
    dns    the resolution: query, type, rcode and — decisively — the ANSWERS

The answers are the point. Until N1 the canonical model had nowhere to put a
DNS response address, so `domain → contacted IP` could not be stored by any
source, and therefore could not be correlated by any rule. That single
missing field is what kept the network side of the chain unprovable.

What this DSM deliberately does NOT do:

* It never invents a process, a user or a host identity. Zeek observes the
  wire; it does not know which process opened a flow, and `id.orig_h` is an
  ADDRESS, not an endpoint identity. Binding an address to a device needs an
  authoritative asset/DHCP inventory that NivX does not have.
* It never derives `direction` from a guess about private ranges. Zeek
  states `local_orig` / `local_resp` when its own network definitions say
  so; when it does not state them, direction stays absent.
* It never reports an allow/deny action. Zeek is an observer, not an
  enforcer, and a firewall's verdict is not available here at any maturity.

Timestamps (D12). Zeek's `ts` is the instant of the packet that opened the
flow / carried the query — the activity itself on the wire — which is the
same basis the Suricata/Snort EVE normalizer already uses. Zeek's `_write_ts`
(when the log record was written) is an OBSERVATION instant and is recorded
as one; it never stands in for activity time. `duration` is carried as the
flow's measured length, not as a second timestamp.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from services import event_time_basis
from services import tenant_authority

from .models import (
    CanonicalTelemetryEvent,
    HostEntity,
    NetworkEntity,
    ProvenanceEnvelope,
)

DSM_ID = "zeek-json"
PARSER_ID = "zeek-json-parser"
NORMALIZER_ID = "zeek-json-normalizer"

#: The Zeek log types N1 interprets. Anything else FAILS CLOSED — a record
#: NivX cannot interpret is refused, never half-read.
SUPPORTED_PATHS = ("conn", "dns")

_EVENT_TYPE_BY_PATH = {"conn": "network_connect", "dns": "dns_query"}


class ZeekJsonParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _path_of(ev: Any) -> str:
    if not isinstance(ev, dict):
        return ""
    return str(ev.get("_path") or "").strip().lower()


def _zeek_shaped(ev: Dict[str, Any]) -> bool:
    """Zeek's own structure, not merely 'has an IP somewhere'.

    A record must carry Zeek's connection uid or its dotted connection
    identifiers. Claiming anything that merely looks network-ish would let
    this DSM absorb another source's payload.
    """
    return bool(ev.get("uid") or ev.get("id.orig_h")
                or isinstance(ev.get("id"), dict))


def _conn_id(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Zeek writes `id.orig_h` flat in JSON logs; some shippers nest it."""
    nested = ev.get("id")
    if isinstance(nested, dict):
        return {f"id.{k}": v for k, v in nested.items()}
    return {k: v for k, v in ev.items() if k.startswith("id.")}


def _str(v: Any) -> str:
    return "" if v is None else str(v)


def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _bool(v: Any) -> Optional[bool]:
    return v if isinstance(v, bool) else None


def _iso_from_zeek_ts(ts: Any) -> str:
    """Zeek emits epoch seconds (float) by default and ISO-8601 when
    `LogAscii::json_timestamps` is set. Both are read; nothing else is."""
    if ts is None or ts == "":
        return ""
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    s = str(ts).strip()
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        # Not epoch — hand the verbatim value to the time-basis resolver,
        # which decides whether it is readable and records the answer.
        return s


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def split_answers(answers: Any) -> Tuple[List[str], List[str]]:
    """`(response_ips, other_records)` — split by what the value IS.

    A CNAME, an MX target or an NXDOMAIN's empty answer set is not an
    address, and pretending otherwise would put a hostname where a
    correlation rule expects a contacted IP.
    """
    ips: List[str] = []
    other: List[str] = []
    if isinstance(answers, str):
        answers = [answers]
    for a in answers or ():
        if a is None:
            continue
        s = str(a).strip()
        if not s or s == "-":
            continue
        (ips if _is_ip(s) else other).append(s)
    return ips, other


class ZeekJsonParser:
    id = PARSER_ID

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise ZeekJsonParserError(
                "INVALID_EVENT", "Zeek record is not a JSON/dict object")
        path = _path_of(ev)
        if not path:
            raise ZeekJsonParserError(
                "MISSING_ZEEK_PATH",
                "a Zeek JSON record must carry `_path` naming its log type; "
                "without it the record's meaning is undeclared and no log "
                "type may be assumed")
        if path not in SUPPORTED_PATHS:
            raise ZeekJsonParserError(
                "UNSUPPORTED_ZEEK_PATH",
                f"Zeek log type {path!r} is not interpreted by this DSM "
                f"(N1 interprets {', '.join(SUPPORTED_PATHS)}); the record is "
                "refused rather than partially read")
        if not _zeek_shaped(ev):
            raise ZeekJsonParserError(
                "MISSING_ZEEK_CONNECTION_IDENTITY",
                "a Zeek conn/dns record must carry `uid` or the `id.*` "
                "connection identifiers")
        cid = _conn_id(ev)
        return {"parser_id": self.id, "zeek_path": path, "raw": ev,
                "data": ev, "conn_id": cid}


class ZeekJsonNormalizer:
    id = NORMALIZER_ID

    def normalize(self, parsed: Dict[str, Any], dsm_id: str = DSM_ID,
                  collector_id: str = "", integration_id: str = "",
                  trace_id: str = "",
                  tenant_id: Optional[str] = None) -> Dict[str, Any]:
        raw = parsed["raw"]
        data = parsed["data"]
        path = parsed["zeek_path"]
        cid = parsed["conn_id"]
        now_iso = datetime.now(timezone.utc).isoformat()

        # D14 · the authenticated delivery owns the tenant; a payload-named
        # tenant is a claim, recorded and never used.
        resolved_tenant, tenant_claim = tenant_authority.resolve(
            tenant_id, *tenant_authority.payload_claims(raw))

        prov: Dict[str, str] = {}

        def put(fieldname: str, value: Any, wire: str) -> Any:
            """Record a field only when the source actually stated it, and
            record WHERE it came from in the same breath."""
            present = value not in (None, "", [], {})
            if present:
                prov[fieldname] = wire
            return value

        net = NetworkEntity()
        net.src_ip = put("src_ip", _str(cid.get("id.orig_h")),
                         f"zeek:{path}.log id.orig_h")
        net.src_port = put("src_port", _int(cid.get("id.orig_p")),
                           f"zeek:{path}.log id.orig_p")
        net.dest_ip = put("dest_ip", _str(cid.get("id.resp_h")),
                          f"zeek:{path}.log id.resp_h")
        net.dest_port = put("dest_port", _int(cid.get("id.resp_p")),
                            f"zeek:{path}.log id.resp_p")
        net.protocol = put("protocol", _str(data.get("proto")),
                           f"zeek:{path}.log proto")
        net.flow_id = put("flow_id", _str(data.get("uid")),
                          f"zeek:{path}.log uid")
        net.community_id = put(
            "community_id",
            _str(data.get("community_id") or data.get("community.id")),
            f"zeek:{path}.log community_id")
        # The sensor that OBSERVED this — never promoted into `host`, which
        # would claim the endpoint's identity.
        net.sensor_device_name = put(
            "sensor_device_name",
            _str(data.get("_system_name") or data.get("_node")
                 or data.get("sensor_name")),
            f"zeek:{path}.log _system_name/_node")
        net.sensor_device_id = put("sensor_device_id",
                                   _str(data.get("_node")),
                                   f"zeek:{path}.log _node")

        additional: Dict[str, Any] = {
            "zeek_path": path,
            "zeek_uid": _str(data.get("uid")),
            "zeek_service": _str(data.get("service")),
        }

        if path == "conn":
            net.bytes_sent = put("bytes_sent", _int(data.get("orig_bytes")),
                                 "zeek:conn.log orig_bytes")
            net.bytes_received = put("bytes_received",
                                     _int(data.get("resp_bytes")),
                                     "zeek:conn.log resp_bytes")
            net.packets_sent = put("packets_sent", _int(data.get("orig_pkts")),
                                   "zeek:conn.log orig_pkts")
            net.packets_received = put("packets_received",
                                       _int(data.get("resp_pkts")),
                                       "zeek:conn.log resp_pkts")
            _dur = _float(data.get("duration"))
            net.duration_ms = put("duration_ms",
                                  None if _dur is None else _dur * 1000.0,
                                  "zeek:conn.log duration (seconds)")
            net.conn_state = put("conn_state", _str(data.get("conn_state")),
                                 "zeek:conn.log conn_state")
            net.conn_history = put("conn_history", _str(data.get("history")),
                                   "zeek:conn.log history")
            # Direction only when ZEEK states locality. No private-range
            # guessing: NivX does not know this network's topology.
            lo, lr = _bool(data.get("local_orig")), _bool(data.get("local_resp"))
            if lo is not None and lr is not None:
                net.direction = put(
                    "direction",
                    "internal" if lo and lr else
                    "outbound" if lo and not lr else
                    "inbound" if lr and not lo else "external",
                    "zeek:conn.log local_orig/local_resp")
            else:
                additional["direction_absent_reason"] = (
                    "this Zeek deployment did not state local_orig/local_resp "
                    "for the flow; direction is NOT inferred from address "
                    "ranges because the site's own network definitions are "
                    "the only authority on locality")
            additional["zeek_conn_end_basis"] = (
                "conn.log ts is the flow's FIRST packet; duration measures "
                "the flow's length. There is no second observed instant, so "
                "no end timestamp is synthesised")

        else:  # dns
            net.dns_query = put("dns_query", _str(data.get("query")),
                                "zeek:dns.log query")
            net.dns_query_type = put("dns_query_type",
                                     _str(data.get("qtype_name")),
                                     "zeek:dns.log qtype_name")
            net.dns_rcode = put("dns_rcode", _str(data.get("rcode_name")),
                                "zeek:dns.log rcode_name")
            ips, other = split_answers(data.get("answers"))
            net.dns_response_ips = put("dns_response_ips", ips,
                                       "zeek:dns.log answers (address records)")
            net.dns_response_records = put(
                "dns_response_records", other,
                "zeek:dns.log answers (non-address records)")
            net.dns_response_ttls = put(
                "dns_response_ttls",
                [t for t in (_float(x) for x in (data.get("TTLs") or []))
                 if t is not None],
                "zeek:dns.log TTLs")
            net.dns_authoritative = put("dns_authoritative",
                                        _bool(data.get("AA")),
                                        "zeek:dns.log AA")
            net.dns_rejected = put("dns_rejected", _bool(data.get("rejected")),
                                   "zeek:dns.log rejected")
            net.dns_transaction_id = put("dns_transaction_id",
                                         _int(data.get("trans_id")),
                                         "zeek:dns.log trans_id")
            if not ips:
                additional["dns_answer_absent_reason"] = (
                    "this DNS record carried no address answer "
                    f"(rcode={net.dns_rcode or 'UNSTATED'}); domain → "
                    "resolved IP cannot be established from it and is not "
                    "inferred")
            additional["zeek_rtt_seconds"] = _float(data.get("rtt"))
            additional["zeek_qclass_name"] = _str(data.get("qclass_name"))

        net.field_provenance = prov

        # ── D12 · the wire instant is the activity; the log-write is not ──
        ts_iso = _iso_from_zeek_ts(data.get("ts"))
        write_iso = _iso_from_zeek_ts(data.get("_write_ts"))
        etb = event_time_basis.resolve(
            activity=([(ts_iso,
                        f"zeek:{path}.log ts — the instant of the packet the "
                        "sensor observed on the wire")] if ts_iso else ()),
            observation=([(write_iso,
                           f"zeek:{path}.log _write_ts — when Zeek wrote the "
                           "log record")] if write_iso else ()),
            clock=now_iso,
            clock_source=f"pipeline:normalizer clock at {self.id}",
            activity_absent_reason=(
                "this Zeek record carried no `ts`; no other field in the "
                "conn/dns format names when the traffic occurred"),
            observation_absent_reason=(
                "this Zeek deployment did not emit `_write_ts`, so the "
                "log-write instant was not observed"))

        # Zeek knows an ADDRESS, not a device. `host` stays empty on
        # purpose so nothing downstream reads a network address as an
        # endpoint identity.
        host = HostEntity()
        additional["endpoint_identity_state"] = "NOT_OBSERVED"
        additional["endpoint_identity_reason"] = (
            "Zeek observes traffic on the wire: it supplies no host, user or "
            "process identity. Binding id.orig_h to a device requires an "
            "authoritative asset/DHCP inventory, which is ABSENT")

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=ZeekJsonParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="Zeek",
            source_product="Zeek / Corelight network sensor",
            source_event_id=_str(data.get("uid")),
            event_type=_EVENT_TYPE_BY_PATH[path],
            event_time=etb.event_time,
            ingest_time=now_iso,
            host=host,
            network=net,
            raw_ref=raw,
            provenance=provenance,
            additional_fields=additional,
        )
        out = canonical.to_dict()
        event_time_basis.apply(out, etb)
        tenant_authority.record(out, tenant_claim)
        return out


class ZeekJsonDSM:
    id = DSM_ID
    vendor = "Zeek"
    product = "Zeek / Corelight JSON logs (conn, dns)"
    version = "1"
    source_type = "NETWORK"

    capability = {
        "log_types": list(SUPPORTED_PATHS),
        "provides": [
            "flow 5-tuple (id.orig_h/p, id.resp_h/p, proto)",
            "bytes and packets by direction",
            "flow duration and connection state/history",
            "DNS query, query type and response code",
            "DNS answers — address records AND non-address records, split",
            "DNS TTLs, authoritative flag, rejected flag, transaction id",
            "Zeek flow uid (and community_id when the deployment emits one)",
            "wire-observation activity time; log-write observation time",
        ],
        "does_not_provide": [
            "process identity — Zeek cannot see which process opened a flow",
            "user identity",
            "endpoint/device identity — id.orig_h is an address, and binding "
            "it to a device needs an authoritative asset/DHCP inventory",
            "allow/deny enforcement action — Zeek observes, it does not deny",
            "NAT pre/post addresses, firewall rule names, zones",
            "reputation or known-malicious-infrastructure verdicts",
        ],
        "caveats": [
            "`_path` must be present; this DSM refuses records that do not "
            "declare their Zeek log type",
            "direction is reported only when the deployment states "
            "local_orig/local_resp",
            "a DNS record with no address answer establishes no domain → IP "
            "relationship and is recorded as such",
        ],
    }

    def supports(self, ev: Any) -> bool:
        if not isinstance(ev, dict):
            return False
        if _path_of(ev) not in SUPPORTED_PATHS:
            return False
        return _zeek_shaped(ev)

    def select_parser(self) -> ZeekJsonParser:
        return ZeekJsonParser()

    def select_normalizer(self) -> ZeekJsonNormalizer:
        return ZeekJsonNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {"id": self.id, "vendor": self.vendor, "product": self.product,
                "version": self.version, "source_type": self.source_type,
                "capability": self.capability}
